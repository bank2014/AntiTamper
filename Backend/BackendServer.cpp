#include "BackendServer.h"

#include "BackendCommon.h"
#include "ProtocolHandler.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include <memory>
#include <sstream>
#include <cstring>
#include <algorithm>

#pragma comment(lib, "ws2_32.lib")

namespace Backend
{
	namespace
	{
		constexpr int kBufferSize = 512;
		constexpr size_t kMaxRequestBytes = 512;

		SOCKET ToSocket(SocketHandle socket)
		{
			return static_cast<SOCKET>(socket);
		}

		SocketHandle FromSocket(SOCKET socket)
		{
			return static_cast<SocketHandle>(socket);
		}
	}

	BackendServer::BackendServer()
		: _running(false), _listenSocket(0)
	{
	}

	BackendServer::~BackendServer()
	{
		Stop();
	}

	void BackendServer::SetCallbacks(LogCallback logCallback, RefreshCallback refreshCallback)
	{
		_logCallback = std::move(logCallback);
		_refreshCallback = std::move(refreshCallback);
	}

	bool BackendServer::Start(uint16_t port, const std::wstring& blacklistPath)
	{
		if (_running.exchange(true))
			return true;

		WSAData wsaData{};
		if (::WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
		{
			_running.store(false);
			return false;
		}

		_banStore.reset(new BanStore(blacklistPath));
		if (!_banStore->Load())
		{
			Log("Failed to load Blacklist.txt; server start aborted.");
			_banStore.reset();
			_running.store(false);
			::WSACleanup();
			Refresh();
			return false;
		}
		else
		{
			Log("Loaded machine ban list.");
		}

		{
			std::lock_guard<std::mutex> lock(_startupMutex);
			_startupCompleted = false;
			_startupSucceeded = false;
		}

		_acceptThread = std::thread([this, port]() { AcceptThreadMain(port); });
		if (!WaitForStartup())
		{
			if (_acceptThread.joinable())
				_acceptThread.join();

			_banStore.reset();
			::WSACleanup();
			Refresh();
			return false;
		}

		Refresh();
		return true;
	}

	void BackendServer::Stop()
	{
		if (!_running.exchange(false))
			return;

		CloseListenSocket();

		std::vector<ClientRecord> clients = _registry.Clients();
		for (const ClientRecord& client : clients)
			CloseSessionSocket(client.sessionId);

		if (_acceptThread.joinable())
			_acceptThread.join();

		{
			std::lock_guard<std::mutex> lock(_threadMutex);
			JoinAllThreads(_clientThreads);
		}

		{
			std::lock_guard<std::mutex> lock(_actionThreadMutex);
			JoinAllThreads(_actionThreads);
		}

		_registry.Clear();
		_banStore.reset();
		::WSACleanup();
		Log("Server stopped.");
		Refresh();
	}

	std::vector<ClientRecord> BackendServer::Clients() const
	{
		return _registry.Clients();
	}

	std::vector<ViolationRecord> BackendServer::Violations() const
	{
		return _registry.Violations();
	}

	std::vector<BanRecord> BackendServer::Bans() const
	{
		std::vector<BanRecord> bans;
		for (const std::string& clientGuid : _registry.SessionBans())
		{
			BanRecord record;
			record.type = "Session";
			record.key = clientGuid;
			record.storage = "Memory ClientGuid";
			bans.push_back(record);
		}

		if (_banStore)
		{
			for (const std::string& machineHwid : _banStore->Snapshot())
			{
				BanRecord record;
				record.type = "Machine";
				record.key = machineHwid;
				record.storage = "Blacklist.txt MachineHwid";
				bans.push_back(record);
			}
		}

		return bans;
	}

	bool BackendServer::DisconnectSession(uint64_t sessionId)
	{
		ClientRecord client;
		if (!_registry.GetClient(sessionId, client))
			return false;

		Log("Operator disconnected Session=" + std::to_string(sessionId) + " ClientGuid=" + client.clientGuid);
		CloseSessionsAsync(std::vector<uint64_t>{ sessionId });
		Refresh();
		return true;
	}

	bool BackendServer::BanSession(uint64_t sessionId)
	{
		ClientRecord client;
		if (!_registry.GetClient(sessionId, client))
			return false;

		if (!_registry.BanSession(client.clientGuid))
			return false;

		Log("Operator session-banned Session=" + std::to_string(sessionId) + " ClientGuid=" + client.clientGuid);
		CloseSessionsAsync(std::vector<uint64_t>{ sessionId });
		Refresh();
		return true;
	}

	bool BackendServer::BanMachine(uint64_t sessionId)
	{
		if (!_banStore)
			return false;

		ClientRecord client;
		if (!_registry.GetClient(sessionId, client))
			return false;

		if (!_banStore->Add(client.machineHwid))
			return false;

		Log("Operator machine-banned MachineHwid=" + client.machineHwid);
		const std::vector<uint64_t> sessions = _registry.SessionIdsForMachine(client.machineHwid);
		CloseSessionsAsync(sessions);
		Refresh();
		return true;
	}

	bool BackendServer::UnbanSession(const std::string& clientGuid)
	{
		if (!_registry.UnbanSession(clientGuid))
			return false;

		Log("Operator session-unbanned ClientGuid=" + clientGuid);
		Refresh();
		return true;
	}

	bool BackendServer::UnbanMachine(const std::string& machineHwid)
	{
		if (!_banStore || !_banStore->Remove(machineHwid))
			return false;

		Log("Operator machine-unbanned MachineHwid=" + machineHwid);
		Refresh();
		return true;
	}

	void BackendServer::ClearViolations(uint64_t sessionId)
	{
		_registry.ClearViolationsForSession(sessionId);
		Log("Cleared violations for Session=" + std::to_string(sessionId));
		Refresh();
	}

	void BackendServer::Log(const std::string& message) const
	{
		if (_logCallback)
			_logCallback("[" + NowText() + "] " + message);
	}

	void BackendServer::Refresh() const
	{
		if (_refreshCallback)
			_refreshCallback();
	}

	void BackendServer::AcceptThreadMain(uint16_t port)
	{
		SOCKET listenSocket = ::socket(AF_INET, SOCK_STREAM, 0);
		if (listenSocket == INVALID_SOCKET)
		{
			Log("socket failed. WSAError=" + std::to_string(::WSAGetLastError()));
			_running.store(false);
			SignalStartup(false);
			Refresh();
			return;
		}

		{
			std::lock_guard<std::mutex> lock(_listenSocketMutex);
			_listenSocket = FromSocket(listenSocket);
		}

		BOOL exclusiveAddressUse = TRUE;
		::setsockopt(
			listenSocket,
			SOL_SOCKET,
			SO_EXCLUSIVEADDRUSE,
			reinterpret_cast<const char*>(&exclusiveAddressUse),
			sizeof(exclusiveAddressUse));

		SOCKADDR_IN serverAddr{};
		serverAddr.sin_family = AF_INET;
		serverAddr.sin_addr.s_addr = ::htonl(INADDR_ANY);
		serverAddr.sin_port = ::htons(port);

		if (::bind(listenSocket, reinterpret_cast<SOCKADDR*>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR)
		{
			Log("bind 0.0.0.0:" + std::to_string(port) + " failed. WSAError=" + std::to_string(::WSAGetLastError()));
			CloseListenSocket();
			_running.store(false);
			SignalStartup(false);
			Refresh();
			return;
		}

		if (::listen(listenSocket, SOMAXCONN) == SOCKET_ERROR)
		{
			Log("listen failed. WSAError=" + std::to_string(::WSAGetLastError()));
			CloseListenSocket();
			_running.store(false);
			SignalStartup(false);
			Refresh();
			return;
		}

		Log("Listening on 0.0.0.0:" + std::to_string(port));
		SignalStartup(true);
		while (_running.load())
		{
			fd_set readSet{};
			FD_ZERO(&readSet);
			FD_SET(listenSocket, &readSet);

			timeval timeout{};
			timeout.tv_sec = 0;
			timeout.tv_usec = 250000;

			const int selected = ::select(0, &readSet, nullptr, nullptr, &timeout);
			if (selected == SOCKET_ERROR)
			{
				if (_running.load())
					Log("select failed. WSAError=" + std::to_string(::WSAGetLastError()));
				break;
			}

			if (selected == 0 || !FD_ISSET(listenSocket, &readSet))
				continue;

			SOCKADDR_IN clientAddr{};
			int addrLen = sizeof(clientAddr);
			SOCKET clientSocket = ::accept(listenSocket, reinterpret_cast<SOCKADDR*>(&clientAddr), &addrLen);
			if (clientSocket == INVALID_SOCKET)
			{
				if (_running.load())
					Log("accept failed. WSAError=" + std::to_string(::WSAGetLastError()));
				continue;
			}

			char ip[INET_ADDRSTRLEN]{};
			::inet_ntop(AF_INET, &clientAddr.sin_addr, ip, sizeof(ip));
			const uint64_t sessionId = _registry.AddClient(FromSocket(clientSocket), ip, NowText());

			Log("Client connected. Session=" + std::to_string(sessionId) + " IP=" + ip);
			Refresh();

			std::lock_guard<std::mutex> threadLock(_threadMutex);
			PruneFinishedThreads(_clientThreads);
			auto finished = std::make_shared<std::atomic<bool>>(false);
			_clientThreads.push_back(ManagedThread{
				std::thread([this, sessionId, clientSocket, finished]() {
					ClientThreadMain(sessionId, FromSocket(clientSocket));
					finished->store(true);
				}),
				finished
			});
		}

		CloseListenSocket();
		Log("Server accept loop stopped.");
	}

	void BackendServer::ClientThreadMain(uint64_t sessionId, SocketHandle socket)
	{
		DWORD timeoutMs = 1000;
		SOCKET rawSocket = ToSocket(socket);
		::setsockopt(rawSocket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeoutMs), sizeof(timeoutMs));
		::setsockopt(rawSocket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeoutMs), sizeof(timeoutMs));

		std::string pending;
		char buffer[kBufferSize]{};
		while (_running.load())
		{
			const int received = ::recv(rawSocket, buffer, sizeof(buffer) - 1, 0);
			if (received > 0)
			{
				buffer[received] = '\0';
				pending.append(buffer, received);
				ProcessPending(sessionId, socket, pending);
				continue;
			}

			const int error = received == SOCKET_ERROR ? ::WSAGetLastError() : 0;
			if (error == WSAETIMEDOUT)
				continue;
			break;
		}

		CloseSessionSocket(sessionId);
		ClientRecord client;
		if (_registry.GetClient(sessionId, client))
			Log("Client disconnected. Session=" + std::to_string(sessionId) + " ClientGuid=" + client.clientGuid);
		_registry.RemoveClient(sessionId);
		Refresh();
	}

	bool BackendServer::HandleRequestLine(uint64_t sessionId, SocketHandle socket, const std::string& line)
	{
		const ParsedRequest request = ParseRequestLine(line);
		if (request.kind == RequestKind::Invalid)
		{
			Log("Invalid request from Session=" + std::to_string(sessionId) + ": " + request.error);
			const std::string reply = BuildReply(ReplyStatus::Error, request.error);
			SendReply(socket, reply.c_str());
			CloseSessionSocket(sessionId);
			return false;
		}

		if (request.kind == RequestKind::Check || request.kind == RequestKind::Heartbeat)
		{
			const char* requestName = request.kind == RequestKind::Check ? "CHECK" : "HEARTBEAT";
			_registry.MarkClientRequest(sessionId, request.clientGuid, request.machineHwid, requestName, NowText());
			const bool banned = _registry.IsSessionBanned(request.clientGuid) || (_banStore && _banStore->IsBanned(request.machineHwid));
			const std::string reply = BanReply(banned);
			if (!SendReply(socket, reply.c_str()))
			{
				CloseSessionSocket(sessionId);
				return false;
			}
			Refresh();
			return true;
		}

		_registry.AddViolation(sessionId, request.severity, request.reason, request.clientGuid, request.machineHwid, NowText());
		Log("Violation: Session=" + std::to_string(sessionId)
			+ " ClientGuid=" + request.clientGuid
			+ " MachineHwid=" + request.machineHwid
			+ " severity=" + request.severity
			+ " reason=" + request.reason);
		const bool banned = _registry.IsSessionBanned(request.clientGuid) || (_banStore && _banStore->IsBanned(request.machineHwid));
		const std::string reply = BanReply(banned);
		if (!SendReply(socket, reply.c_str()))
		{
			CloseSessionSocket(sessionId);
			return false;
		}
		Refresh();
		return true;
	}

	void BackendServer::ProcessPending(uint64_t sessionId, SocketHandle socket, std::string& pending)
	{
		size_t lineEnd = std::string::npos;
		while ((lineEnd = pending.find('\n')) != std::string::npos)
		{
			std::string line = pending.substr(0, lineEnd);
			pending.erase(0, lineEnd + 1);
			if (!HandleRequestLine(sessionId, socket, line))
			{
				pending.clear();
				return;
			}
		}

		if (pending.size() > kMaxRequestBytes)
		{
			Log("Closing client with oversized pending request. Session=" + std::to_string(sessionId));
			CloseSessionSocket(sessionId);
			pending.clear();
		}
	}

	void BackendServer::CloseSessionsAsync(std::vector<uint64_t> sessionIds)
	{
		std::lock_guard<std::mutex> lock(_actionThreadMutex);
		PruneFinishedThreads(_actionThreads);
		auto finished = std::make_shared<std::atomic<bool>>(false);
		_actionThreads.push_back(ManagedThread{
			std::thread([this, sessionIds, finished]() {
				for (uint64_t sessionId : sessionIds)
					CloseSessionSocket(sessionId);
				Refresh();
				finished->store(true);
			}),
			finished
		});
	}

	void BackendServer::CloseListenSocket()
	{
		SocketHandle socket = 0;
		{
			std::lock_guard<std::mutex> lock(_listenSocketMutex);
			socket = _listenSocket;
			_listenSocket = 0;
		}
		CloseRawSocket(socket);
	}

	void BackendServer::CloseSessionSocket(uint64_t sessionId)
	{
		CloseRawSocket(_registry.TakeSocket(sessionId));
	}

	void BackendServer::CloseRawSocket(SocketHandle socket)
	{
		if (socket == 0)
			return;

		const SOCKET rawSocket = ToSocket(socket);
		::shutdown(rawSocket, SD_BOTH);
		::closesocket(rawSocket);
	}

	bool BackendServer::SendReply(SocketHandle socket, const char* reply) const
	{
		const SOCKET rawSocket = ToSocket(socket);
		const int totalLength = static_cast<int>(strlen(reply));
		int sentTotal = 0;
		while (sentTotal < totalLength)
		{
			const int sent = ::send(rawSocket, reply + sentTotal, totalLength - sentTotal, 0);
			if (sent == SOCKET_ERROR || sent == 0)
			{
				if (_running.load())
					Log("send reply failed. WSAError=" + std::to_string(::WSAGetLastError()));
				return false;
			}

			sentTotal += sent;
		}
		return true;
	}

	void BackendServer::PruneFinishedThreads(std::vector<ManagedThread>& threads)
	{
		for (ManagedThread& managedThread : threads)
		{
			if (managedThread.finished != nullptr
				&& managedThread.finished->load()
				&& managedThread.thread.joinable())
			{
				managedThread.thread.join();
			}
		}

		threads.erase(
			std::remove_if(threads.begin(), threads.end(), [](const ManagedThread& managedThread) {
				return managedThread.finished != nullptr && managedThread.finished->load() && !managedThread.thread.joinable();
			}),
			threads.end());
	}

	void BackendServer::JoinAllThreads(std::vector<ManagedThread>& threads)
	{
		for (ManagedThread& managedThread : threads)
		{
			if (managedThread.thread.joinable())
				managedThread.thread.join();
		}
		threads.clear();
	}

	void BackendServer::SignalStartup(bool succeeded)
	{
		{
			std::lock_guard<std::mutex> lock(_startupMutex);
			_startupSucceeded = succeeded;
			_startupCompleted = true;
		}
		_startupCv.notify_all();
	}

	bool BackendServer::WaitForStartup()
	{
		std::unique_lock<std::mutex> lock(_startupMutex);
		_startupCv.wait(lock, [this]() { return _startupCompleted; });
		return _startupSucceeded;
	}
}
