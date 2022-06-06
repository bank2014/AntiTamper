#pragma once

#include "BanStore.h"
#include "ClientRegistry.h"

#include <atomic>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace Backend
{
	struct BanRecord
	{
		std::string type;
		std::string key;
		std::string storage;
	};

	class BackendServer
	{
	public:
		using LogCallback = std::function<void(const std::string&)>;
		using RefreshCallback = std::function<void()>;

		BackendServer();
		~BackendServer();

		void SetCallbacks(LogCallback logCallback, RefreshCallback refreshCallback);
		bool Start(uint16_t port, const std::wstring& blacklistPath);
		void Stop();

		std::vector<ClientRecord> Clients() const;
		std::vector<ViolationRecord> Violations() const;
		std::vector<BanRecord> Bans() const;

		bool DisconnectSession(uint64_t sessionId);
		bool BanSession(uint64_t sessionId);
		bool BanMachine(uint64_t sessionId);
		bool UnbanSession(const std::string& clientGuid);
		bool UnbanMachine(const std::string& machineHwid);
		void ClearViolations(uint64_t sessionId);

	private:
		struct ManagedThread
		{
			std::thread thread;
			std::shared_ptr<std::atomic<bool>> finished;
		};

		void Log(const std::string& message) const;
		void Refresh() const;
		void AcceptThreadMain(uint16_t port);
		void ClientThreadMain(uint64_t sessionId, SocketHandle socket);
		bool HandleRequestLine(uint64_t sessionId, SocketHandle socket, const std::string& line);
		void ProcessPending(uint64_t sessionId, SocketHandle socket, std::string& pending);
		void CloseSessionsAsync(std::vector<uint64_t> sessionIds);
		void CloseListenSocket();
		void CloseSessionSocket(uint64_t sessionId);
		void CloseRawSocket(SocketHandle socket);
		bool SendReply(SocketHandle socket, const char* reply) const;
		void PruneFinishedThreads(std::vector<ManagedThread>& threads);
		void JoinAllThreads(std::vector<ManagedThread>& threads);
		void SignalStartup(bool succeeded);
		bool WaitForStartup();

		std::atomic<bool> _running;
		SocketHandle _listenSocket;
		mutable std::mutex _startupMutex;
		std::condition_variable _startupCv;
		bool _startupCompleted = false;
		bool _startupSucceeded = false;
		mutable std::mutex _listenSocketMutex;
		mutable std::mutex _threadMutex;
		mutable std::mutex _actionThreadMutex;
		std::thread _acceptThread;
		std::vector<ManagedThread> _clientThreads;
		std::vector<ManagedThread> _actionThreads;
		ClientRegistry _registry;
		std::unique_ptr<BanStore> _banStore;
		LogCallback _logCallback;
		RefreshCallback _refreshCallback;
	};
}
