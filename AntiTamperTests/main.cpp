#include <cassert>
#include <atomic>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "BackendServer.h"
#include "BackendCommon.h"
#include "AntivirusState.h"
#include "BanStore.h"
#include "ClientIdentity.h"
#include "ClientRegistry.h"
#include "ClientNetworkRules.h"
#include "PeIntegrity.h"
#include "ProtocolHandler.h"

#pragma comment(lib, "ws2_32.lib")

namespace
{
	void TestClientIdentity()
	{
		using AntiTamperIdentity::BuildClientGuidForProcess;
		using AntiTamperIdentity::IsUsableMachineHwid;
		using AntiTamperIdentity::NormalizeGuid;

		assert(NormalizeGuid("  ABCD-1234 \r\n") == "abcd-1234");
		assert(IsUsableMachineHwid("machine-guid"));
		assert(!IsUsableMachineHwid(""));
		assert(!IsUsableMachineHwid("unknown-guid"));
		assert(!IsUsableMachineHwid("unknown-guid-suffix"));
		assert(!IsUsableMachineHwid("machine-unknown"));
		assert(!IsUsableMachineHwid("machine-unknown-suffix"));

		const std::string first = BuildClientGuidForProcess(" Machine-Guid ", 1000, 2000);
		const std::string same = BuildClientGuidForProcess("machine-guid", 1000, 2000);
		const std::string secondProcess = BuildClientGuidForProcess("machine-guid", 1001, 2000);
		const std::string secondStart = BuildClientGuidForProcess("machine-guid", 1000, 2001);

		assert(first == same);
		assert(first != secondProcess);
		assert(first != secondStart);
		assert(first.find("machine-guid") == 0);
		assert(first.size() <= 128);
		assert(BuildClientGuidForProcess("", 1000, 2000).empty());
		assert(BuildClientGuidForProcess("unknown-guid", 1000, 2000).empty());
		assert(BuildClientGuidForProcess("unknown-guid-suffix", 1000, 2000).empty());
	}

	void TestBackendCommon()
	{
		assert(Backend::NormalizeToken("  ABCD-1234 \r\n") == "abcd-1234");
		const std::wstring korean = Backend::Utf8ToWide("\xec\x84\x9c\xeb\xb2\x84");
		assert(korean == L"\xc11c\xbc84");

		std::wstring longPath = L"C:\\";
		longPath.append(300, L'a');
		longPath += L"\\Backend.exe";
		std::wstring expectedDirectory = L"C:\\";
		expectedDirectory.append(300, L'a');
		assert(Backend::GetDirectoryNameFromPath(longPath) == expectedDirectory);
	}

	void TestProtocolHandler()
	{
		Backend::ParsedRequest check = Backend::ParseRequestLine("CHECK|client-1|machine-1");
		assert(check.kind == Backend::RequestKind::Check);
		assert(check.clientGuid == "client-1");
		assert(check.machineHwid == "machine-1");

		Backend::ParsedRequest heartbeat = Backend::ParseRequestLine("HEARTBEAT|CLIENT-1|MACHINE-1");
		assert(heartbeat.kind == Backend::RequestKind::Heartbeat);
		assert(heartbeat.clientGuid == "client-1");
		assert(heartbeat.machineHwid == "machine-1");

		Backend::ParsedRequest violation = Backend::ParseRequestLine("VIOLATION|2|DebuggerAttached|client-1|machine-1");
		assert(violation.kind == Backend::RequestKind::Violation);
		assert(violation.severity == "2");
		assert(violation.reason == "DebuggerAttached");
		assert(violation.clientGuid == "client-1");
		assert(violation.machineHwid == "machine-1");

		assert(Backend::ParseRequestLine("CHECK|client-only").kind == Backend::RequestKind::Invalid);
		assert(Backend::ParseRequestLine("CHECK|client|unknown-guid").kind == Backend::RequestKind::Invalid);
		assert(Backend::ParseRequestLine("HEARTBEAT|client|machine-unknown").kind == Backend::RequestKind::Invalid);
		assert(Backend::ParseRequestLine("VIOLATION|2|reason|client-only").kind == Backend::RequestKind::Invalid);
		assert(Backend::ParseRequestLine("VIOLATION|2|reason|client|unknown-guid").kind == Backend::RequestKind::Invalid);
		assert(Backend::ParseRequestLine("VIOLATION|999|reason|client|machine").kind == Backend::RequestKind::Invalid);
		assert(Backend::ParseRequestLine("VIOLATION|abc|reason|client|machine").kind == Backend::RequestKind::Invalid);
		assert(Backend::ParseRequestLine("UNKNOWN|client|machine").kind == Backend::RequestKind::Invalid);

		assert(Backend::BuildReply(Backend::ReplyStatus::Allow) == "ALLOW\n");
		assert(Backend::BuildReply(Backend::ReplyStatus::Banned) == "BANNED\n");
		assert(Backend::BuildReply(Backend::ReplyStatus::Error, "bad-request") == "ERROR|bad-request\n");

		Backend::ParsedReply allow = Backend::ParseReplyLine("ALLOW");
		assert(allow.status == Backend::ReplyStatus::Allow);
		Backend::ParsedReply banned = Backend::ParseReplyLine("BANNED\r");
		assert(banned.status == Backend::ReplyStatus::Banned);
		Backend::ParsedReply error = Backend::ParseReplyLine("ERROR|bad-request");
		assert(error.status == Backend::ReplyStatus::Error);
		assert(error.error == "bad-request");
		assert(Backend::ParseReplyLine("Yes").status == Backend::ReplyStatus::Invalid);
	}

	void TestClientNetworkRules()
	{
		using AntiTamperNetworkRules::ClassifyReplyBuffer;
		using AntiTamperNetworkRules::ReplyParseResult;

		assert(ClassifyReplyBuffer("ALLOW\n") == ReplyParseResult::Allow);
		assert(ClassifyReplyBuffer("BANNED\r\n") == ReplyParseResult::Banned);
		assert(ClassifyReplyBuffer("ERROR|bad-request\n") == ReplyParseResult::ProtocolError);
		assert(ClassifyReplyBuffer("ALLOW") == ReplyParseResult::Incomplete);
		assert(ClassifyReplyBuffer(std::string(AntiTamperNetworkRules::kMaxReplyBytes + 1, 'A')) == ReplyParseResult::Oversized);
	}

	void TestAntivirusState()
	{
		using AntiTamperAntivirus::ClassifyWmiNextResult;
		using AntiTamperAntivirus::WmiNextDecision;

		assert(ClassifyWmiNextResult(WBEM_S_TIMEDOUT, 0) == WmiNextDecision::Unknown);
		assert(ClassifyWmiNextResult(WBEM_S_FALSE, 0) == WmiNextDecision::Finished);
		assert(ClassifyWmiNextResult(S_OK, 0) == WmiNextDecision::Finished);
		assert(ClassifyWmiNextResult(S_OK, 1) == WmiNextDecision::ProductAvailable);
		assert(ClassifyWmiNextResult(E_FAIL, 0) == WmiNextDecision::Unknown);
	}

	void TestPeIntegrityPolicy()
	{
		using PeIntegrity::IntegrityStatus;

		assert(PeIntegrity::EvaluateIntegrity(false, "", false, true, std::string(64, 'a')) == IntegrityStatus::MissingExpectedHash);
		assert(PeIntegrity::EvaluateIntegrity(true, "not-a-sha256", true, true, std::string(64, 'a')) == IntegrityStatus::InvalidExpectedHash);
		assert(PeIntegrity::EvaluateIntegrity(true, std::string(64, 'A'), false, true, std::string(64, 'a')) == IntegrityStatus::UntrustedManifest);
		assert(PeIntegrity::EvaluateIntegrity(true, std::string(64, 'A'), true, false, "") == IntegrityStatus::HashCalculationFailed);
		assert(PeIntegrity::EvaluateIntegrity(true, std::string(64, 'A'), true, true, std::string(64, 'a')) == IntegrityStatus::Clean);
		assert(PeIntegrity::EvaluateIntegrity(true, std::string(64, 'a'), true, true, std::string(64, 'b')) == IntegrityStatus::Tampered);

		assert(PeIntegrity::IsTamperStatus(IntegrityStatus::MissingExpectedHash));
		assert(PeIntegrity::IsTamperStatus(IntegrityStatus::InvalidExpectedHash));
		assert(PeIntegrity::IsTamperStatus(IntegrityStatus::UntrustedManifest));
		assert(PeIntegrity::IsTamperStatus(IntegrityStatus::HashCalculationFailed));
		assert(!PeIntegrity::IsTamperStatus(IntegrityStatus::Clean));

		const std::wstring modulePath = PeIntegrity::GetModulePathForAddress(reinterpret_cast<const void*>(&TestPeIntegrityPolicy));
		assert(modulePath.find(L"AntiTamperTests.exe") != std::wstring::npos);

		const std::string signedHash = PeIntegrity::kManifestSignatureTestHash;
		const std::string validSignature = PeIntegrity::kManifestSignatureTestSignature;
		assert(PeIntegrity::VerifyManifestSignature(signedHash, validSignature));

		std::string alteredSignature = validSignature;
		alteredSignature.back() = alteredSignature.back() == '0' ? '1' : '0';
		assert(!PeIntegrity::VerifyManifestSignature(signedHash, alteredSignature));

		PeIntegrity::ExpectedManifest manifest;
		const std::string fullManifest =
			std::string(PeIntegrity::kManifestMagic) + "\r\n" +
			signedHash + "\r\n" +
			validSignature + "\r\n";
		assert(PeIntegrity::ParseManifestText(fullManifest, manifest));
		assert(manifest.hash == signedHash);
		assert(manifest.signature == validSignature);
	}

	void TestBanStore()
	{
		const std::wstring path = L"BackendBanStoreTest.txt";
		std::remove("BackendBanStoreTest.txt");

		Backend::BanStore store(path);
		assert(store.Load());
		assert(!store.IsBanned("machine-a"));
		assert(store.Add(" Machine-A "));
		assert(store.IsBanned("machine-a"));
		assert(store.Add("machine-a"));
		assert(store.Remove("machine-a"));
		assert(!store.IsBanned("machine-a"));
		assert(store.Add("machine-b"));

		Backend::BanStore loaded(path);
		assert(loaded.Load());
		assert(!loaded.IsBanned("machine-a"));
		assert(loaded.IsBanned("machine-b"));
		assert(loaded.Remove("machine-b"));
		assert(!loaded.IsBanned("machine-b"));
		std::remove("BackendBanStoreTest.txt");
	}

	void TestBanStoreConcurrentDuplicateAdd()
	{
		const std::wstring path = L"BackendBanStoreConcurrentTest.txt";
		std::remove("BackendBanStoreConcurrentTest.txt");

		Backend::BanStore store(path);
		assert(store.Load());

		std::atomic<bool> start(false);
		std::atomic<int> failures(0);
		std::vector<std::thread> threads;
		for (int i = 0; i < 32; ++i)
		{
			threads.emplace_back([&]() {
				while (!start.load())
					std::this_thread::yield();
				if (!store.Add("machine-concurrent"))
					++failures;
			});
		}

		start.store(true);
		for (std::thread& thread : threads)
			thread.join();

		assert(failures.load() == 0);

		std::ifstream file("BackendBanStoreConcurrentTest.txt");
		std::string line;
		int matchingLines = 0;
		while (std::getline(file, line))
		{
			if (Backend::NormalizeToken(line) == "machine-concurrent")
				++matchingLines;
		}

		assert(matchingLines == 1);
		file.close();
		std::remove("BackendBanStoreConcurrentTest.txt");
	}

	void TestBanStoreLoadRejectsUnreadablePath()
	{
		const wchar_t* path = L"BackendBanStoreDirectoryTest";
		::RemoveDirectoryW(path);
		assert(::CreateDirectoryW(path, nullptr));

		Backend::BanStore store(path);
		assert(!store.Load());

		::RemoveDirectoryW(path);
	}

	void TestBanStoreRemoveDoesNotRewriteOnNoOp()
	{
		const std::wstring path = L"BackendBanStoreNoOpRemoveTest.txt";
		std::remove("BackendBanStoreNoOpRemoveTest.txt");

		Backend::BanStore store(path);
		assert(store.Load());
		assert(store.Add("machine-a"));

		FILETIME beforeWrite{};
		WIN32_FILE_ATTRIBUTE_DATA beforeAttributes{};
		assert(::GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &beforeAttributes));
		beforeWrite = beforeAttributes.ftLastWriteTime;

		assert(store.Remove("machine-b"));

		WIN32_FILE_ATTRIBUTE_DATA afterAttributes{};
		assert(::GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &afterAttributes));
		assert(::CompareFileTime(&beforeWrite, &afterAttributes.ftLastWriteTime) == 0);
		assert(store.IsBanned("machine-a"));
		std::remove("BackendBanStoreNoOpRemoveTest.txt");
	}

	void TestClientRegistry()
	{
		Backend::ClientRegistry registry;
		const uint64_t first = registry.AddClient(1, "127.0.0.1", "10:00:00");
		const uint64_t second = registry.AddClient(2, "127.0.0.1", "10:00:01");

		registry.MarkClientRequest(first, "client-a", "machine-a", "HEARTBEAT", "10:00:02");
		registry.MarkClientRequest(second, "client-b", "machine-a", "HEARTBEAT", "10:00:02");
		assert(!registry.IsSessionBanned("client-a"));
		assert(!registry.IsSessionBanned("client-b"));

		assert(registry.BanSession("client-a"));
		assert(registry.IsSessionBanned("client-a"));
		assert(!registry.IsSessionBanned("client-b"));
		std::vector<std::string> sessionBans = registry.SessionBans();
		assert(sessionBans.size() == 1);
		assert(sessionBans[0] == "client-a");
		assert(registry.UnbanSession("client-a"));
		assert(!registry.IsSessionBanned("client-a"));
		assert(registry.SessionBans().empty());

		std::vector<uint64_t> machineSessions = registry.SessionIdsForMachine("machine-a");
		assert(machineSessions.size() == 2);

		registry.AddViolation(first, "2", "DebuggerAttached", "client-a", "machine-a", "10:00:03");
		assert(registry.Violations().size() == 1);
		registry.ClearViolationsForSession(first);
		assert(registry.Violations().empty());
	}

	SOCKET ConnectToLocalServer(uint16_t port)
	{
		SOCKET socketHandle = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		assert(socketHandle != INVALID_SOCKET);

		sockaddr_in address{};
		address.sin_family = AF_INET;
		address.sin_port = htons(port);
		inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);

		for (int attempt = 0; attempt < 50; ++attempt)
		{
			if (::connect(socketHandle, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0)
				return socketHandle;
			std::this_thread::sleep_for(std::chrono::milliseconds(20));
		}

		assert(false && "connect to local backend failed");
		return INVALID_SOCKET;
	}

	std::string ReceiveReply(SOCKET socketHandle)
	{
		std::string reply;
		char buffer[64]{};
		while (reply.find('\n') == std::string::npos)
		{
			const int received = ::recv(socketHandle, buffer, sizeof(buffer) - 1, 0);
			assert(received > 0);
			reply.append(buffer, received);
		}

		return reply;
	}

	bool WaitForConnectionClosed(SOCKET socketHandle)
	{
		DWORD timeoutMs = 250;
		::setsockopt(socketHandle, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeoutMs), sizeof(timeoutMs));

		const DWORD deadline = ::GetTickCount() + 3000;
		while (::GetTickCount() < deadline)
		{
			char buffer[64]{};
			const int received = ::recv(socketHandle, buffer, sizeof(buffer), 0);
			if (received == 0)
				return true;
			if (received == SOCKET_ERROR)
			{
				const int error = ::WSAGetLastError();
				if (error == WSAETIMEDOUT)
					continue;
				return true;
			}
		}

		return false;
	}

	struct TestClientConnection
	{
		explicit TestClientConnection(uint16_t port)
			: socketHandle(ConnectToLocalServer(port))
		{
		}

		~TestClientConnection()
		{
			if (socketHandle != INVALID_SOCKET)
				::closesocket(socketHandle);
		}

		std::string Send(const std::string& request)
		{
			const std::string line = request + "\n";
			const int sent = ::send(socketHandle, line.c_str(), static_cast<int>(line.size()), 0);
			assert(sent == static_cast<int>(line.size()));
			return ReceiveReply(socketHandle);
		}

		void SendRaw(const std::string& request)
		{
			const int sent = ::send(socketHandle, request.c_str(), static_cast<int>(request.size()), 0);
			assert(sent == static_cast<int>(request.size()));
		}

		SOCKET socketHandle = INVALID_SOCKET;
	};

	std::string SendBackendRequest(uint16_t port, const std::string& request)
	{
		TestClientConnection connection(port);
		return connection.Send(request);
	}

	uint64_t FindSessionByClientGuid(Backend::BackendServer& server, const std::string& clientGuid)
	{
		for (int attempt = 0; attempt < 50; ++attempt)
		{
			for (const Backend::ClientRecord& client : server.Clients())
			{
				if (client.clientGuid == clientGuid)
					return client.sessionId;
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(20));
		}

		assert(false && "client session was not registered");
		return 0;
	}

	void TestBackendIntegration()
	{
		WSAData wsaData{};
		assert(::WSAStartup(MAKEWORD(2, 2), &wsaData) == 0);

		const uint16_t port = 17777;
		const std::wstring blacklistPath = L"BackendIntegrationBlacklist.txt";
		std::remove("BackendIntegrationBlacklist.txt");

		Backend::BackendServer server;
		assert(server.Start(port, blacklistPath));

		TestClientConnection clientA(port);
		assert(clientA.Send("CHECK|client-a|machine-a") == "ALLOW\n");
		TestClientConnection invalidClient(port);
		assert(invalidClient.Send("BAD|client-a|machine-a") == "ERROR|unknown request kind\n");
		assert(WaitForConnectionClosed(invalidClient.socketHandle));

		TestClientConnection oversizedLineClient(port);
		oversizedLineClient.SendRaw(std::string(513, 'A') + "\n");
		assert(WaitForConnectionClosed(oversizedLineClient.socketHandle));

		TestClientConnection oversizedPendingClient(port);
		oversizedPendingClient.SendRaw(std::string(513, 'A'));
		assert(WaitForConnectionClosed(oversizedPendingClient.socketHandle));

		const uint64_t firstSession = FindSessionByClientGuid(server, "client-a");
		assert(server.BanSession(firstSession));
		assert(SendBackendRequest(port, "HEARTBEAT|client-a|machine-a") == "BANNED\n");

		TestClientConnection clientB(port);
		assert(clientB.Send("CHECK|client-b|machine-a") == "ALLOW\n");

		const uint64_t secondSession = FindSessionByClientGuid(server, "client-b");
		assert(server.BanMachine(secondSession));
		assert(SendBackendRequest(port, "CHECK|client-c|machine-a") == "BANNED\n");
		assert(server.UnbanMachine("machine-a"));
		assert(SendBackendRequest(port, "CHECK|client-c|machine-a") == "ALLOW\n");

		server.Stop();
		std::remove("BackendIntegrationBlacklist.txt");
		::WSACleanup();
	}

	void TestBackendStartFailsWhenPortIsAlreadyBound()
	{
		WSAData wsaData{};
		assert(::WSAStartup(MAKEWORD(2, 2), &wsaData) == 0);

		const uint16_t port = 17778;
		SOCKET occupiedSocket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		assert(occupiedSocket != INVALID_SOCKET);

		BOOL exclusiveAddressUse = TRUE;
		::setsockopt(
			occupiedSocket,
			SOL_SOCKET,
			SO_EXCLUSIVEADDRUSE,
			reinterpret_cast<const char*>(&exclusiveAddressUse),
			sizeof(exclusiveAddressUse));

		sockaddr_in address{};
		address.sin_family = AF_INET;
		address.sin_port = htons(port);
		address.sin_addr.s_addr = htonl(INADDR_ANY);
		assert(::bind(occupiedSocket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
		assert(::listen(occupiedSocket, SOMAXCONN) == 0);

		Backend::BackendServer server;
		assert(!server.Start(port, L"BackendStartFailureBlacklist.txt"));

		server.Stop();
		::closesocket(occupiedSocket);
		std::remove("BackendStartFailureBlacklist.txt");
		::WSACleanup();
	}

	void TestBackendStartFailsWhenBlacklistLoadFails()
	{
		WSAData wsaData{};
		assert(::WSAStartup(MAKEWORD(2, 2), &wsaData) == 0);

		const uint16_t port = 17779;
		const wchar_t* blacklistPath = L"BackendUnreadableBlacklist";
		::RemoveDirectoryW(blacklistPath);
		assert(::CreateDirectoryW(blacklistPath, nullptr));

		Backend::BackendServer server;
		const bool started = server.Start(port, blacklistPath);
		if (started)
			server.Stop();
		assert(!started);

		::RemoveDirectoryW(blacklistPath);
		::WSACleanup();
	}
}

int main()
{
	TestClientIdentity();
	TestBackendCommon();
	TestProtocolHandler();
	TestClientNetworkRules();
	TestAntivirusState();
		TestPeIntegrityPolicy();
		TestBanStore();
		TestBanStoreConcurrentDuplicateAdd();
		TestBanStoreLoadRejectsUnreadablePath();
		TestBanStoreRemoveDoesNotRewriteOnNoOp();
		TestClientRegistry();
	TestBackendIntegration();
	TestBackendStartFailsWhenPortIsAlreadyBound();
	TestBackendStartFailsWhenBlacklistLoadFails();

	std::cout << "AntiTamperTests passed\n";
	return 0;
}
