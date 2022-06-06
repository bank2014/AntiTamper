#pragma once

#include <cstdint>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace Backend
{
	using SocketHandle = uintptr_t;

	struct ClientRecord
	{
		uint64_t sessionId = 0;
		SocketHandle socket = 0;
		std::string ip;
		std::string clientGuid = "unknown";
		std::string machineHwid = "unknown";
		std::string lastRequest = "connected";
		std::string lastSeen;
		std::string status = "Connected";
	};

	struct ViolationRecord
	{
		uint64_t sessionId = 0;
		std::string clientGuid;
		std::string machineHwid;
		std::string ip;
		std::string severity;
		std::string level;
		std::string reason;
		std::string time;
	};

	class ClientRegistry
	{
	public:
		uint64_t AddClient(SocketHandle socket, const std::string& ip, const std::string& now);
		bool RemoveClient(uint64_t sessionId);
		bool GetClient(uint64_t sessionId, ClientRecord& out) const;
		std::vector<ClientRecord> Clients() const;
		std::vector<ViolationRecord> Violations() const;

		bool MarkClientRequest(uint64_t sessionId, const std::string& clientGuid, const std::string& machineHwid, const std::string& request, const std::string& now);
		bool AddViolation(uint64_t sessionId, const std::string& severity, const std::string& reason, const std::string& clientGuid, const std::string& machineHwid, const std::string& now);
		void ClearViolationsForSession(uint64_t sessionId);

		bool BanSession(const std::string& clientGuid);
		bool UnbanSession(const std::string& clientGuid);
		bool IsSessionBanned(const std::string& clientGuid) const;
		std::vector<std::string> SessionBans() const;
		std::vector<uint64_t> SessionIdsForMachine(const std::string& machineHwid) const;
		SocketHandle TakeSocket(uint64_t sessionId);
		void Clear();

	private:
		mutable std::mutex _mutex;
		uint64_t _nextSessionId = 1;
		std::map<uint64_t, ClientRecord> _clients;
		std::vector<ViolationRecord> _violations;
		std::set<std::string> _sessionBans;
	};
}
