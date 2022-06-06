#include "ClientRegistry.h"

#include "BackendCommon.h"
#include "ProtocolHandler.h"

#include <algorithm>

namespace Backend
{
	namespace
	{
		bool IsValidIdentity(const std::string& value)
		{
			return IsUsableIdentityToken(value);
		}
	}

	uint64_t ClientRegistry::AddClient(SocketHandle socket, const std::string& ip, const std::string& now)
	{
		std::lock_guard<std::mutex> lock(_mutex);
		const uint64_t sessionId = _nextSessionId++;

		ClientRecord record;
		record.sessionId = sessionId;
		record.socket = socket;
		record.ip = ip;
		record.lastSeen = now;
		_clients[sessionId] = record;
		return sessionId;
	}

	bool ClientRegistry::RemoveClient(uint64_t sessionId)
	{
		std::lock_guard<std::mutex> lock(_mutex);
		return _clients.erase(sessionId) != 0;
	}

	bool ClientRegistry::GetClient(uint64_t sessionId, ClientRecord& out) const
	{
		std::lock_guard<std::mutex> lock(_mutex);
		const auto found = _clients.find(sessionId);
		if (found == _clients.end())
			return false;
		out = found->second;
		return true;
	}

	std::vector<ClientRecord> ClientRegistry::Clients() const
	{
		std::lock_guard<std::mutex> lock(_mutex);
		std::vector<ClientRecord> result;
		for (const auto& entry : _clients)
			result.push_back(entry.second);
		return result;
	}

	std::vector<ViolationRecord> ClientRegistry::Violations() const
	{
		std::lock_guard<std::mutex> lock(_mutex);
		return _violations;
	}

	bool ClientRegistry::MarkClientRequest(uint64_t sessionId, const std::string& clientGuid, const std::string& machineHwid, const std::string& request, const std::string& now)
	{
		std::lock_guard<std::mutex> lock(_mutex);
		const auto found = _clients.find(sessionId);
		if (found == _clients.end())
			return false;

		found->second.clientGuid = NormalizeToken(clientGuid);
		found->second.machineHwid = NormalizeToken(machineHwid);
		found->second.lastRequest = request;
		found->second.lastSeen = now;
		found->second.status = _sessionBans.find(found->second.clientGuid) != _sessionBans.end() ? "Session Banned" : "Connected";
		return true;
	}

	bool ClientRegistry::AddViolation(uint64_t sessionId, const std::string& severity, const std::string& reason, const std::string& clientGuid, const std::string& machineHwid, const std::string& now)
	{
		std::lock_guard<std::mutex> lock(_mutex);
		const auto found = _clients.find(sessionId);
		if (found == _clients.end())
			return false;

		found->second.clientGuid = NormalizeToken(clientGuid);
		found->second.machineHwid = NormalizeToken(machineHwid);
		found->second.lastRequest = "VIOLATION";
		found->second.lastSeen = now;

		ViolationRecord event;
		event.sessionId = sessionId;
		event.ip = found->second.ip;
		event.clientGuid = found->second.clientGuid;
		event.machineHwid = found->second.machineHwid;
		event.severity = NormalizeToken(severity);
		event.level = ViolationLevelName(event.severity);
		event.reason = reason.empty() ? "Unknown" : reason;
		event.time = now;
		_violations.push_back(event);
		return true;
	}

	void ClientRegistry::ClearViolationsForSession(uint64_t sessionId)
	{
		std::lock_guard<std::mutex> lock(_mutex);
		_violations.erase(
			std::remove_if(_violations.begin(), _violations.end(), [sessionId](const ViolationRecord& event) {
				return event.sessionId == sessionId;
			}),
			_violations.end());
	}

	bool ClientRegistry::BanSession(const std::string& clientGuid)
	{
		const std::string normalized = NormalizeToken(clientGuid);
		if (!IsValidIdentity(normalized))
			return false;

		std::lock_guard<std::mutex> lock(_mutex);
		_sessionBans.insert(normalized);
		for (auto& entry : _clients)
		{
			if (entry.second.clientGuid == normalized)
				entry.second.status = "Session Banned";
		}
		return true;
	}

	bool ClientRegistry::UnbanSession(const std::string& clientGuid)
	{
		const std::string normalized = NormalizeToken(clientGuid);
		if (!IsValidIdentity(normalized))
			return false;

		std::lock_guard<std::mutex> lock(_mutex);
		if (_sessionBans.erase(normalized) == 0)
			return true;

		for (auto& entry : _clients)
		{
			if (entry.second.clientGuid == normalized && entry.second.status == "Session Banned")
				entry.second.status = "Connected";
		}
		return true;
	}

	bool ClientRegistry::IsSessionBanned(const std::string& clientGuid) const
	{
		const std::string normalized = NormalizeToken(clientGuid);
		std::lock_guard<std::mutex> lock(_mutex);
		return _sessionBans.find(normalized) != _sessionBans.end();
	}

	std::vector<std::string> ClientRegistry::SessionBans() const
	{
		std::lock_guard<std::mutex> lock(_mutex);
		return std::vector<std::string>(_sessionBans.begin(), _sessionBans.end());
	}

	std::vector<uint64_t> ClientRegistry::SessionIdsForMachine(const std::string& machineHwid) const
	{
		const std::string normalized = NormalizeToken(machineHwid);
		std::lock_guard<std::mutex> lock(_mutex);
		std::vector<uint64_t> result;
		for (const auto& entry : _clients)
		{
			if (entry.second.machineHwid == normalized)
				result.push_back(entry.first);
		}
		return result;
	}

	SocketHandle ClientRegistry::TakeSocket(uint64_t sessionId)
	{
		std::lock_guard<std::mutex> lock(_mutex);
		const auto found = _clients.find(sessionId);
		if (found == _clients.end())
			return 0;

		const SocketHandle socket = found->second.socket;
		found->second.socket = 0;
		found->second.status = "Disconnecting";
		return socket;
	}

	void ClientRegistry::Clear()
	{
		std::lock_guard<std::mutex> lock(_mutex);
		_clients.clear();
		_violations.clear();
		_sessionBans.clear();
	}
}
