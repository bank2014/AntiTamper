#include "ProtocolHandler.h"

#include "BackendCommon.h"

#include <cstring>
#include <vector>

namespace Backend
{
	namespace
	{
		std::vector<std::string> SplitPipe(const std::string& text)
		{
			std::vector<std::string> parts;
			size_t start = 0;
			while (start <= text.size())
			{
				const size_t separator = text.find('|', start);
				if (separator == std::string::npos)
				{
					parts.push_back(text.substr(start));
					break;
				}

				parts.push_back(text.substr(start, separator - start));
				start = separator + 1;
			}
			return parts;
		}

		ParsedRequest InvalidRequest(const char* error)
		{
			ParsedRequest request;
			request.error = error;
			return request;
		}

		bool IsValidViolationSeverity(const std::string& severity)
		{
			return severity == "0" || severity == "1" || severity == "2";
		}
	}

	ParsedRequest ParseRequestLine(const std::string& rawLine)
	{
		if (rawLine.empty())
			return InvalidRequest("empty request");
		if (rawLine.size() > 512)
			return InvalidRequest("oversized request");

		std::string line = rawLine;
		if (!line.empty() && line.back() == '\r')
			line.pop_back();

		const std::vector<std::string> parts = SplitPipe(line);
		if (parts.empty())
			return InvalidRequest("missing request kind");

		ParsedRequest request;
		const std::string kind = parts[0];
		if (kind == "CHECK" || kind == "HEARTBEAT")
		{
			if (parts.size() != 3)
				return InvalidRequest("identity request needs clientGuid and machineHwid");

			request.kind = kind == "CHECK" ? RequestKind::Check : RequestKind::Heartbeat;
			request.clientGuid = NormalizeToken(parts[1]);
			request.machineHwid = NormalizeToken(parts[2]);
			if (!IsUsableIdentityToken(request.clientGuid) || !IsUsableIdentityToken(request.machineHwid))
				return InvalidRequest("invalid identity");
			return request;
		}

		if (kind == "VIOLATION")
		{
			if (parts.size() != 5)
				return InvalidRequest("violation request needs severity, reason, clientGuid, and machineHwid");

			request.kind = RequestKind::Violation;
			request.severity = NormalizeToken(parts[1]);
			request.reason = Trim(parts[2]);
			request.clientGuid = NormalizeToken(parts[3]);
			request.machineHwid = NormalizeToken(parts[4]);
			if (!IsValidViolationSeverity(request.severity) || !IsUsableIdentityToken(request.clientGuid) || !IsUsableIdentityToken(request.machineHwid))
				return InvalidRequest("empty violation field");
			if (request.reason.empty())
				request.reason = "Unknown";
			return request;
		}

		return InvalidRequest("unknown request kind");
	}

	std::string BuildReply(ReplyStatus status, const std::string& error)
	{
		switch (status)
		{
		case ReplyStatus::Allow:
			return "ALLOW\n";
		case ReplyStatus::Banned:
			return "BANNED\n";
		case ReplyStatus::Error:
			return "ERROR|" + (error.empty() ? std::string("unknown") : NormalizeToken(error)) + "\n";
		default:
			return "ERROR|invalid-reply\n";
		}
	}

	ParsedReply ParseReplyLine(const std::string& rawLine)
	{
		ParsedReply reply;
		std::string line = rawLine;
		if (!line.empty() && line.back() == '\r')
			line.pop_back();

		if (line == "ALLOW")
		{
			reply.status = ReplyStatus::Allow;
			return reply;
		}

		if (line == "BANNED")
		{
			reply.status = ReplyStatus::Banned;
			return reply;
		}

		constexpr const char* kErrorPrefix = "ERROR|";
		if (line.find(kErrorPrefix) == 0)
		{
			reply.status = ReplyStatus::Error;
			reply.error = NormalizeToken(line.substr(strlen(kErrorPrefix)));
			if (reply.error.empty())
				reply.error = "unknown";
			return reply;
		}

		return reply;
	}

	const char* ViolationLevelName(const std::string& severity)
	{
		if (severity == "0")
			return "Trivial";
		if (severity == "1")
			return "Moderate";
		if (severity == "2")
			return "Severe";
		return "Unknown";
	}

	std::string BanReply(bool banned)
	{
		return BuildReply(banned ? ReplyStatus::Banned : ReplyStatus::Allow);
	}
}
