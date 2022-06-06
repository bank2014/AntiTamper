#pragma once

#include <string>

namespace Backend
{
	enum class RequestKind
	{
		Invalid,
		Check,
		Heartbeat,
		Violation
	};

	enum class ReplyStatus
	{
		Invalid,
		Allow,
		Banned,
		Error
	};

	struct ParsedRequest
	{
		RequestKind kind = RequestKind::Invalid;
		std::string severity;
		std::string reason;
		std::string clientGuid;
		std::string machineHwid;
		std::string error;
	};

	struct ParsedReply
	{
		ReplyStatus status = ReplyStatus::Invalid;
		std::string error;
	};

	ParsedRequest ParseRequestLine(const std::string& line);
	std::string BuildReply(ReplyStatus status, const std::string& error = std::string());
	ParsedReply ParseReplyLine(const std::string& line);
	const char* ViolationLevelName(const std::string& severity);
	std::string BanReply(bool banned);
}
