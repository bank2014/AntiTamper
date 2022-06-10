#pragma once

#include <string>

namespace AntiTamperNetworkRules
{
	constexpr size_t kMaxReplyBytes = 512;

	enum class ReplyParseResult
	{
		Incomplete,
		Allow,
		Banned,
		ProtocolError,
		Oversized
	};

	inline ReplyParseResult ClassifyReplyBuffer(const std::string& replyBuffer)
	{
		if (replyBuffer.size() > kMaxReplyBytes)
			return ReplyParseResult::Oversized;

		const size_t lineEnd = replyBuffer.find('\n');
		if (lineEnd == std::string::npos)
			return ReplyParseResult::Incomplete;

		std::string line = replyBuffer.substr(0, lineEnd);
		if (!line.empty() && line.back() == '\r')
			line.pop_back();

		if (line == "ALLOW")
			return ReplyParseResult::Allow;
		if (line == "BANNED")
			return ReplyParseResult::Banned;
		if (line.find("ERROR|") == 0)
			return ReplyParseResult::ProtocolError;
		return ReplyParseResult::ProtocolError;
	}
}
