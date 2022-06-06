#pragma once

#include <cstdint>
#include <string>

namespace Backend
{
	std::wstring Utf8ToWide(const std::string& text);
	std::string ToLowerAscii(std::string value);
	std::string Trim(std::string value);
	std::string NormalizeToken(std::string value);
	bool IsUsableIdentityToken(const std::string& value);
	std::string NowText();
	std::wstring GetDirectoryNameFromPath(std::wstring path);
	std::wstring GetExeDirectory();
}
