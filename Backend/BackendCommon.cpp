#include "BackendCommon.h"

#include <windows.h>

#include <chrono>
#include <cctype>
#include <iomanip>
#include <sstream>
#include <vector>

namespace Backend
{
	std::wstring Utf8ToWide(const std::string& text)
	{
		if (text.empty())
			return std::wstring();

		const int required = ::MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, nullptr, 0);
		if (required <= 1)
			return std::wstring(text.begin(), text.end());

		std::wstring result(static_cast<size_t>(required), L'\0');
		const int converted = ::MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, &result[0], required);
		if (converted <= 0)
			return std::wstring(text.begin(), text.end());

		if (!result.empty() && result.back() == L'\0')
			result.pop_back();
		return result;
	}

	std::string ToLowerAscii(std::string value)
	{
		for (char& ch : value)
			ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
		return value;
	}

	std::string Trim(std::string value)
	{
		while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())))
			value.erase(value.begin());
		while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())))
			value.pop_back();
		return value;
	}

	std::string NormalizeToken(std::string value)
	{
		return ToLowerAscii(Trim(value));
	}

	bool IsUsableIdentityToken(const std::string& value)
	{
		const std::string normalized = NormalizeToken(value);
		return !normalized.empty()
			&& normalized != "unknown"
			&& normalized != "unknown-guid"
			&& normalized != "machine-unknown"
			&& normalized.find("unknown-guid") != 0
			&& normalized.find("machine-unknown") != 0;
	}

	std::string NowText()
	{
		const auto now = std::chrono::system_clock::now();
		const time_t timeValue = std::chrono::system_clock::to_time_t(now);
		tm localTime{};
		localtime_s(&localTime, &timeValue);

		std::ostringstream stream;
		stream << std::put_time(&localTime, "%H:%M:%S");
		return stream.str();
	}

	std::wstring GetDirectoryNameFromPath(std::wstring path)
	{
		const size_t slash = path.find_last_of(L"\\/");
		if (slash != std::wstring::npos)
			path.erase(slash);
		return path;
	}

	std::wstring GetExeDirectory()
	{
		std::vector<wchar_t> path(MAX_PATH);
		while (true)
		{
			const DWORD copied = ::GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
			if (copied == 0)
				return std::wstring();
			if (copied < path.size() - 1)
				return GetDirectoryNameFromPath(std::wstring(path.data(), copied));
			path.resize(path.size() * 2);
		}
	}
}
