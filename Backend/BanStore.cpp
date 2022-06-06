#include "BanStore.h"

#include "BackendCommon.h"

#include <windows.h>

#include <sstream>
#include <utility>

namespace Backend
{
	namespace
	{
		bool AppendLineToFile(const std::wstring& path, const std::string& line)
		{
			HANDLE file = ::CreateFileW(
				path.c_str(),
				FILE_APPEND_DATA,
				FILE_SHARE_READ,
				nullptr,
				OPEN_ALWAYS,
				FILE_ATTRIBUTE_NORMAL,
				nullptr);

			if (file == INVALID_HANDLE_VALUE)
				return false;

			const std::string text = line + "\r\n";
			DWORD bytesWritten = 0;
			const BOOL written = ::WriteFile(file, text.data(), static_cast<DWORD>(text.size()), &bytesWritten, nullptr);
			::CloseHandle(file);
			return written && bytesWritten == text.size();
		}

		std::wstring BuildTemporaryPath(const std::wstring& path)
		{
			return path + L".tmp";
		}

		bool WriteLinesToTemporaryFile(const std::wstring& path, const std::set<std::string>& lines)
		{
			HANDLE file = ::CreateFileW(
				path.c_str(),
				GENERIC_WRITE,
				0,
				nullptr,
				CREATE_ALWAYS,
				FILE_ATTRIBUTE_NORMAL,
				nullptr);

			if (file == INVALID_HANDLE_VALUE)
				return false;

			std::string text;
			for (const std::string& line : lines)
				text += line + "\r\n";

			DWORD bytesWritten = 0;
			const BOOL written = text.empty()
				? TRUE
				: ::WriteFile(file, text.data(), static_cast<DWORD>(text.size()), &bytesWritten, nullptr);
			if (written)
				::FlushFileBuffers(file);
			::CloseHandle(file);
			return written && bytesWritten == text.size();
		}

		bool ReplaceFileAtomically(const std::wstring& path, const std::set<std::string>& lines)
		{
			const std::wstring temporaryPath = BuildTemporaryPath(path);
			::DeleteFileW(temporaryPath.c_str());

			if (!WriteLinesToTemporaryFile(temporaryPath, lines))
			{
				::DeleteFileW(temporaryPath.c_str());
				return false;
			}

			if (::MoveFileExW(
				temporaryPath.c_str(),
				path.c_str(),
				MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
				return true;

			::DeleteFileW(temporaryPath.c_str());
			return false;
		}

		bool IsValidBanKey(const std::string& value)
		{
			return IsUsableIdentityToken(value);
		}
	}

	BanStore::BanStore(std::wstring path)
		: _path(std::move(path))
	{
	}

	bool BanStore::Load()
	{
		HANDLE file = ::CreateFileW(
			_path.c_str(),
			GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			nullptr,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			nullptr);

		if (file == INVALID_HANDLE_VALUE)
		{
			const DWORD error = ::GetLastError();
			return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
		}

		LARGE_INTEGER fileSize{};
		if (!::GetFileSizeEx(file, &fileSize) || fileSize.QuadPart < 0 || fileSize.QuadPart > 1024 * 1024)
		{
			::CloseHandle(file);
			return false;
		}

		std::string contents(static_cast<size_t>(fileSize.QuadPart), '\0');
		DWORD bytesRead = 0;
		const BOOL read = contents.empty()
			? TRUE
			: ::ReadFile(file, &contents[0], static_cast<DWORD>(contents.size()), &bytesRead, nullptr);
		::CloseHandle(file);

		if (!read)
			return false;

		contents.resize(bytesRead);
		std::set<std::string> loaded;
		std::istringstream stream(contents);
		std::string line;
		while (std::getline(stream, line))
		{
			const std::string machineHwid = NormalizeToken(line);
			if (IsValidBanKey(machineHwid))
				loaded.insert(machineHwid);
		}

		std::lock_guard<std::mutex> lock(_mutex);
		_bannedMachines.swap(loaded);
		return true;
	}

	bool BanStore::Add(const std::string& machineHwid)
	{
		const std::string normalized = NormalizeToken(machineHwid);
		if (!IsValidBanKey(normalized))
			return false;

		std::lock_guard<std::mutex> lock(_mutex);
		if (_bannedMachines.find(normalized) != _bannedMachines.end())
			return true;

		if (!AppendLineToFile(_path, normalized))
			return false;

		_bannedMachines.insert(normalized);
		return true;
	}

	bool BanStore::Remove(const std::string& machineHwid)
	{
		const std::string normalized = NormalizeToken(machineHwid);
		if (!IsValidBanKey(normalized))
			return false;

		std::lock_guard<std::mutex> lock(_mutex);
		if (_bannedMachines.find(normalized) == _bannedMachines.end())
			return true;

		std::set<std::string> remaining = _bannedMachines;
		remaining.erase(normalized);
		if (!ReplaceFileAtomically(_path, remaining))
			return false;

		_bannedMachines.swap(remaining);
		return true;
	}

	bool BanStore::IsBanned(const std::string& machineHwid) const
	{
		const std::string normalized = NormalizeToken(machineHwid);
		std::lock_guard<std::mutex> lock(_mutex);
		return _bannedMachines.find(normalized) != _bannedMachines.end();
	}

	std::vector<std::string> BanStore::Snapshot() const
	{
		std::lock_guard<std::mutex> lock(_mutex);
		return std::vector<std::string>(_bannedMachines.begin(), _bannedMachines.end());
	}

	const std::wstring& BanStore::Path() const
	{
		return _path;
	}
}
