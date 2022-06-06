#pragma once

#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace Backend
{
	class BanStore
	{
	public:
		explicit BanStore(std::wstring path);

		bool Load();
		bool Add(const std::string& machineHwid);
		bool Remove(const std::string& machineHwid);
		bool IsBanned(const std::string& machineHwid) const;
		std::vector<std::string> Snapshot() const;
		const std::wstring& Path() const;

	private:
		std::wstring _path;
		mutable std::mutex _mutex;
		std::set<std::string> _bannedMachines;
	};
}
