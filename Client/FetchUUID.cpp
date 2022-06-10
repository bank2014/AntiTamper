#include "pch.h"

namespace AntiTamperIdentity
{
	namespace
	{
		uint64_t GetProcessStartStamp()
		{
			FILETIME creationTime{};
			FILETIME exitTime{};
			FILETIME kernelTime{};
			FILETIME userTime{};
			if (::GetProcessTimes(::GetCurrentProcess(), &creationTime, &exitTime, &kernelTime, &userTime))
			{
				return (static_cast<uint64_t>(creationTime.dwHighDateTime) << 32) |
					static_cast<uint64_t>(creationTime.dwLowDateTime);
			}

			return static_cast<uint64_t>(::GetCurrentProcessId());
		}
	}

	// get machine guid
	std::string GetHardwareID()
	{
		char guid[128]{};
		DWORD guidSize = sizeof(guid);
		const LSTATUS status = ::RegGetValueA(
			HKEY_LOCAL_MACHINE,
			"SOFTWARE\\Microsoft\\Cryptography",
			"MachineGuid",
			RRF_RT_REG_SZ,
			nullptr,
			guid,
			&guidSize);

		if (status != ERROR_SUCCESS || guid[0] == '\0')
		{
			cout << "[client] MachineGuid read failed. Error=" << status << endl;
			return std::string();
		}

		const std::string normalized = NormalizeGuid(guid);
		if (!IsUsableMachineHwid(normalized))
		{
			cout << "[client] MachineGuid is not usable for machine identity" << endl;
			return std::string();
		}

		return normalized;
	}

	std::string GetClientGuid()
	{
		static const std::string clientGuid = BuildClientGuidForProcess(
			GetHardwareID(),
			::GetCurrentProcessId(),
			GetProcessStartStamp());
		return clientGuid;
	}
}
