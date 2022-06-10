#pragma once

#include <cstdint>
#include <cctype>
#include <sstream>
#include <string>

namespace AntiTamperIdentity
{
	inline std::string NormalizeGuid(std::string value)
	{
		while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())))
			value.erase(value.begin());
		while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())))
			value.pop_back();

		for (char& ch : value)
			ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));

		return value;
	}

	inline std::string ToLowerHex(uint64_t value)
	{
		std::ostringstream stream;
		stream << std::hex << std::nouppercase << value;
		return stream.str();
	}

	inline bool IsUsableMachineHwid(const std::string& machineGuid)
	{
		const std::string normalized = NormalizeGuid(machineGuid);
		return !normalized.empty()
			&& normalized != "unknown"
			&& normalized != "unknown-guid"
			&& normalized != "machine-unknown"
			&& normalized.find("unknown-guid") != 0
			&& normalized.find("machine-unknown") != 0;
	}

	inline std::string BuildClientGuidForProcess(const std::string& machineGuid, uint32_t processId, uint64_t startStamp)
	{
		std::string normalizedMachineGuid = NormalizeGuid(machineGuid);
		if (!IsUsableMachineHwid(normalizedMachineGuid))
			return std::string();

		const std::string suffix =
			"-p" + ToLowerHex(processId) +
			"-s" + ToLowerHex(startStamp);

		constexpr size_t kMaxClientGuidLength = 128;
		if (normalizedMachineGuid.size() + suffix.size() > kMaxClientGuidLength)
			normalizedMachineGuid.resize(kMaxClientGuidLength - suffix.size());

		return normalizedMachineGuid + suffix;
	}

	std::string GetHardwareID();
	std::string GetClientGuid();
}
