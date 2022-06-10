#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wbemidl.h>

namespace AntiTamperAntivirus
{
	enum class WmiNextDecision
	{
		ProductAvailable,
		Finished,
		Unknown
	};

	inline WmiNextDecision ClassifyWmiNextResult(HRESULT result, ULONG objectCount)
	{
		if (objectCount > 0)
			return WmiNextDecision::ProductAvailable;

		if (result == WBEM_S_FALSE)
			return WmiNextDecision::Finished;

		if (result == WBEM_S_TIMEDOUT || FAILED(result))
			return WmiNextDecision::Unknown;

		return WmiNextDecision::Finished;
	}
}
