#pragma once

#include "DLLExport.h"

#ifdef _DEBUG
#pragma comment(lib, "x64/Debug/ServerCore.lib")
#else
#pragma comment(lib, "x64/Release/ServerCore.lib")
#endif

#include "CorePch.h"
#include "ClientIdentity.h"
#include "Violation.h"

enum RequestType {
	CheckBanStatus = 10101 // 서버에 밴 여부 확인 request 보냄
};

enum ReplyType {
	Yes = 0,
	No = 1
};

bool IsHypervisorPresent();

void BSOD(uint32 delay);

bool IsAntivirusDisabled();

bool IsDebugging();

bool IsBlacklistedProgramPresent();

bool IsPeFileTampered();

bool IsSecureBootDisabled();

// to_string 오류 - https://yyman.tistory.com/466
namespace patch
{
	template < typename T > std::string to_string(const T& n)
	{
		std::ostringstream stm;
		stm << n;
		return stm.str();
	}
}
