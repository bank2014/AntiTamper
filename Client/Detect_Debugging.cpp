#include "pch.h"


bool AntiDebugEvasionDetection()
{
	// isDebuggerPresent() 와 직접 구현한 디버거 탐지 함수의 return 값이 서로 다르면
	// debugging 탐지를 우회한 것이라 판단하고 return 1
}

bool CheckDebugingPresent()
{
	// 5초마다 호출되는 함수
	// debugging 상태인지 체크
		// if yes -> return 1
}