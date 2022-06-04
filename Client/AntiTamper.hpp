#pragma once
#include "CorePch.h"


class AntiTamper
{
public:
	// 초기화 및 main loop 시작
	int main();

public:
	void SendUserInfo(SOCKET clientSocket);
	
	void ViolationDetected(int severity,SOCKET clientSocket);

	void ValidateExecution(SOCKET clientSocket, SOCKADDR_IN serverAddr, bool IsSendUserInfoTrue);

};