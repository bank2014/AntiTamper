#pragma once
#include "CorePch.h"
#include "AntiTamperNetwork.h"
#include "Violation.h"


class AntiTamper
{
public:
	// 초기화 및 main loop 시작
	int main();

public:
	bool SendUserInfo(SOCKET clientSocket);

	bool SendHeartbeat(SOCKET clientSocket);
	
	bool ViolationDetected(SOCKET clientSocket, const Violation& violation);

	bool ValidateExecution(SOCKET clientSocket, const SOCKADDR_IN& serverAddr, bool sendInitialCheck);

};
