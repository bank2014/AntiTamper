#include "pch.h"
#include "AntiTamper.hpp"
#include "AntiTamperNetwork.h"
#include "ClientShutdown.h"
#include "ViolationScanner.h"

#pragma warning(disable: 4996)

namespace
{
	const bool kWaitForCheckReply = true;
	set<string> g_reportedViolationReasons;

	const char* NormalizeReason(const Violation& violation)
	{
		const char* reason = violation.Reason();
		return reason == nullptr || reason[0] == '\0' ? "Unknown" : reason;
	}

	bool HandleNetworkResult(AntiTamperNetwork::RequestResult result)
	{
		switch (result)
		{
		case AntiTamperNetwork::RequestResult::Allow:
			return true;
		case AntiTamperNetwork::RequestResult::Banned:
			AntiTamperShutdown::RequestHostShutdown(L"You are banned user.", -1);
			return false;
		case AntiTamperNetwork::RequestResult::ServerUnavailable:
			AntiTamperShutdown::RequestHostShutdown(L"Backend server has stopped. The client will close.", -2);
			return false;
		case AntiTamperNetwork::RequestResult::ProtocolError:
			AntiTamperShutdown::RequestHostShutdown(L"Backend server returned an invalid response. The client will close.", -3);
			return false;
		default:
			AntiTamperShutdown::RequestHostShutdown(L"AntiTamper encountered an unknown network state. The client will close.", -4);
			return false;
		}
	}
}

bool AntiTamper::SendUserInfo(SOCKET clientSocket)
{
	return HandleNetworkResult(AntiTamperNetwork::SendIdentityRequest(clientSocket, "CHECK", kWaitForCheckReply));
}

bool AntiTamper::SendHeartbeat(SOCKET clientSocket)
{
	return HandleNetworkResult(AntiTamperNetwork::SendIdentityRequest(clientSocket, "HEARTBEAT", true));
}

bool AntiTamper::ViolationDetected(SOCKET clientSocket, const Violation& violation)
{
	const char* reason = NormalizeReason(violation);
	if (!g_reportedViolationReasons.insert(reason).second)
	{
		cout << "[client] Duplicate violation suppressed. Reason=" << reason << endl;
		return true;
	}

	if (!HandleNetworkResult(AntiTamperNetwork::SendViolationRequest(clientSocket, violation)))
		return false;

	cout << "[client] " << violation.SeverityName()
		<< " violation reported to server. Reason=" << reason << endl;
	return true;
}

/* 다음과 같은 조건을 만족할 때 응용 프로그램 실행을 허용
	1. 서버와 연결된 경우
	2. Blacklisted 프로그램이 컴퓨터에 없는 경우
	3. Secureboot이 enable된 경우
	4. Anti virus가 설치된 경우
	5. VM 및 Hypervisor 환경이 아닌 경우
	6. UUID가 밴된 컴퓨터 환경이 아닌 경우
*/
bool AntiTamper::ValidateExecution(SOCKET clientSocket, const SOCKADDR_IN& serverAddr, bool sendInitialCheck)
{
	// 1. 서버와 연결을 확인 (heartbeat)
	if (!HandleNetworkResult(AntiTamperNetwork::EnsureConnected(clientSocket, serverAddr)))
		return false;

	// 처음 접속시 HWID 전송
	// 6. UUID가 밴된 컴퓨터 환경이 아닌 경우인지 한번만 확인
	if (sendInitialCheck)
	{
		if (!AntiTamper::SendUserInfo(clientSocket))
			return false;
	}
	else if (!AntiTamper::SendHeartbeat(clientSocket))
	{
		return false;
	}

	for (const Violation& violation : ViolationScanner::CollectCurrentViolations())
	{
		if (!ViolationDetected(clientSocket, violation))
			return false;
	}

	return true;
}

int AntiTamper::main()
{	
	// 소켓 초기화
	WSAData wsaData;
	if (::WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		AntiTamperShutdown::RequestHostShutdown(L"WSAStartup failed. The client will close.", -1);
		return -1;
	}

	SOCKET clientSocket = AntiTamperNetwork::CreateClientSocket();
	if (clientSocket == INVALID_SOCKET)
	{
		::WSACleanup();
		AntiTamperShutdown::RequestHostShutdown(L"Client socket creation failed. The client will close.", -1);
		return -1;
	}

	SOCKADDR_IN serverAddr = AntiTamperNetwork::BuildServerAddress();

	if (!ValidateExecution(clientSocket, serverAddr, true)) // 첫 검증은 sendUserInfo() 호출
	{
		::closesocket(clientSocket);
		::WSACleanup();
		return -2;
	}

	while (ValidateExecution(clientSocket, serverAddr, false)) // main loop
	{
		std::this_thread::sleep_for(std::chrono::seconds(3));
	}

	// 소켓 리소스 반환
	::closesocket(clientSocket);

	// 윈속 종료
	::WSACleanup();
	return 0;
}
