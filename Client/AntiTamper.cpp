#include "pch.h"
#include "AntiTamper.hpp"
#pragma warning(disable: 4996)

const PCSTR MY_IP = "127.0.0.1";	// 클라이언트 아이피 
const u_short SERVER_PORT = 7777;	// 서버 포트
const int BUFFER_SIZE = 50;			// send & recv 버퍼 크기
bool RECV_FROM_SERVER = true;		// 서버로 응답을 받는 걸 활성화할지 말지


// 서버에 유저 HWID를 보냄
void AntiTamper::SendUserInfo(SOCKET clientSocket)
{

	int32 wsaBufferLen = BUFFER_SIZE;
	char sendBuffer[BUFFER_SIZE]{};

	WSABUF wsaBuf{};
	wsaBuf.buf = sendBuffer;
	wsaBuf.len = wsaBufferLen;

	strcpy(sendBuffer, GetHardwareID().c_str());

	WSAEVENT wsaEvent = ::WSACreateEvent();
	WSAOVERLAPPED overlapped = {};
	overlapped.hEvent = wsaEvent;

	
	/*===============
	sent HWID to server
	=============== */

	DWORD sendLen = 0;
	DWORD flags = 0;
	if (::WSASend(clientSocket, &wsaBuf, 1, &sendLen, flags, &overlapped, nullptr) == SOCKET_ERROR)
	{
		if (::WSAGetLastError() == WSA_IO_PENDING)
		{
			// Pending
			::WSAWaitForMultipleEvents(1, &wsaEvent, TRUE, WSA_INFINITE, FALSE);
			::WSAGetOverlappedResult(clientSocket, &overlapped, &sendLen, FALSE, &flags);
		}
		else
		{
			// 서버 연결 실패
			MessageBox(NULL, L"Server connection failed", L"Warning", MB_OK);
			exit(-2);
		}
	}


#ifdef _DEBUG
	cout << "[*]=== send HWID ===" << endl;
	cout << "[-] HWID	: " << wsaBuf.buf << endl;
	cout << "[-] length	: " << wsaBuf.len << endl;
#endif
	

	/*===============
	Recv reply from server
	=============== */
//
//	if (RECV_FROM_SERVER)
//	{
//		char recvBuffer[BUFFER_SIZE]{};
//
//		wsaBuf.buf = recvBuffer;
//		wsaBuf.len = BUFFER_SIZE;
//		DWORD recvLen = 0;
//		if (::WSARecv(clientSocket, &wsaBuf, 1, &recvLen, &flags, &overlapped, NULL))
//		{
//#ifdef _DEBUG
//			if (strcmp(recvBuffer, "Yes") == 0)
//			{
//				cout << "[*] Reply from server	:" << "Yes" << endl;
//				MessageBox(NULL, L"You are banned user", L"Warnning", MB_OK);
//				AntiTamper::ViolationDetected(Moderate, clientSocket);
//			}
//			else if (strcmp(recvBuffer, "No") == 0)
//				cout << "[*] Reply from server	:" << "No" << endl;
//			else
//			{
//				cout << "Reply failed" << endl;
//				//exit(-1);
//			}
//		}
//#endif
	//	
	//}
}





// 비허가 행위가 감지된 경우
void AntiTamper::ViolationDetected(int severity, SOCKET clientSocket)
{
	switch (severity) {
	case Trivial:
		DeleteMyself();
		MessageBox(NULL, L"Trivial Violation detected. Shutting down the application", L"Warning", MB_OK);
		exit(-1);

	case Moderate: // moderate 부터 무통보
		DeleteMyself();
		AntiTamper::SendUserInfo(clientSocket);
		BSOD(3);
		exit(-1); //혹시 모르니..

	case Severe: // 우회행위가 감지된 유저는 system32/hal.dll 삭제 후 블루스크린. 다음 부팅 때 부팅 못함
		DeleteMyself();
		AntiTamper::SendUserInfo(clientSocket);
		std::remove("%systemroot%\\system32\\hal.dll");
		BSOD(3);
		exit(-1); //혹시 모르니..

	default:
		DeleteMyself();
		MessageBox(NULL, L"VD Error", L"Error", MB_OK);
		exit(-1);
	}
}









/* 다음과 같은 조건을 만족할 때 응용 프로그램 실행을 허용
	1. 서버와 연결된 경우
	2. Blacklisted 프로그램이 컴퓨터에 없는 경우
	3. Secureboot이 enable된 경우
	4. Anti virus가 설치된 경우
	5. VM 및 Hypervisor 환경이 아닌 경우
	6. UUID가 밴된 컴퓨터 환경이 아닌 경우
*/
void AntiTamper::ValidateExecution(SOCKET clientSocket, SOCKADDR_IN serverAddr, bool IsSendUserInfoTrue)
{

	// 1. 서버와 연결을 확인 (heartbeat)
	while (true) // Connect
	{
		if (::connect(clientSocket, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
		{
			// 계속 연결 시도
			if (::WSAGetLastError() == WSAEWOULDBLOCK)
				continue;
			// 이미 연결된 상태라면 break
			if (::WSAGetLastError() == WSAEISCONN)
				break;
			// 서버 연결 실패
			MessageBox(NULL, L"Server connection failed", L"Warning", MB_OK);
			exit(-2);
		}
	}


	// 처음 접속시 HWID 전송
	// 6. UUID가 밴된 컴퓨터 환경이 아닌 경우인지 한번만 확인
	if(IsSendUserInfoTrue)
		AntiTamper::SendUserInfo(clientSocket); 


	//2. Blacklisted 프로그램 확인
	if (IsBlacklistedProgramPresent())
	{
		ViolationDetected(Trivial, clientSocket);
	}

	//3. Secureboot 체크
	if (IsSecureBootDisabled())
	{
		MessageBox(NULL, L"Enable Secure boot before running this application", L"Error", MB_OK);
		DeleteMyself();
		exit(-1);
	}

	//4. Anti virus 체크
	if (IsAntivirusDisabled())
	{
		MessageBox(NULL, L"Enable Anti virus before running this application", L"Error", MB_OK);
		DeleteMyself();
		exit(-1);
	}

	//5. VM 및 Hypervisor 환경 체크
	if (IsHypervisorPresent())
	{
		MessageBox(NULL, L"This program can not run under Hypervisor", L"Error", MB_OK);
		DeleteMyself();
		exit(-1);
	}

}



int AntiTamper::main()
{	
	// 소켓 초기화
	WSAData wsaData;
	if (::WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
		exit(-1);

	SOCKET clientSocket = ::socket(AF_INET, SOCK_STREAM, 0);
	if (clientSocket == INVALID_SOCKET)
		exit(-1);

	u_long on = 1;
	if (::ioctlsocket(clientSocket, FIONBIO, &on) == INVALID_SOCKET)
		exit(-1);

	SOCKADDR_IN serverAddr;
	::memset(&serverAddr, 0, sizeof(serverAddr));
	serverAddr.sin_family = AF_INET;
	::inet_pton(AF_INET, MY_IP, &serverAddr.sin_addr);
	serverAddr.sin_port = ::htons(SERVER_PORT);



	ValidateExecution(clientSocket, serverAddr, true); // 첫 검증은 sendUserInfo() 호출
	RECV_FROM_SERVER = false; // 검증 후 밴된 유저인지 확인할 필요 없으므로 false

	while (true) // main loop
	{
		AntiTamper::ValidateExecution(clientSocket, serverAddr, false);
		this_thread::sleep_for(3s);
	}


	// 소켓 리소스 반환
	::closesocket(clientSocket);

	// 윈속 종료
	::WSACleanup();
	return 0;
}