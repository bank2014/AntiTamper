#include "pch.h"
#include <iostream>

#include <winsock2.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

inline void HandleError(const char* cause)
{
	int32 errCode = ::WSAGetLastError();
	cout << cause << " ErrorCode : " << errCode << endl;
}

/* 다음과 같은 조건을 만족할 때 응용 프로그램의 시작을 허용
	1. Blacklisted 프로그램이 컴퓨터에 없는 경우
	2. 서버와 연결된 경우
	3. Secureboot이 enable된 경우
	4. Anti virus가 설치된 경우
	5. VM 및 Hypervisor 환경이 아닌 경우
	6. UUID가 밴된 컴퓨터 환경이 아닌 경우
*/
void PermitExecution()
{
	// TODO

}

int CommunicateWithServer()
{
	//WSAData wsaData;
	//if (::WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	//	return 0;

	//SOCKET clientSocket = ::socket(AF_INET, SOCK_STREAM, 0);
	//if (clientSocket == INVALID_SOCKET)
	//	return 0;

	//u_long on = 1;
	//if (::ioctlsocket(clientSocket, FIONBIO, &on) == INVALID_SOCKET)
	//	return 0;

	//SOCKADDR_IN serverAddr;
	//::memset(&serverAddr, 0, sizeof(serverAddr));
	//serverAddr.sin_family = AF_INET;
	//::inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr);
	//serverAddr.sin_port = ::htons(7777);

	//// Connect
	//while (true)
	//{
	//	if (::connect(clientSocket, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
	//	{
	//		if (::WSAGetLastError() == WSAEWOULDBLOCK)
	//			continue;
	//		// 이미 연결된 상태라면 break
	//		if (::WSAGetLastError() == WSAEISCONN)
	//			break;
	//		// Error
	//		break;
	//	}
	//}

	//cout << "Connected to Server!" << endl;

	//char sendBuffer[100] = "Hello World";
	//WSAEVENT wsaEvent = ::WSACreateEvent();
	//WSAOVERLAPPED overlapped = {};
	//overlapped.hEvent = wsaEvent;

	//// Send
	//while (true)
	//{
	//	WSABUF wsaBuf;
	//	wsaBuf.buf = sendBuffer;
	//	wsaBuf.len = 100;

	//	DWORD sendLen = 0;
	//	DWORD flags = 0;
	//	if (::WSASend(clientSocket, &wsaBuf, 1, &sendLen, flags, &overlapped, nullptr) == SOCKET_ERROR)
	//	{
	//		if (::WSAGetLastError() == WSA_IO_PENDING)
	//		{
	//			// Pending
	//			::WSAWaitForMultipleEvents(1, &wsaEvent, TRUE, WSA_INFINITE, FALSE);
	//			::WSAGetOverlappedResult(clientSocket, &overlapped, &sendLen, FALSE, &flags);
	//		}
	//		else
	//		{
	//			// 진짜 문제 있는 상황
	//			break;
	//		}
	//	}

	//	cout << "Send Data ! Len = " << sizeof(sendBuffer) << endl;

	//	this_thread::sleep_for(1s);
	//}

	//// 소켓 리소스 반환
	//::closesocket(clientSocket);

	//// 윈속 종료
	//::WSACleanup();
}