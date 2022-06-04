#include "pch.h"
#include "CorePch.h"

#include <future>
#include "ThreadManager.h"
#include "Memory.h"

const int32 BUFSIZE = 50;
const u_short SERVER_PORT = 7777;
char Client_IP[16]{};




int main()
{
	WSAData wsaData;
	if (::WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
		return 0;

	cout << "Initiate listen socket ..." << endl;
	SOCKET listenSocket = ::socket(AF_INET, SOCK_STREAM, 0);
	if (listenSocket == INVALID_SOCKET)
		return 0;

	SOCKADDR_IN serverAddr;
	::memset(&serverAddr, 0, sizeof(serverAddr));
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_addr.s_addr = ::htonl(INADDR_ANY);
	serverAddr.sin_port = ::htons(SERVER_PORT);

	cout << "binding ..." << endl;
	if (::bind(listenSocket, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
		return 0;

	cout << "listening ..." << endl;
	if (::listen(listenSocket, SOMAXCONN) == SOCKET_ERROR)
		return 0;


	vector<Session*> sessionManager;

	// CP 생성
	HANDLE iocpHandle = ::CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);

	// WorkerThreads
	for (int32 i = 0; i < 5; i++)
		GThreadManager->Launch([=]() { WorkerThreadMain(iocpHandle); });


	// Main Thread = Accept 담당


	GThreadManager->Join();

	// 윈속 종료
	::WSACleanup();
}