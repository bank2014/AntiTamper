#include "pch.h"
#include "CorePch.h"

#include <future>
#include "ThreadManager.h"
#include "Memory.h"

const int32 BUFSIZE = 50;
const u_short SERVER_PORT = 7777;
char Client_IP[16]{};


struct Session
{
	SOCKET socket = INVALID_SOCKET;
	char recvBuffer[BUFSIZE] = {};
	char sendBuffer[BUFSIZE] = {};
	int32 recvBytes = 0;
	int32 sentBytes = 0;
};



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
	while (true)
	{
		SOCKADDR_IN clientAddr{};
		int32 addrLen = sizeof(clientAddr);

		SOCKET clientSocket = ::accept(listenSocket, (SOCKADDR*)&clientAddr, &addrLen);
		if (clientSocket == INVALID_SOCKET)
			return 0;

		Session* session = xnew<Session>();
		session->socket = clientSocket;
		sessionManager.push_back(session);

		::inet_ntop(AF_INET, &clientAddr.sin_addr, Client_IP, sizeof(Client_IP));
		cout << "[*] Client Connected! IP : " << Client_IP << endl;

		// 소켓을 CP에 등록
		::CreateIoCompletionPort((HANDLE)clientSocket, iocpHandle, /*Key*/(ULONG_PTR)session, 0);

		WSABUF wsaBuf;
		wsaBuf.buf = session->recvBuffer;
		wsaBuf.len = BUFSIZE;

		OverlappedEx* overlappedEx = new OverlappedEx();
		overlappedEx->type = IO_TYPE::READ;

		// ADD_REF
		DWORD recvLen = 0;
		DWORD flags = 0;
		::WSARecv(clientSocket, &wsaBuf, 1, &recvLen, &flags, &overlappedEx->overlapped, NULL);

	}

	GThreadManager->Join();

	// 윈속 종료
	::WSACleanup();
}