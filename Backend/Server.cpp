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

enum IO_TYPE
{
	READ,
	WRITE,
	ACCEPT,
	CONNECT,
};

struct OverlappedEx
{
	WSAOVERLAPPED overlapped = {};
	int32 type = 0; // read, write, accept, connect ...
};


void WorkerThreadMain(HANDLE iocpHandle)
{
	bool REPLY = true;

	while (true)
	{
		DWORD bytesTransferred = 0;
		Session* session = nullptr;
		OverlappedEx* overlappedEx = nullptr;

		BOOL ret = ::GetQueuedCompletionStatus(iocpHandle, &bytesTransferred,
			(ULONG_PTR*)&session, (LPOVERLAPPED*)&overlappedEx, INFINITE);

		if (ret == FALSE || bytesTransferred == 0)
		{
			// 연결 끊김
			continue;
		}

		ASSERT_CRASH(overlappedEx->type == IO_TYPE::READ);

		WSABUF wsaBuf;
		wsaBuf.buf = session->recvBuffer;
		wsaBuf.len = BUFSIZE;

		DWORD recvLen = 0;
		DWORD flags = 0;
		if (::WSARecv(session->socket, &wsaBuf, 1, &recvLen, &flags, &overlappedEx->overlapped, NULL))
		{
			cout << "[*] Received data from Client IP : " << Client_IP << endl;
			cout << "Received data	: " << wsaBuf.buf << endl;
			cout << "length	: " << bytesTransferred << endl;

		}

		bool enable = true;
		::setsockopt(session->socket, SOL_SOCKET, SO_KEEPALIVE, (char*)&enable, sizeof(enable));

		/*===============
		 Reply to Client
		=============== */
		if (REPLY) // client로 부터 Request: check ban status 받은 경우
		{
			char sendBuffer[BUFSIZE] = "No"; // 기본은 no
			wsaBuf.buf = session->sendBuffer;
			DWORD sendLen = 0;
			if (::WSASend(session->socket, &wsaBuf, 1, &sendLen, flags, &overlappedEx->overlapped, nullptr) == SOCKET_ERROR)
			{
				if (::WSAGetLastError() == WSA_IO_PENDING)
				{
					// Pending
					//::WSAWaitForMultipleEvents(1, &wsaEvent, TRUE, WSA_INFINITE, FALSE);

					::WSAGetOverlappedResult(session->socket, &overlappedEx->overlapped, &sendLen, FALSE, &flags);
				}
				else
				{
					int32 errCode = ::WSAGetLastError();
					cout << "[*] Reply failed. ErrorCode : " << errCode << endl;
				}
				cout << "[*] Reply success : " << wsaBuf.buf << endl;
			}
		}
		REPLY = false;


	}
}



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