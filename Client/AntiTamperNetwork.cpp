#include "pch.h"
#include "AntiTamperNetwork.h"
#include "ClientNetworkRules.h"

namespace AntiTamperNetwork
{
	namespace
	{
		const PCSTR kServerIp = "127.0.0.1";
		const u_short kServerPort = 7777;
		const int kBufferSize = 512;
		const int kHeartbeatTimeoutSec = 3;

		RequestResult LogServerUnavailable(const char* action, int32 errorCode = 0)
		{
			cout << "[client] Backend server has stopped during " << action;
			if (errorCode != 0)
				cout << ". WSAError=" << errorCode;
			cout << endl;
			return RequestResult::ServerUnavailable;
		}

		bool WaitForSocket(SOCKET socket, long seconds, bool writeReady)
		{
			fd_set set{};
			FD_ZERO(&set);
			FD_SET(socket, &set);

			timeval timeout{};
			timeout.tv_sec = seconds;
			timeout.tv_usec = 0;

			const int32 result = ::select(
				0,
				writeReady ? nullptr : &set,
				writeReady ? &set : nullptr,
				nullptr,
				&timeout);

			return result > 0;
		}

		RequestResult SendAll(SOCKET clientSocket, const char* message)
		{
			const int32 totalLen = static_cast<int32>(strlen(message));
			int32 sentTotal = 0;

			while (sentTotal < totalLen)
			{
				const int32 sent = ::send(clientSocket, message + sentTotal, totalLen - sentTotal, 0);
				if (sent == SOCKET_ERROR)
				{
					const int32 errCode = ::WSAGetLastError();
					if (errCode == WSAEWOULDBLOCK && WaitForSocket(clientSocket, kHeartbeatTimeoutSec, true))
						continue;

					cout << "[client] Send failed. WSAError=" << errCode << endl;
					return LogServerUnavailable("send", errCode);
				}

				sentTotal += sent;
			}
			return RequestResult::Allow;
		}

		RequestResult ParseReply(const string& reply)
		{
			using AntiTamperNetworkRules::ReplyParseResult;

			const ReplyParseResult result = AntiTamperNetworkRules::ClassifyReplyBuffer(reply + "\n");
			if (result == ReplyParseResult::Allow)
				return RequestResult::Allow;
			if (result == ReplyParseResult::Banned)
				return RequestResult::Banned;
			return RequestResult::ProtocolError;
		}

		RequestResult ReceiveReply(SOCKET clientSocket, const char* requestType)
		{
			string reply;
			while (reply.find('\n') == string::npos)
			{
				if (!WaitForSocket(clientSocket, kHeartbeatTimeoutSec, false))
				{
					cout << "[client] " << requestType << " reply timed out" << endl;
					return LogServerUnavailable("reply timeout");
				}

				char recvBuffer[kBufferSize]{};
				const int32 recvLen = ::recv(clientSocket, recvBuffer, kBufferSize - 1, 0);
				if (recvLen <= 0)
				{
					const int32 errCode = recvLen == SOCKET_ERROR ? ::WSAGetLastError() : 0;
					cout << "[client] " << requestType << " reply failed. WSAError=" << errCode << endl;
					return LogServerUnavailable("reply", errCode);
				}

				reply.append(recvBuffer, recvLen);
				if (reply.size() > AntiTamperNetworkRules::kMaxReplyBytes)
				{
					cout << "[client] " << requestType << " reply exceeded "
						<< AntiTamperNetworkRules::kMaxReplyBytes << " bytes" << endl;
					return RequestResult::ProtocolError;
				}
			}

			reply.erase(reply.find('\n'));
			if (!reply.empty() && reply.back() == '\r')
				reply.pop_back();

			cout << "[client] " << requestType << " reply=" << reply << endl;
			return ParseReply(reply);
		}
	}

	SOCKADDR_IN BuildServerAddress()
	{
		SOCKADDR_IN serverAddr{};
		serverAddr.sin_family = AF_INET;
		::inet_pton(AF_INET, kServerIp, &serverAddr.sin_addr);
		serverAddr.sin_port = ::htons(kServerPort);
		return serverAddr;
	}

	SOCKET CreateClientSocket()
	{
		SOCKET clientSocket = ::socket(AF_INET, SOCK_STREAM, 0);
		if (clientSocket == INVALID_SOCKET)
			return INVALID_SOCKET;

		u_long nonBlocking = 1;
		if (::ioctlsocket(clientSocket, FIONBIO, &nonBlocking) == INVALID_SOCKET)
		{
			::closesocket(clientSocket);
			return INVALID_SOCKET;
		}

		return clientSocket;
	}

	RequestResult EnsureConnected(SOCKET clientSocket, const SOCKADDR_IN& serverAddr)
	{
		if (::connect(clientSocket, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) != SOCKET_ERROR)
			return RequestResult::Allow;

		const int32 errCode = ::WSAGetLastError();
		if (errCode == WSAEISCONN)
			return RequestResult::Allow;

		if (errCode != WSAEWOULDBLOCK && errCode != WSAEINPROGRESS && errCode != WSAEINVAL)
		{
			cout << "[client] Server connection failed. WSAError=" << errCode << endl;
			return LogServerUnavailable("connect", errCode);
		}

		if (!WaitForSocket(clientSocket, kHeartbeatTimeoutSec, true))
		{
			cout << "[client] Server connection timed out" << endl;
			return LogServerUnavailable("connect timeout");
		}

		int32 connectError = 0;
		int32 connectErrorLen = sizeof(connectError);
		if (::getsockopt(clientSocket, SOL_SOCKET, SO_ERROR, (char*)&connectError, &connectErrorLen) == SOCKET_ERROR || connectError != 0)
		{
			cout << "[client] Server connection failed after select. WSAError=" << connectError << endl;
			return LogServerUnavailable("connect status", connectError);
		}

		return RequestResult::Allow;
	}

	RequestResult SendIdentityRequest(SOCKET clientSocket, const char* requestType, bool waitReply)
	{
		char sendBuffer[kBufferSize]{};
		const string clientGuid = AntiTamperIdentity::GetClientGuid();
		const string machineHwid = AntiTamperIdentity::GetHardwareID();
		if (clientGuid.empty() || !AntiTamperIdentity::IsUsableMachineHwid(machineHwid))
		{
			cout << "[client] Cannot send " << requestType << ": invalid local machine identity" << endl;
			return RequestResult::ProtocolError;
		}

		sprintf_s(sendBuffer, "%s|%s|%s\n", requestType, clientGuid.c_str(), machineHwid.c_str());

		const RequestResult sendResult = SendAll(clientSocket, sendBuffer);
		if (sendResult != RequestResult::Allow)
			return sendResult;

		cout << "[client] " << requestType
			<< " sent. ClientGuid=" << clientGuid
			<< " MachineHwid=" << machineHwid
			<< " Length=" << strlen(sendBuffer) << endl;

		if (waitReply)
			return ReceiveReply(clientSocket, requestType);
		return RequestResult::Allow;
	}

	RequestResult SendViolationRequest(SOCKET clientSocket, const Violation& violation)
	{
		char sendBuffer[kBufferSize]{};
		const string clientGuid = AntiTamperIdentity::GetClientGuid();
		const string machineHwid = AntiTamperIdentity::GetHardwareID();
		if (clientGuid.empty() || !AntiTamperIdentity::IsUsableMachineHwid(machineHwid))
		{
			cout << "[client] Cannot send VIOLATION: invalid local machine identity" << endl;
			return RequestResult::ProtocolError;
		}

		sprintf_s(sendBuffer, "VIOLATION|%d|%s|%s|%s\n", violation.SeverityCode(), violation.Reason(), clientGuid.c_str(), machineHwid.c_str());

		const RequestResult sendResult = SendAll(clientSocket, sendBuffer);
		if (sendResult != RequestResult::Allow)
			return sendResult;

		cout << "[client] VIOLATION sent. Severity=" << violation.SeverityCode()
			<< " Reason=" << violation.Reason()
			<< " ClientGuid=" << clientGuid
			<< " MachineHwid=" << machineHwid
			<< " Length=" << strlen(sendBuffer) << endl;
		return ReceiveReply(clientSocket, "VIOLATION");
	}
}
