#pragma once

#include "CorePch.h"
#include "Violation.h"

namespace AntiTamperNetwork
{
	enum class RequestResult
	{
		Allow,
		Banned,
		ServerUnavailable,
		ProtocolError
	};

	SOCKADDR_IN BuildServerAddress();
	SOCKET CreateClientSocket();

	RequestResult EnsureConnected(SOCKET clientSocket, const SOCKADDR_IN& serverAddr);
	RequestResult SendIdentityRequest(SOCKET clientSocket, const char* requestType, bool waitReply);
	RequestResult SendViolationRequest(SOCKET clientSocket, const Violation& violation);
}
