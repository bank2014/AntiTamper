#include "pch.h"
#include "DetectHypervisor.h"
#include "debugapi.h"

//Trap flag check execute code - https://m.blog.naver.com/PostView.naver?isHttpsRedirect=true&blogId=kby88power&logNo=220946995468
bool ResCheckTrapFlag()
{
	BOOL bDetected = FALSE;
	INT singleStepCount = NULL;
	CONTEXT ctx{};
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	GetThreadContext(GetCurrentThread(), &ctx);
	ctx.Dr0 = (size_t)TrapflagCheck + 11;
	ctx.Dr7 = 1;
	SetThreadContext(GetCurrentThread(), &ctx);
	__try
	{
		TrapflagCheck(); //trap flag
	}
	__except (DetectHyp::filter(GetExceptionCode(), GetExceptionInformation(), bDetected, singleStepCount))

	{
		if (singleStepCount != 1)
		{
			bDetected = true;
		}
	}
	return bDetected;
}


bool IsDebugging()
{
	uint8 status = 0;
	status = ResCheckTrapFlag();
	::IsDebuggerPresent();

	switch (status)
	{
	case 1: // no evasion, only debugging attempt

		break;
	case 2: // evasion detected

		break;
	}

	return false;
}