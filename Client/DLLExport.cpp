#include "pch.h"
#include "DLLExport.h"


extern "C" DECLSPEC int AntiTampermain()
{
	AntiTamper* antiTamper = new AntiTamper();
	return antiTamper->main();
}

extern "C" DECLSPEC const char* AntiTamperClientGuid()
{
	static string guid = AntiTamperIdentity::GetClientGuid();
	return guid.c_str();
}

