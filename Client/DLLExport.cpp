#include "pch.h"
#include "DLLExport.h"


extern "C" DECLSPEC int AntiTampermain()
{
	AntiTamper* antiTamper = new AntiTamper();
	return antiTamper->main();
}

