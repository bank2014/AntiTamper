#include "pch.h"
#include "dllExportHeaders.h"

void ViolationDetected()
{
	
}


// DLL의 main loop
int AntiTamper()
{


	// Communication();


	std::this_thread::sleep_for(std::chrono::seconds(5));
	return 0;
}