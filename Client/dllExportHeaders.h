#pragma once

#ifdef CREATEDLL_EXPORTS
#define DECLSPEC __declspec(dllexport)
#else
#define DECLSPEC __declspec(dllimport)
#endif

/*---------------
AntiTamper Main loop
---------------*/

extern "C" DECLSPEC int AntiTamper();

/*---------------
  Communication
---------------*/

extern "C" DECLSPEC int CommunicateWithServer();
extern "C" DECLSPEC void HandleError(const char* cause);


/*---------------
	Protection
---------------*/

extern "C" DECLSPEC void DetectHypervisor();
extern "C" DECLSPEC void BSOD();