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
extern "C" DECLSPEC void PermitExecution();
extern "C" DECLSPEC void ViolationDetected();

/*---------------
  Communication
---------------*/

extern "C" DECLSPEC int CommunicateWithServer();
extern "C" DECLSPEC void HandleError(const char* cause);


/*---------------
	Protection
---------------*/

extern "C" DECLSPEC char* DetectHypervisor();
extern "C" DECLSPEC void BSOD();
extern "C" DECLSPEC bool CheckBlacklistedPrograms();

extern "C" DECLSPEC void HashHardwareID();
extern "C" DECLSPEC std::string GetHardwareID();
