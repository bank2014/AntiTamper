#include "pch.h"

// return true if Secure boot is disabled
bool IsSecureBootDisabled()
{
	BYTE secureBoot = 0;
	DWORD result = ::GetFirmwareEnvironmentVariableW(
		L"SecureBoot",
		L"{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}",
		&secureBoot,
		sizeof(secureBoot));

	if (result == sizeof(secureBoot))
		return secureBoot == 0;

	const DWORD error = ::GetLastError();
	if (error == ERROR_INVALID_FUNCTION)
		return true;

	cout << "[client] Secure Boot status unavailable. Error=" << error << endl;
	return false;
}
