#include <iostream>
#include <windows.h>
#include <thread>

using std::cout;
using std::endl;

int LoadAntiTamperDLL()
{
	typedef int (*fpInit) ();
	HMODULE hDLL = LoadLibrary(L"Client.dll");

	if (hDLL == NULL)
	{
		std::cout << "Failed to load library.\n";
		return 1;
	}

	LPCSTR name = "AntiTamper";
	fpInit Heartbeat = (fpInit)GetProcAddress(hDLL, name);
	if (Heartbeat) Heartbeat();

	FreeLibrary(hDLL);

	return 0;
}

int main()
{
	std::thread ATthread(LoadAntiTamperDLL);
	ATthread;

	for (int i =0; i<100; ++i)
	{
		cout << "===Application main loop: " << i << "===" << endl;

		Sleep(500);
	}

	return 0;
}
