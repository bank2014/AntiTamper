#include <iostream>
#include <windows.h>
#include <thread>

using namespace std;

typedef int (*fp) ();
HMODULE hDLL = LoadLibrary(L"Client.dll");

int LoadDLL()
{
	LPCSTR name = "AntiTampermain";
	fp Entry = (fp)GetProcAddress(hDLL, name);
	if (Entry == NULL)
	{
		cout << "Error code :" << GetLastError() << endl;
		exit(-43);
	}

	Entry();

	FreeLibrary(hDLL);
	return 0;
}

int main()
{
	/*std::thread ATthread(LoadDLL);
	ATthread;*/
	LoadDLL();

	for (int i =0; i<100; ++i)
	{
		cout << "[main loop]"<< endl;
		this_thread::sleep_for(0.5s);
	}

	return 0;
}
