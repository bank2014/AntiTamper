#include "pch.h"

#include <algorithm>
#include <cwctype>
#include <tlhelp32.h>

// 프로그램 목록 중 아래 string이 발견되면 return true
bool IsBlacklistedProgramPresent()
{
	const vector<std::wstring> badProcessNames = {
		L"ollydbg.exe",
		L"ida.exe",
		L"ida64.exe",
		L"idag.exe",
		L"idag64.exe",
		L"idaw.exe",
		L"idaw64.exe",
		L"idaq.exe",
		L"idaq64.exe",
		L"idau.exe",
		L"idau64.exe",
		L"scylla.exe",
		L"scylla_x64.exe",
		L"scylla_x86.exe",
		L"protection_id.exe",
		L"x64dbg.exe",
		L"x32dbg.exe",
		L"x96dbg.exe",
		L"windbg.exe",
		L"reshacker.exe",
		L"importrec.exe",
		L"immunitydebugger.exe",
		L"megadumper.exe",
		L"cheatengine-x86_64.exe",
		L"processhacker.exe",
		L"procmon.exe",
		L"procmon64.exe",
		L"hxd.exe",
		L"wireshark.exe"
	};

	HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE)
		return false;

	PROCESSENTRY32W entry{};
	entry.dwSize = sizeof(entry);

	if (!::Process32FirstW(snapshot, &entry))
	{
		::CloseHandle(snapshot);
		return false;
	}

	do
	{
		std::wstring exeName(entry.szExeFile);
		std::transform(exeName.begin(), exeName.end(), exeName.begin(),
			[](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });

		for (const std::wstring& badName : badProcessNames)
		{
			if (exeName == badName)
			{
				std::wcout << L"[client] Blacklisted process detected: " << exeName << endl;
				::CloseHandle(snapshot);
				return true;
			}
		}
	} while (::Process32NextW(snapshot, &entry));

	::CloseHandle(snapshot);
	return false;
}

//BadProcessnameList.Add("ollydbg");
//BadProcessnameList.Add("ida");
//BadProcessnameList.Add("ida64");
//BadProcessnameList.Add("idag");
//BadProcessnameList.Add("idag64");
//BadProcessnameList.Add("idaw");
//BadProcessnameList.Add("idaw64");
//BadProcessnameList.Add("idaq");
//BadProcessnameList.Add("idaq64");
//BadProcessnameList.Add("idau");
//BadProcessnameList.Add("idau64");
//BadProcessnameList.Add("scylla");
//BadProcessnameList.Add("scylla_x64");
//BadProcessnameList.Add("scylla_x86");
//BadProcessnameList.Add("protection_id");
//BadProcessnameList.Add("x64dbg");
//BadProcessnameList.Add("x32dbg");
//BadProcessnameList.Add("windbg");
//BadProcessnameList.Add("reshacker");
//BadProcessnameList.Add("ImportREC");
//BadProcessnameList.Add("IMMUNITYDEBUGGER");
//BadProcessnameList.Add("MegaDumper");
//BadWindowTextList.Add("HTTPDebuggerUI");
//BadWindowTextList.Add("HTTPDebuggerSvc");
//BadWindowTextList.Add("HTTP Debugger");
//BadWindowTextList.Add("HTTP Debugger (32 bit)");
//BadWindowTextList.Add("HTTP Debugger (64 bit)");
//BadWindowTextList.Add("OLLYDBG");
//BadWindowTextList.Add("ida");
//BadWindowTextList.Add("disassembly");
//BadWindowTextList.Add("scylla");
//BadWindowTextList.Add("Debug");
//BadWindowTextList.Add("[CPU");
//BadWindowTextList.Add("Immunity");
//BadWindowTextList.Add("WinDbg");
//BadWindowTextList.Add("x32dbg");
//BadWindowTextList.Add("x64dbg");
//BadWindowTextList.Add("Import reconstructor");
//BadWindowTextList.Add("MegaDumper");
//BadWindowTextList.Add("MegaDumper 1.0 by CodeCracker / SnD");
//
//"procmon64",
//"codecracker",
//"ida",
//"idag",
//"idaw",
//"idaq",
//"idau",
//"scylla",
//"de4dot",
//"de4dotmodded",
//"protection_id",
//"ollydbg",
//"x64dbg",
//"x32dbg",
//"x96dbg",
//"x64netdumper",
//"petools",
//"dnspy",
//"windbg",
//"reshacker",
//"simpleassembly",
//"process hacker",
//"process monitor",
//"qt5core",
//"importREC",
//"immunitydebugger",
//"megadumper",
//"cheatengine-x86_64",
//"dump",
//"dbgclr",
//"wireshark",
//"hxd"
//"disassembly",
//"scylla",
//"debug",
//"[cpu",
//"immunity",
//"windbg",
//"x32dbg",
//"x64dbg",
//"x96dbg",
//"import reconstructor",
//"dumper"
