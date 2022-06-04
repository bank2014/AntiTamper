#include "pch.h"
#include <atlbase.h> // For ATL autorelease classes (CComBSTR, CComPtr)
#include <wbemidl.h> // For WMI

#pragma comment(lib, "wbemuuid.lib") // Link to WMI library

// https://stackoverflow.com/questions/6284524/bstr-to-stdstring-stdwstring-and-vice-versa
string ConvertWCSToMBS(const wchar_t* pstr, long wslen)
{
	int len = ::WideCharToMultiByte(CP_ACP, 0, pstr, wslen, NULL, 0, NULL, NULL);

	string dblstr(len, '\0');
	len = ::WideCharToMultiByte(CP_ACP, 0 /* no flags */,
		pstr, wslen /* not necessary NULL-terminated */,
		&dblstr[0], len,
		NULL, NULL /* no default char */);

	return dblstr;
}
string ConvertBSTRToMBS(BSTR bstr)
{
	int wslen = ::SysStringLen(bstr);
	return ConvertWCSToMBS((wchar_t*)bstr, wslen);
}


// returns true if Anti virus is disabled
bool IsAntivirusDisabled()
{
#ifndef _DEBUG
	std::string antivirus_name = "unkown";
	HRESULT hr = ::CoInitializeSecurity(NULL, -1, NULL, NULL,
		RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL, EOAC_NONE, NULL);

	CComPtr<IWbemLocator> pWbemLocator;
	hr = pWbemLocator.CoCreateInstance(CLSID_WbemLocator);

	CComPtr<IWbemServices> pWbemServices;

	hr = pWbemLocator->ConnectServer(CComBSTR(L"root\\SecurityCenter2"), NULL, NULL, 0, NULL, 0, NULL, &pWbemServices);

	CComPtr<IEnumWbemClassObject> pEnum;
	CComBSTR cbsQuery = L"Select * From AntivirusProduct";
	hr = pWbemServices->ExecQuery(CComBSTR("WQL"), cbsQuery, WBEM_FLAG_FORWARD_ONLY, NULL, &pEnum);

	ULONG uObjectCount = 0;
	CComPtr<IWbemClassObject> pWmiObject;
	hr = pEnum->Next(WBEM_INFINITE, 1, &pWmiObject, &uObjectCount);

	CComVariant cvtVersion;
	hr = pWmiObject->Get(L"displayName", 0, &cvtVersion, 0, 0);


	 antivirus_name = ConvertBSTRToMBS(cvtVersion.bstrVal);

	if (antivirus_name == "unknown")
	{
		return true;
	}
#endif
	return false;
}

