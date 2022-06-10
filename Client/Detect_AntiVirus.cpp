#include "pch.h"
#include "AntivirusState.h"
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
	bool coInitialized = false;
	HRESULT hr = ::CoInitializeEx(nullptr, COINIT_MULTITHREADED);
	if (SUCCEEDED(hr))
		coInitialized = true;
	else if (hr != RPC_E_CHANGED_MODE)
	{
		cout << "[client] Antivirus WMI COM init failed. HRESULT=" << hr << endl;
		return false;
	}

	hr = ::CoInitializeSecurity(NULL, -1, NULL, NULL,
		RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL, EOAC_NONE, NULL);
	if (FAILED(hr) && hr != RPC_E_TOO_LATE)
	{
		cout << "[client] Antivirus WMI security init failed. HRESULT=" << hr << endl;
		if (coInitialized)
			::CoUninitialize();
		return false;
	}

	CComPtr<IWbemLocator> pWbemLocator;
	hr = pWbemLocator.CoCreateInstance(CLSID_WbemLocator);
	if (FAILED(hr))
	{
		cout << "[client] Antivirus WMI locator creation failed. HRESULT=" << hr << endl;
		if (coInitialized)
			::CoUninitialize();
		return false;
	}

	CComPtr<IWbemServices> pWbemServices;

	hr = pWbemLocator->ConnectServer(CComBSTR(L"root\\SecurityCenter2"), NULL, NULL, 0, NULL, 0, NULL, &pWbemServices);
	if (FAILED(hr))
	{
		cout << "[client] Antivirus WMI connect failed. HRESULT=" << hr << endl;
		if (coInitialized)
			::CoUninitialize();
		return false;
	}

	hr = ::CoSetProxyBlanket(
		pWbemServices,
		RPC_C_AUTHN_WINNT,
		RPC_C_AUTHZ_NONE,
		NULL,
		RPC_C_AUTHN_LEVEL_CALL,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_NONE);
	if (FAILED(hr))
	{
		cout << "[client] Antivirus WMI proxy setup failed. HRESULT=" << hr << endl;
		if (coInitialized)
			::CoUninitialize();
		return false;
	}

	CComPtr<IEnumWbemClassObject> pEnum;
	CComBSTR cbsQuery = L"Select * From AntivirusProduct";
	hr = pWbemServices->ExecQuery(CComBSTR("WQL"), cbsQuery, WBEM_FLAG_FORWARD_ONLY, NULL, &pEnum);
	if (FAILED(hr))
	{
		cout << "[client] Antivirus WMI query failed. HRESULT=" << hr << endl;
		if (coInitialized)
			::CoUninitialize();
		return false;
	}

	bool sawProduct = false;
	bool sawEnabledProduct = false;
	bool sawUnknownState = false;

	while (true)
	{
		ULONG objectCount = 0;
		CComPtr<IWbemClassObject> pWmiObject;
		hr = pEnum->Next(1000, 1, &pWmiObject, &objectCount);
		const AntiTamperAntivirus::WmiNextDecision nextDecision = AntiTamperAntivirus::ClassifyWmiNextResult(hr, objectCount);
		if (nextDecision == AntiTamperAntivirus::WmiNextDecision::Finished)
			break;
		if (nextDecision == AntiTamperAntivirus::WmiNextDecision::Unknown)
		{
			cout << "[client] Antivirus WMI enumeration did not return a reliable state. HRESULT=" << hr << endl;
			sawUnknownState = true;
			break;
		}

		sawProduct = true;

		CComVariant productState;
		hr = pWmiObject->Get(L"productState", 0, &productState, 0, 0);
		if (FAILED(hr) || (productState.vt != VT_I4 && productState.vt != VT_UI4))
		{
			sawUnknownState = true;
			continue;
		}

		const DWORD state = productState.vt == VT_I4
			? static_cast<DWORD>(productState.lVal)
			: productState.ulVal;
		const DWORD realtimeState = (state >> 8) & 0xff;
		if (realtimeState == 0x10 || realtimeState == 0x11)
		{
			sawEnabledProduct = true;
			break;
		}
	}

	if (coInitialized)
		::CoUninitialize();

	if (sawUnknownState)
		return false;

	if (!sawProduct)
		return true;

	return !sawEnabledProduct;
}
