#include "pch.h"
#include <string>
#include <atlbase.h> // For ATL autorelease classes (CComBSTR, CComPtr)
#include <wbemidl.h> // For WMI
#include<iostream>

#pragma comment(lib, "wbemuuid.lib") // Link to WMI library

std::string GetAntivirusName()
{
	HRESULT hr = ::CoInitializeEx(NULL, COINIT_MULTITHREADED);

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

	::CoUninitialize();
	// TODO
	//std::string antivirus_name = CW2A(cvtVersion.bstrVal);
	//return antivirus_name;

}