#pragma once
#include "Struct.h"
#include "typecast.h"

EXTERN_C NTSTATUS NTAPI
NtQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID               SystemInformation,
	IN ULONG                SystemInformationLength,
	OUT PULONG              ReturnLength OPTIONAL);


// 어셈블리 매크로용 선언
EXTERN_C __int16 LazyCheckHyperv();
EXTERN_C void TrapflagCheck();

namespace DetectHyp {

	inline bool RdtscpSupport()
	{
		INT cpuid[4] = { -1 };
		__cpuid(cpuid, 0x80000001);
		return ((cpuid[3] >> 27) & 1);// chekc 27 bit EDX
	}

	inline bool CpuidIsHyperv()
	{// Check 31 bit  in ECX 
		INT cpuinf[4] = { 0 };
		__cpuid(cpuinf, 1);
		return ((cpuinf[2] >> 31) & 1);
	}

	inline bool RdtscCpu()
	{
		DWORD tsc1 = 0;
		DWORD tsc2 = 0;
		DWORD avg = 0;
		INT cpuInfo[4] = {};
		for (INT i = 0; i < 10; i++)
		{
			tsc1 = __rdtsc();
			__cpuid(cpuInfo, 0);
			tsc2 = __rdtsc();
			avg += (tsc2 - tsc1);
		}
		avg = avg / 10;
		return (avg < 500 && avg > 25) ? FALSE : TRUE;
	}

	inline bool Rdtscp()
	{
		unsigned int  flag = 0;
		DWORD tscp1 = 0;
		DWORD tscp2 = 0;
		DWORD avg = 0;
		INT cpuid[4] = {};

		if (DetectHyp::RdtscpSupport()) {
			for (INT j = 0; j < 10; j++)
			{
				tscp1 = __rdtscp(&flag);
				//call 3 cpuid for normal detect
				__cpuid(cpuid, 0);
				__cpuid(cpuid, 0);
				__cpuid(cpuid, 0);
				tscp2 = __rdtscp(&flag);
				avg += tscp2 - tscp1;
				if (avg < 500 && avg > 25)
					return false;
				else
					avg = 0;
			}
			return true;
		}
		else
			return false; //rdtscp dont support
	}

	inline bool RdtscHeap()
	{
		ULONGLONG tsc1 = 0;
		ULONGLONG tsc2 = 0;
		ULONGLONG tsc3 = 0;

		for (DWORD i = 0; i < 10; i++)
		{
			tsc1 = __rdtsc();

			GetProcessHeap();

			tsc2 = __rdtsc();

			CloseHandle(0);

			tsc3 = __rdtsc();

			if ((tsc3 - tsc2) / (tsc2 - tsc1) >= 10)
				return FALSE;
		}

		return TRUE;
	}

	inline bool UmpIsSystemVirtualized()
	{
		DWORD invalid_leaf = 0x13371337;
		DWORD valid_leaf = 0x40000000;
		INT  InvalidLeafResponse[4] = { -1 };
		INT ValidLeafResponse[4] = { -1 };

		__cpuid(InvalidLeafResponse, invalid_leaf);
		__cpuid(ValidLeafResponse, valid_leaf);

		if ((InvalidLeafResponse[0] != ValidLeafResponse[0]) ||
			(InvalidLeafResponse[1] != ValidLeafResponse[1]) ||
			(InvalidLeafResponse[2] != ValidLeafResponse[2]) ||
			(InvalidLeafResponse[3] != ValidLeafResponse[3]))
			return true;

		return false;
	}

	inline int filter(unsigned int code, struct _EXCEPTION_POINTERS* ep, BOOL& bDetected, int& singleStepCount)
	{
		if (code != EXCEPTION_SINGLE_STEP)
		{
			bDetected = true;
			return EXCEPTION_CONTINUE_SEARCH;
		}

		singleStepCount++;
		if ((size_t)ep->ExceptionRecord->ExceptionAddress != (size_t)TrapflagCheck + 11)
		{
			bDetected = true;
			return EXCEPTION_EXECUTE_HANDLER;
		}

		bool bIsRaisedBySingleStep = ep->ContextRecord->Dr6 & (1 << 14);
		bool bIsRaisedByDr0 = ep->ContextRecord->Dr6 & 1;
		if (!bIsRaisedBySingleStep || !bIsRaisedByDr0)
		{
			bDetected = true;
		}
		return EXCEPTION_EXECUTE_HANDLER;
	}


	inline bool CheckKnowHypervisor()
	{
		INT CPUInfo[4] = { -1 };
		CHAR szHypervisorVendor[0x40];
		WCHAR* pwszConverted;

		BOOL bResult = FALSE;

		const TCHAR* szBlacklistedHypervisors[] = {
			(L"KVMKVMKVM\0\0\0"),	//KVM
			(L"Microsoft Hv"),		//Microsoft Hyper-V | Windows Virtual PC
			(L"VMwareVMware"),		//VMware
			(L"XenVMMXenVMM"),		//Xen
			(L"prl hyperv  "),		//Parallels
			(L"VBoxVBoxVBox"),		//VirtualBox
		};

		WORD dwlength = sizeof(szBlacklistedHypervisors) / sizeof(szBlacklistedHypervisors[0]);

		__cpuid(CPUInfo, 0x40000000);
		memset(szHypervisorVendor, 0, sizeof(szHypervisorVendor));
		memcpy(szHypervisorVendor, CPUInfo + 1, 12);

		for (int i = 0; i < dwlength; i++)
		{
			pwszConverted = typeCast::CharToWChar_T(szHypervisorVendor);
			if (pwszConverted) {

				bResult = (wcscmp(pwszConverted, szBlacklistedHypervisors[i]) == 0); // 이름 비교

				free(pwszConverted);

				if (bResult)
					return TRUE;
			}
		}
		return FALSE;
	}

	// https://pastebin.com/2gv72r7d
	// waleedassar's hypervisor detection - 상업 Anti cheat에서 사용하는 방식
	inline bool LazyCheckHypervisor() {

		if (LazyCheckHyperv())
			return true;
		else
			return false;
	}

	// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/hypervisor_detail.htm
	// SYSTEM_HYPERVISOR_DETAIL_INFORMATION 
	inline bool SystemHypDetailInformation() {

		SYSTEM_HYPERVISOR_DETAIL_INFORMATION systHypervDetailInf{ 0 };
		ULONG retLenth = NULL;

		NtQuerySystemInformation(
			SystemHypervisorDetailInformation,
			&systHypervDetailInf,
			sizeof(SYSTEM_HYPERVISOR_DETAIL_INFORMATION), //0x70
			&retLenth
		);
		if (systHypervDetailInf.ImplementationLimits.Data[0] != 0
			|| systHypervDetailInf.HypervisorInterface.Data[0] != 0
			|| systHypervDetailInf.EnlightenmentInfo.Data[0] != 0
			|| systHypervDetailInf.HvVendorAndMaxFunction.Data[0] != 0
			|| systHypervDetailInf.HvVendorAndMaxFunction.Data[1] != 0)
			return true;
		else
			return false;

	}

}