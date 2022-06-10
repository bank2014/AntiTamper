#pragma once
#include "pch.h"

#include <malloc.h>
#include <intrin.h>
#include <iostream>

#pragma comment(lib, "ntdll.lib")

#include "Struct.h"
#include "DetectHypervisor.h"


// Hypervisor/VM 환경을 탐지한다.
// RDTSC/RDTSCP timing check는 일반 장비에서도 부하와 CPU 상태에 따라 흔들리므로
// 차단 판정에는 사용하지 않고, CPUID vendor와 firmware marker처럼 안정적인 증거만 사용한다.
bool IsHypervisorPresent()
{
	if (DetectHyp::HasKnownVirtualMachineFirmware())
		return true;

	if (!DetectHyp::CpuidIsHyperv())
		return false;

	const std::string vendor = DetectHyp::GetHypervisorVendor();
	if (!DetectHyp::IsKnownHypervisorVendor(vendor))
		return false;

	// Bare-metal Windows can expose "Microsoft Hv" when Hyper-V/VBS is enabled.
	// Treat it as VM only when firmware/model data also says this is virtual hardware.
	if (DetectHyp::IsMicrosoftHypervisorVendor(vendor))
		return DetectHyp::HasKnownVirtualMachineFirmware();

	return true;

}

