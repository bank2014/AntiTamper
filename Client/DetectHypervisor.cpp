#pragma once
#include "pch.h"

#include <malloc.h>
#include <intrin.h>
#include <iostream>

#pragma comment(lib, "ntdll.lib")

#include "Struct.h"
#include "DetectHypervisor.h"


// Hypervisor 를 탐지 (상용 VM, KVM 등 모두 포함)
// returns true if the application is running inside a hypervisor
bool IsHypervisorPresent()
{
	//Rdtscp support check - https://modoocode.com/en/inst/rdtscp
	if (!DetectHyp::RdtscpSupport())
	{
		MessageBox(NULL, L"Rdtscp check failed. aborting..", L"Error", MB_OK);
		DeleteMyself();
		exit(-1);
	}

	uint8 flag = 0; // bit flag

	//Time attack with rdtsc 
	if (DetectHyp::RdtscCpu()) flag += 0x1;
	//Time attack with rdtscp 
	if (DetectHyp::Rdtscp()) flag += 0x2;
	//Time attack with rdtsc using GetHeap & CloseHandle 
	if (DetectHyp::RdtscHeap()) flag += 0x4;
	//SYSTEM_HYPERVISOR_DETAIL_INFORMATION 
	if (DetectHyp::SystemHypDetailInformation()) flag += 0x8;
	//Detect known hypervisor with cpuid & name 
	if (DetectHyp::CheckKnowHypervisor()) flag += 0x10;
	//Cpuid is hyperv 
	if (DetectHyp::CpuidIsHyperv()) flag += 0x20;
	//Lazy check Hypervisor - 상업 Anti cheat에서 사용하는 방식 https://pastebin.com/2gv72r7d
	if (DetectHyp::LazyCheckHypervisor()) flag += 0x40;
	//Compare cpuid list - cpuid 목록을 비교하고 일치하면 hypervisor 안에 있는 것
	if (DetectHyp::UmpIsSystemVirtualized()) flag += 0x80;
		
	if (flag) // 어떤 것 중 하나라도 true 이면 hypervisor
	{
		return true;
	}

	return false;
}

