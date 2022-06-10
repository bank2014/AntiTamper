#include "pch.h"
#include <winternl.h>

// 기존 구현은 커널 hard error로 의도적인 블루스크린을 발생시켰다.
// 안전 종료 정책에 따라 위험 호출은 주석 처리하고 경고창으로 대체한다.
void BSOD(uint32 delay)
{
    Sleep(delay);

    /*
    typedef NTSTATUS(NTAPI* pdef_NtRaiseHardError)(NTSTATUS ErrorStatus,
        ULONG NumberOfParameters,
        ULONG UnicodeStringParameterMask OPTIONAL,
        PULONG_PTR Parameters, ULONG ResponseOption,
        PULONG Response);
    typedef NTSTATUS(NTAPI* pdef_RtlAdjustPrivilege)(ULONG Privilege,
        BOOLEAN Enable,
        BOOLEAN CurrentThread,
        PBOOLEAN Enabled);

    BOOLEAN bEnabled;
    ULONG uResp;
    LPVOID lpFuncAddress = GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlAdjustPrivilege");
    LPVOID lpFuncAddress2 = GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtRaiseHardError");
    pdef_RtlAdjustPrivilege NtCall = (pdef_RtlAdjustPrivilege)lpFuncAddress;
    pdef_NtRaiseHardError NtCall2 = (pdef_NtRaiseHardError)lpFuncAddress2;
    NTSTATUS NtRet = NtCall(19, TRUE, FALSE, &bEnabled);
    NtCall2(STATUS_FLOAT_MULTIPLE_FAULTS, 0, 0, 0, 6, &uResp);
    */

    MessageBox(NULL, L"Security violation detected. Shutting down the application.", L"AntiTamper", MB_OK | MB_ICONWARNING);
}
