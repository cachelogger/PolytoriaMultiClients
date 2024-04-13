#include "pch.h"
#include "MinHook.h"
#include <tlhelp32.h>

#include <vector>
#include <algorithm>

#include <fstream>
#include <format>
#include <locale>
#include <codecvt>

#include <psapi.h>
#include <winternl.h>

wchar_t selfDllPath[MAX_PATH];

std::string to_narrow(const std::wstring& wide) {
    std::string narrow;
    narrow.reserve(wide.size());
    for (auto wc : wide) {
        narrow.push_back(static_cast<char>(wc));  // Naive conversion, only safe for ASCII
    }
    return narrow;
}

void LogMessage(const char* message) {
    LPCWSTR path = L"%USERPROFILE%\\AppData\\Local\\Temp\\DontTerminate.log";
    WCHAR dest[MAX_PATH];
    ExpandEnvironmentStringsW(path, dest, MAX_PATH);

    std::ofstream logFile(dest, std::ios::app);
    logFile << message << std::endl;
    logFile.close();
}

BOOL InjectDLL(DWORD dwProcessId, const char* dllPath) {
    LogMessage(std::format("Injecting DLL into process: {}", dwProcessId).c_str());
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwProcessId);
    if (!hProcess) {
        LogMessage(std::format("Failed to open process: {}, Error: {}", dwProcessId, GetLastError()).c_str());
        return FALSE;
    }

    void* pLibRemote = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (!pLibRemote) {
        LogMessage(std::format("Failed to allocate memory in process: {}, Error: {}", dwProcessId, GetLastError()).c_str());
        CloseHandle(hProcess);
        return FALSE;
    }

    if (!WriteProcessMemory(hProcess, pLibRemote, (void*)dllPath, strlen(dllPath) + 1, NULL)) {
        LogMessage(std::format("Failed to write memory in process: {}, Error: {}", dwProcessId, GetLastError()).c_str());
        VirtualFreeEx(hProcess, pLibRemote, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryA"),
        pLibRemote, 0, NULL);
    if (!hThread) {
        LogMessage(std::format("Failed to create remote thread in process: {}, Error: {}", dwProcessId, GetLastError()).c_str());
        VirtualFreeEx(hProcess, pLibRemote, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    LogMessage(std::format("Successfully injected DLL into process: {}", dwProcessId).c_str());
    WaitForSingleObject(hThread, INFINITE);

    // Check the exit code to verify successful DLL load
    DWORD dwExitCode;
    if (GetExitCodeThread(hThread, &dwExitCode) && dwExitCode == 0) {
        LogMessage(std::format("DLL was not loaded properly by the target process. Error: {}", GetLastError()).c_str());
    }


    VirtualFreeEx(hProcess, pLibRemote, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return TRUE;
}

typedef BOOL(WINAPI* _TerminateProcess)(HANDLE hProcess, UINT uExitCode);
typedef BOOL(WINAPI* _Process32First)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
typedef BOOL(WINAPI* _Process32Next)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
typedef BOOL(WINAPI* _CreateProcessW)(
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation);
typedef BOOL(WINAPI* _CreateProcessA)(
	LPCSTR lpApplicationName,
	LPSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCSTR lpCurrentDirectory,
	LPSTARTUPINFOA lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation);

typedef BOOL(WINAPI* PFN_EnumProcesses)(DWORD* pProcessIds, DWORD cb, DWORD* pBytesReturned);
PFN_EnumProcesses oEnumProcesses = NULL;  // Original function pointer

typedef NTSTATUS(NTAPI* PFN_NtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
PFN_NtQuerySystemInformation oNtQuerySystemInformation = NULL;  // Original


_TerminateProcess oTerminateProcess = NULL;
_Process32First oProcess32First = NULL;
_Process32Next oProcess32Next = NULL;
_CreateProcessW oCreateProcessW = NULL;  // Original function pointer
_CreateProcessA oCreateProcessA = NULL;

// Example: Store the process IDs of "hidden" processes
std::vector<DWORD> hiddenProcesses;

bool WINAPI hkTerminateProcess(HANDLE hProcess, UINT uExitCode)
{
    LogMessage(std::format("Terminating process: {}", GetProcessId(hProcess)).c_str());
    DWORD processId = GetProcessId(hProcess);
    DWORD currentProcessId = GetCurrentProcessId();

    // Allow current process to terminate itself only if it's "Polytoria.exe"
    if (processId == currentProcessId) {
        // Get the process name of the current process
        WCHAR currentProcessName[MAX_PATH];
        if (GetModuleFileNameW(NULL, currentProcessName, MAX_PATH) != 0) {
            std::wstring processName(currentProcessName);
            std::wstring allowedProcessName = L"Polytoria.exe";
            if (processName.find(allowedProcessName) != std::wstring::npos) {
                LogMessage("Terminating current process, allowed because it's Polytoria.exe");
                return oTerminateProcess(hProcess, uExitCode);
            }
        }
    }

    // For other processes, pretend the termination was successful
    hiddenProcesses.push_back(processId);
    return true;
}


BOOL WINAPI hkProcess32First(HANDLE hSnapshot, LPPROCESSENTRY32 lppe) {
    LogMessage(std::format("Process32First: {}", lppe->th32ProcessID).c_str());
    BOOL result = oProcess32First(hSnapshot, lppe);
    // Check both the hiddenProcesses list and the process name for "Polytoria"
    while (result && (std::find(hiddenProcesses.begin(), hiddenProcesses.end(), lppe->th32ProcessID) != hiddenProcesses.end() || wcsstr(lppe->szExeFile, L"Polytoria") != nullptr)) {
        result = oProcess32Next(hSnapshot, lppe);  // Skip hidden processes and any with "Polytoria" in the name
    }
    return result;
}

BOOL WINAPI hkProcess32Next(HANDLE hSnapshot, LPPROCESSENTRY32 lppe) {
    LogMessage(std::format("Process32Next: {}", lppe->th32ProcessID).c_str());
    BOOL result = oProcess32Next(hSnapshot, lppe);
    // Check both the hiddenProcesses list and the process name for "Polytoria"
    while (result && (std::find(hiddenProcesses.begin(), hiddenProcesses.end(), lppe->th32ProcessID) != hiddenProcesses.end() || wcsstr(lppe->szExeFile, L"Polytoria") != nullptr)) {
        result = oProcess32Next(hSnapshot, lppe);  // Skip hidden processes and any with "Polytoria" in the name
    }

    return result;
}

BOOL WINAPI hkCreateProcessW(
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
    LogMessage("CreateProcessW called");

    // log lpApplicationName
    if (lpApplicationName) {
		std::wstring appName(lpApplicationName);
		LogMessage(to_narrow(std::format(L"Application name: {}", appName)).c_str());
	}

    if (lpCommandLine) {
        std::wstring cmdLine(lpCommandLine);
        LogMessage(to_narrow(std::format(L"Command line: {}", cmdLine)).c_str());

        if (cmdLine.find(L"taskkill") != std::wstring::npos) {
            LogMessage("Attempt to start taskkill blocked.");
            // Replace Polytoria.exe in the command with random.exe
            std::wstring randomExe = L"random";
            std::wstring::size_type pos = cmdLine.find(L"Polytoria");
            if (pos != std::wstring::npos) {
                cmdLine.replace(pos, 9, randomExe);
				LogMessage(to_narrow(std::format(L"Command line after replacement: {}", cmdLine)).c_str());
				return oCreateProcessW(lpApplicationName, const_cast<LPWSTR>(cmdLine.c_str()), lpProcessAttributes, lpThreadAttributes,
                    					bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory,
                    					lpStartupInfo, lpProcessInformation);
            }
        }
    }

    // Call original function if not handling a taskkill attempt
    oCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
        bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory,
        lpStartupInfo, lpProcessInformation);

    // Inject self into the new process
    InjectDLL(lpProcessInformation->dwProcessId, to_narrow(selfDllPath).c_str());

    return TRUE;
}

// With createprocessa, we just log the command line
BOOL WINAPI hkCreateProcessA(
    LPCSTR lpApplicationName,
    LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,
    LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
	LogMessage("CreateProcessA called");

    if (lpCommandLine) {
		std::string cmdLine(lpCommandLine);
		LogMessage(std::format("Command line: {}", cmdLine).c_str());
    }
    else if (lpApplicationName) {
		std::string appName(lpApplicationName);
		LogMessage(std::format("Application name: {}", appName).c_str());
	}

    
	oCreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
        		bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory,
        		lpStartupInfo, lpProcessInformation);

    // Inject self into the new process
    InjectDLL(lpProcessInformation->dwProcessId, to_narrow(selfDllPath).c_str());

    return TRUE;
}

BOOL WINAPI hkEnumProcesses(DWORD* pProcessIds, DWORD cb, DWORD* pBytesReturned) {
    BOOL result = oEnumProcesses(pProcessIds, cb, pBytesReturned);
    if (result) {
        DWORD numProcesses = *pBytesReturned / sizeof(DWORD);
        DWORD index = 0;
        for (DWORD i = 0; i < numProcesses; i++) {
            DWORD pid = pProcessIds[i];
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (hProcess) {
                WCHAR szProcessName[MAX_PATH] = { 0 };
                if (GetProcessImageFileName(hProcess, szProcessName, MAX_PATH) > 0) {
                    if (wcsstr(szProcessName, L"Polytoria Client.exe")) {
                        // Skip this process
                        continue;
                    }
                }
                CloseHandle(hProcess);
            }
            pProcessIds[index++] = pid;  // Only increment index if not skipping
        }
        *pBytesReturned = index * sizeof(DWORD);  // Adjust the number of bytes returned
    }
    return result;
}

NTSTATUS NTAPI hkNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
    NTSTATUS status = oNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
    if (NT_SUCCESS(status) && SystemInformationClass == SystemProcessInformation) {
        PSYSTEM_PROCESS_INFORMATION current = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
        PSYSTEM_PROCESS_INFORMATION previous = NULL;

        while (current) {
            UNICODE_STRING name = current->ImageName;
            if (name.Buffer != NULL && wcsstr(name.Buffer, L"Polytoria Client.exe")) {
                if (previous) {
                    if (current->NextEntryOffset == 0) previous->NextEntryOffset = 0;
                    else previous->NextEntryOffset += current->NextEntryOffset;
                }
                else {
                    if (current->NextEntryOffset == 0) SystemInformation = NULL;
                    else SystemInformation = (PBYTE)current + current->NextEntryOffset;
                }
            }
            else {
                previous = current;
            }
            if (current->NextEntryOffset == 0) break;
            current = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)current + current->NextEntryOffset);
        }
    }
    return status;
}

void SetupHooks() {
    if (MH_Initialize() != MH_OK) {
		LogMessage("Failed to initialize MinHook");
		return;
	}

    if (MH_CreateHookApi(L"kernel32.dll", "TerminateProcess", &hkTerminateProcess, reinterpret_cast<void**>(&oTerminateProcess)) != MH_OK) {
		LogMessage("Failed to hook TerminateProcess");
		return;
	}

    if (MH_CreateHookApi(L"kernel32.dll", "Process32First", &hkProcess32First, reinterpret_cast<void**>(&oProcess32First)) != MH_OK) {
        LogMessage("Failed to hook Process32First");
        return;
    }

    if (MH_CreateHookApi(L"kernel32.dll", "Process32Next", &hkProcess32Next, reinterpret_cast<void**>(&oProcess32Next)) != MH_OK) {
		LogMessage("Failed to hook Process32Next");
		return;
	}

    if (MH_CreateHookApi(L"kernel32.dll", "CreateProcessW", &hkCreateProcessW, reinterpret_cast<void**>(&oCreateProcessW)) != MH_OK) {
        LogMessage("Failed to hook CreateProcessW");
        return;
    }

    if (MH_CreateHookApi(L"kernel32.dll", "CreateProcessA", &hkCreateProcessA, reinterpret_cast<void**>(&oCreateProcessA)) != MH_OK) {
		LogMessage("Failed to hook CreateProcessA");
		return;
	}

    //if (MH_CreateHookApi(L"psapi.dll", "EnumProcesses", &hkEnumProcesses, reinterpret_cast<void**>(&oEnumProcesses)) != MH_OK) {
    //    LogMessage("Failed to hook EnumProcesses");
    //    return;
	//}

    if (MH_CreateHookApi(L"ntdll.dll", "NtQuerySystemInformation", &hkNtQuerySystemInformation, reinterpret_cast<void**>(&oNtQuerySystemInformation)) != MH_OK) {
		LogMessage("Failed to hook NtQuerySystemInformation");
		return;
	}

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
		LogMessage("Failed to enable hooks");
		return;
	}

    LogMessage("Hooks set up successfully");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        GetTempPathW(MAX_PATH, selfDllPath);
        wcscat_s(selfDllPath, L"DontTerminate.dll");
        LogMessage("Attached.");
        LogMessage(std::format("DLL attached. Is copied to: {}", to_narrow(selfDllPath)).c_str());

        SetupHooks();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
