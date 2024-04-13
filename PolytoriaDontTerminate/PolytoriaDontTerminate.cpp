#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <vector>

BOOL InjectDLL(DWORD dwProcessId, const char* dllPath) {
    printf("Injecting DLL into process: %lu\n", dwProcessId);
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwProcessId);
    if (!hProcess) {
        printf("Failed to open process: %lu, Error: %lu\n", dwProcessId, GetLastError());
        return FALSE;
    }

    void* pLibRemote = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (!pLibRemote) {
        printf("Failed to allocate memory in process: %lu, Error: %lu\n", dwProcessId, GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    if (!WriteProcessMemory(hProcess, pLibRemote, (void*)dllPath, strlen(dllPath) + 1, NULL)) {
        printf("Failed to write memory in process: %lu, Error: %lu\n", dwProcessId, GetLastError());
        VirtualFreeEx(hProcess, pLibRemote, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryA"),
        pLibRemote, 0, NULL);
    if (!hThread) {
        printf("Failed to create remote thread in process: %lu, Error: %lu\n", dwProcessId, GetLastError());
        VirtualFreeEx(hProcess, pLibRemote, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("Successfully injected DLL into process: %lu\n", dwProcessId);
    WaitForSingleObject(hThread, INFINITE);

    // Check the exit code to verify successful DLL load
    DWORD dwExitCode;
    if (GetExitCodeThread(hThread, &dwExitCode) && dwExitCode == 0) {
        printf("DLL was not loaded properly by the target process. Error: %lu\n", GetLastError());
    }


    VirtualFreeEx(hProcess, pLibRemote, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return TRUE;
}

std::vector<DWORD> alreadyInjected = {};

void FindAndInject(const wchar_t* processName, const char* dllPath) {
    printf("Searching for process: %ls\n", processName);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("Failed to create process snapshot, Error: %lu\n", GetLastError());
        return;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (wcscmp(pe32.szExeFile, processName) == 0) {
                printf("Found process: %ls (PID: %lu)\n", pe32.szExeFile, pe32.th32ProcessID);
                if (std::find(alreadyInjected.begin(), alreadyInjected.end(), pe32.th32ProcessID) != alreadyInjected.end()) {
					printf("DLL already injected into process: %lu\n", pe32.th32ProcessID);
					continue;
				}

                alreadyInjected.push_back(pe32.th32ProcessID);
                InjectDLL(pe32.th32ProcessID, dllPath);
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    else {
        printf("Failed to retrieve processes information, Error: %lu\n", GetLastError());
    }

    CloseHandle(hSnapshot);
}

int main() {
    const char* dllPath = "C:\\Users\\franc\\source\\repos\\DontTerminate\\x64\\Release\\DontTerminate.dll";  // Use an absolute path
    const wchar_t* processName = L"Polytoria.exe";
    const wchar_t* clientProcessName = L"Polytoria Client.exe";

    while (1) {
        FindAndInject(processName, dllPath);
        FindAndInject(clientProcessName, dllPath);
        Sleep(250);
    }

    return 0;
}
