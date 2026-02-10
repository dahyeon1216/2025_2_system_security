// injector.c 
// 빌드: Visual Studio (x86) -> Console App
#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <wchar.h>

DWORD FindProcIdByName(const wchar_t* processName) {
    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, processName) == 0) {
                DWORD pid = entry.th32ProcessID;
                CloseHandle(snapshot);
                return pid;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return 0;
}

// Returns TRUE if process is running under WOW64 (i.e., 32-bit process on 64-bit OS)
// If function fails, returns FALSE and sets *pOk = FALSE.
BOOL IsProcessWow64(HANDLE hProcess, BOOL* pOk) {
    BOOL isWow = FALSE;
    typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);
    LPFN_ISWOW64PROCESS fn = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandleA("kernel32"), "IsWow64Process");
    if (!fn) { *pOk = FALSE; return FALSE; }
    if (!fn(hProcess, &isWow)) { *pOk = FALSE; return FALSE; }
    *pOk = TRUE;
    return isWow;
}

int wmain(int argc, wchar_t* argv[])
{
    wprintf(L"Simple Injector (32-bit) - Usage: %s <procname.exe | pid> <full_path_to_dll>\n\n", argv[0]);

    if (argc < 3) {
        wprintf(L"Example: %s notepad.exe C:\\full\\path\\hook.dll\n", argv[0]);
        return 1;
    }

    // Get target pid
    DWORD pid = 0;
    if (iswdigit(argv[1][0])) {
        pid = (DWORD)_wtoi(argv[1]);
    }
    else {
        pid = FindProcIdByName(argv[1]);
    }
    if (!pid) {
        wprintf(L"[error] Target process not found: %s\n", argv[1]);
        return 1;
    }

    // dll path
    const wchar_t* dllPath = argv[2];
    if (dllPath[0] == L'\0' || wcslen(dllPath) < 4) {
        wprintf(L"[error] Invalid DLL path\n");
        return 1;
    }

    // Check architecture compatibility
    BOOL ok;
    BOOL curWow = IsProcessWow64(GetCurrentProcess(), &ok);
    if (!ok) curWow = FALSE; // If API unavailable, assume not wow64
    HANDLE hTarget = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hTarget) {
        wprintf(L"[error] OpenProcess(PROCESS_QUERY_INFORMATION) failed: %u\n", GetLastError());
        wprintf(L"-> Try running injector as Administrator.\n");
        return 1;
    }
    BOOL targetWow = IsProcessWow64(hTarget, &ok);
    if (!ok) {
        // cannot determine; warn but continue
        wprintf(L"[warning] Cannot determine target architecture; continuing anyway.\n");
    }
    else {
        // If injector is 32-bit on 64-bit OS (curWow==TRUE) and targetWow==FALSE => target is 64-bit -> incompatible
        if (curWow && !targetWow) {
            wprintf(L"[error] Architecture mismatch: this injector is 32-bit but target is 64-bit. Cannot inject.\n");
            CloseHandle(hTarget);
            return 1;
        }
    }
    CloseHandle(hTarget);

    size_t dllPathLen = (wcslen(dllPath) + 1) * sizeof(wchar_t);

    // Open target with required minimal rights
    DWORD desired = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
    HANDLE hProc = OpenProcess(desired, FALSE, pid);
    if (!hProc) {
        wprintf(L"[error] OpenProcess failed: %u\n", GetLastError());
        wprintf(L"-> Try running as Administrator or use a process with same integrity level.\n");
        return 1;
    }

    // Allocate memory in target
    LPVOID remoteMem = VirtualAllocEx(hProc, NULL, dllPathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        wprintf(L"[error] VirtualAllocEx failed: %u\n", GetLastError());
        CloseHandle(hProc);
        return 1;
    }

    // Write path
    if (!WriteProcessMemory(hProc, remoteMem, dllPath, dllPathLen, NULL)) {
        wprintf(L"[error] WriteProcessMemory failed: %u\n", GetLastError());
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }

    // Get address of LoadLibraryW in our process (kernel32 is loaded in every process at same base in user space conceptually)
    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    if (!hK32) {
        wprintf(L"[error] GetModuleHandleW(kernel32) failed\n");
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }
    FARPROC pLoadLibW = GetProcAddress(hK32, "LoadLibraryW");
    if (!pLoadLibW) {
        wprintf(L"[error] GetProcAddress(LoadLibraryW) failed\n");
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }

    // Create remote thread
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibW, remoteMem, 0, NULL);
    if (!hThread) {
        wprintf(L"[error] CreateRemoteThread failed: %u\n", GetLastError());
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }

    // Wait and clean up
    WaitForSingleObject(hThread, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    CloseHandle(hThread);

    // Free remote memory (optional)
    VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hProc);

    if (exitCode == 0) {
        wprintf(L"[warning] Remote LoadLibrary returned NULL (DLL may have failed to load).\n");
    }
    else {
        wprintf(L"[ok] DLL injected. LoadLibrary returned HMODULE=0x%08X\n", exitCode);
    }
    return 0;
}
