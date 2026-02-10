#include <windows.h>
#include <iostream>
#include <cstdio>
#include <cstring>
#include <strsafe.h>
#include <shlobj.h>
#include <tlhelp32.h>

#define TARGET_PROCESS "CRACKME.exe"
#define DLL_NAME       "attack_dll.dll"

// ───────────────────────────────────────
// 1) CrackMe.exe PID 찾기 
// ───────────────────────────────────────
DWORD FindProcessId(const char* processName)
{
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe = { 0 };
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(snap, &pe)) {
        CloseHandle(snap);
        return 0;
    }

    do {
        char exeNameA[MAX_PATH] = { 0 };
#ifdef UNICODE
        WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, exeNameA, MAX_PATH, NULL, NULL);
        const char* exeName = exeNameA;
#else
        const char* exeName = pe.szExeFile;
#endif
        if (_stricmp(exeName, processName) == 0) {
            pid = pe.th32ProcessID;
            break;
        }
    } while (Process32Next(snap, &pe));

    CloseHandle(snap);
    return pid;
}

// ───────────────────────────────────────
// 2) DLL 절대 경로 만들기 
// ───────────────────────────────────────
char* make_absolute_dll_path(const char* dllName, char* buffer, DWORD bufSize)
{
    char exePath[MAX_PATH] = { 0 };
    DWORD len = GetModuleFileNameA(NULL, exePath, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return nullptr;

    char* p = strrchr(exePath, '\\');
    if (p) *(p + 1) = '\0';

    size_t dirLen = strlen(exePath);
    size_t nameLen = strlen(dllName);
    if (dirLen + nameLen + 1 > bufSize) return nullptr;

    strcpy_s(buffer, bufSize, exePath);
    strcat_s(buffer, bufSize, dllName);
    return buffer;
}

// ───────────────────────────────────────
// [NEW] NtCreateThreadEx (비공개 API)를 이용한 인젝션
// ───────────────────────────────────────

// NtCreateThreadEx 구조체 정의 (헤더에 없어서 직접 정의해야 함)
struct NtCreateThreadExBuffer {
    ULONG Size;
    ULONG Unknown1;
    ULONG Unknown2;
    PULONG Unknown3;
    ULONG Unknown4;
    ULONG Unknown5;
    ULONG Unknown6;
    PULONG Unknown7;
    ULONG Unknown8;
};

typedef NTSTATUS(WINAPI* LP_NtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    LPVOID ObjectAttributes,
    HANDLE ProcessHandle,
    LPTHREAD_START_ROUTINE StartRoutine,
    LPVOID Argument,
    BOOL CreateSuspended,
    ULONG_PTR ZeroBits,
    ULONG_PTR StackSize,
    ULONG_PTR MaximumStackSize,
    LPVOID AttributeList
    );

bool InjectDll(DWORD pid, const char* dllPath)
{
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        std::cout << "[ERROR] OpenProcess failed.\n";
        return false;
    }

    // 1. DLL 경로 메모리 할당 및 쓰기
    size_t len = strlen(dllPath) + 1;
    LPVOID remoteBuf = VirtualAllocEx(hProc, NULL, len, MEM_COMMIT, PAGE_READWRITE);
    if (!remoteBuf) {
        CloseHandle(hProc);
        return false;
    }
    WriteProcessMemory(hProc, remoteBuf, dllPath, len, NULL);

    // 2. LoadLibraryA 주소 구하기
    LPTHREAD_START_ROUTINE pLoadLibraryA =
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

    // 3. ntdll.dll에서 NtCreateThreadEx 함수 주소 가져오기
    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    LP_NtCreateThreadEx NtCreateThreadEx =
        (LP_NtCreateThreadEx)GetProcAddress(hNtDll, "NtCreateThreadEx");

    if (!NtCreateThreadEx) {
        std::cout << "[ERROR] Could not find NtCreateThreadEx.\n";
        CloseHandle(hProc);
        return false;
    }

    // 4. NtCreateThreadEx 호출 (CreateRemoteThread 우회)
    HANDLE hRemoteThread = NULL;
    NtCreateThreadExBuffer buffer = { 0 };
    buffer.Size = sizeof(NtCreateThreadExBuffer);
    buffer.Unknown1 = 0x10003;
    buffer.Unknown2 = 0x8;
    buffer.Unknown3 = NULL; // &temp2;
    buffer.Unknown4 = 0;
    buffer.Unknown5 = 0x10004;
    buffer.Unknown6 = 4;
    buffer.Unknown7 = NULL; // &temp1;
    buffer.Unknown8 = 0;

    NTSTATUS status = NtCreateThreadEx(
        &hRemoteThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProc,
        pLoadLibraryA,
        remoteBuf,
        FALSE, // CreateSuspended
        0, 0, 0, NULL
    );

    if (hRemoteThread) {
        std::cout << "[SUCCESS] NtCreateThreadEx Call Successful!\n";
        WaitForSingleObject(hRemoteThread, INFINITE);
        CloseHandle(hRemoteThread);
        CloseHandle(hProc);
        return true;
    }
    else {
        std::cout << "[ERROR] NtCreateThreadEx Failed. Status: " << std::hex << status << "\n";
        VirtualFreeEx(hProc, remoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }
}

// ───────────────────────────────────────
// 4) name → serial 계산 함수들
// ───────────────────────────────────────
DWORD CalcSerialFromName(char* name)
{
    char* p = name;
    while (1) {
        char ch = *p;
        if (ch == 0) break;
        if (ch < 'A') return 0; // Invalid char
        if (ch >= 'Z') {
            ch = ch - 0x20;
            *p = ch;
        }
        p++;
    }
    DWORD sum = 0;
    p = name;
    while (*p) {
        sum += (unsigned char)*p;
        p++;
    }
    return sum ^ 0x5678;
}

DWORD MakeSerialFromName(const char* nameInput)
{
    char buf[256];
    strcpy_s(buf, sizeof(buf), nameInput);
    DWORD nameResult = CalcSerialFromName(buf);
    return nameResult ^ 0x1234;
}

// ───────────────────────────────────────
// 5) R1 루프: 기존 Register 감시 + Serial 자동 입력
// ───────────────────────────────────────
void RunR1Loop()
{
    char prevName[256] = { 0 };
    std::cout << "[INFO] Starting R1 Loop (Auto Serial Input)...\n";

    while (true)
    {
        HWND hDlg = NULL;
        // Register 창 찾기
        while (hDlg == NULL) {
            hDlg = FindWindowA("#32770", "Register");
            if (hDlg == NULL) Sleep(500);
        }

        // Edit 컨트롤 찾기
        HWND hEdit1 = FindWindowExA(hDlg, NULL, "Edit", NULL);
        HWND hEdit2 = FindWindowExA(hDlg, hEdit1, "Edit", NULL);

        if (!hEdit1 || !hEdit2) {
            Sleep(500);
            continue;
        }

        RECT r1, r2;
        GetWindowRect(hEdit1, &r1);
        GetWindowRect(hEdit2, &r2);

        HWND hNameEdit = (r1.top < r2.top) ? hEdit1 : hEdit2;
        HWND hSerialEdit = (r1.top < r2.top) ? hEdit2 : hEdit1;

        // Register 창이 켜져 있는 동안 계속 감시
        while (IsWindow(hDlg))
        {
            char curName[256] = { 0 };
            SendMessageA(hNameEdit, WM_GETTEXT, (WPARAM)255, (LPARAM)curName);

            if (strcmp(curName, prevName) != 0)
            {
                strcpy_s(prevName, sizeof(prevName), curName);
                if (curName[0] == '\0') {
                    SendMessageA(hSerialEdit, WM_SETTEXT, 0, (LPARAM)"");
                }
                else {
                    DWORD serialVal = MakeSerialFromName(curName);
                    char serialStr[32];
                    sprintf_s(serialStr, sizeof(serialStr), "%u", serialVal);
                    SendMessageA(hSerialEdit, WM_SETTEXT, 0, (LPARAM)serialStr);
                    std::cout << "[R1] Name: " << curName << " -> Serial: " << serialStr << "\n";
                }
            }
            Sleep(100);
        }
        std::cout << "[INFO] Register dialog closed. Waiting for next...\n";
    }
}

// ───────────────────────────────────────
// 6) main
// ───────────────────────────────────────
int main()
{
    std::cout << "[INFO] Attack started.\n";

    // 1) CrackMe PID 찾기
    DWORD pid = FindProcessId(TARGET_PROCESS);
    if (pid == 0) {
        std::cout << "[ERROR] target process not found: " << TARGET_PROCESS << "\n";
        return 1;
    }

    // 2) DLL 경로 생성
    char dllPath[MAX_PATH] = { 0 };
    if (!make_absolute_dll_path(DLL_NAME, dllPath, MAX_PATH)) {
        std::cout << "[ERROR] make_absolute_dll_path failed.\n";
        return 1;
    }
    std::cout << "[INFO] DLL Path: " << dllPath << "\n";

    // 3) DLL 인젝션 (R2 공격 시작)
    if (InjectDll(pid, dllPath)) {
        std::cout << "[SUCCESS] DLL Injected! (Subclassing Hook Active)\n";
    }
    else {
        std::cout << "[ERROR] DLL Injection Failed.\n";
        return 1;
    }

 
    RunR1Loop();

    return 0;
}