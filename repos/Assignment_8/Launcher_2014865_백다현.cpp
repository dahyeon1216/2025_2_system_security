// Launcher_학번_이름.cpp
#include <windows.h>
#include <intrin.h>   // __readfsdword, __readgsqword
#include <stdio.h>
#include <debugapi.h> // DebugActiveProcess 등

// 전역 변수 (Watchdog 제어용)
volatile BOOL g_StopWatchdog = FALSE;
HANDLE g_hWatchdogThread = NULL;

// PEB 구조체: BeingDebugged 필드만 사용
typedef struct _PEB {
    BYTE   Reserved1[2];
    BYTE   BeingDebugged;
    BYTE   Reserved2[1];
    PVOID  Reserved3[2];
    PVOID  Ldr;
    PVOID  ProcessParameters;
} PEB, * PPEB;

// PEB를 통한 디버거 탐지
BOOL CheckDebuggerByPEB()
{
#ifdef _M_IX86
    PEB* peb = (PEB*)__readfsdword(0x30);   // x86: TEB[0x30] → PEB
#elif _M_X64
    PEB* peb = (PEB*)__readgsqword(0x60);   // x64: TEB[0x60] → PEB
#else
    return FALSE;
#endif
    return (peb->BeingDebugged != 0);
}

// 자기 자신 디버깅 여부 확인
BOOL IsDebuggingSelf()
{
    if (CheckDebuggerByPEB()) return TRUE;

    // 과제 8에서 IsDebuggerPresent() 직접 호출은 감점이므로 사용 X
    // 필요하면 CheckRemoteDebuggerPresent(GetCurrentProcess(), ...)를 추가할 수 있음.

    return FALSE;
}

// 주기적으로 디버깅 여부를 검사하는 Watchdog 스레드
DWORD WINAPI WatchdogThread(LPVOID lpParam)
{
    (void)lpParam;

    while (!g_StopWatchdog)
    {
        if (IsDebuggingSelf())
        {
            printf("[WATCHDOG] Debugger detected! __fastfail()\n");
            __fastfail(1);  // 즉시 프로세스 강제 종료
        }

        Sleep(300);  // 0.3초마다 검사
    }

    printf("[WATCHDOG] 정상 종료\n");
    return 0;
}

// Client 실행 함수
// - 성공 시 Client의 PID를 out 매개변수로 반환
BOOL StartClientProcess(DWORD* pClientPid)
{
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);

    if (!CreateProcessA(
        "Client.exe",    // lpApplicationName
        NULL,            // lpCommandLine
        NULL, NULL, FALSE,
        0,               // 디버그 플래그 없이 일반 실행
        NULL, NULL,
        &si, &pi
    )) {
        printf("[Launcher] Failed to start Client.exe. error=%lu\n", GetLastError());
        return FALSE;
    }

    *pClientPid = pi.dwProcessId;

    // 핸들은 더 이상 사용하지 않으므로 닫아준다.
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    printf("[Launcher] Client started. pid=%lu\n", *pClientPid);
    return TRUE;
}

// Client 프로세스를 디버깅하는 함수
BOOL DebugClient(DWORD clientPid)
{
    if (!DebugActiveProcess(clientPid)) {
        printf("[Launcher] DebugActiveProcess failed. error=%lu\n", GetLastError());
        return FALSE;
    }

    printf("[Launcher] Debugging client pid=%lu\n", clientPid);

    DEBUG_EVENT dbgEvent;
    BOOL running = TRUE;

    while (running)
    {
        // 디버그 이벤트 대기
        if (!WaitForDebugEvent(&dbgEvent, INFINITE)) {
            printf("[Launcher] WaitForDebugEvent failed. error=%lu\n", GetLastError());
            break;
        }

        DWORD continueStatus = DBG_CONTINUE;

        switch (dbgEvent.dwDebugEventCode)
        {
        case EXIT_PROCESS_DEBUG_EVENT:
            printf("[Launcher] Client process exited. code=%lu\n",
                   dbgEvent.u.ExitProcess.dwExitCode);
            running = FALSE;
            break;

        default:
            break;
        }

        if (!ContinueDebugEvent(dbgEvent.dwProcessId,
                                dbgEvent.dwThreadId,
                                continueStatus))
        {
            printf("[Launcher] ContinueDebugEvent failed. error=%lu\n", GetLastError());
            break;
        }
    }

    // Client는 이미 종료된 상태. Detach는 선택적
    DebugActiveProcessStop(clientPid);

    return TRUE;
}

int main()
{
    printf("=== Launcher start ===\n");

    // (1) Watchdog 스레드 시작 (자기 자신 디버깅 탐지)
    g_hWatchdogThread = CreateThread(
        NULL, 0,
        WatchdogThread,
        NULL, 0, NULL
    );

    if (g_hWatchdogThread == NULL) {
        printf("[Launcher] Failed to create watchdog thread. error=%lu\n", GetLastError());
        return 1;
    }

    // 시작 직후 한 번 더 디버깅 여부 확인
    if (IsDebuggingSelf()) {
        printf("[Launcher] Error: Launcher must not be debugged.\n");
        g_StopWatchdog = TRUE;
        WaitForSingleObject(g_hWatchdogThread, INFINITE);
        CloseHandle(g_hWatchdogThread);
        return 1;
    }

    // (2) Client 프로세스 실행
    DWORD clientPid = 0;
    if (!StartClientProcess(&clientPid)) {
        g_StopWatchdog = TRUE;
        WaitForSingleObject(g_hWatchdogThread, INFINITE);
        CloseHandle(g_hWatchdogThread);
        return 1;
    }

    // (3) Client 프로세스를 디버깅 (선점 디버거 역할)
    DebugClient(clientPid);

    // (4) 종료 시 워치독 스레드 정리
    g_StopWatchdog = TRUE;
    WaitForSingleObject(g_hWatchdogThread, INFINITE);
    CloseHandle(g_hWatchdogThread);

    printf("[Launcher] graceful shutdown.\n");
    return 0;
}
