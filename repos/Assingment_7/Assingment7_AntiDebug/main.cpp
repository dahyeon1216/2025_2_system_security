#include <windows.h>
#include <stdio.h>

// ---- PEB 구조 (BeingDebugged만 사용) ----
typedef struct _MY_PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PVOID Ldr;
    PVOID ProcessParameters;
} MY_PEB;

// ---- PEB 기반 디버거 체크 ----
BOOL CheckDebuggerByPEB()
{
#ifdef _M_IX86
    MY_PEB* peb = (MY_PEB*)__readfsdword(0x30);   // x86: FS:[0x30] = PEB
#elif defined(_M_X64)
    MY_PEB* peb = (MY_PEB*)__readgsqword(0x60);   // x64: GS:[0x60] = PEB
#else
    return FALSE;
#endif
    return (peb->BeingDebugged != 0);
}

// ---- 전역 (Watchdog 제어) ----
volatile BOOL g_StopWatchdog = FALSE;
HANDLE g_hWatchdogThread = NULL;

// ---- 디버깅 여부 종합 판단 ----
BOOL IsDebugging()
{
    if (CheckDebuggerByPEB())
        return TRUE;

    if (IsDebuggerPresent())
        return TRUE;

    return FALSE;
}

// ---- Watchdog 스레드 ----
DWORD WINAPI WatchdogThread(LPVOID)
{
    while (!g_StopWatchdog)
    {
        if (IsDebugging())
        {
            printf("[WATCHDOG] Debugger detected! Protecting program...\n");
            __fastfail(1); // 디버거 감지 시 의도적 크래시
        }

        Sleep(300);
    }

    printf("[WATCHDOG] 정상 종료\n");
    return 0;
}

// ================= TLS CALLBACK =================

extern "C" {

    // main보다 먼저 호출되는 TLS 콜백
    void NTAPI TlsCallback(PVOID, DWORD reason, PVOID)
    {
        if (reason == DLL_PROCESS_ATTACH)
        {
            g_hWatchdogThread = CreateThread(
                NULL,
                0,
                WatchdogThread,
                NULL,
                0,
                NULL
            );
        }
    }

    /*
     * TLS 콜백 등록
     * - .CRT$XLB 섹션에 콜백 배열을 두고
     * - 링커에게 이 심볼을 강제로 포함시키도록 지시
     * - __tls_used를 포함시켜 TLS 섹션이 제거되지 않게 함
     */

#ifdef _M_IX86

#pragma comment(linker, "/INCLUDE:__tls_used")
#pragma comment(linker, "/INCLUDE:_tls_callback_table")

#pragma const_seg(".CRT$XLB")
    EXTERN_C const PIMAGE_TLS_CALLBACK tls_callback_table[] = { TlsCallback, 0 };
#pragma const_seg()

#elif defined(_M_X64)

#pragma comment(linker, "/INCLUDE:__tls_used")
#pragma comment(linker, "/INCLUDE:tls_callback_table")

#pragma const_seg(".CRT$XLB")
    EXTERN_C const PIMAGE_TLS_CALLBACK tls_callback_table[] = { TlsCallback, 0 };
#pragma const_seg()

#endif

} // extern "C"

// ================= MAIN =================

int main()
{
    printf("[MAIN] 주요 기능 시작\n");

    for (int i = 0; i < 5; ++i)
    {
        printf("[MAIN] Working... (%d)\n", i);
        Sleep(1000);
    }

    printf("[MAIN] 작업 완료. Watchdog 종료 요청\n");

    g_StopWatchdog = TRUE;

    if (g_hWatchdogThread != NULL)
    {
        WaitForSingleObject(g_hWatchdogThread, INFINITE);
        CloseHandle(g_hWatchdogThread);
        g_hWatchdogThread = NULL;
    }

    printf("[MAIN] 모든 자원 정리 완료. 정상 종료.\n");
    return 0;
}
