#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <shlobj.h>
#include <strsafe.h>
#include <cstdio>

// 전역 변수
HINSTANCE g_hInst = NULL;
WNDPROC   g_pOriginalWndProc = NULL; // 원본 함수 주소 저장용
HWND      g_hTargetWnd = NULL;       // 현재 훅이 걸린 타겟 윈도우 핸들

// ───────── 파일 저장 함수 ─────────
void SaveNameToFile(const char* name)
{
    if (!name || !name[0]) return;

    char docPath[MAX_PATH] = { 0 };

    if (!SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_PERSONAL, NULL, 0, docPath))) {
        OutputDebugStringA("[DLL] SHGetFolderPath FAILED");
        return;
    }

    StringCchCatA(docPath, MAX_PATH, "\\names.txt");

    FILE* fp = fopen(docPath, "at");
    if (!fp) {
        char buf[512];
        wsprintfA(buf, "[DLL] fopen FAILED path=%s err=%lu", docPath, GetLastError());
        OutputDebugStringA(buf);
        return;
    }

    fprintf(fp, "%s\n", name);
    fclose(fp);
    OutputDebugStringA("[DLL] Name Saved to File!");
}

// ───────── Register 다이얼로그에서 Name 훔치기 ─────────
void StealNameFromRegisterDlg(HWND hDlg)
{
    if (!hDlg) return;

    // Edit 컨트롤 두 개 찾기
    HWND hEdit1 = FindWindowExA(hDlg, NULL, "Edit", NULL);
    HWND hEdit2 = FindWindowExA(hDlg, hEdit1, "Edit", NULL);

    if (!hEdit1 || !hEdit2) return;

    RECT r1, r2;
    GetWindowRect(hEdit1, &r1);
    GetWindowRect(hEdit2, &r2);

    HWND hNameEdit = (r1.top < r2.top) ? hEdit1 : hEdit2;

    char nameBuf[256] = { 0 };
    SendMessageA(hNameEdit, WM_GETTEXT, sizeof(nameBuf), (LPARAM)nameBuf);

    if (!nameBuf[0]) return;

    SaveNameToFile(nameBuf);
}

// ────────────────────────────────────────────────────────────────
// 서브클래스 프로시저
// ────────────────────────────────────────────────────────────────
LRESULT CALLBACK MySubclassProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    if (uMsg == WM_COMMAND)
    {
        WORD code = HIWORD(wParam);
        WORD id = LOWORD(wParam);
        HWND hCtrl = (HWND)lParam;

        if (code == BN_CLICKED && hCtrl)
        {
            char clsName[64] = { 0 };
            char wndText[64] = { 0 };

            GetClassNameA(hCtrl, clsName, sizeof(clsName));
            GetWindowTextA(hCtrl, wndText, sizeof(wndText));

            if (_stricmp(clsName, "Button") == 0 && _stricmp(wndText, "OK") == 0)
            {
                OutputDebugStringA("[DLL] OK Button Clicked! Stealing Name...");
                StealNameFromRegisterDlg(hWnd);
            }
        }
    }
    // 원본 프로시저 호출
    return CallWindowProc(g_pOriginalWndProc, hWnd, uMsg, wParam, lParam);
}

// ────────────────────────────────────────────────────────────────
// 서브클래싱 설치 스레드 -> 무한 루프로 변경
// ────────────────────────────────────────────────────────────────
DWORD WINAPI InstallSubclassThread(LPVOID lpParam)
{
    OutputDebugStringA("[DLL] Subclass Monitor Thread Started.");

    while (true)
    {
        // 1. 현재 떠 있는 Register 창을 찾는다.
        HWND hCurrentWnd = FindWindowA("#32770", "Register");

        // 2. 창이 발견되었고 && (우리가 알던 그 창이 아니거나, 처음 발견했으면)
        if (hCurrentWnd != NULL && hCurrentWnd != g_hTargetWnd)
        {
            // 새로운 창이 떴다! -> 훅 설치
            g_hTargetWnd = hCurrentWnd;

            OutputDebugStringA("[DLL] New Register window found. Installing Hook...");

            g_pOriginalWndProc = (WNDPROC)SetWindowLongPtrA(
                g_hTargetWnd,
                GWLP_WNDPROC,
                (LONG_PTR)MySubclassProc
            );

            if (g_pOriginalWndProc) {
                OutputDebugStringA("[DLL] Hook Installed Successfully!");
            }
            else {
                OutputDebugStringA("[DLL] Failed to Install Hook.");
            }
        }

        // 3. 훅을 걸었던 창이 사라졌다면? (IsWindow로 유효성 체크)
        if (g_hTargetWnd != NULL && !IsWindow(g_hTargetWnd))
        {
            OutputDebugStringA("[DLL] Hooked Window Destroyed. Resetting...");
            g_hTargetWnd = NULL; // 다시 NULL로 만들어서 다음 창을 기다림
            g_pOriginalWndProc = NULL;
        }

        // 0.5초마다 검사
        Sleep(500);
    }

    return 0;
}

// ────────────────────────────────────────────────────────────────
// DllMain
// ────────────────────────────────────────────────────────────────
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        g_hInst = (HINSTANCE)hModule;
        CreateThread(NULL, 0, InstallSubclassThread, NULL, 0, NULL);
    }
    return TRUE;
}