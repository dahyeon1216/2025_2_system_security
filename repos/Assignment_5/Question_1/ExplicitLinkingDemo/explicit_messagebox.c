#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

typedef int (WINAPI* PFN_MessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);

int main(void)
{
    const char* studentId = "학번: 2014865"; 

    HMODULE hUser32 = LoadLibraryA("user32.dll");
    if (!hUser32) {
        printf("LoadLibrary 실패!\n");
        return 1;
    }

    PFN_MessageBoxA pMessageBoxA =
        (PFN_MessageBoxA)GetProcAddress(hUser32, "MessageBoxA");
    if (!pMessageBoxA) {
        printf("GetProcAddress 실패!\n");
        FreeLibrary(hUser32);
        return 1;
    }

    pMessageBoxA(NULL, studentId, "Explicit Linking Demo", MB_OK | MB_ICONINFORMATION);

    FreeLibrary(hUser32);
    return 0;
}
