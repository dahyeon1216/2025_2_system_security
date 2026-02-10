// FakeWriteFile.cpp
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

// C++ 컴파일 시 이름 맹글링 방지
extern "C" {

    // __declspec(dllexport)로 내보내기
    __declspec(dllexport)
        BOOL WINAPI FakeWriteFile(
            HANDLE hFile,
            LPCVOID lpBuffer,
            DWORD nNumberOfBytesToWrite,
            LPDWORD lpNumberOfBytesWritten,
            LPOVERLAPPED lpOverlapped
        ) {
        // 예: 버퍼 내용(처음 몇 바이트)를 디버그 출력으로 찍기
        char out[128] = { 0 };
        SIZE_T toDump = nNumberOfBytesToWrite;
        if (toDump > 32) toDump = 32; // 너무 길면 자름
        for (SIZE_T i = 0; i < toDump && i < sizeof(out) - 1; ++i) {
            unsigned char c = ((unsigned char*)lpBuffer)[i];
            if (c >= 32 && c < 127) out[i] = (char)c;
            else out[i] = '.';
        }
        char msg[256];
        wsprintfA(msg, "FakeWriteFile called: bytes=%u, sample=\"%s\"\n", nNumberOfBytesToWrite, out);
        OutputDebugStringA(msg);

        // 원래 WriteFile 호출(원한다면 조작 가능)
        BOOL ret = WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
        return ret;
    }

    BOOL WINAPI FakeWriteFile(
        HANDLE hFile,
        LPCVOID lpBuffer,
        DWORD nNumberOfBytesToWrite,
        LPDWORD lpNumberOfBytesWritten,
        LPOVERLAPPED lpOverlapped
    ) { 
        puts((LPCSTR)lpBuffer);
        return TRUE;
    }

} // extern "C"

// DLL 진입점 (필요하면 사용)
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // 초기화 코드
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
