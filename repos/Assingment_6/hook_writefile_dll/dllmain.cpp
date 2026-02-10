// hook_writefile_dll.cpp

#include <Windows.h>
#include "pch.h"

typedef BOOL(WINAPI* WriteFile_t)(
    HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED
    );

static WriteFile_t g_original_WriteFile = NULL;

// 매우 단순한 훅: 메시지박스 띄우고 원본 호출
static BOOL WINAPI HookedWriteFile(HANDLE hFile, LPCVOID buf, DWORD n, LPDWORD written, LPOVERLAPPED ov)
{
    MessageBoxA(NULL, "WriteFile hooked!", "hook", MB_OK);
    if (g_original_WriteFile) return g_original_WriteFile(hFile, buf, n, written, ov);
    SetLastError(ERROR_INVALID_FUNCTION);
    return FALSE;
}

// 단순화된 IAT 패치: moduleBase + ImportDirectory 순회 -> kernel32.dll의 WriteFile 찾아 덮어씀
static BOOL PatchWriteFileIAT(HMODULE moduleBase)
{
    if (!moduleBase) return FALSE;
    BYTE* base = (BYTE*)moduleBase;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    IMAGE_DATA_DIRECTORY impDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir.VirtualAddress == 0) return FALSE;

    PIMAGE_IMPORT_DESCRIPTOR desc = (PIMAGE_IMPORT_DESCRIPTOR)(base + impDir.VirtualAddress);
    for (; desc->Name; ++desc) {
        const char* dll = (const char*)(base + desc->Name);
        if (_stricmp(dll, "KERNEL32.dll") != 0) continue;

        PIMAGE_THUNK_DATA nameThunk = NULL;
        if (desc->OriginalFirstThunk)
            nameThunk = (PIMAGE_THUNK_DATA)(base + desc->OriginalFirstThunk);
        else
            nameThunk = (PIMAGE_THUNK_DATA)(base + desc->FirstThunk);

        PIMAGE_THUNK_DATA iatThunk = (PIMAGE_THUNK_DATA)(base + desc->FirstThunk);

        for (; nameThunk && nameThunk->u1.AddressOfData; ++nameThunk, ++iatThunk) {
            if (nameThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
            PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)(base + nameThunk->u1.AddressOfData);
            const char* fname = (const char*)ibn->Name;
            if (fname && strcmp(fname, "WriteFile") == 0) {
                DWORD old;
                SIZE_T sz = sizeof(ULONG_PTR);
                if (!VirtualProtect(&iatThunk->u1.Function, sz, PAGE_EXECUTE_READWRITE, &old)) return FALSE;
                g_original_WriteFile = (WriteFile_t)(iatThunk->u1.Function);
                iatThunk->u1.Function = (ULONG_PTR)HookedWriteFile;
                VirtualProtect(&iatThunk->u1.Function, sz, old, &old);
                return TRUE;
            }
        }
    }
    return FALSE;
}

// 스레드에서 패치 실행
static DWORD WINAPI InitThread(LPVOID lp)
{
    HMODULE host = GetModuleHandle(NULL);
    PatchWriteFileIAT(host);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinst);
        CreateThread(NULL, 0, InitThread, NULL, 0, NULL);
        break;
    case DLL_PROCESS_DETACH:
        // 원복 로직 필요하면 여기 추가
        break;
    }
    return TRUE;
}
