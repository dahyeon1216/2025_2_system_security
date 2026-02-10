// main.cpp
#include <windows.h>
#include <cstdio>
//#include "pch.h"

typedef int(__cdecl* add_fn)(int, int);

int main(int argc, char* argv[]) {
    const char* dllName = (argc > 1) ? argv[1] : "add.dll"; // 기본은 add.dll
    HMODULE h = LoadLibraryA(dllName);
    if (!h) {
        std::printf("LoadLibrary failed. GetLastError=%lu\n", GetLastError());
        return 1;
    }

    add_fn add = (add_fn)GetProcAddress(h, "add");
    if (!add) {
        std::printf("GetProcAddress('add') failed. GetLastError=%lu\n", GetLastError());
        FreeLibrary(h);
        return 1;
    }

    int r = add(10, 3);
    std::printf("Using %s -> add(10,3) = %d\n", dllName, r);

    FreeLibrary(h);
    std::puts("Press Enter to exit...");
    (void)std::getchar();
    return 0;
}
