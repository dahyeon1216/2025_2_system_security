// test_write.cpp
#include <windows.h>
#include <stdio.h>
#include <string.h>

void print_last_error(const char* ctx) {
    DWORD err = GetLastError();
    LPSTR msg = NULL;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, err, 0, (LPSTR)&msg, 0, NULL);
    if (msg) {
        printf("%s failed. Error %u: %s\n", ctx, err, msg);
        LocalFree(msg);
    }
    else {
        printf("%s failed. Error %u.\n", ctx, err);
    }
}

int main(void) {
    // ensure folder exists (if not, create it)
    if (!CreateDirectoryA("C:\\temp", NULL)) {
        DWORD e = GetLastError();
        if (e != ERROR_ALREADY_EXISTS) {
            // folder creation failed for a reason other than "already exists"
            print_last_error("CreateDirectoryA");
            // continue anyway — CreateFile will also fail and show a clear message
        }
    }

    // Try to open / create the file
    HANDLE h = CreateFileA(
        "C:\\temp\\test_out.txt",
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, // allow others to read/write while we have it
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (h == INVALID_HANDLE_VALUE) {
        print_last_error("CreateFileA");
        return 1;
    }

    const char* msg = "hello\n";
    DWORD written = 0;
    if (!WriteFile(h, msg, (DWORD)strlen(msg), &written, NULL)) {
        print_last_error("WriteFile");
        CloseHandle(h);
        return 1;
    }

    CloseHandle(h);
    printf("Wrote %u bytes to C:\\temp\\test_out.txt\n", written);
    printf("Press Enter to exit (keeps process alive so injector can attach)...\n");
    getchar();
    return 0;
}

