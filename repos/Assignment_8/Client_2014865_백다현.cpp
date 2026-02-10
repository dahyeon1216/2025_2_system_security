// Client_2014865_백다현
#include <windows.h>
#include <tlhelp32.h>   // 프로세스 스냅샷용
#include <tchar.h>      // TCHAR, _tcsicmp
#include <stdio.h>
#include <string.h>

// 1. 디버깅 여부 확인 함수
// - 현재 프로세스에 디버거가 붙어 있으면 true
// - 아니면 false
bool is_being_debugged() {
    BOOL bDebugged = FALSE;

    // 현재 프로세스를 대상으로 디버거 연결 여부 확인
    if (!CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebugged)) {
        // 실패한 경우, 일단 "디버깅 안 된다" 쪽으로 처리
        return false;
    }

    return (bDebugged == TRUE);
}

// 2. 부모 프로세스 이름이 Launcher.exe 인지 확인하는 함수
bool is_parent_launcher() {
    DWORD myPid = GetCurrentProcessId();
    DWORD parentPid = 0;

    // (1) 전체 프로세스 스냅샷에서 "나 자신의 항목"을 찾아서 부모 PID 얻기
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnap, &pe)) {
        do {
            if (pe.th32ProcessID == myPid) {
                parentPid = pe.th32ParentProcessID;
                break;
            }
        } while (Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);

    if (parentPid == 0) {
        // 부모 PID를 못 찾았으면 실패로 처리
        return false;
    }

    // (2) 다시 스냅샷을 떠서 parentPid에 해당하는 프로세스를 찾고, 이름 비교
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        return false;
    }

    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnap, &pe)) {
        do {
            if (pe.th32ProcessID == parentPid) {
                wprintf(L"[DEBUG] Parent Name = %s\n", pe.szExeFile);

                // pe.szExeFile 에 부모 프로세스의 exe 파일 이름이 들어 있음
                // Unicode / MBCS 둘 다 대응되도록 TCHAR + TEXT 매크로 사용
                bool ok = (_tcsicmp(pe.szExeFile, TEXT("Launcher.exe")) == 0);
                CloseHandle(hSnap);
                return ok;
            }
        } while (Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return false;
}

int main() {
    // 1) 부모가 Launcher.exe 인지 먼저 검사
    if (!is_parent_launcher()) {
        printf("[Client] Error: Parent process must be Launcher.exe\n");
        printf("[Client] 부모 프로세스가 Launcher.exe가 아니므로 종료합니다.\n");
        Sleep(3000);  // 메시지 보이도록 3초 기다리기
        return 1;
    }

    // 2) 디버깅 중인지 검사 (항상 디버거가 붙어 있어야 함)
    if (!is_being_debugged()) {
        printf("[Client] Error: This program must be run under a debugger.\n");
        printf("[Client] 디버깅 상태가 아니므로 종료합니다.\n");
        Sleep(3000);
        return 1;
    }

    // 3) 여기부터는 에코 기능
    char buf[256];   // 사용자가 입력할 문자열 버퍼

    printf("=== Client Echo Program ===\n");
    printf("문자열을 입력하면 그대로 다시 출력합니다.\n");
    printf("프로그램을 종료하려면 \"exit\" 를 입력하세요.\n\n");

    while (1) {
        printf("> ");                  // 프롬프트 표시

        // 한 줄 입력 받기 (공백 포함)
        if (fgets(buf, sizeof(buf), stdin) == NULL) {
            // EOF나 입력 오류 시 루프 종료
            printf("\n[Client] 입력 오류 또는 EOF. 프로그램을 종료합니다.\n");
            break;
        }

        // 끝에 붙은 개행 문자(\n) 제거
        size_t len = strlen(buf);
        if (len > 0 && buf[len - 1] == '\n') {
            buf[len - 1] = '\0';
        }

        // 종료 명령 처리
        if (strcmp(buf, "exit") == 0) {
            printf("[Client] 종료 명령을 받았습니다. 프로그램을 종료합니다.\n");
            break;
        }

        // 에코 출력
        printf("echo: %s\n", buf);
    }

    return 0;
}
