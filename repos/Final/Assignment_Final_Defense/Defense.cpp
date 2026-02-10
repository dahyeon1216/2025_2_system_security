#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <cstdio>
#include <set>
#include <cstring> 
#include <winternl.h>
#include <unordered_set>
#include <unordered_map>

static bool g_iatBaselineReady = false;
static std::string prevName, prevSerial;
static DWORD lastNameChangeTick = 0;


// key: "dllLower:funcNameOrOrdinal:idx"  value: fnPtr
static std::unordered_map<std::string, uintptr_t> g_iatBaseline;

// 스팸 방지: 변화 로그는 동일 건 1번만
static std::unordered_set<std::string> g_iatChangedPrinted;

static bool g_verboseInfo = false;  // 캡처용: false로 두면 INFO 로그 안 찍힘



// ------------------------------------------------------------
// [ModuleInfoSimple]
// - 타겟 프로세스(CRACKME)에 로드된 "모듈(DLL/EXE)" 하나의 정보
// - WndProc 주소가 어떤 모듈 주소 범위에 속하는지 판별하기 위해 사용
// ------------------------------------------------------------
struct ModuleInfoSimple {
    uintptr_t base = 0;      // 모듈 베이스 주소(메모리 상 시작 주소)
    DWORD size = 0;          // 모듈 메모리 크기
    std::string name;        // 모듈 파일명(소문자) 예: "crackme.exe", "user32.dll"
    std::string fullPath;    // 전체 경로(보고서/디버깅용)
};

// ===== Forward declarations (아래에서 정의되지만 위에서 먼저 사용되는 함수들) =====
static bool ReadFileAll(const char* path, std::vector<unsigned char>& out);
static DWORD RvaToOffset32(const std::vector<unsigned char>& pe, DWORD rva);
static uintptr_t GetMainModuleBase(DWORD pid);
static const ModuleInfoSimple* ResolveAddressToModule(const std::vector<ModuleInfoSimple>& mods, uintptr_t addr);
static std::vector<ModuleInfoSimple> GetRemoteModules(DWORD pid);
static const ModuleInfoSimple* FindRemoteModuleByName(
    const std::vector<ModuleInfoSimple>& mods,
    const std::string& nameLower);

static std::vector<std::string> GetModuleNameListLower(DWORD pid);


// 문자열을 소문자로 변환하여 모듈 이름 비교 시 대소문자 차이를 제거
static std::string ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)tolower(c); });
    return s;
}

// 현재 시스템 시간을 "YYYY-MM-DD HH:MM:SS" 형식의 문자열로 반환
static std::string NowString() {
    SYSTEMTIME st{};
    GetLocalTime(&st);
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

// 탐지 시각과 함께 공격 유형(R1/R2/R3)을 콘솔에 출력
static void LogDetect(const char* tag) {
    std::cout << NowString() << " 이상 행위 탐지 (" << tag << ")\n";
}

// 특정 프로세스 이름(EXE 파일명)으로 PID 획득
static DWORD FindProcessIdByNameA(const char* processName) {
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);

    if (Process32First(snap, &pe)) {
        do {
            char exeName[MAX_PATH]{};
#ifdef UNICODE
            WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, exeName, MAX_PATH, NULL, NULL);
#else
            strcpy_s(exeName, pe.szExeFile);
#endif
            if (_stricmp(exeName, processName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    return pid;
}

// “프로세스 상태(State)” 구조체로 전역 변수 정리
// ===============================
// WndProc baseline (정상 WndProc 스냅샷 저장용)
// ===============================
struct WndProcBaseline {
    bool ready = false;
    uintptr_t dlg = 0;
    uintptr_t e1 = 0;
    uintptr_t e2 = 0;
    uintptr_t ok = 0;

    void Clear() {
        ready = false;
        dlg = e1 = e2 = ok = 0;
    }
};

// ===============================
// “프로세스 상태(State)”
// ===============================
struct DefenseState {
    DWORD pid = 0;

    bool baselineReady = false;
    std::vector<std::string> baselineModules;
    bool didSuspend = false;
    bool didTerminate = false;
    bool didDetectAny = false;   // R1/R2/R3 중 하나라도 탐지 로그를 찍었는가?


    DWORD startTick = 0;     // 프로세스 감지 시각(GetTickCount)
    bool graceDone = false;  // 초기 학습 구간 종료 여부

    std::set<std::string> printedNewMods;
    std::set<DWORD> printedSuspTids;
    std::unordered_set<std::string> printedIatFindings;

    WndProcBaseline wndBase;

    void Reset(DWORD newPid) {
        pid = newPid;

        baselineReady = false;
        baselineModules.clear();
        didDetectAny = false;

        startTick = GetTickCount();
        graceDone = false;

        didSuspend = false;
        didTerminate = false;


        printedNewMods.clear();
        printedSuspTids.clear();
        printedIatFindings.clear();

        wndBase.Clear();
    }
};

static DefenseState g_state;


/*baseline + grace(학습 구간)
프로세스 잡히자마자 baseline 저장*/
static void EnsureBaselineModules2(DefenseState& st) {
    if (st.baselineReady) return;
    st.baselineModules = GetModuleNameListLower(st.pid);
    st.baselineReady = true;
}
static bool InGracePeriod(DefenseState& st, DWORD ms = 1500) {
    if (st.graceDone) return false;
    DWORD now = GetTickCount();
    if (now - st.startTick >= ms) {
        st.graceDone = true;
        return false;
    }
    return true;
}

//“신규 모듈” + “의심 모듈”을 분리해서 평가 
// 의심 경로/이름 판별
static bool IsSuspiciousModuleName(const std::string& nameLower) {
    // 실험/과제용 시그니처
    return (nameLower.find("attack") != std::string::npos ||
        nameLower.find("hook") != std::string::npos ||
        nameLower.find("inject") != std::string::npos);
}

static bool StartsWithI(const std::string& s, const char* prefix) {
    return _strnicmp(s.c_str(), prefix, (int)strlen(prefix)) == 0;
}

static bool IsSystemPath(const std::string& fullPath) {
    // 너무 빡세게 하면 오탐 가능 → 1차 필터 정도로만
    // (대소문자 무시)
    std::string p = ToLower(fullPath);
    return (p.find("\\windows\\system32\\") != std::string::npos ||
        p.find("\\windows\\winsxs\\") != std::string::npos);
}

//모듈 스냅샷에서 의심 모듈 뽑기
static std::vector<ModuleInfoSimple> GetSuspiciousModules(DWORD pid) {
    std::vector<ModuleInfoSimple> out;
    auto mods = GetRemoteModules(pid);
    for (auto& m : mods) {
        // 시스템 폴더가 아니고, 이름도 수상하면 가점
        if (!IsSystemPath(m.fullPath) && IsSuspiciousModuleName(m.name)) {
            out.push_back(m);
        }
    }
    return out;
}

// NtQueryInformationThread 동적 로딩용 타입
typedef NTSTATUS(NTAPI* PFN_NtQueryInformationThread)(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
    );


//LoadLibraryA/W 시작 스레드 탐지
static bool DetectLoadLibraryStartThread(DefenseState& st) {
    auto mods = GetRemoteModules(st.pid);
    if (mods.empty()) return false;

    const ModuleInfoSimple* k32 = FindRemoteModuleByName(mods, "kernel32.dll");
    if (!k32) return false;

    // 로컬에서 LoadLibraryA 주소 구하고, kernel32 내 오프셋을 계산
    // (x86 동일 모듈이라도 ASLR로 베이스는 달라짐 → offset 기반으로 매핑)
    HMODULE localK32 = GetModuleHandleA("kernel32.dll");
    FARPROC localLLA = GetProcAddress(localK32, "LoadLibraryA");
    FARPROC localLLW = GetProcAddress(localK32, "LoadLibraryW");
    if (!localLLA && !localLLW) return false;

    uintptr_t localBase = (uintptr_t)localK32;
    uintptr_t offLLA = localLLA ? ((uintptr_t)localLLA - localBase) : 0;
    uintptr_t offLLW = localLLW ? ((uintptr_t)localLLW - localBase) : 0;

    uintptr_t remoteLLA = offLLA ? (k32->base + offLLA) : 0;
    uintptr_t remoteLLW = offLLW ? (k32->base + offLLW) : 0;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;

    auto NtQueryInformationThread =
        (PFN_NtQueryInformationThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");
    if (!NtQueryInformationThread) { CloseHandle(hSnap); return false; }

    bool found = false;

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);

    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID != st.pid) continue;

            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            if (!hThread) continue;

            PVOID startAddr = nullptr;
            NTSTATUS s = NtQueryInformationThread(
                hThread, (THREADINFOCLASS)9,
                &startAddr, sizeof(startAddr), nullptr
            );
            CloseHandle(hThread);
            if (s != 0 || !startAddr) continue;

            uintptr_t sa = (uintptr_t)startAddr;

            if ((remoteLLA && sa == remoteLLA) || (remoteLLW && sa == remoteLLW)) {
                if (st.printedSuspTids.insert(te.th32ThreadID).second) {
#if 0   //  과제 요구: R1/R2/R3 탐지 로그가 무조건 먼저 나오게 하기 위해 INFO 출력 비활성화
                    std::cout << NowString()
                        << " [INFO] LoadLibrary 시작 스레드 감지: TID=" << te.th32ThreadID
                        << " Start=0x" << std::hex << sa << std::dec << "\n";
#endif
                }
                found = true;
            }

        } while (Thread32Next(hSnap, &te));
    }

    CloseHandle(hSnap);
    return found;
}



//판정 로직을 “점수화 + 조합”으로 정리

struct Signals {
    bool newDll = false;
    bool privExec = false;
    bool suspThreadStart = false;      // 기존 no-module start
    bool loadLibraryThread = false;    // NEW: Attack7 커버
    bool iatHook = false;
    bool wndprocEdit = false;
    bool wndprocOkOrDlg = false;
    bool suspLoadedMod = false; //의심 DLL 상시 존재 탐지
    bool autoSerialPattern = false;
};

static int ScoreR1(const Signals& s) {
    int score = 0;

    // R1의 직접 증거: Edit WndProc 변조
    if (s.wndprocEdit) score += 5;

    // 보조 신호들(인젝션/수상 모듈이 있으면 R1 가능성도 올라감)
    if (s.autoSerialPattern) score += 5;
    if (s.suspLoadedMod)     score += 3;
    if (s.newDll)            score += 2;
    if (s.loadLibraryThread) score += 2;
    if (s.suspThreadStart)   score += 2;
    if (s.privExec)          score += 3;
    if (s.iatHook) score += 3;

    return score;
}


static int ScoreR2(const Signals& s) {
    int score = 0;
    if (s.suspLoadedMod) score += 5;   
    if (s.privExec)      score += 5;   // 거의 확정
    if (s.wndprocOkOrDlg)score += 5;   // 직접 후킹

    if (s.newDll)        score += 3;
    if (s.loadLibraryThread) score += 3;
    if (s.suspThreadStart)   score += 3;
    if (s.iatHook)       score += 3;

    return score;
}


// -------------------------------
// 1) Spy++에서 찾은 Register 창/컨트롤 핸들 잡기
// -------------------------------

// Spy++로 확인한 구조를 기반으로 Register 창과 하위 컨트롤(Edit, OK)의 HWND를 획득
static bool FindRegisterHandles(HWND& hDlg, HWND& hEdit1, HWND& hEdit2, HWND& hOk) {
    // 최상위 다이얼로그(대화상자) 찾기
    hDlg = FindWindowA("#32770", "Register");
    if (!hDlg) return false;

    // 첫 번째 Edit 찾기 (Name)
    hEdit1 = FindWindowExA(hDlg, NULL, "Edit", NULL);
    if (!hEdit1) return false;

    // 두 번째 Edit 찾기 (Serial) : 첫 번째 Edit 다음으로 검색
    hEdit2 = FindWindowExA(hDlg, hEdit1, "Edit", NULL);
    if (!hEdit2) return false;

    // "OK" 버튼 찾기
    hOk = FindWindowExA(hDlg, NULL, "Button", "OK");
    if (!hOk) return false;

    return true;
}

// 특정 HWND가 속한 프로세스의 PID를 획득 (HWND → PID 변환)
static DWORD GetPidFromHwnd(HWND h) {
    DWORD pid = 0;
    GetWindowThreadProcessId(h, &pid);
    return pid;
}

// -------------------------------
// 2) 원격(타겟 프로세스) 모듈 목록 얻기 (주소가 "어느 모듈"에 속하는지 판별용)
//    -> WndProc 주소가 낯선 DLL 범위면 훅/인젝션 의심(R1/R2)
// -------------------------------

// 타겟 프로세스에 로드된 모든 모듈(EXE/DLL)의 메모리 정보 목록을 획득
static std::vector<ModuleInfoSimple> GetRemoteModules(DWORD pid) {
    std::vector<ModuleInfoSimple> mods;

    HANDLE snap = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE)
        return mods;

    MODULEENTRY32 me{};
    me.dwSize = sizeof(me);

    if (Module32First(snap, &me)) {
        do {
            ModuleInfoSimple m;
            m.base = (uintptr_t)me.modBaseAddr;
            m.size = me.modBaseSize;

            // WCHAR → char 변환 (UNICODE 대응)
            char modName[MAX_PATH];
            char exePath[MAX_PATH];

            WideCharToMultiByte(CP_ACP, 0,
                me.szModule, -1, modName, MAX_PATH, NULL, NULL);
            WideCharToMultiByte(CP_ACP, 0,
                me.szExePath, -1, exePath, MAX_PATH, NULL, NULL);

            m.name = ToLower(std::string(modName));
            m.fullPath = std::string(exePath);

            mods.push_back(std::move(m));
        } while (Module32Next(snap, &me));
    }

    CloseHandle(snap);
    return mods;
}

static bool IsAllowedLoadedModule(const std::string& modLower) {
    // 실행 중에 흔히 로드될 수 있는 정상 DLL들(필요시 추가)
    static const char* allow[] = {
        "crackme.exe",
        "ntdll.dll", "kernel32.dll", "kernelbase.dll", "win32u.dll",
        "user32.dll", "gdi32.dll", "comctl32.dll", "uxtheme.dll", "imm32.dll",
        "msctf.dll", "msvcp140.dll", "vcruntime140.dll", "ucrtbase.dll",
        "advapi32.dll", "rpcrt4.dll", "ole32.dll", "oleaut32.dll",
        "shell32.dll", "shlwapi.dll"
    };

    for (auto a : allow) {
        if (modLower == a) return true;
    }

    // api-ms-win-core-*.dll 같은 계열은 prefix로 허용
    if (modLower.rfind("api-ms-win-", 0) == 0) return true;

    return false;
}

static bool DetectSuspiciousLoadedModule(DWORD pid, std::string& hitName, std::string& hitPath) {
    auto mods = GetRemoteModules(pid);
    for (auto& m : mods) {
        // (1) 시스템 폴더가 아니고
        if (!IsSystemPath(m.fullPath)) {
            // (2) allowlist에도 없으면 -> 의심 모듈
            if (!IsAllowedLoadedModule(m.name)) {
                hitName = m.name;
                hitPath = m.fullPath;
                return true;
            }
        }
    }
    return false;
}


static const ModuleInfoSimple* FindRemoteModuleByName(const std::vector<ModuleInfoSimple>& mods,
    const std::string& nameLower) {
    for (const auto& m : mods) {
        if (m.name == nameLower) return &m;
    }
    return nullptr;
}

static bool IsExecuteProtect(DWORD p) {
    return (p & PAGE_EXECUTE) ||
        (p & PAGE_EXECUTE_READ) ||
        (p & PAGE_EXECUTE_READWRITE) ||
        (p & PAGE_EXECUTE_WRITECOPY);
}

// 특정 주소가 MEM_PRIVATE + EXEC 인지 확인 (쉘코드/수동맵 흔적 보조 판정)
static bool IsPrivateExecutableAt(DWORD pid, uintptr_t addr) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) return false;

    MEMORY_BASIC_INFORMATION mbi{};
    SIZE_T q = VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi));
    CloseHandle(hProc);

    if (q != sizeof(mbi)) return false;

    bool isCommit = (mbi.State == MEM_COMMIT);
    bool isPrivate = (mbi.Type == MEM_PRIVATE);
    bool isExec = IsExecuteProtect(mbi.Protect) && !(mbi.Protect & PAGE_GUARD);

    return (isCommit && isPrivate && isExec);
}

static bool IsLikelySystemRedirectOk(const std::string& importedDllLower,
    const std::string& actualDllLower)
{
   
    auto isGuiImport = [&](const std::string& s) {
        return (s == "user32.dll" || s == "gdi32.dll" || s == "comctl32.dll" ||
            s == "uxtheme.dll" || s == "imm32.dll");
        };

    auto isCoreSystem = [&](const std::string& s) {
        return (s == "ntdll.dll" || s == "win32u.dll" || s == "kernel32.dll" ||
            s == "kernelbase.dll" || s == "ucrtbase.dll");
        };

    if (isGuiImport(importedDllLower) && isCoreSystem(actualDllLower)) return true;

    // 같은 DLL이면 당연히 OK
    if (importedDllLower == actualDllLower) return true;

    return false;
}


static bool DetectIATHook(DWORD pid, const char* crackmePath) {
    std::vector<unsigned char> pe;
    if (!ReadFileAll(crackmePath, pe)) return false;

    if (pe.size() < sizeof(IMAGE_DOS_HEADER)) return false;

    auto* dos = (IMAGE_DOS_HEADER*)pe.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    auto* nt = (IMAGE_NT_HEADERS32*)(pe.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    DWORD impRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!impRva) return false;

    DWORD impOff = RvaToOffset32(pe, impRva);
    if (!impOff) return false;

    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) return false;

    uintptr_t base = GetMainModuleBase(pid);
    if (!base) { CloseHandle(hProc); return false; }

    auto remoteMods = GetRemoteModules(pid);
    if (remoteMods.empty()) { CloseHandle(hProc); return false; }

    // 스팸 방지: 같은 의심 케이스는 1번만 출력
    static std::unordered_set<std::string> g_printedIatFindings;

    bool suspiciousFound = false;   // “의심” (단, 정상 리다이렉션은 제외)
    bool strongFound = false;       // “강한 의심” (no module / MEM_PRIVATE+EXEC)

    auto* impDesc = (IMAGE_IMPORT_DESCRIPTOR*)(pe.data() + impOff);

    for (; impDesc->Name; ++impDesc) {
        DWORD nameOff = RvaToOffset32(pe, impDesc->Name);
        if (!nameOff) continue;

        const char* dllNameA = (const char*)(pe.data() + nameOff);
        std::string dllLower = ToLower(std::string(dllNameA));

        const ModuleInfoSimple* dllMod = FindRemoteModuleByName(remoteMods, dllLower);
        if (!dllMod) {
            continue;
        }

        DWORD firstThunkRva = impDesc->FirstThunk;
        if (!firstThunkRva) continue;

        uintptr_t iatAddr = base + firstThunkRva;

        for (int idx = 0; idx < 2048; idx++) {
            DWORD fnPtr = 0;
            SIZE_T read = 0;

            if (!ReadProcessMemory(hProc, (LPCVOID)(iatAddr + idx * sizeof(DWORD)),
                &fnPtr, sizeof(DWORD), &read) || read != sizeof(DWORD)) {
                break;
            }

            if (fnPtr == 0) break;

            uintptr_t fn = (uintptr_t)fnPtr;

            uintptr_t start = dllMod->base;
            uintptr_t end = dllMod->base + (uintptr_t)dllMod->size;

            // 정상 범위면 OK
            if (fn >= start && fn < end) continue;

            // “원래 DLL 범위 밖” → 실제 어디 모듈인지 확인
            const ModuleInfoSimple* actual = ResolveAddressToModule(remoteMods, fn);
            std::string actualName = actual ? actual->name : std::string("(no module)");

            // 추가 강한 신호: MEM_PRIVATE + EXEC 영역이면 거의 확실히 위험
            bool privExec = IsPrivateExecutableAt(pid, fn);

            // 정상 리다이렉션(시스템 DLL)인 경우는 오탐 줄이기 위해 스킵
            if (actual && !privExec && IsLikelySystemRedirectOk(dllLower, actual->name)) {
                continue;
            }

            suspiciousFound = true;
            if (!actual || privExec) strongFound = true;

            // 중복 출력 억제 키
            char keyBuf[256];
            std::snprintf(keyBuf, sizeof(keyBuf), "%s:%d:%s:%p",
                dllLower.c_str(), idx, actualName.c_str(), (void*)fn);

            if (g_printedIatFindings.insert(std::string(keyBuf)).second) {
                std::cout << NowString()
                    << " [INFO] IAT 의심: dll=" << dllLower
                    << " iat[" << idx << "]=0x" << std::hex << fn << std::dec
                    << " -> " << actualName
                    << (privExec ? " (MEM_PRIVATE+EXEC)" : "")
                    << "\n";
            }

            break;
        }

        if (strongFound) break;
    }

    CloseHandle(hProc);

    // 반환 정책:
    // - strongFound: 매우 강한 의심 → true
    // - suspiciousFound: 시스템 리다이렉션 제외한 의심 → true 
    return (strongFound || suspiciousFound);
}



// 특정 메모리 주소가 어느 모듈의 주소 범위에 속하는지 판별
// - 예: WndProc 주소가 user32.dll 범위에 있으면 그 모듈을 반환
static const ModuleInfoSimple* ResolveAddressToModule(const std::vector<ModuleInfoSimple>& mods, uintptr_t addr) {
    for (const auto& m : mods) {
        uintptr_t start = m.base;
        uintptr_t end = m.base + (uintptr_t)m.size;
        if (addr >= start && addr < end) return &m;
    }
    return nullptr;
}

// ===============================
// [R1/R2 강화] Baseline 모듈 diff + Private Exec 메모리 탐지
// ===============================

// 모듈명 목록(소문자)만 정렬해서 반환
static std::vector<std::string> GetModuleNameListLower(DWORD pid) {
    std::vector<std::string> out;
    auto mods = GetRemoteModules(pid);
    out.reserve(mods.size());
    for (auto& m : mods) out.push_back(m.name); // 이미 ToLower로 저장됨
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

static bool DetectNewModules2(DefenseState& st, std::vector<std::string>& newOnes) {
    newOnes.clear();
    if (!st.baselineReady) return false;

    auto now = GetModuleNameListLower(st.pid);

    size_t i = 0, j = 0;
    while (i < now.size() && j < st.baselineModules.size()) {
        if (now[i] == st.baselineModules[j]) { i++; j++; }
        else if (now[i] < st.baselineModules[j]) { newOnes.push_back(now[i]); i++; }
        else { j++; }
    }
    while (i < now.size()) { newOnes.push_back(now[i]); i++; }

    return !newOnes.empty();
}

static bool SuspendProcessThreads(DWORD pid) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);

    bool any = false;

    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;

            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
            if (!hThread) continue;

            if (SuspendThread(hThread) != (DWORD)-1) {
                any = true;
            }
            CloseHandle(hThread);

        } while (Thread32Next(hSnap, &te));
    }

    CloseHandle(hSnap);

    if (any) std::cout << NowString() << " [RESPONSE] Suspended all threads of target.\n";
    return any;
}

static bool TerminateTargetProcess(DWORD pid, UINT exitCode = 1) {
    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProc) return false;
    BOOL ok = TerminateProcess(hProc, exitCode);
    CloseHandle(hProc);

    if (ok) std::cout << NowString() << " [RESPONSE] Target terminated (isolation).\n";
    return ok == TRUE;
}


static bool DetectSuspiciousThreadStart(DWORD pid) {
    auto mods = GetRemoteModules(pid);
    if (mods.empty()) return false;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;

    PFN_NtQueryInformationThread NtQueryInformationThread =
        (PFN_NtQueryInformationThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");

    if (!NtQueryInformationThread) {
        CloseHandle(hSnap);
        return false;
    }

    static std::set<DWORD> printedTids; // 스팸 방지(이미 출력한 TID는 재출력하지 않음)
    bool suspicious = false;

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);

    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;

            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            if (!hThread) continue;

            PVOID startAddr = nullptr;
            NTSTATUS st = NtQueryInformationThread(
                hThread,
                (THREADINFOCLASS)9,  // ThreadQuerySetWin32StartAddress
                &startAddr,
                sizeof(startAddr),
                nullptr
            );

            CloseHandle(hThread);

            if (st != 0 || !startAddr) continue;

            uintptr_t sa = (uintptr_t)startAddr;

            // 시작 주소가 어떤 모듈에도 속하지 않으면 의심
            const ModuleInfoSimple* m = ResolveAddressToModule(mods, sa);

            if (!m) {
                // 추가로 "Private + Exec"이면 더 강한 신호
                bool privExec = IsPrivateExecutableAt(pid, sa);

                if (printedTids.insert(te.th32ThreadID).second) {
                    // INFO 로그는 main의 R1/R2/R3 출력보다 먼저 나올 수 있어서 여기서는 출력 금지
#if 0
                    std::cout << NowString()
                        << " [INFO] 수상 스레드 감지: TID=" << te.th32ThreadID
                        << " Start=0x" << std::hex << sa << std::dec
                        << (privExec ? " (MEM_PRIVATE+EXEC)\n" : " (no module matched)\n");
#endif
                }


                suspicious = true;
            }
        } while (Thread32Next(hSnap, &te));
    }

    CloseHandle(hSnap);
    return suspicious;
}



// MEM_PRIVATE + EXEC 영역이 있으면 인젝션/쉘코드/manual map 흔적 가능성
static bool DetectPrivateExecutableMemory(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) return false;

    SYSTEM_INFO si{};
    GetSystemInfo(&si);

    uintptr_t addr = (uintptr_t)si.lpMinimumApplicationAddress;
    uintptr_t max = (uintptr_t)si.lpMaximumApplicationAddress;

    MEMORY_BASIC_INFORMATION mbi{};
    while (addr < max) {
        SIZE_T q = VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi));
        if (q != sizeof(mbi)) break;

        bool isCommit = (mbi.State == MEM_COMMIT);
        bool isPrivate = (mbi.Type == MEM_PRIVATE);
        bool isExec = IsExecuteProtect(mbi.Protect) && !(mbi.Protect & PAGE_GUARD);

        if (isCommit && isPrivate && isExec) {
            CloseHandle(hProc);
            return true;
        }

        addr += mbi.RegionSize;
    }

    CloseHandle(hProc);
    return false;
}

// 새로 들어온 DLL 목록을 한 줄로 출력
static void LogNewDlls(const std::vector<std::string>& newMods) {
    std::cout << NowString() << " [INFO] 신규 모듈 로드 감지: ";
    for (size_t i = 0; i < newMods.size(); i++) {
        std::cout << newMods[i];
        if (i + 1 < newMods.size()) std::cout << ", ";
    }
    std::cout << "\n";
}

static uintptr_t ReadWndProc(HWND h) {
    SetLastError(0);
    LONG_PTR p = GetWindowLongPtr(h, GWLP_WNDPROC);
    if (p == 0 && GetLastError() != 0) return 0;
    return (uintptr_t)p;
}

static void CaptureWndProcBaselineIfNeeded(DefenseState& st, HWND hDlg, HWND hEdit1, HWND hEdit2, HWND hOk, bool grace) {
    if (st.wndBase.ready) return;
    if (grace) return; // grace 중엔 흔들릴 수 있으니 저장 X

    uintptr_t pd = ReadWndProc(hDlg);
    uintptr_t p1 = ReadWndProc(hEdit1);
    uintptr_t p2 = ReadWndProc(hEdit2);
    uintptr_t pk = ReadWndProc(hOk);

    if (pd && p1 && p2 && pk) {
        st.wndBase.dlg = pd;
        st.wndBase.e1 = p1;
        st.wndBase.e2 = p2;
        st.wndBase.ok = pk;
        st.wndBase.ready = true;

        std::cout << NowString() << " [INFO] WndProc baseline captured.\n";
    }
}


static bool RestoreWndProcIfHooked(DefenseState& st, HWND hDlg, HWND hEdit1, HWND hEdit2, HWND hOk) {
    if (!st.wndBase.ready) return false;

    bool changed = false;

    auto restoreOne = [&](HWND h, uintptr_t expect, const char* tag) {
        uintptr_t cur = ReadWndProc(h);
        if (!cur || cur == expect) return;

        // 원복 시도
        SetLastError(0);
        LONG_PTR r = SetWindowLongPtr(h, GWLP_WNDPROC, (LONG_PTR)expect);
        DWORD gle = GetLastError();

        if (r != 0 || gle == 0) {
            std::cout << NowString() << " [RESPONSE] WndProc restored: " << tag
                << " (0x" << std::hex << cur << " -> 0x" << expect << std::dec << ")\n";
            changed = true;
        }
        else {
            std::cout << NowString() << " [RESPONSE] WndProc restore FAILED: " << tag
                << " GLE=" << gle << "\n";
        }
        };

    restoreOne(hDlg, st.wndBase.dlg, "DLG");
    restoreOne(hEdit1, st.wndBase.e1, "EDIT1");
    restoreOne(hEdit2, st.wndBase.e2, "EDIT2");
    restoreOne(hOk, st.wndBase.ok, "OK");

    return changed;
}



// -------------------------------
// 3) R1/R2 탐지: WndProc 포인터가 "정상 모듈"이 아닌 곳을 가리키는지
// -------------------------------

// WndProc가 정상적으로 속할 수 있는 모듈(allowlist)인지 여부를 판단
static bool IsAllowedProcModule(const std::string& modNameLower) {
    static const char* allow[] = {
        "crackme.exe",
        "user32.dll",
        "ntdll.dll",
        "kernel32.dll",
        "kernelbase.dll",
        "comctl32.dll",
        "uxtheme.dll",
        "imm32.dll",
        "msctf.dll",
        "msctfime.ime",
        "msctfime.dll",
        "windows.ui.textinput.dll",
        "vcruntime140.dll",
        "msvcp140.dll",
        "ucrtbase.dll",
        "windows.storage.dll",
        "api-ms-win-core-*.dll"
    };

    for (auto a : allow) {
        if (modNameLower == a) return true;
    }
    return false;
}



// R1(R1: Edit 입력창), R2(OK 버튼/다이얼로그) 탐지 결과를 담는 구조체
struct R12Result {
    bool r1 = false;
    bool r2 = false;
};

// Edit/OK/다이얼로그의 WndProc 주소가 정상 모듈에 속하는지 검사하여
// R1(입력창 후킹), R2(버튼/메시지 후킹) 공격 여부를 탐지
static R12Result DetectR1R2_ByWndProc(HWND hDlg, HWND hEdit1, HWND hEdit2, HWND hOk, DWORD pid) {
    R12Result out{};

    auto mods = GetRemoteModules(pid);
    if (mods.empty()) return out;

    struct WndProcRead {
        uintptr_t proc;
        DWORD gle;
    };

    auto readWndProc = [&](HWND h) -> WndProcRead {
        SetLastError(0);
        LONG_PTR p = GetWindowLongPtr(h, GWLP_WNDPROC);
        DWORD e = GetLastError();
        return { (uintptr_t)p, e };
        };

    auto dlg = readWndProc(hDlg);
    auto e1 = readWndProc(hEdit1);
    auto e2 = readWndProc(hEdit2);
    auto ok = readWndProc(hOk);

    auto check = [&](const WndProcRead& r) -> bool {
        // 접근 거부/읽기 실패는 공격으로 판정하지 않음
        if (r.proc == 0) return false;
        if (r.gle == ERROR_ACCESS_DENIED) return false;

        const ModuleInfoSimple* m = ResolveAddressToModule(mods, r.proc);
        if (!m) return true;

        return !IsAllowedProcModule(m->name);
        };

    bool sEdit = check(e1) || check(e2);
    bool sOk = check(ok);
    bool sDlg = check(dlg);

    if (sEdit) out.r1 = true;
    if (sOk || sDlg) out.r2 = true;

    return out;
}


// -------------------------------
// 4) R3 탐지: CRACKME.exe의 .text 코드 섹션 무결성(디스크 vs 메모리)
// -------------------------------

#pragma pack(push, 1)
struct IMAGE_DOS_HEADER_SIMPLE {
    WORD e_magic;
    WORD e_cblp; WORD e_cp; WORD e_crlc; WORD e_cparhdr;
    WORD e_minalloc; WORD e_maxalloc; WORD e_ss; WORD e_sp;
    WORD e_csum; WORD e_ip; WORD e_cs; WORD e_lfarlc; WORD e_ovno;
    WORD e_res[4];
    WORD e_oemid; WORD e_oeminfo; WORD e_res2[10];
    LONG e_lfanew;
};
#pragma pack(pop)

// 디스크에 있는 실행 파일(CRACKME.exe)을 통째로 메모리에 로드
static bool ReadFileAll(const char* path, std::vector<unsigned char>& out) {
    FILE* fp = std::fopen(path, "rb");
    if (!fp) return false;
    std::fseek(fp, 0, SEEK_END);
    long sz = std::ftell(fp);
    std::fseek(fp, 0, SEEK_SET);
    if (sz <= 0) { std::fclose(fp); return false; }
    out.resize((size_t)sz);
    if (std::fread(out.data(), 1, out.size(), fp) != out.size()) { std::fclose(fp); return false; }
    std::fclose(fp);
    return true;
}


static uint32_t crc32_table[256];

// CRC32 해시 테이블 초기화
static void InitCrc32() {
    static bool inited = false;
    if (inited) return;
    inited = true;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++) {
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        }
        crc32_table[i] = c;
    }
}

// 주어진 바이트 배열에 대해 CRC32 해시 값을 계산
static uint32_t Crc32(const unsigned char* data, size_t len) {
    InitCrc32();
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        c = crc32_table[(c ^ data[i]) & 0xFF] ^ (c >> 8);
    }
    return c ^ 0xFFFFFFFFu;
}

struct TextSectionInfo {
    DWORD rva = 0;
    DWORD rawPtr = 0;
    DWORD rawSize = 0;
};

// 디스크에 있는 PE 파일에서 .text 섹션의 정보(RVA, Raw Pointer, Raw Size)를 획득
static bool GetTextSectionInfoFromDisk(const std::vector<unsigned char>& pe, TextSectionInfo& out) {
    if (pe.size() < sizeof(IMAGE_DOS_HEADER_SIMPLE)) return false;

    auto* dos = (const IMAGE_DOS_HEADER_SIMPLE*)pe.data();
    if (dos->e_magic != 0x5A4D) return false; // "MZ"

    DWORD ntOff = (DWORD)dos->e_lfanew;
    if (ntOff + 4 > pe.size()) return false;
    if (*(DWORD*)(pe.data() + ntOff) != 0x00004550) return false; // "PE\0\0"

    // FILE_HEADER: ntOff+4, OPTIONAL_HEADER: 그 뒤
    auto* fileHeader = (IMAGE_FILE_HEADER*)(pe.data() + ntOff + 4);
    auto* optHeader = (IMAGE_OPTIONAL_HEADER32*)(pe.data() + ntOff + 4 + sizeof(IMAGE_FILE_HEADER));

    // 섹션 헤더 시작
    BYTE* secBase = (BYTE*)optHeader + fileHeader->SizeOfOptionalHeader;
    IMAGE_SECTION_HEADER* sec = (IMAGE_SECTION_HEADER*)secBase;

    for (int i = 0; i < fileHeader->NumberOfSections; i++) {
        char name[9]{};
        std::memcpy(name, sec[i].Name, 8);
        std::string sname = name;
        if (sname == ".text") {
            out.rva = sec[i].VirtualAddress;
            out.rawPtr = sec[i].PointerToRawData;
            out.rawSize = sec[i].SizeOfRawData;
            return true;
        }
    }
    return false;
}

// 타겟 프로세스에서 메인 실행 파일(CRACKME.exe)의 메모리 베이스 주소를 획득
static uintptr_t GetMainModuleBase(DWORD pid) {
    auto mods = GetRemoteModules(pid);
    for (auto& m : mods) {
        if (m.name == "crackme.exe") return m.base;
    }
    if (!mods.empty()) return mods[0].base;
    return 0;
}

// 디스크의 CRACKME.exe와 실행 중 프로세스 메모리의 .text 섹션을 비교하여
// 코드 패치 여부(R3 공격)를 탐지
static bool DetectR3_TextIntegrity(DWORD pid, const char* crackmePath) {
    // 디스크에서 .text 읽기
    std::vector<unsigned char> pe;
    if (!ReadFileAll(crackmePath, pe)) return false;

    TextSectionInfo ti{};
    if (!GetTextSectionInfoFromDisk(pe, ti)) return false;
    if (ti.rawPtr + ti.rawSize > pe.size()) return false;

    const unsigned char* diskText = pe.data() + ti.rawPtr;
    uint32_t diskCrc = Crc32(diskText, ti.rawSize);

    // 메모리에서 .text 읽기
    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) return false;

    uintptr_t base = GetMainModuleBase(pid);
    if (!base) { CloseHandle(hProc); return false; }

    std::vector<unsigned char> memText(ti.rawSize);
    SIZE_T readBytes = 0;
    BOOL ok = ReadProcessMemory(hProc, (LPCVOID)(base + ti.rva), memText.data(), ti.rawSize, &readBytes);
    CloseHandle(hProc);

    if (!ok || readBytes != ti.rawSize) return false;

    uint32_t memCrc = Crc32(memText.data(), memText.size());

    // 다르면 패치 의심(R3)
    return (diskCrc != memCrc);
}

// PE 파일에서 RVA를 파일 오프셋으로 변환 (섹션 테이블 기반)
static DWORD RvaToOffset32(const std::vector<unsigned char>& pe, DWORD rva) {
    auto* dos = (IMAGE_DOS_HEADER*)pe.data();
    auto* nt = (IMAGE_NT_HEADERS32*)(pe.data() + dos->e_lfanew);

    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD va = sec[i].VirtualAddress;
        DWORD vsz = sec[i].Misc.VirtualSize;
        DWORD raw = sec[i].PointerToRawData;
        DWORD rawS = sec[i].SizeOfRawData;

        DWORD size = (vsz > 0) ? vsz : rawS;
        if (rva >= va && rva < va + size) {
            return (rva - va) + raw;
        }
    }
    return 0;
}



int main(int argc, char* argv[]) {
    const char* crackmePath = "CRACKME.exe";
    if (argc >= 2) crackmePath = argv[1];

    std::cout << "[DEFENSE] started. target=" << crackmePath << "\n";
    std::cout << "[DEFENSE] tip: If target is x86, build DEFENSE as x86.\n\n";

    bool prevR1 = false, prevR2 = false, prevR3 = false;

    while (true) {
        DWORD pid = FindProcessIdByNameA("CRACKME.exe");
        if (!pid) { Sleep(300); continue; }

        if (g_state.pid != pid) g_state.Reset(pid);

        EnsureBaselineModules2(g_state);
        bool grace = InGracePeriod(g_state, 1500);

        Signals sig{};

        // 1) 신규 모듈
        std::vector<std::string> newMods;
        sig.newDll = DetectNewModules2(g_state, newMods);

        // 2) private exec
        sig.privExec = DetectPrivateExecutableMemory(pid);

        // 3) 기존 수상 start(no module)
        sig.suspThreadStart = DetectSuspiciousThreadStart(pid);

        // 4) LoadLibrary start thread
        sig.loadLibraryThread = DetectLoadLibraryStartThread(g_state);

        // 5) IAT(보조)
        sig.iatHook = DetectIATHook(pid, crackmePath);

        // 6) 로드된 의심 DLL 탐지
        std::string hitName, hitPath;
        sig.suspLoadedMod = DetectSuspiciousLoadedModule(pid, hitName, hitPath);

        if (sig.suspLoadedMod) {
            static std::set<std::string> printed;
            if (printed.insert(hitName).second) {
                std::cout << NowString()
                    << " [INFO] 의심 모듈 존재: "
                    << hitName << " (" << hitPath << ")\n";
            }
        }

        // 7) UI 핸들 잡히면 WndProc 검사 + (대응까지)
        HWND hDlg = NULL, hEdit1 = NULL, hEdit2 = NULL, hOk = NULL;
        if (FindRegisterHandles(hDlg, hEdit1, hEdit2, hOk)) {

            // baseline (성공하면 1회 로그)
            CaptureWndProcBaselineIfNeeded(g_state, hDlg, hEdit1, hEdit2, hOk, grace);

            // WndProc 기반 훅 탐지
            auto r12 = DetectR1R2_ByWndProc(hDlg, hEdit1, hEdit2, hOk, pid);
            sig.wndprocEdit = r12.r1;
            sig.wndprocOkOrDlg = r12.r2;

            // (가능하면) 즉시 원복
            if (sig.wndprocEdit || sig.wndprocOkOrDlg) {
                RestoreWndProcIfHooked(g_state, hDlg, hEdit1, hEdit2, hOk);
            }

            // R1 증상 기반(자동 Serial 입력) 탐지
            RECT r1{}, r2{};
            GetWindowRect(hEdit1, &r1);
            GetWindowRect(hEdit2, &r2);

            HWND hNameEdit = (r1.top < r2.top) ? hEdit1 : hEdit2;
            HWND hSerialEdit = (r1.top < r2.top) ? hEdit2 : hEdit1;

            char nameBuf[256]{}, serialBuf[256]{};
            GetWindowTextA(hNameEdit, nameBuf, 255);
            GetWindowTextA(hSerialEdit, serialBuf, 255);

            std::string curName(nameBuf);
            std::string curSerial(serialBuf);

            DWORD now = GetTickCount();

            if (curName != prevName) {
                lastNameChangeTick = now;
                prevName = curName;
            }

            bool autoSerialPattern = false;
            if (curSerial != prevSerial) {
                if (lastNameChangeTick != 0 && (now - lastNameChangeTick) <= 150) {
                    autoSerialPattern = true;
                }
                prevSerial = curSerial;
            }

            sig.autoSerialPattern = autoSerialPattern;

            if (sig.autoSerialPattern) {
                static bool printed = false;
                if (!printed) {
                    std::cout << NowString()
                        << " [INFO] R1 패턴 의심: Name 변경 직후 Serial 자동 변경\n";
                    printed = true;
                }
            }
        }

        // 신규 DLL 로그
        if (sig.newDll) {
            std::vector<std::string> toPrint;
            for (auto& s : newMods) {
                if (g_state.printedNewMods.insert(s).second) toPrint.push_back(s);
            }
            if (!toPrint.empty()) LogNewDlls(toPrint);
        }

        // ====== 점수 판정 ======
        int r1Score = ScoreR1(sig);
        int r2Score = ScoreR2(sig);

        int r1Threshold = grace ? 6 : 5;
        int r2Threshold = grace ? 6 : 5;

        bool r1 = (r1Score >= r1Threshold);
        bool r2 = (r2Score >= r2Threshold);

        bool r3 = DetectR3_TextIntegrity(pid, crackmePath);

        // ====== (1) 탐지 로그를 먼저 "상태 변화시에만" 출력 ======
        bool r1Now = (r1 && !prevR1);
        bool r2Now = (r2 && !prevR2);
        bool r3Now = (r3 && !prevR3);

        if (r1Now) { LogDetect("R1"); g_state.didDetectAny = true; }
        if (r2Now) { LogDetect("R2"); g_state.didDetectAny = true; }
        if (r3Now) { LogDetect("R3"); g_state.didDetectAny = true; }

        std::cout << std::flush; // 탐지 로그 먼저 출력 보장

        // ====== (2) 그 다음 대응 (딱 1회만) ======

        // (강한 침해 종료는 그대로)
        if ((r3 || sig.privExec) && !g_state.didTerminate) {
            g_state.didTerminate = true;
            TerminateTargetProcess(pid, 1);
            g_state.Reset(0);
            prevR1 = prevR2 = prevR3 = false;
            Sleep(500);
            continue;
        }

        // Suspend는 "탐지 로그가 최소 1번은 찍힌 후"에만 허용
        bool needSuspend =
            (sig.suspThreadStart || sig.loadLibraryThread || sig.iatHook || sig.suspLoadedMod);

        if (g_state.didDetectAny && needSuspend && !g_state.didSuspend) {
            g_state.didSuspend = true;
            SuspendProcessThreads(pid);
        }


        // ====== prev 갱신 ======
        prevR1 = r1;
        prevR2 = r2;
        prevR3 = r3;

        Sleep(300);
    }
}

