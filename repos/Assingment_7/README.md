# 🛡 Anti-Debugging Program (PEB · TLS Callback · Watchdog)

본 프로젝트는 **PEB의 `BeingDebugged` 플래그**, **TLS Callback**, **Watchdog 스레드**를 활용하여

프로그램이 디버깅 환경에서 실행되거나 런타임 중 디버거가 attach 되는 것을 탐지하고 차단하는

**안티 디버깅(Anti-Debugging)** 기법을 구현한 것이다.

과제 요구사항에 따라 **main() 이전 감시 시작**, **지속적 디버깅 감시**,

**정상 실행 시 graceful shutdown** 을 모두 만족하도록 설계되었다.

---

## 🎯 목표

- PEB `BeingDebugged` 플래그 직접 참조 기반 디버깅 탐지
- TLS Callback을 활용하여 **main() 이전** 감시 시작
- Watchdog 스레드로 **실행 중 지속 감시**
- 정상 환경에서는 **자원 정리 후 정상 종료**
- 디버깅 환경에서는 **즉시 보호 동작 수행**

---

## 🧩 전체 동작 흐름

```
[프로세스 시작]
       │
       ▼[ TLS Callback 실행 ]
       │
       └─▶ Watchdog 스레드 생성
       │
       ▼[ main() 함수 실행 ]
       │
       ├─ 정상 실행 → watchdog 지속 감시
       │
       ├─ 디버거 감지 →__fastfail() 호출
       │
       ▼[ main() 작업 완료 ]
       │
       ▼[ watchdog 종료 요청 ]
       │
       ▼[ 스레드 join & 자원 해제 ]
       │
       ▼[ return 0 (graceful shutdown) ]
```

---

## 🔧 주요 구성 요소

| 구성 요소 | 설명 |
| --- | --- |
| **PEB BeingDebugged** | PEB 내부 플래그를 직접 읽어 디버거 attach 여부 판단 |
| **TLS Callback** | main() 이전 실행되는 초기화 루틴, watchdog 조기 시작 |
| **Watchdog Thread** | 주기적으로 디버깅 여부 검사 |
| **Graceful Shutdown** | 정상 실행 시 스레드 종료 후 return 0 |

---

## 🧠 디버깅 탐지 방식

### 1️⃣ PEB 기반 탐지

- `PEB->BeingDebugged == 1` 이면 디버거 attach 상태
- x86 / x64 환경 모두 지원 (FS / GS 레지스터 사용)

```cpp
BOOL CheckDebuggerByPEB()
{#ifdef _M_IX86
    PEB* peb = (PEB*)__readfsdword(0x30);#elif _M_X64
    PEB* peb = (PEB*)__readgsqword(0x60);#elsereturn FALSE;#endifreturn (peb->BeingDebugged !=0);
}
```

### 2️⃣ API 기반 탐지

- `IsDebuggerPresent()` 병행 사용

```c
BOOLIsDebugging()
{if (CheckDebuggerByPEB())return TRUE;if (IsDebuggerPresent())return TRUE;return FALSE;
}
```

---

## 🧵 Watchdog 스레드

- TLS Callback에서 생성
- 0.3초 주기로 디버깅 여부 검사
- 디버거 감지 시 즉시 보호 동작 수행

```c
DWORD WINAPIWatchdogThread(LPVOID lpParam)
{while (!g_StopWatchdog)
    {if (IsDebugging())
        {printf("[WATCHDOG] Debugger detected!\n");
            __fastfail(1);
        }
        Sleep(300);
    }return0;
}
```

---

## 🧬 TLS Callback

- main() 함수보다 **먼저 실행**
- watchdog 스레드를 가장 이른 시점에 활성화

```c
void NTAPITlsCallback(PVOID, DWORD reason, PVOID)
{if (reason == DLL_PROCESS_ATTACH)
    {
        g_hWatchdogThread = CreateThread(NULL,0, WatchdogThread,NULL,0,NULL
        );
    }
}
```

- `.CRT$XLB` 섹션에 등록되어 PE의 TLS Directory에 포함됨

---

## 🚦 main() & Graceful Shutdown

- 정상 환경에서만 main() 전체 실행
- 작업 완료 후 watchdog 종료 요청
- `exit()` / `ExitProcess()` **사용하지 않음**

```c
intmain()
{printf("[MAIN] Program running...\n");

    Sleep(5000);// 주요 작업

    g_StopWatchdog = TRUE;

    WaitForSingleObject(g_hWatchdogThread, INFINITE);
    CloseHandle(g_hWatchdogThread);printf("[MAIN] Graceful shutdown\n");return0;
}
```

---

## 🧪 실험 결과 요약

| Case | 실행 환경 | 결과 |
| --- | --- | --- |
| 정상 실행 | 디버거 없음 | 정상 실행 후 graceful shutdown |
| VS F5 실행 | 디버거 자동 attach | TLS 단계에서 즉시 fastfail |
| x64dbg Attach | 실행 중 attach | watchdog이 실시간 감지 후 종료 |
| PE 분석 | TLS Directory 확인 | TLS Callback 정상 등록 확인 |

---

## 📌 핵심 정리

- **TLS Callback + Watchdog** 조합으로 main 이전부터 보호 가능
- **PEB 직접 참조**로 디버깅 환경 정확히 탐지
- 정상 환경에서는 **리소스 누수 없는 종료**
- 디버깅 환경에서는 **즉각적인 보호 동작 수행**
- 안티 디버깅이 **PE 구조 레벨 + 런타임 레벨**에서 모두 동작함을 검증

---

## 📝Full Notes
https://delicate-dish-b60.notion.site/7-Anti-debugging-routine-2a6a4c0c427280fb9bb9fc580c9f82ae?source=copy_link
