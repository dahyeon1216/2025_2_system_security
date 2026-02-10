# 🛡️ System Security Final Project

## Attack & Defense Program README

---

# 🔴 Attacker Program README

## 1. 개요 (Overview)

본 **공격자 프로그램(Attacker)** 은

Windows 환경에서 **IAT(Import Address Table) Hooking** 기법을 이용하여

대상 프로세스의 **`kernel32!WriteFile()` API 호출 흐름을 탈취(hijack)** 하는 것을 목표로 한다.

공격자는 DLL 형태로 제작되며,

외부 **Injector 프로그램**을 통해 실행 중인 프로세스에 주입된다.

이를 통해 다음 보안 위협을 실습 수준에서 재현한다.

- API 호출 경로 변조
- 사용자 모드 후킹 공격
- 정상 프로그램 동작 중 악성 코드 개입 가능성 검증

---

## 2. 공격 시나리오 (Attack Scenario)

### 전체 흐름

```
[Injector 실행]
      ↓
[대상 프로세스(test_write.exe) 실행]
      ↓
[DLL Injection (LoadLibrary)]
      ↓
[Hook DLL 로드]
      ↓
[IAT 내 WriteFile 함수 주소 변경]
      ↓
[WriteFile 호출 시 공격자 코드 실행]
```

---

## 3. 구성 요소 (Components)

| 파일 | 설명 |
| --- | --- |
| `test_write.exe` | WriteFile을 호출하는 타깃 프로그램 |
| `hook_writefile.dll` | IAT Hooking 공격 DLL |
| `injector.exe` | DLL Injection 수행 프로그램 |

---

## 4. 공격 기법 설명

### 4.1 IAT Hooking

- PE 파일의 Import Table을 순회하여
- `KERNEL32.dll` → `WriteFile` 항목 탐색
- IAT 엔트리를 공격자 함수 주소로 덮어씀

```
Before:
IAT → WriteFile → kernel32!WriteFile

After:
IAT → WriteFile → HookedWriteFile
```

---

### 4.2 Hook 동작 방식

```c
BOOL WINAPIHookedWriteFile(...)
{
    MessageBoxA(NULL,"WriteFile hooked!","hook", MB_OK);return OriginalWriteFile(...);
}
```

- API 호출을 가로채어 **공격자 코드 실행**
- 이후 원본 API를 호출하여 프로그램이 멈추지 않도록 유지

---

## 5. 실험 결과

### 5.1 공격 전

- `test_write.exe` 실행
- `WriteFile()` 정상 호출
- 파일 정상 생성 및 쓰기 수행

---

### 5.2 공격 후 (DLL Injection 성공)

- WriteFile 호출 시마다 **MessageBox 출력**
- 파일 쓰기 동작은 유지됨
- **API 흐름이 공격자에 의해 제어됨을 확인**

---

## 6. 공격 요약

| 항목 | 결과 |
| --- | --- |
| 공격 기법 | IAT Hooking |
| 후킹 대상 | kernel32!WriteFile |
| 공격 성공 | ✔ |
| 프로그램 유지 | ✔ |
| 사용자 모드 공격 | ✔ |

---

# 🔵 Defender Program README

## 1. 개요 (Overview)

본 **방어자 프로그램(Defender)** 은

**안티 디버깅(Anti-Debugging)** 기법을 통해

프로그램이 디버거에 의해 분석·공격당하는 상황을 탐지하고 차단한다.

다음 3가지 핵심 기술을 결합하여 방어를 구성한다.

- **PEB → BeingDebugged 플래그 검사**
- **TLS Callback 기반 조기 실행**
- **Watchdog 스레드 기반 지속 감시**

---

## 2. 방어 목표 (Defense Goals)

- 디버거가 **프로그램 실행 전 / 실행 중** 붙는 것을 모두 탐지
- 정상 실행 환경에서는 **graceful shutdown 보장**
- 디버깅 환경에서는 **즉시 보호 동작 수행**

---

## 3. 방어 구조 (Defense Architecture)

```
[프로세스 시작]
      ↓
[TLS Callback 실행]
      ↓
[Watchdog 스레드 생성]
      ↓
[main() 실행]
      ↓
[주기적 디버깅 검사]
      ↓
[정상 종료 or 보호 동작]
```

---

## 4. 핵심 방어 기법

### 4.1 PEB 기반 디버깅 탐지

```c
PEB* peb = (PEB*)__readfsdword(0x30);// x86return peb->BeingDebugged !=0;
```

- 운영체제 내부 구조를 직접 참조
- API Hooking 우회 가능
- 디버거 attach 시 즉시 값 변경

---

### 4.2 TLS Callback 활용

- `main()` 이전에 실행되는 초기화 루틴
- 디버거가 **시작 시 자동 attach (VS F5)** 되어도 탐지 가능

```
TLS Callback → Watchdog 생성 → main 진입
```

---

### 4.3 Watchdog 스레드

- 독립 스레드에서 지속 감시
- 0.3초 주기로 디버깅 여부 검사
- 런타임 attach(x64dbg 등)도 탐지 가능

---

## 5. 보호 동작 (Protection Behavior)

- 디버깅 감지 시:

```c
__fastfail(1);
```

- 즉시 예외 발생
- 분석 지속 불가능
- 공격자 디버깅 환경 차단

---

## 6. 정상 종료 설계 (Graceful Shutdown)

- 디버깅 미탐지 시
    - main 함수 정상 수행
    - Watchdog 종료 플래그 설정
    - 스레드 join 후 리소스 해제
    - `return 0`으로 정상 종료

> ❌ `exit(0)`, `ExitProcess()` 사용하지 않음
> 
> 
> ✔ 과제 요구사항 충족
> 

---

## 7. 실험 결과 요약

| 환경 | 결과 |
| --- | --- |
| 정상 실행 (Ctrl+F5) | 정상 종료 |
| Visual Studio F5 | TLS 단계에서 탐지 후 종료 |
| x64dbg Attach | 런타임 감지 후 종료 |
| PE 분석 | TLS Callback 정상 등록 확인 |

---

## 8. 방어 요약

| 항목 | 결과 |
| --- | --- |
| 디버깅 탐지 | ✔ |
| 조기 탐지(TLS) | ✔ |
| 런타임 탐지 | ✔ |
| 정상 종료 | ✔ |
| 리소스 누수 없음 | ✔ |

---

## 📌 최종 정리

본 프로젝트는

**공격자(IAT Hooking) – 방어자(Anti-Debugging)** 구조를 통해

- 실제 보안 공격이 **어떻게 동작하는지**
- 이를 **어디서, 어떻게 탐지·차단할 수 있는지**

를 **시스템 보안 관점에서 실증적으로 구현**하였다.

---
## 📝 Full Notes
https://delicate-dish-b60.notion.site/CrackMe-exe-2bda4c0c427280839252c88da321facf?source=copy_link
