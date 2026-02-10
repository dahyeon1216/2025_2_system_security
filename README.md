# 📘 2025_2_system_security

> 2025-2학기 **시스템보안(System Security)** 수업 실습 및 프로젝트 아카이브
> 
> 
> Windows 환경에서의 **공격(Attack)과 방어(Defense)** 기법을 직접 구현하고 실험한 결과를 정리한 레포지토리입니다.
> 

---

## 🧭 Repository Overview

본 레포지토리는 시스템 보안 수업에서 다룬 내용을 **이론이 아닌 실습 중심**으로 정리한 저장소입니다.

Windows 내부 구조(PE, PEB, IAT, TLS 등)를 기반으로 다음과 같은 주제를 다룹니다.

- Windows API 기반 **공격 기법 구현**
- 프로세스 / 메모리 / 디버깅 관점의 **보안 취약점 분석**
- 공격을 탐지·차단하기 위한 **방어 로직 설계**
- 실제 디버거(Visual Studio, x64dbg) 환경에서의 **실험 및 검증**

---

## 🗂️ Directory Structure

```
.
├── Assignment_4 # PE 구조 분석, Import Table, 링킹 기초
├── Assignment_5 # 명시적 링킹 / DLL 동적 로딩 실습
├── Assignment_6 # 프로세스 메모리 접근 (WriteProcessMemory 등)
├── Assignment_7 # Anti-Debugging (PEB, TLS Callback, Watchdog)
├── Assignment_8 # Launcher-Client 디버깅 보호 구조
├── Final
│ ├── Assignment_Final_Attack # 공격자 프로그램 (Hook / Injection)
│ ├── Assignment_Final_Attack_DLL # 공격용 DLL
│ └── Assignment_Final_Defense # 방어자 프로그램 (Anti-Debugging)
└── test # 수업 중 실습 및 개인 학습 코드 모음
```

> 각 과제 디렉토리에는 **소스 코드, 실험 결과, 스크린샷, 과제 설명**이 함께 포함되어 있습니다.

---

## 🧪 Assignments Overview

| 구분 | 주제 | 핵심 내용 |
| --- | --- | --- |
| Assignment 4 | PE 기초 | PE Header, Import Table, IAT 구조 |
| Assignment 5 | 링킹 | Explicit Linking, DLL 교체 실험 |
| Assignment 6 | 메모리 | VirtualAllocEx, WriteProcessMemory |
| Assignment 7 | Anti-Debugging | PEB, BeingDebugged, TLS Callback |
| Assignment 8 | Debug Protection | Launcher–Client 구조 |
| Final | 종합 | 공격자 vs 방어자 시스템 |

> 각 과제 폴더에는 **개별 [README.md](http://readme.md/)** 가 포함되어 있으며, 과제 목표, 구현 방식, 실험 결과를 정리하였습니다.
 

---

## ⚔️ Attack & Defense Model

본 수업의 핵심은 **공격과 방어를 분리해서 이해하는 것**입니다.

### 🔴 Attack (공격자 관점)

- IAT Hooking을 통한 API 흐름 가로채기
- DLL Injection 및 WriteFile / MessageBoxA Hook
- 프로세스 메모리 조작 및 실행 흐름 변조
- 디버거를 활용한 동적 분석

### 🟢 Defense (방어자 관점)

- PEB BeingDebugged 기반 디버깅 탐지
- Watchdog Thread를 이용한 지속 감시
- TLS Callback을 활용한 main 이전 보호
- Debugger Attach / F5 실행 시 즉각 탐지 및 차단

👉 **Final 프로젝트에서는 공격자/방어자 프로그램을 분리 구현**하여

실제 공격이 어떻게 발생하고, 이를 어떻게 탐지·차단할 수 있는지 실험적으로 검증하였습니다.

---

## 🧪 Experiment Environment

- **OS**: Windows 10 / Windows 11 (x86, x64)
- **Compiler**: Visual Studio (MSVC)
- **Debugger**:
    - Visual Studio Debugger
    - x32dbg,x64dbg
- **Analysis Tools**:
    - PE-bear / CFF Explorer / custom PE parser

---

## 🎯 Key Learning Outcomes

이 레포지토리를 통해 다음을 직접 구현하고 검증하였습니다.

- Windows 프로세스 구조 (PE / PEB / IAT / TLS)에 대한 이해
- API 호출 흐름이 공격에 의해 어떻게 변조될 수 있는지
- 디버깅이 보안 관점에서 어떤 위협이 될 수 있는지
- 디버깅 및 동적 분석을 탐지·차단하는 실질적인 방법

---

## ⚠️ Disclaimer

본 레포지토리에 포함된 코드는 **교육 및 학습 목적**으로만 작성되었습니다.

악의적인 사용이나 실제 환경에서의 공격 행위에 대한 책임은 사용자에게 있습니다.

---

## 👩‍💻 Author

- **백다현**
- System Security (2025-2)
