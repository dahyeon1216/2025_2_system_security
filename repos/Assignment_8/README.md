# 🧩 Assignment #8 — Launcher & Client Debug Control

본 프로젝트는 **Launcher–Client 구조**를 통해

중요한 기능을 수행하는 `Client.exe`를 **외부 디버거로부터 보호**하는 메커니즘을 구현한 것이다.

Launcher는 **선점 디버거(preemptive debugger)** 역할을 수행하며,

Client는 **Launcher에 의해 디버깅 중일 때만 정상 실행**되도록 설계되었다.

---

## 🎯 목표 요약

- Client.exe
    - 표준 입력을 받아 echo 출력하는 핵심 기능 구현
    - **부모 프로세스가 Launcher.exe일 때만 실행**
    - **디버깅 중일 때만 실행**
- Launcher.exe
    - **자기 자신이 디버깅 당하지 않도록 탐지**
    - Client를 실행하고 **DebugActiveProcess로 선점 디버깅**
    - Client 실행 중 발생하는 모든 디버그 이벤트를 처리

---

## 🧠 전체 구조

```
Explorer.exe
 └─ Launcher.exe   (디버거 역할,Client 보호)
     └─Client.exe (중요 기능 수행)
```

---

## 🔷 Client.exe

### 1️⃣ 핵심 기능 (Echo Loop)

- 표준 입력을 받아 그대로 출력
- `"exit"` 입력 시 정상 종료

```
scanf / fgets → printf → 반복
```

---

### 2️⃣ 디버깅 상태 필수 조건

- Client는 **반드시 디버깅 중이어야만 실행**
- 디버깅 상태가 아닐 경우 즉시 종료

**구현 방식**

- `CheckRemoteDebuggerPresent(GetCurrentProcess())`

```cpp
if (!is_being_debugged()) {printf("[Client] Error: This program must be run under a debugger.\n");return1;
}
```

✔️ Ctrl+F5 실행 → 실패

✔️ F5 실행 → 성공

---

### 3️⃣ 부모 프로세스 검증

- Client의 부모 프로세스가 **Launcher.exe** 인지 확인
- 아니라면 즉시 종료

**구현 방식**

- `CreateToolhelp32Snapshot`
- `PROCESSENTRY32.th32ParentProcessID`
- 부모 PID → 프로세스 이름 비교

```cpp
if (!is_parent_launcher()) {printf("[Client] Error: Parent process must be Launcher.exe\n");return1;
}
```

✔️ Explorer / devenv.exe → 실패

✔️ Launcher.exe → 통과

---

## 🔷 Launcher.exe

### 1️⃣ 자기 자신 디버깅 탐지 (Assignment 7 재활용)

- **PEB → BeingDebugged** 직접 참조
- 워치독 스레드가 주기적으로 검사
- 디버깅 감지 시 즉시 종료

```cpp
if (CheckDebuggerByPEB()) {
    __fastfail(1);
}
```

✔️ F5 실행 → 즉시 종료

✔️ Ctrl+F5 실행 → 정상

---

### 2️⃣ Client 프로세스 실행

- `CreateProcessA("Client.exe")`
- Client PID 획득

```cpp
CreateProcessA("Client.exe", ...);
```

✔️ Client는 항상 Launcher의 자식 프로세스로 실행됨

---

### 3️⃣ Client 선점 디버깅 (핵심)

Launcher는 Client에 **선제적으로 디버거로 attach**한다.

```cpp
DebugActiveProcess(clientPid);
```

이로 인해:

- x64dbg
- OllyDbg
- WinDbg
- Visual Studio

👉 **어떤 외부 디버거도 Client에 추가로 attach 불가**

---

### 4️⃣ 디버그 이벤트 루프

- `WaitForDebugEvent()`
- 모든 이벤트를 `DBG_CONTINUE`로 처리
- Client 종료 이벤트 시 루프 탈출

```cpp
while (running) {WaitForDebugEvent(&dbgEvent, INFINITE);ContinueDebugEvent(..., DBG_CONTINUE);
}
```

---

## 🧪 최종 테스트 결과

### ✅ Case 1. Client 단독 실행

| 실행 방식 | 결과 |
| --- | --- |
| Ctrl+F5 | ❌ 부모 아님 + 디버깅 아님 |
| F5 | ❌ 부모가 Launcher 아님 |

---

### ✅ Case 2. Launcher 디버깅 시도

| 실행 방식 | 결과 |
| --- | --- |
| F5 | ❌ Watchdog → fastfail |
| Ctrl+F5 | ✅ 정상 실행 |

---

### ✅ Case 3. Launcher → Client 보호 성공

| 항목 | 결과 |
| --- | --- |
| Client 실행 | 성공 |
| Echo 기능 | 정상 |
| 외부 디버거 attach | ❌ 불가 |
| 종료 | 정상 종료 |

---

## 📌 핵심 포인트 정리

- Client는 **Launcher + 디버깅 상태**가 아니면 실행 불가
- Launcher는 **스스로 디버깅을 차단**
- Launcher가 Client를 **선점 디버깅**하여 외부 디버거 차단
- Debug API를 활용한 **실제 디버거 구조 구현**
- Access Violation / 비정상 종료 없이 **정상 종료(return 0)** 보장

---

## 🏁 결론

본 과제는 단순한 디버깅 탐지를 넘어,

**“누가 디버깅을 하고 있는가”** 를 제어하는 구조를 구현하였다.

Launcher가 Client를 디버깅함으로써

Client는 오직 **신뢰된 디버거(Launcher)** 에 의해서만 실행되며,

이는 실전 환경에서 **Anti-Debugging + Debugger Authentication 구조**의 기초가 된다.

--

## 📝Full Notes
https://delicate-dish-b60.notion.site/8-2b2a4c0c4272802b99d6d6d829b892df?source=copy_link
