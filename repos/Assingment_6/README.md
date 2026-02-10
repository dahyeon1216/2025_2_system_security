# 🧷 IAT Hooking & Remote Memory Verification

본 문서는 시스템 보안 과제에서 수행한 **IAT 패치 기반 API 후킹(WriteFile)** 과 **원격 프로세스 메모리 검증 방식**을 정리한 것이다.

- **Q1. IAT 조작을 통한 kernel32!WriteFile 후킹 DLL + 인젝터**
- **Q2. WriteProcessMemory 검증을 printf로 할 수 없는 이유와 개선 코드**

---

## Q1. IAT 조작으로 `WriteFile()` 호출 흐름 가로채기

### 📌 목표

- 대상 프로세스의 **Import Address Table(IAT)** 을 조작하여
    
    `kernel32!WriteFile()` 호출을 **HookedWriteFile()로 우회**시키는 DLL을 구현한다.
    
- 이후 인젝터로 DLL을 주입하여 다음 대상에서 공격 성공 여부를 확인한다.
    - (1) notepad++
    - (2) 파일 입출력을 수행하는 x86 프로그램(테스트용)

---

### ✅ 구성 요소

### 1) Target 프로그램: `test_write.cpp`

- `C:\temp\test_out.txt` 파일을 생성하고 `"hello\n"`를 `WriteFile()`로 기록한다.
- 마지막에 `getchar()`로 프로세스를 유지하여 인젝터가 붙을 수 있게 구성한다.

**기대 동작(기본 상태)**

- 실행 시 파일이 생성되고 `"hello\n"`가 기록됨

---

### 2) Hook DLL: `hook_writefile_dll.c`

핵심 동작 흐름은 다음과 같다.

1. `DllMain(PROCESS_ATTACH)`에서 별도 스레드 실행
2. `GetModuleHandle(NULL)`로 **호스트 EXE 베이스 주소 확보**
3. PE Import Directory 순회
4. `KERNEL32.dll`의 `WriteFile` Import 항목 탐색
5. IAT 엔트리를 `HookedWriteFile`로 덮어쓰기
    - `VirtualProtect`로 IAT 쓰기 가능하도록 권한 변경
    - 원본 함수 포인터(`g_original_WriteFile`) 저장

**Hook 함수 동작**

- `HookedWriteFile()`에서 `MessageBoxA("WriteFile hooked!")`를 띄운 뒤
- 원본 `WriteFile`로 실제 동작을 이어감 (기능 파괴 없이 “가로채기”만 수행)

---

### 3) Injector: `injector.cpp`

- `CreateToolhelp32Snapshot`으로 PID 검색 (프로세스명 또는 pid 입력)
- `VirtualAllocEx` + `WriteProcessMemory`로 원격 프로세스 메모리에 DLL 경로 기록
- `CreateRemoteThread(LoadLibraryW)`로 DLL 로드
- WOW64 여부 체크로 **32bit 인젝터 → 64bit 대상** 인 경우 차단

---

### 🧪 수행 과정 요약 (체크리스트)

1. **대상 프로그램 실행 전**
- `WriteFile` 호출 지점/동작 존재 확인
1. **`test_write.exe` 실행**
- `C:\temp\test_out.txt` 생성 및 내용 기록 확인
1. **인젝터 실행**
- `injector.exe <pid|procname> <dll full path>`
- “DLL injected” 메시지 출력 확인
1. **후킹 성공 확인**
- `WriteFile` 호출 시점에 **MessageBox 팝업 발생**
- 동시에 원본 WriteFile이 실행되어 파일 기록도 정상 수행됨

👉 결론: **IAT 엔트리 패치로 API 호출 흐름이 Hook 함수로 변경됨을 확인**

---

## Q2. `printf("%s", lpAddr)`로 원격 메모리 복사 성공을 검증할 수 없는 이유

### 📌 질문 요지

`VirtualAllocEx` + `WriteProcessMemory`로 **원격 프로세스**에 문자열을 복사한 뒤

`printf("%s\n", lpAddr);`로 복사 성공 여부를 확인할 수 있는가?

(단, OpenProcess / VirtualAllocEx / WriteProcessMemory는 성공한다고 가정)

---

### ✅ 정답

**불가능하다.**

`printf("%s", lpAddr)`는 원격 프로세스 메모리를 읽지 못한다.

---

### ❗ 이유 (핵심 논리)

Windows는 **프로세스마다 독립된 가상 주소 공간**을 가진다.

- `lpAddr`는 `VirtualAllocEx`로 할당된 **원격 프로세스(B)의 주소**
- `printf("%s", lpAddr)`는 **현재 프로세스(A)** 에서
    
    `lpAddr`를 **역참조**하여 `'\0'`을 만날 때까지 읽으려 한다.
    

즉,

- A의 주소 공간에서 `lpAddr`가 매핑되지 않으면 → **Access Violation(크래시)**
- 우연히 매핑되어 있어도 → **엉뚱한 데이터 출력 / 과다 읽기 위험**

> `%s`는 “주소값을 출력”하는 게 아니라,
> 
> 
> “그 주소를 따라가서 문자열을 읽어 출력”하는 동작이다.
> 

---

### ✅ 올바른 검증 방법

원격 메모리 내용을 확인하려면:

1. `ReadProcessMemory()`로 원격 메모리를 **로컬 버퍼**로 가져온다
2. 그 로컬 버퍼를 `printf("%s")`로 출력한다

---

### 🔧 개선 코드 예시 (핵심만)

```c
char verify[256] = {0};
SIZE_T bytesRead =0;

ReadProcessMemory(hProcess, lpAddr, verify,strlen(buf) +1, &bytesRead);printf("Copied data from remote process: %s\n", verify);
```

---

### 요약 표

| 방법 | 가능 여부 | 이유 |
| --- | --- | --- |
| `printf("%s", lpAddr)` | ❌ | 원격 프로세스 주소를 현재 프로세스에서 역참조 시도 → 접근 위반/오동작 |
| `ReadProcessMemory()` 후 출력 | ✅ | OS가 원격 프로세스 메모리를 읽어 로컬 버퍼로 복사해줌 |
