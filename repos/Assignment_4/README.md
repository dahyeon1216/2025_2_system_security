# 🛡 System Security – PE Analysis & Patching

본 저장소는 **시스템 보안 수업**에서 수행한

PE(Portable Executable) 파일 분석 및 크래킹 실습 과제를 정리한 것이다.

과제는 크게 다음 두 부분으로 구성된다.

- **Q1. PE 파일 패치 (Static Binary Patching)**
- **Q2. x86 PE 파서 제작 (PE Header / Section / IAT 분석)**

---

## Q1. PE 파일 패치 (Static Patching)

### 🔍 과제 개요

`abex_crackme1.exe` 파일은 내부 조건 분기를 통해 정상/비정상 실행 경로를 결정한다.

본 과제에서는 **조건 분기 명령어(JE)를 JNE로 변경**하여 프로그램의 실행 흐름을 우회한다.

- 메모리 상에서 디버거로 수정한 코드는 **프로그램 재실행 시 원상복구**됨
- 따라서 **PE 파일 자체를 Hex Editor(HxD)** 로 직접 패치해야 함
- 이를 위해 **RVA → RAW 주소 변환**이 필요함

---

### ✏️ 패치 대상 명령어

- 메모리 주소 (VA): `0x401026`
- RVA: `0x1026`
- 기존 명령어: `JE 40103D` (`74 15`)
- 변경 명령어: `JNE 40103D` (`75 15`)

---

### 📐 RVA → RAW 주소 계산

```
RAW = (RVA - VirtualAddress) + PointerToRawData
    = (0x1026 - 0x1000) + 0x0600
    = 0x0026 + 0x0600
    = 0x0626
```

- 해당 코드는 **CODE 섹션**
    - `VirtualAddress = 0x1000`
    - `PointerToRawData = 0x600`

---

### 🛠 패치 과정

1. **HxD로 `abex_crackme1.exe` 파일 열기**
2. RAW 주소 `0x0626`으로 이동
3. 기존 Opcode 확인
    
    ```
    74 15   ; JE
    ```
    
4. Opcode 수정
    
    ```
    75 15   ; JNE
    ```
    
5. 파일 저장 후 프로그램 실행

---

### ✅ 패치 결과

- 조건 분기가 반대로 동작
- 인증/검증 루틴 우회 성공
- 프로그램 정상 실행 확인

👉 **Static Binary Patching을 통해 프로그램의 실행 흐름을 영구적으로 변경함**

---

## Q2. x86 PE 파서 제작

### 🔍 과제 개요

첨부된 `PE_parser.cpp`를 기반으로 **콘솔 기반 x86 PE 파서**를 제작하였다.

제작한 파서는 다음 정보를 파싱한다.

- DOS Header / NT Header
- Optional Header 주요 필드
- Section Table
- Import Address Table (IAT)
- IAT 내부 함수 이름

검증 대상 PE 파일:

- `abex_crackme1.exe`
- 그 외 x86 PE 파일 1종 이상

---

## 📦 주요 기능 요약

### 1️⃣ PE 기본 정보 파싱

- File Signature (`MZ`)
- NT Header Offset
- Entry Point
- ImageBase
- Code / Data 영역 정보

---

### 2️⃣ Section Table 파싱

각 섹션에 대해 다음 정보 출력:

- Section Name
- VirtualAddress
- VirtualSize
- PointerToRawData
- SizeOfRawData

출력 예시:

```
1번째 section: CODE
VirtualAddress: 0x1000
PointerToRawData: 0x600
```

---

### 3️⃣ Import Address Table (IAT) 파싱

- Import Directory 위치 탐색
- **RVA → RAW 변환을 직접 구현**
- Import Descriptor 순회
- DLL 이름 출력
- 각 DLL에 포함된 함수 이름 파싱

---

### 📄 실행 결과 예시
<img width="232" height="90" alt="image" src="https://github.com/user-attachments/assets/b535363d-6904-4035-9365-ee3d7f68cbb6" />


---

## 🧠 구현 포인트

- `CreateFileW` + `CreateFileMapping` + `MapViewOfFile` 기반 **Memory-mapped I/O**
- `IMAGE_DOS_HEADER`, `IMAGE_NT_HEADERS`, `IMAGE_SECTION_HEADER` 직접 활용
- **IMAGE_FIRST_SECTION 매크로 없이 수동 계산**
- IAT / Thunk / IMAGE_IMPORT_BY_NAME 구조체 직접 파싱
- **Ordinal Import / Name Import 구분 처리**
- 모든 RVA → RAW 변환을 직접 구현하여 PE 구조 이해도 강화

---

## 📌 정리

본 과제를 통해 다음을 직접 구현하고 검증하였다.

- PE 파일 구조에 대한 이해
- RVA / VA / RAW 주소 변환 원리
- Static Binary Patching 기법
- Import Table 기반 API 분석
- 실전 PE 파싱 로직 구현

👉 단순 사용이 아닌 **“PE 내부 구조를 직접 해석하고 조작하는 경험”**에 초점을 둔 과제이다.

---
## 📝 Full Notes
https://delicate-dish-b60.notion.site/4-27da4c0c42728058939efc4c8161f07b?source=copy_link
