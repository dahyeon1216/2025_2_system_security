# 🔗 System Security – Explicit & Dynamic Linking Practice

본 문서는 **시스템 보안 수업**에서 수행한

**명시적 링킹(Explicit Linking)** 및 **동적 DLL 교체 실습** 과제를 정리한 것이다.

과제는 다음 두 개의 실습으로 구성된다.

- **Q1. MessageBoxA 명시적 링킹**
- **Q2. DLL 교체에 따른 실행 결과 변화 확인**

---

## Q1. MessageBoxA() 명시적 링킹

### 📌 과제 개요

`MessageBoxA()` 함수를 **명시적 링킹(Explicit Linking)** 방식으로 호출하는 프로그램을 작성한다.

프로그램 실행 시 메시지 박스에 **본인의 학번**이 출력되어야 한다.

또한, 명시적 링킹의 특성상 **Import Address Table(IAT)에 MessageBoxA 함수가 등록되지 않음**을

PE 분석기를 통해 검증한다.

---

### 1️⃣ MessageBoxA() 함수의 위치

- **`USER32.dll`**
- Win32 GUI 관련 API들이 포함된 Windows 시스템 DLL

---

### 2️⃣ MessageBoxA() 함수 프로토타입

```c
int WINAPIMessageBoxA(
    HWND   hWnd,
    LPCSTR lpText,
    LPCSTR lpCaption,
    UINT   uType
);
```

- ANSI 문자열을 사용하는 MessageBox 함수
- 일반적인 암시적 링킹에서는 링커에 의해 IAT에 등록됨
- **명시적 링킹 시에는 직접 LoadLibrary / GetProcAddress 사용**

---

### 3️⃣ 명시적 링킹 방식 구현 코드

```cpp
// explicit_messagebox.c#define WIN32_LEAN_AND_MEAN#include<windows.h>#include<stdio.h>typedefint(WINAPI *PFN_MessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);intmain(void)
{constchar* studentId ="학번: 2014865";

    HMODULE hUser32 =LoadLibraryA("user32.dll");if (!hUser32) {printf("LoadLibraryA 실패. GetLastError()=%lu\n",GetLastError());return1;
    }

    PFN_MessageBoxA pMessageBoxA =
        (PFN_MessageBoxA)GetProcAddress(hUser32,"MessageBoxA");if (!pMessageBoxA) {printf("GetProcAddress 실패. GetLastError()=%lu\n",GetLastError());FreeLibrary(hUser32);return1;
    }pMessageBoxA(NULL,
        studentId,"Explicit Linking Demo",
        MB_OK | MB_ICONINFORMATION
    );FreeLibrary(hUser32);return0;
}
```

---

### 4️⃣ 실행 결과

- 메시지 박스에 **학번이 정상적으로 출력됨**
- 함수 호출 성공 확인

---

### 5️⃣ IAT 분석 결과 검증

PE 파서 / PEView / 기타 PE 분석 도구로 확인한 결과:

- **Import Table에 `USER32.dll` 존재하지 않음**
- **MessageBoxA 심볼 또한 IAT에 등록되지 않음**

이는 명시적 링킹의 특징으로,

> 암시적 링킹에서만 Import Address Table에 DLL 및 함수 심볼이 등록되기 때문
> 

👉 과제 요구사항 충족 확인

---

## Q2. DLL 교체에 따른 실행 결과 변화 확인

### 📌 과제 개요

동일한 함수 이름 `add()`를 가진 **두 개의 DLL**을 제작하고,

EXE가 이를 **동적으로 로드**하도록 구현한다.

DLL을 교체함에 따라 **동일한 EXE의 실행 결과가 달라지는지**를 검증한다.

---

### 1️⃣ AddPlusDll (덧셈 DLL)

```cpp
// AddPlusDll.cpp#include"pch.h"extern"C" __declspec(dllexport)intadd(int a,int b) {return a + b;
}
```

---

### 2️⃣ AddMinusDll (뺄셈 DLL)

```cpp
// AddMinusDll.cpp#include"pch.h"extern"C" __declspec(dllexport)intadd(int a,int b) {return a - b;
}
```

---

### 3️⃣ 동적 링킹 EXE 프로그램

```cpp
// main.cpp#include<windows.h>#include<cstdio>typedefint(__cdecl* add_fn)(int,int);intmain(int argc,char* argv[]) {constchar* dllName = (argc >1) ? argv[1] :"add.dll";

    HMODULE h =LoadLibraryA(dllName);if (!h) {printf("LoadLibrary failed. GetLastError=%lu\n",GetLastError());return1;
    }

    add_fn add = (add_fn)GetProcAddress(h,"add");if (!add) {printf("GetProcAddress failed. GetLastError=%lu\n",GetLastError());FreeLibrary(h);return1;
    }int result =add(10,3);printf("Using %s -> add(10,3) = %d\n", dllName, result);FreeLibrary(h);getchar();return0;
}
```

---

### 4️⃣ 실행 결과 비교

### 4-1. AddPlusDll 사용

- `AddPlusDll.dll` → `add.dll` 로 이름 변경
- EXE와 동일한 디렉터리에 배치
- 실행 결과:

```
add(10, 3) = 13
```

---

### 4-2. AddMinusDll 사용

- `AddMinusDll.dll` → `add.dll` 로 이름 변경
- 동일 EXE 실행
- 실행 결과:

```
add(10, 3) = 7
```

---

## 🧠 정리 및 학습 포인트

- **명시적 링킹**
    - Import Table에 함수 정보가 남지 않음
    - 런타임에 DLL 및 함수 주소를 직접 해석
    - IAT 분석을 통한 행위 추적 회피 가능성 존재
- **동적 DLL 교체**
    - 동일한 EXE라도 외부 DLL에 따라 동작 변경 가능
    - 플러그인 구조, 악성 DLL 하이재킹 이해에 중요한 개념

👉 본 과제는 **Windows 로더, 링킹 방식, IAT 구조 이해**를 목표로 수행되었다.

# 🔗 System Security – Explicit & Dynamic Linking Practice

본 문서는 **시스템 보안 수업**에서 수행한

**명시적 링킹(Explicit Linking)** 및 **동적 DLL 교체 실습** 과제를 정리한 것이다.

과제는 다음 두 개의 실습으로 구성된다.

- **Q1. MessageBoxA 명시적 링킹**
- **Q2. DLL 교체에 따른 실행 결과 변화 확인**

---

## Q1. MessageBoxA() 명시적 링킹

### 📌 과제 개요

`MessageBoxA()` 함수를 **명시적 링킹(Explicit Linking)** 방식으로 호출하는 프로그램을 작성한다.

프로그램 실행 시 메시지 박스에 **본인의 학번**이 출력되어야 한다.

또한, 명시적 링킹의 특성상 **Import Address Table(IAT)에 MessageBoxA 함수가 등록되지 않음**을

PE 분석기를 통해 검증한다.

---

### 1️⃣ MessageBoxA() 함수의 위치

- **`USER32.dll`**
- Win32 GUI 관련 API들이 포함된 Windows 시스템 DLL

---

### 2️⃣ MessageBoxA() 함수 프로토타입

```c
int WINAPIMessageBoxA(
    HWND   hWnd,
    LPCSTR lpText,
    LPCSTR lpCaption,
    UINT   uType
);
```

- ANSI 문자열을 사용하는 MessageBox 함수
- 일반적인 암시적 링킹에서는 링커에 의해 IAT에 등록됨
- **명시적 링킹 시에는 직접 LoadLibrary / GetProcAddress 사용**

---

### 3️⃣ 명시적 링킹 방식 구현 코드

```cpp
// explicit_messagebox.c#define WIN32_LEAN_AND_MEAN#include<windows.h>#include<stdio.h>typedefint(WINAPI *PFN_MessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);intmain(void)
{constchar* studentId ="학번: 2014865";

    HMODULE hUser32 =LoadLibraryA("user32.dll");if (!hUser32) {printf("LoadLibraryA 실패. GetLastError()=%lu\n",GetLastError());return1;
    }

    PFN_MessageBoxA pMessageBoxA =
        (PFN_MessageBoxA)GetProcAddress(hUser32,"MessageBoxA");if (!pMessageBoxA) {printf("GetProcAddress 실패. GetLastError()=%lu\n",GetLastError());FreeLibrary(hUser32);return1;
    }pMessageBoxA(NULL,
        studentId,"Explicit Linking Demo",
        MB_OK | MB_ICONINFORMATION
    );FreeLibrary(hUser32);return0;
}
```

---

### 4️⃣ 실행 결과

- 메시지 박스에 **학번이 정상적으로 출력됨**
- 함수 호출 성공 확인

---

### 5️⃣ IAT 분석 결과 검증

PE 파서 / PEView / 기타 PE 분석 도구로 확인한 결과:

- **Import Table에 `USER32.dll` 존재하지 않음**
- **MessageBoxA 심볼 또한 IAT에 등록되지 않음**

이는 명시적 링킹의 특징으로,

> 암시적 링킹에서만 Import Address Table에 DLL 및 함수 심볼이 등록되기 때문
> 

👉 과제 요구사항 충족 확인

---

## Q2. DLL 교체에 따른 실행 결과 변화 확인

### 📌 과제 개요

동일한 함수 이름 `add()`를 가진 **두 개의 DLL**을 제작하고,

EXE가 이를 **동적으로 로드**하도록 구현한다.

DLL을 교체함에 따라 **동일한 EXE의 실행 결과가 달라지는지**를 검증한다.

---

### 1️⃣ AddPlusDll (덧셈 DLL)

```cpp
// AddPlusDll.cpp#include"pch.h"extern"C" __declspec(dllexport)intadd(int a,int b) {return a + b;
}
```

---

### 2️⃣ AddMinusDll (뺄셈 DLL)

```cpp
// AddMinusDll.cpp#include"pch.h"extern"C" __declspec(dllexport)intadd(int a,int b) {return a - b;
}
```

---

### 3️⃣ 동적 링킹 EXE 프로그램

```cpp
// main.cpp#include<windows.h>#include<cstdio>typedefint(__cdecl* add_fn)(int,int);intmain(int argc,char* argv[]) {constchar* dllName = (argc >1) ? argv[1] :"add.dll";

    HMODULE h =LoadLibraryA(dllName);if (!h) {printf("LoadLibrary failed. GetLastError=%lu\n",GetLastError());return1;
    }

    add_fn add = (add_fn)GetProcAddress(h,"add");if (!add) {printf("GetProcAddress failed. GetLastError=%lu\n",GetLastError());FreeLibrary(h);return1;
    }int result =add(10,3);printf("Using %s -> add(10,3) = %d\n", dllName, result);FreeLibrary(h);getchar();return0;
}
```

---

### 4️⃣ 실행 결과 비교

### 4-1. AddPlusDll 사용

- `AddPlusDll.dll` → `add.dll` 로 이름 변경
- EXE와 동일한 디렉터리에 배치
- 실행 결과:

```
add(10, 3) = 13
```

---

### 4-2. AddMinusDll 사용

- `AddMinusDll.dll` → `add.dll` 로 이름 변경
- 동일 EXE 실행
- 실행 결과:

```
add(10, 3) = 7
```

---

## 🧠 정리 및 학습 포인트

- **명시적 링킹**
    - Import Table에 함수 정보가 남지 않음
    - 런타임에 DLL 및 함수 주소를 직접 해석
    - IAT 분석을 통한 행위 추적 회피 가능성 존재
- **동적 DLL 교체**
    - 동일한 EXE라도 외부 DLL에 따라 동작 변경 가능
    - 플러그인 구조, 악성 DLL 하이재킹 이해에 중요한 개념

👉 본 과제는 **Windows 로더, 링킹 방식, IAT 구조 이해**를 목표로 수행되었다.

---
## 📝Full Notes
https://delicate-dish-b60.notion.site/5-289a4c0c4272800fbb44fb00f285b5c7?source=copy_link
