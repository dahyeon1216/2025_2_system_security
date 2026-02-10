#include <Windows.h>
#include <stdio.h>

int main(void)
{
    wchar_t path_pefile[] = L"C:\\Users\\백다현\\Desktop\\abex_crackme1.exe\\abex_crackme1.exe";

    HANDLE hFile = NULL, hFileMap = NULL;
    LPBYTE lpFileBase = NULL;
    DWORD dwSize = 0;

    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNtHeader = NULL;

    hFile = CreateFileW(path_pefile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("CreateFileW() failed. Error code=%lu\n", GetLastError());
        return GetLastError();
    }
    dwSize = GetFileSize(hFile, 0);
    printf("File size=%lu bytes\n\n", dwSize);


    hFileMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    // lpFileBase 포인터는 OS에 의해 메모리에 로드된 PE 파일의 가장 첫 바이트를 가리킴.
    //lpFileBase가 NULL이라면 MapViewOfFile() 함수가 실패했다는 의미이다. 여기서는 예외 처리를 생략한다.
    lpFileBase = (LPBYTE)MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, dwSize);

    printf("File signature=%c%c\n", lpFileBase[0], lpFileBase[1]);

    pDosHeader = (PIMAGE_DOS_HEADER)lpFileBase;
    printf("Offset to the NT header=%#x\n\n", pDosHeader->e_lfanew);

    pNtHeader = (PIMAGE_NT_HEADERS)(lpFileBase + pDosHeader->e_lfanew);
    printf("OptionalHeader.BaseOfCode=%#x\n", pNtHeader->OptionalHeader.BaseOfCode);
    printf("OptionalHeader.SizeOfCode=%#x\n", pNtHeader->OptionalHeader.SizeOfCode);
    printf("OptionalHeader.AddressOfEntryPoint=%#x\n", pNtHeader->OptionalHeader.AddressOfEntryPoint);
    printf("OptionalHeader.BaseOfData=%#x\n", pNtHeader->OptionalHeader.BaseOfData);
    printf("OptionalHeader.ImageBase=%#x\n\n", pNtHeader->OptionalHeader.ImageBase);

    printf("### SECTION INFORMATION ###\n");
    /*TODO: 여기서부터 코딩 시작*/
    // ---------------------------
    // [1] 섹션 테이블 출력
    // ---------------------------
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    WORD numberOfSections = pFileHeader->NumberOfSections;

    // IMAGE_FIRST_SECTION(pNtHeader) 대신 수동 계산
    PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)(
        (LPBYTE)&pNtHeader->OptionalHeader + pNtHeader->FileHeader.SizeOfOptionalHeader
        );

    for (WORD i = 0; i < numberOfSections; ++i) {
        char name[9] = { 0 };
        memcpy(name, pSection[i].Name, 8);

        printf("%d번째 section: %s\n", i + 1, name);
        printf("PointerToRawData: %#x\n", pSection[i].PointerToRawData);
        printf("SizeOfRawData: %#x\n", pSection[i].SizeOfRawData);
        printf("VirtualAddress: %#x\n", pSection[i].VirtualAddress);
        printf("VirtualSize: %#x\n\n", pSection[i].Misc.VirtualSize);
    }

    // ---------------------------
    // [2] IAT(Import Directory) 파싱
    // ---------------------------
    printf("### IAT ###\n");

    IMAGE_DATA_DIRECTORY importDir =
        pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]; // index 1

    if (importDir.VirtualAddress == 0 || importDir.Size == 0) {
        printf("No Import Directory found.\n");
    }
    else {
        // (a) IAT가 저장된 섹션 찾기 + RVA→RAW 계산(인라인)
        int importRaw = -1;
        char containingSection[9] = "Unknown";
        for (WORD i = 0; i < numberOfSections; ++i) {
            DWORD va = pSection[i].VirtualAddress;
            DWORD vsize = pSection[i].Misc.VirtualSize ? pSection[i].Misc.VirtualSize : pSection[i].SizeOfRawData;
            if (importDir.VirtualAddress >= va && importDir.VirtualAddress < va + vsize) {
                importRaw = (int)(pSection[i].PointerToRawData + (importDir.VirtualAddress - va));
                memset(containingSection, 0, sizeof(containingSection));
                memcpy(containingSection, pSection[i].Name, 8);
                break;
            }
        }
        // 헤더 내부면 RAW == RVA
        if (importRaw < 0 && importDir.VirtualAddress < pNtHeader->OptionalHeader.SizeOfHeaders) {
            importRaw = (int)importDir.VirtualAddress;
            strcpy_s(containingSection, sizeof(containingSection), "Headers");
        }

        printf("IAT가 저장된 섹션: %s\n", containingSection);
        if (importRaw >= 0)
            printf("RVA to RAW: %#x->0x%x \n", importDir.VirtualAddress, importRaw);
        else
            printf("RVA to RAW 변환 실패 (IAT 위치 계산 불가)\n");

        if (importRaw >= 0 && (DWORD)importRaw < dwSize) {
            PIMAGE_IMPORT_DESCRIPTOR pDesc = (PIMAGE_IMPORT_DESCRIPTOR)(lpFileBase + importRaw);

            // (b) ImportDescriptor 배열 순회 (모두 0이면 종료)
            for (int idx = 0; ; ++idx, ++pDesc) {
                SIZE_T curOff = (SIZE_T)((LPBYTE)pDesc - lpFileBase);
                if (curOff + sizeof(IMAGE_IMPORT_DESCRIPTOR) > dwSize) break;

                if (pDesc->OriginalFirstThunk == 0 &&
                    pDesc->FirstThunk == 0 &&
                    pDesc->Name == 0 &&
                    pDesc->TimeDateStamp == 0 &&
                    pDesc->ForwarderChain == 0) {
                    break;
                }

                // DLL 이름: Name(RVA) → RAW
                int nameRaw = -1;
                if (pDesc->Name < pNtHeader->OptionalHeader.SizeOfHeaders) {
                    nameRaw = (int)pDesc->Name;
                }
                else {
                    for (WORD i = 0; i < numberOfSections; ++i) {
                        DWORD va = pSection[i].VirtualAddress;
                        DWORD vsize = pSection[i].Misc.VirtualSize ? pSection[i].Misc.VirtualSize : pSection[i].SizeOfRawData;
                        if (pDesc->Name >= va && pDesc->Name < va + vsize) {
                            nameRaw = (int)(pSection[i].PointerToRawData + (pDesc->Name - va));
                            break;
                        }
                    }
                }

                char dllName[512] = { 0 };
                if (nameRaw >= 0 && (DWORD)nameRaw < dwSize)
                    strncpy_s(dllName, sizeof(dllName), (const char*)(lpFileBase + nameRaw), _TRUNCATE);
                else
                    strcpy_s(dllName, sizeof(dllName), "<invalid>");
                printf("ImportDescriptor[%d].Name=%s\n", idx, dllName);

                // (c) Thunk 테이블: OriginalFirstThunk 우선, 없으면 FirstThunk
                DWORD thunkRVA = pDesc->OriginalFirstThunk ? pDesc->OriginalFirstThunk : pDesc->FirstThunk;

                // thunkRVA → RAW
                int thunkRaw = -1;
                if (thunkRVA < pNtHeader->OptionalHeader.SizeOfHeaders) {
                    thunkRaw = (int)thunkRVA;
                }
                else {
                    for (WORD i = 0; i < numberOfSections; ++i) {
                        DWORD va = pSection[i].VirtualAddress;
                        DWORD vsize = pSection[i].Misc.VirtualSize ? pSection[i].Misc.VirtualSize : pSection[i].SizeOfRawData;
                        if (thunkRVA >= va && thunkRVA < va + vsize) {
                            thunkRaw = (int)(pSection[i].PointerToRawData + (thunkRVA - va));
                            break;
                        }
                    }
                }

                if (thunkRaw < 0 || (DWORD)thunkRaw >= dwSize) {
                    printf("  Thunk RVA -> RAW 변환 실패\n");
                    continue;
                }

                // (d) 개별 thunk 순회 (32-bit: 4바이트, 0이면 종료)
                SIZE_T off = (SIZE_T)thunkRaw;
                while (off + 4 <= dwSize) {
                    DWORD entry = 0;
                    memcpy(&entry, lpFileBase + off, 4);
                    if (entry == 0) break;

                    if (entry & 0x80000000u) {
                        WORD ord = (WORD)(entry & 0xFFFF);
                        printf("- ordinal: %u\n", ord);
                    }
                    else {
                        // entry는 IMAGE_IMPORT_BY_NAME 구조체의 RVA
                        int ibnRaw = -1;
                        if (entry < pNtHeader->OptionalHeader.SizeOfHeaders) {
                            ibnRaw = (int)entry;
                        }
                        else {
                            for (WORD i = 0; i < numberOfSections; ++i) {
                                DWORD va = pSection[i].VirtualAddress;
                                DWORD vsize = pSection[i].Misc.VirtualSize ? pSection[i].Misc.VirtualSize : pSection[i].SizeOfRawData;
                                if (entry >= va && entry < va + vsize) {
                                    ibnRaw = (int)(pSection[i].PointerToRawData + (entry - va));
                                    break;
                                }
                            }
                        }

                        if (ibnRaw >= 0 && (DWORD)(ibnRaw + 2) < dwSize) {
                            // [2바이트 hint] 다음이 함수명(ASCII, null-terminated)
                            const char* fname = (const char*)(lpFileBase + ibnRaw + 2);
                            printf("- function name (RVA=%#x), %s\n", entry, fname);
                        }
                        else {
                            printf("- function name (RVA=%#x), <cannot read>\n", entry);
                        }
                    }
                    off += 4;
                }
            }
        }
    }



    /*TODO: 여기까지 코딩*/

    /*Windows로부터 할당받은 리소스를 역순으로 반환*/
    UnmapViewOfFile(lpFileBase);
    CloseHandle(hFileMap);
    CloseHandle(hFile);
    /*main() 함수가 끝까지 실행되었음을 알리기 위해 0을 반환*/
    return 0;
}