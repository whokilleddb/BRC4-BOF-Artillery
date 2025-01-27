#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#include "badger_exports.h"

DECLSPEC_IMPORT WINBOOL WINAPI Kernel32$Module32First(HANDLE hSnapshot,LPMODULEENTRY32 lpme);
DECLSPEC_IMPORT WINBOOL WINAPI Kernel32$Module32Next(HANDLE hSnapshot,LPMODULEENTRY32 lpme);
DECLSPEC_IMPORT WINBOOL WINAPI Kernel32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT HANDLE WINAPI Kernel32$CreateToolhelp32Snapshot(DWORD dwFlags,DWORD th32ProcessID);
DECLSPEC_IMPORT DWORD Kernel32$GetLastError();

DECLSPEC_IMPORT WINBOOL WINAPI Version$GetFileVersionInfoA(LPCSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData);
DECLSPEC_IMPORT DWORD WINAPI Version$GetFileVersionInfoSizeA(LPCSTR lptstrFilenamea ,LPDWORD lpdwHandle);
DECLSPEC_IMPORT WINBOOL WINAPI Version$VerQueryValueA(LPCVOID pBlock, LPCSTR lpSubBlock, LPVOID *lplpBuffer, PUINT puLen);

void coffee(char* argv[], int argc, WCHAR** dispatch) {
    if (argc < 1) {
        BadgerDispatch(dispatch, "[!] Usage: proc_version.c <pid>\n[!] Eg.: proc_version.c 2920\n");
        return;
    }

    int pid;
    HANDLE snapshot;
    MODULEENTRY32 moduleEntry;
    VS_FIXEDFILEINFO* fileInfo;
    pid = BadgerAtoi(argv[0]);

    if (pid == 0) {
        BadgerDispatch(dispatch, "[-] Invalid process ID with error: %lu\n", Kernel32$GetLastError());
        return;
    }
    snapshot = Kernel32$CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) {
        BadgerDispatch(dispatch, "[-] Unable to create snapshot of the process with error: %lu\n", Kernel32$GetLastError());
        return;
    }
    moduleEntry.dwSize = sizeof(MODULEENTRY32);
    if (Kernel32$Module32First(snapshot, &moduleEntry)) {
        do {
            if (moduleEntry.th32ProcessID == pid) {
                BadgerDispatch(dispatch, "[*] Name: %s\n [*] File Path: %s\n", moduleEntry.szModule, moduleEntry.szExePath);
                DWORD dwHandle;
                DWORD dwSize = Version$GetFileVersionInfoSizeA(moduleEntry.szExePath, &dwHandle);
                if (dwSize > 0) {
                    LPVOID lpVersionInfo = BadgerAlloc(dwSize);
                    if (Version$GetFileVersionInfoA(moduleEntry.szExePath, dwHandle, dwSize, lpVersionInfo)) {
                        UINT len;
                        if (Version$VerQueryValueA(lpVersionInfo, "\\", (LPVOID*)&fileInfo, &len)) {
                            BadgerDispatch(dispatch, "[*] Version: %u.%u.%u.%u\n", HIWORD(fileInfo->dwFileVersionMS), LOWORD(fileInfo->dwFileVersionMS), HIWORD(fileInfo->dwFileVersionLS), LOWORD(fileInfo->dwFileVersionLS));
                        }
                    }
                    BadgerFree((PVOID*)&lpVersionInfo);
                }
                break;
            }
        } while(Kernel32$Module32Next(snapshot, &moduleEntry));
    }
    Kernel32$CloseHandle(snapshot);
    return;
}
