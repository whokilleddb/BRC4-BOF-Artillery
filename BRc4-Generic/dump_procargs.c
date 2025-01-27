#include <windows.h>
#include <stdio.h>
#include <winternl.h>
#include "badger_exports.h"

DECLSPEC_IMPORT DWORD Kernel32$GetLastError();
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);

DECLSPEC_IMPORT NTSTATUS NTDLL$NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);

void coffee(char* argv[], int argc,  WCHAR** dispatch) {
    if (argc < 1) {
        BadgerDispatch(dispatch, "[!] Usage: procargs-COFF.o <pid>\n[!] Eg.: procargs-COFF.o 2920\n");
        return;
    }

    WCHAR* commandLineBuffer = NULL;
    HANDLE hProcess = NULL;
    PROCESS_BASIC_INFORMATION pbi;
    PEB peb;
    RTL_USER_PROCESS_PARAMETERS parameters;
    int pid = BadgerAtoi(argv[0]);

    if(pid == 0) {
        BadgerDispatch(dispatch, "\n[-] Invalid process ID %lu\n", Kernel32$GetLastError());
        return;
    }
    hProcess = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        BadgerDispatch(dispatch, "\n[-] Failed to open process %lu\n", Kernel32$GetLastError());
        return;
    }
    NTSTATUS status = NTDLL$NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);
    if (!NT_SUCCESS(status)) {
        BadgerDispatch(dispatch, "\n[-] Failed to query process information %lu\n", Kernel32$GetLastError());
        goto cleanUp;
    }
    if (!KERNEL32$ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(PEB), NULL)) {
        BadgerDispatch(dispatch, "\n[-] Failed to read PEB %lu\n", Kernel32$GetLastError());
        goto cleanUp;
    }
    if (!KERNEL32$ReadProcessMemory(hProcess, peb.ProcessParameters, &parameters, sizeof(RTL_USER_PROCESS_PARAMETERS), NULL)) {
        BadgerDispatch(dispatch, "\n[-] Failed to read process parameters %lu\n", Kernel32$GetLastError());
        goto cleanUp;
    }
    commandLineBuffer = (WCHAR*)BadgerAlloc(parameters.CommandLine.Length + sizeof(WCHAR));
    if (!KERNEL32$ReadProcessMemory(hProcess, parameters.CommandLine.Buffer, commandLineBuffer, parameters.CommandLine.Length, NULL)) {
        BadgerDispatch(dispatch, "\n[-] Failed to read command line buffer %lu\n", Kernel32$GetLastError());
        goto cleanUp;
    }
    commandLineBuffer[parameters.CommandLine.Length / sizeof(WCHAR)] = L'\0';
    BadgerDispatch(dispatch, "\n[*] CmdLine Args: %ls\n", commandLineBuffer);

    cleanUp:
        if (commandLineBuffer) {
            BadgerFree((PVOID*)commandLineBuffer);
        }
        if (hProcess) {
            KERNEL32$CloseHandle(hProcess);
        }
    return;
}