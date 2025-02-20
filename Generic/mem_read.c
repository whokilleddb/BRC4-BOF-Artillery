#include <windows.h>
#include <stdio.h>
#include "../badger_exports.h"

WINADVAPI FARPROC WINAPI Kernel32$GetProcAddress(HMODULE hModule, LPCSTR  lpProcName);
WINADVAPI HMODULE WINAPI Kernel32$GetModuleHandleA(LPCSTR lpModuleName);

void coffee(char** argv, int argc, WCHAR** dispatch) {
    if (argc > 1) {
        BadgerDispatch(dispatch, "[*] Loading library '%s'\n", argv[0]);
        HANDLE hModule = Kernel32$GetModuleHandleA(argv[0]);
        BadgerDispatch(dispatch, "[*] Library loaded at '%p'\n", hModule);
        for (int i = 1; i < argc; i++) {
            unsigned char buf[11] = { 0 };
            PVOID myProc = (PVOID) Kernel32$GetProcAddress(hModule, argv[i]);
            BadgerDispatch(dispatch, "[+] Reading first 10 bytes from '%s (%p)'\n  - Bytes: { ", argv[i], myProc);
            BadgerMemcpy(buf, (PVOID) myProc, 10);
            for (int j = 0; j < 10; j++) {
                BadgerDispatch(dispatch, "0x%02X ", buf[j]);
            }
            BadgerDispatch(dispatch, "}\n");
        }
        return;
    }
    BadgerDispatch(dispatch, "[!] No arguments provided. Usage: 'read_mem.o <dllname> <function1> <function2> ...'\n");
}