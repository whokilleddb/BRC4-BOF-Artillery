#include <windows.h>
#include <ntstatus.h>
#include <winternl.h>
#include "badger_exports.h"
 
#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2
 
DECLSPEC_IMPORT NTSTATUS Ntdll$NtQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
DECLSPEC_IMPORT NTSTATUS Ntdll$NtQueryObject(HANDLE ObjectHandle, ULONG ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);
DECLSPEC_IMPORT NTSTATUS Ntdll$NtDuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG Attributes, ULONG Options);

DECLSPEC_IMPORT DWORD WINAPI Kernel32$GetLastError();
DECLSPEC_IMPORT HANDLE WINAPI Kernel32$GetProcessHeap();
DECLSPEC_IMPORT HANDLE WINAPI Kernel32$GetCurrentProcess();
DECLSPEC_IMPORT DWORD WINAPI Kernel32$CloseHandle(HANDLE hObjec);
DECLSPEC_IMPORT BOOL WINAPI Kernel32$HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
DECLSPEC_IMPORT LPVOID WINAPI Kernel32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
DECLSPEC_IMPORT LPVOID WINAPI Kernel32$HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes);
DECLSPEC_IMPORT HANDLE WINAPI Kernel32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);


DWORD ListProcessHandles(DWORD pid) {
    DWORD dwErrorCode = ERROR_SUCCESS;
    PSYSTEM_HANDLE_INFORMATION handleInfo = NULL;
    ULONG handleInfoSize = 0x10000;
    HANDLE processHandle = NULL;
    ULONG i = 0;
    HANDLE dupHandle = NULL;
    POBJECT_TYPE_INFORMATION objectTypeInfo = NULL;
    PVOID objectNameInfo = NULL;

    processHandle = Kernel32$OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
    if (NULL == processHandle) {
        dwErrorCode = Kernel32$GetLastError();
        BadgerDispatch(g_dispatch, "[-] Could not open PID %lu! (Don't try to open a system process.)\n", pid);
        goto cleanup;
    }
    handleInfo = (PSYSTEM_HANDLE_INFORMATION)Kernel32$HeapAlloc(Kernel32$GetProcessHeap(), HEAP_ZERO_MEMORY, handleInfoSize);
    if ( NULL == handleInfo ) {
        dwErrorCode = ERROR_OUTOFMEMORY;
        BadgerDispatch(g_dispatch, "[-] Failed to allocate handle info\n");
        goto cleanup;
    }
    while ((dwErrorCode = (DWORD)Ntdll$NtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH) {
        handleInfo = (PSYSTEM_HANDLE_INFORMATION)Kernel32$HeapReAlloc(Kernel32$GetProcessHeap(), HEAP_ZERO_MEMORY, handleInfo, handleInfoSize *= 2);
        if ( NULL == handleInfo ) {
            dwErrorCode = ERROR_OUTOFMEMORY;
            BadgerDispatch(g_dispatch, "[-] Failed to reallocate handle info\n");
            goto cleanup;
        }
    }
    if (!NT_SUCCESS(dwErrorCode)) {
        BadgerDispatch(g_dispatch, "[-] NtQuerySystemInformation failed! (%lu)\n", dwErrorCode);
        goto cleanup;
    }
    for (i = 0; i < handleInfo->Count; i++) {
        SYSTEM_HANDLE_ENTRY handle = handleInfo->Handle[i];
        UNICODE_STRING objectName;
        ULONG returnLength = 0;
        BadgerMemset(&objectName, 0, sizeof(UNICODE_STRING));
        if (objectTypeInfo) {
            Kernel32$HeapFree(Kernel32$GetProcessHeap(), 0, objectTypeInfo);
            objectTypeInfo = NULL;
        }
        if (objectNameInfo) {
            Kernel32$HeapFree(Kernel32$GetProcessHeap(), 0, objectNameInfo);
            objectNameInfo = NULL;
        }
        if (dupHandle) {
            Kernel32$CloseHandle(dupHandle);
            dupHandle = NULL;
        }
        if (handle.OwnerPid != pid)
            continue;
        #pragma GCC diagnostic ignored "-Wint-to-pointer-cast"
        dwErrorCode = (DWORD)Ntdll$NtDuplicateObject(processHandle,  (HANDLE) handle.HandleValue, Kernel32$GetCurrentProcess(), &dupHandle, 0,  0,  0);
        #pragma GCC diagnostic pop
        if (!NT_SUCCESS(dwErrorCode)) {
            BadgerDispatch(g_dispatch, "[-] Failed to duplicate handle %lx in pid:%lu (%lu)\n", handle.HandleValue, pid, dwErrorCode);
            continue;
        } 
        objectTypeInfo = (POBJECT_TYPE_INFORMATION)Kernel32$HeapAlloc(Kernel32$GetProcessHeap(), HEAP_ZERO_MEMORY, 0x1000);
        if ( NULL == objectTypeInfo ) {
            BadgerDispatch(g_dispatch, "[-] Failed to allocate objectTypeInfo\n");
            continue;
        }
        dwErrorCode = (DWORD)Ntdll$NtQueryObject(dupHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, NULL);
        if (!NT_SUCCESS(dwErrorCode)) {
            BadgerDispatch(g_dispatch, "[-] Failed to query the object type for handle %#X in pid:%lu (%lu)\n", (UINT)handle.HandleValue, pid, dwErrorCode);
            continue;
        } 
        // (unless it has an access of 0x0012019f, on which NtQueryObject could hang)
        if (handle.AccessMask == 0x0012019f) {
            BadgerDispatch(g_dispatch, "[*] [%d] %ls: (did not get name)\n", handle.HandleValue, objectTypeInfo->TypeName.Buffer );
            continue;
        }
        objectNameInfo = Kernel32$HeapAlloc(Kernel32$GetProcessHeap(), HEAP_ZERO_MEMORY, 0x1000);
        if (!objectNameInfo) {
            BadgerDispatch(g_dispatch, "[-] Failed to allocate objectNameInfo\n");
            continue;
        }
        dwErrorCode = (DWORD)Ntdll$NtQueryObject(dupHandle, ObjectNameInformation, objectNameInfo, 0x1000, &returnLength);
        if (!NT_SUCCESS(dwErrorCode)) {
            objectNameInfo = Kernel32$HeapReAlloc(Kernel32$GetProcessHeap(), HEAP_ZERO_MEMORY, objectNameInfo, returnLength);
            if ( NULL == objectNameInfo ) {
                BadgerDispatch(g_dispatch, "[-] Failed to allocate objectNameInfo\n");
                continue;
            }
            dwErrorCode = (DWORD)Ntdll$NtQueryObject(dupHandle, ObjectNameInformation, objectNameInfo, returnLength, NULL);
            if (!NT_SUCCESS(dwErrorCode)) {
                BadgerDispatch(g_dispatch, "[*] [%d] %ls: (could not get name)\n", handle.HandleValue, objectTypeInfo->TypeName.Buffer );
                continue;
            }
        }
        objectName = *(PUNICODE_STRING)objectNameInfo;
        if (objectName.Length)
        {
            BadgerDispatch(g_dispatch, "[*] [%d] %ls: %ls\n", handle.HandleValue, objectTypeInfo->TypeName.Buffer, objectName.Buffer);
        } else {
            BadgerDispatch(g_dispatch, "[*] [%d] %ls: (unnamed)\n", handle.HandleValue, objectTypeInfo->TypeName.Buffer );
        }
    }
    dwErrorCode = ERROR_SUCCESS;
 
 cleanup:
    if (handleInfo) {
        Kernel32$HeapFree(Kernel32$GetProcessHeap(), 0, handleInfo);
        handleInfo = NULL;
    }
    if (processHandle) {
        Kernel32$CloseHandle(processHandle);
        processHandle = NULL;
    }
    if (objectTypeInfo) {
        Kernel32$HeapFree(Kernel32$GetProcessHeap(), 0, objectTypeInfo);
        objectTypeInfo = NULL;
    }
    if (objectNameInfo) {
        Kernel32$HeapFree(Kernel32$GetProcessHeap(), 0, objectNameInfo);
        objectNameInfo = NULL;
    }
    if (dupHandle) {
        Kernel32$CloseHandle(dupHandle);
        dupHandle = NULL;
    }
    return dwErrorCode;
}

void coffee(char ** argv, int argc, WCHAR** dispatch) {
	DWORD dwErrorCode = ERROR_SUCCESS;
	DWORD dwPid = 0;
    g_dispatch = dispatch;

	 dwPid = BadgerAtoi(argv[0]);
     BadgerDispatch(dispatch, "PID: %lu\n", dwPid);
	 BadgerDispatch(dispatch, "[+] Listing handles for PID:%lu\n", dwPid);
    dwErrorCode = ListProcessHandles(dwPid);
    if (ERROR_SUCCESS != dwErrorCode) {
        BadgerDispatch(dispatch, "[-] ListProcessHandles failed: %lu\n", dwErrorCode);
        return;
    }
	return;
}
