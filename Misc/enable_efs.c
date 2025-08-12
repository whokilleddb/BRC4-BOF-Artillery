#include "common.h" 

#define STATUS_UNSUCCESSFUL        0xc0000001
#define STATUS_INVALID_PARAMETER_1 0xc00000EF


// https://x.com/0x64616e/status/1787936133491355866

int IsEfsServiceRunning(void) {
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCManager) {
        ERR_PRINT("OpenSCManager");
        return -1; // Couldn't open Service Control Manager
    }

    SC_HANDLE hService = OpenServiceA(hSCManager, "EFS", SERVICE_QUERY_STATUS);
    if (!hService) {
        ERR_PRINT("OpenServiceA");
        CloseServiceHandle(hSCManager);
        return -1; // Couldn't open EFS service
    }

    SERVICE_STATUS_PROCESS ssp;
    DWORD bytesNeeded;
    BOOL success = QueryServiceStatusEx(
        hService,
        SC_STATUS_PROCESS_INFO,
        (LPBYTE)&ssp,
        sizeof(SERVICE_STATUS_PROCESS),
        &bytesNeeded
    );

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    if (!success) {
        ERR_PRINT("QueryServiceStatusEx");
        return -1;
    }

    return (ssp.dwCurrentState == SERVICE_RUNNING);
}

void issue_trigger() {
    HANDLE hFile = NULL;
    UNICODE_STRING unicodeString; 
    OBJECT_ATTRIBUTES objectAttributes; 
    IO_STATUS_BLOCK ioStatusBlock; 
    NTSTATUS status = (NTSTATUS)STATUS_UNSUCCESSFUL;
    PCWSTR      wstrFileName = L".\\.cache";

    RtlZeroMemory(&unicodeString, sizeof(UNICODE_STRING));
    RtlZeroMemory(&objectAttributes, sizeof(OBJECT_ATTRIBUTES));
    RtlZeroMemory(&ioStatusBlock, sizeof(IO_STATUS_BLOCK));

    if (RtlDosPathNameToNtPathName_U(wstrFileName, &unicodeString, NULL, NULL) == FALSE) {
        status = (NTSTATUS)STATUS_INVALID_PARAMETER_1;
        EPRINT("[-] RtlDosPathNameToNtPathName_U() failed at %ld\n", __LINE__);
        return;
    }

    InitializeObjectAttributes(&objectAttributes, &unicodeString, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtCreateFile(
        &hFile,
        DELETE | FILE_READ_ATTRIBUTES | GENERIC_WRITE | SYNCHRONIZE,
        &objectAttributes,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_ENCRYPTED | FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_WRITE,
        FILE_OPEN_IF,
        FILE_DELETE_ON_CLOSE | FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );
    PRINT("[+] NtCreateFile() returned:\t0x%lx\n", status);
}

void coffee(char** argv, int argc, WCHAR** dispatch) {
    g_dispatch = dispatch;

    int ret = IsEfsServiceRunning();
    
    if (ret < 0) {
        PRINT("[!] Could not get status of EFS Service!\n");
    } else if (ret == 0 ) {
        PRINT("[*] EFS service is not running\n");
    } else {
        PRINT("[+] EFS service is already running\n");
        return;
    }

    PRINT("[+] Issuing trigger\n");
	issue_trigger();

    ret = IsEfsServiceRunning();
    
    if (ret < 0) {
        PRINT("[!] Could not get status of EFS Service!\n");
    } else if (ret == 0 ) {
        PRINT("[-] EFS service could not be started\n");
    } else {
        PRINT("[+] EFS service has been started!\n");
        return;
    }
}
