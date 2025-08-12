#include "common.h" 

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

    PRINT("[+] Issuing CreateFile() trigger\n");
	HANDLE file = CreateFileA(".\\test.txt", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_ENCRYPTED | FILE_FLAG_DELETE_ON_CLOSE, NULL);
	if (file != INVALID_HANDLE_VALUE) {
		CloseHandle(file);
	}

    ret = IsEfsServiceRunning();
    
    if (ret < 0) {
        PRINT("[!] Could not get status of EFS Service!\n");
    } else if (ret == 0 ) {
        PRINT("[*] EFS service could not be started\n");
    } else {
        PRINT("[+] EFS service has been started!\n");
        return;
    }
}
