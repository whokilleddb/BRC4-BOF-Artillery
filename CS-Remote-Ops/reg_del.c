#define _WIN32_WINNT 0x0600  // Required for RegDeleteKeyValueA
#include <windows.h>
#include "badger_exports.h"

#define REG_DELETE_KEY 1
#define REG_DELETE_VALUE 0

DECLSPEC_IMPORT WINADVAPI LONG WINAPI Advapi32$RegConnectRegistryA(LPCSTR lpMachineName,HKEY hKey,PHKEY phkResult);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI Advapi32$RegOpenKeyExA(HKEY hKey,LPCSTR lpSubKey,DWORD ulOptions,REGSAM samDesired,PHKEY phkResult);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI Advapi32$RegDeleteKeyExA(HKEY hKey,LPCSTR lpSubKey,REGSAM samDesired,DWORD Reserved);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI Advapi32$RegDeleteKeyValueA(HKEY hKey, LPCSTR lpSubKey, LPCSTR lpValueName);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI Advapi32$RegCloseKey(HKEY hKey);

DWORD delete_regkey(char* hostname, HKEY hive, char *path, char *key) {
	DWORD dwresult = ERROR_SUCCESS;
	HKEY rootkey = NULL;
	HKEY RemoteKey = NULL;
	HKEY targetkey = NULL;

    if (hostname) {
        dwresult = Advapi32$RegConnectRegistryA(hostname, hive, &RemoteKey);
        if(ERROR_SUCCESS != dwresult) {
            BadgerDispatch(g_dispatch, "[-] Error RegConnectRegistryA %lX\n", dwresult); 
            goto delete_regkey_end;
        }
    }
    dwresult = Advapi32$RegOpenKeyExA((hostname ? RemoteKey : hive), NULL, 0, KEY_READ | KEY_SET_VALUE, &rootkey);
    if(ERROR_SUCCESS != dwresult) {
        BadgerDispatch(g_dispatch, "[-] Error RegOpenKeyExA: %lX\n", dwresult); 
        goto delete_regkey_end;
    }
	if (key) {
		dwresult = Advapi32$RegDeleteKeyValueA(rootkey, path, key);
		if (ERROR_SUCCESS != dwresult) {
			BadgerDispatch(g_dispatch, "[-] Error RegDeleteKeyValueA: %lX\n", dwresult); 
			goto delete_regkey_end;
		}
	} else {
		dwresult = Advapi32$RegDeleteKeyExA(rootkey, path, 0, 0);
		if (ERROR_SUCCESS != dwresult) {
			BadgerDispatch(g_dispatch, "[-] Error RegDeleteKeyExA: %lX\n", dwresult); 
			goto delete_regkey_end;
		}
	}
    BadgerDispatch(g_dispatch, "[+] Success\n"); 

delete_regkey_end:
	if (RemoteKey) {
		Advapi32$RegCloseKey(RemoteKey);
	}
	if (rootkey) {
		Advapi32$RegCloseKey(rootkey);
	}
    if (targetkey) {
		Advapi32$RegCloseKey(targetkey);
	}	
	return dwresult;
}

void coffee(char* argv[], int argc, WCHAR** dispatch) {
	g_dispatch = dispatch;
	HKEY hkRootKey = NULL;
	if (argc < 3) {
        BadgerDispatch(dispatch, "[!] Usage: reg_del.o <hostname> <Registry Hive> <Registry Path> <optional:Registry Key>\n[!] NOTE: Specify Registry hive as follows, HKEY_CLASSES_ROOT as HKCR, HKEY_CURRENT_USER as HKCU, HKEY_LOCAL_MACHINE as HKLM, HKEY_USERS as HKU and HKEY_CURRENT_CONFIG as HKCC\n");
        return;
    }
    CHAR* hostname = NULL;
	CHAR* hkey = argv[1];
	char *path = argv[2];
	char *key = NULL;
    if (argc == 4) {
    	key = argv[3];
    }
    if (BadgerStrcmp(argv[0], "localhost") != 0) {
        hostname = argv[0];
    }
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

    if (key) {
        BadgerDispatch(dispatch, "[+] Deleting: %s\\%s\\%s => %s\n", (hostname ? hostname : "localhost"), hkey, path, key);
    } else {
        BadgerDispatch(dispatch, "[+] Deleting: %s\\%s\\%s\n", (hostname ? hostname : "localhost"), hkey, path);
    }

	delete_regkey(hostname, hkRootKey, path, key);
};