#include <windows.h>
#include <stdio.h>
#include <lmaccess.h>
#include "lmerr.h"
#include "../badger_exports.h"

DECLSPEC_IMPORT WINBASEAPI int WINAPI Kernel32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
DECLSPEC_IMPORT NET_API_STATUS WINAPI Netapi32$NetUserSetInfo(LPCWSTR servername,LPCWSTR username,DWORD level,LPBYTE buf,LPDWORD parm_err);

VOID ConvertCharToWChar(char* charString, wchar_t** wcharString) {
    int size_needed = Kernel32$MultiByteToWideChar(CP_ACP, 0, charString, -1, NULL, 0);
    *wcharString = (wchar_t*) BadgerAlloc(size_needed * sizeof(wchar_t));
    if (*wcharString) {
        Kernel32$MultiByteToWideChar(CP_ACP, 0, charString, -1, *wcharString, size_needed);
    }
}

void coffee(char** argv, int argc, WCHAR** dispatch) {
    if (argc < 1) {
        BadgerDispatch(g_dispatch, "[!] Usage: unexpire_user.o <username> <optional:hostname>\n");
        return;
    }
    WCHAR* wusername = NULL;
    WCHAR* whostname = NULL;
    ConvertCharToWChar(argv[0], &wusername);
    if (argc == 2) {
        ConvertCharToWChar(argv[1], &whostname);
    }
	BadgerDispatch(dispatch, "[+] Enabling user: '%ls\\%ls'\n", (whostname ? whostname : L"localhost"), wusername);

	USER_INFO_1017 NewFlags = {0};	
	NET_API_STATUS dwErrorCode = NERR_Success;
	DWORD dwParmErr = 0;
	NewFlags.usri1017_acct_expires = TIMEQ_FOREVER;
	dwErrorCode = Netapi32$NetUserSetInfo(whostname, wusername, 1017, (LPBYTE)&NewFlags, &dwParmErr);
	if (NERR_Success != dwErrorCode) {
		BadgerDispatch(dispatch, "[-] Error NetUserSetInfo: %lX\n", dwErrorCode);
	} else {
    	BadgerDispatch(dispatch, "[+] Success. Account set to never expire\n");
    }
    BadgerFree((PVOID*)&wusername);
    BadgerFree((PVOID*)&whostname);
}