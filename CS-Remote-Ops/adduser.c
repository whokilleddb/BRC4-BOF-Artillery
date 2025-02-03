#include <windows.h>
#include <stdio.h>
#include <lm.h>
#include "badger_exports.h"

DECLSPEC_IMPORT NET_API_STATUS NET_API_FUNCTION Netapi32$NetUserAdd(LPCWSTR servername, DWORD level, LPBYTE buf, LPDWORD parm_err);
DECLSPEC_IMPORT int WINAPI Kernel32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
DECLSPEC_IMPORT DWORD WINAPI Kernel32$GetLastError();

DWORD AddUser(LPWSTR lpswzUserName, LPWSTR lpswzPassword, LPWSTR lpswzServerName) {
    LOCALGROUP_MEMBERS_INFO_3 mi[1] = {0};
    USER_INFO_1 ui = { 0 };
    BadgerMemset(&ui, 0, sizeof(ui));
    ui.usri1_name        = lpswzUserName;
    ui.usri1_password    = lpswzPassword;
    ui.usri1_priv        = USER_PRIV_USER;
    ui.usri1_home_dir    = NULL;
    ui.usri1_comment     = NULL;
    ui.usri1_flags       = UF_SCRIPT | UF_NORMAL_ACCOUNT | UF_DONT_EXPIRE_PASSWD;
    ui.usri1_script_path = NULL;
	return Netapi32$NetUserAdd(lpswzServerName, 1, (LPBYTE)&ui, NULL);
}

wchar_t* ChartoWchar(char* charString, wchar_t* wcharString) {
    int size_needed;
    
    size_needed = Kernel32$MultiByteToWideChar(CP_ACP, 0, charString, -1, NULL, 0);
    wcharString = BadgerAlloc(size_needed * sizeof(WCHAR));
    if(!Kernel32$MultiByteToWideChar(CP_ACP, 0, charString, -1, wcharString, size_needed)) {
        BadgerDispatch(g_dispatch, "[-] Error converting %s to wchar: %lu \n", charString, Kernel32$GetLastError());
        return NULL;
    }
    return wcharString;
}

void coffee(char* argv[], int argc, WCHAR** dispatch) {
    if (argc != 3) {
        BadgerDispatch(dispatch, "[!] Usage: adduser.o <user> <password> <hostname>\n Note: Keep hostname 'localhost' for local machine\n");
        return;
    }
    g_dispatch = dispatch;
	DWORD dwErrorCode = NERR_Success;
	WCHAR *lpswzUserName;
    WCHAR *lpswzPassword;
    WCHAR *lpswzServerName = NULL;
    CHAR *username = argv[0];
    CHAR *password = argv[1];
    CHAR *servername = argv[2];

    lpswzUserName = ChartoWchar(username, lpswzUserName);
    BadgerDispatch(dispatch, "[*] Username: %ls\n", lpswzUserName);
    lpswzPassword = ChartoWchar(password, lpswzPassword);
    BadgerDispatch(dispatch, "[*] Password: %ls\n", lpswzPassword);
    if ((BadgerStrcmp(servername, "localhost") != 0)) {
        lpswzServerName = ChartoWchar(servername, lpswzServerName);
    }
    BadgerDispatch(dispatch, "[*] Server name: %ls\n\n", lpswzServerName);
	BadgerDispatch(dispatch, "[*] Adding user %ls to %ls\n", lpswzUserName, lpswzServerName ? lpswzServerName : L"the local machine\n\n");
	dwErrorCode = AddUser(lpswzUserName, lpswzPassword, lpswzServerName);
	if (NERR_Success != dwErrorCode ) {
		BadgerDispatch(dispatch, "[-] Failed to add the user to the system: %lu\n", dwErrorCode);
		return;
	}
	BadgerDispatch(dispatch, "[+] Successfully added a user to the system.\n");
}