#include <windows.h>
#include <winreg.h>
#include "../badger_exports.h"

DECLSPEC_IMPORT DWORD WINAPI Kernel32$GetLastError();
DECLSPEC_IMPORT BOOL Advapi32$InitiateSystemShutdownExA(LPSTR lpMachineName, LPSTR lpMessage, DWORD dwTimeout, BOOL bForceAppsClosed, BOOL bRebootAfterShutdown, DWORD dwReason);

void coffee(char** argv, int argc, WCHAR** dispatch) {
    g_dispatch = dispatch;
    if (argc < 5) {
        BadgerDispatch(g_dispatch, "[!] Usage: make_toke_cert.o <localhost/remote-hostname> <message> <timeout> <bool:reboot> <bool:closeapps>\n");
        return;
    }

	HANDLE currentTokenHandle = NULL;
    CHAR* hostname = NULL;
    CHAR* message = argv[1];
    CHAR* privilege = NULL;
    DWORD timeout = BadgerAtoi(argv[2]);
    BOOL reboot = FALSE;
    BOOL closeapps = FALSE;

    if (BadgerStrcmp(argv[0], "localhost") == 0) {
        privilege = "SeShutdownPrivilege";
    } else {
        hostname = argv[0];
        privilege = "SeRemoteShutdownPrivilege";
    }
    if (BadgerStrcmp(argv[3], "true") == 0) {
        reboot = TRUE;
    }
    if (BadgerStrcmp(argv[4], "true") == 0) {
        closeapps = TRUE;
    }

    BadgerDispatch(dispatch, "[+] Setting '%s' privilege\n", privilege);
	if (BadgerAddPrivilege(privilege)) {
		BadgerDispatch(dispatch, "[+] Privilege enabled\n");
        if (Advapi32$InitiateSystemShutdownExA((LPSTR) hostname, (LPSTR) message, timeout, closeapps, reboot, SHTDN_REASON_MAJOR_OPERATINGSYSTEM | SHTDN_REASON_MINOR_SECURITYFIX | SHTDN_REASON_FLAG_PLANNED)) {
            BadgerDispatch(dispatch, "[+] Shutdown executed\n");
        } else {
            BadgerDispatch(dispatch, "[-] Error InitiateSystemShutdownExA: %lu\n", Kernel32$GetLastError());
        }
	} else {
		BadgerDispatch(dispatch, "[-] Error setting privilege\n");
    }
}