#define _WIN32_DCOM
#include <windows.h>
#include <taskschd.h>
#include <sddl.h>
#include <wchar.h>
#include "../../badger_exports.h"

#define SCHTASKS_USER 0
#define SCHTASKS_SYSTEM 1
#define SCHTASKS_XML_PRINCIPAL 2

#define USER_SYSTEM_STRING L"nt authority\\SYSTEM"

DECLSPEC_IMPORT WINADVAPI WINBOOL WINAPI Advapi32$OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
DECLSPEC_IMPORT WINADVAPI WINBOOL WINAPI Advapi32$GetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);
DECLSPEC_IMPORT WINADVAPI WINBOOL WINAPI Advapi32$InitializeSecurityDescriptor(PSECURITY_DESCRIPTOR pSecurityDescriptor, DWORD dwRevision);
DECLSPEC_IMPORT WINADVAPI WINBOOL WINAPI Advapi32$SetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR pSecurityDescriptor, WINBOOL bDaclPresent, PACL pDacl, WINBOOL bDaclDefaulted);
DECLSPEC_IMPORT WINADVAPI WINBOOL WINAPI Advapi32$ConvertSecurityDescriptorToStringSecurityDescriptorW(PSECURITY_DESCRIPTOR SecurityDescriptor,DWORD RequestedStringSDRevision,SECURITY_INFORMATION SecurityInformation,LPWSTR *StringSecurityDescriptor,PULONG StringSecurityDescriptorLen);
DECLSPEC_IMPORT WINADVAPI WINBOOL WINAPI Advapi32$LookupAccountSidW(LPCWSTR lpSystemName, PSID Sid, LPWSTR Name, LPDWORD cchName, LPWSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse);

DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI Kernel32$GetLastError(VOID);
DECLSPEC_IMPORT WINBASEAPI HLOCAL WINAPI Kernel32$LocalFree(HLOCAL hMem);
DECLSPEC_IMPORT WINBASEAPI WINBOOL WINAPI Kernel32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT WINBASEAPI int WINAPI Kernel32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);

DECLSPEC_IMPORT wchar_t* Msvcrt$wcsncat(wchar_t* destination, const wchar_t* source, size_t num);
DECLSPEC_IMPORT wchar_t* Msvcrt$wcsrchr(const wchar_t *_Str, wchar_t _Ch);
DECLSPEC_IMPORT wchar_t* Msvcrt$wcstok(wchar_t * _Str,const wchar_t * _Delim);
DECLSPEC_IMPORT wchar_t* Msvcrt$wcscpy(wchar_t * __dst, const wchar_t * __src);

DECLSPEC_IMPORT WINOLEAUTAPI_(void) Oleaut32$VariantInit(VARIANTARG *pvarg);
DECLSPEC_IMPORT WINOLEAUTAPI_(BSTR) Oleaut32$SysAllocString(const OLECHAR *);
DECLSPEC_IMPORT WINOLEAUTAPI_(void) Oleaut32$SysFreeString(BSTR);
DECLSPEC_IMPORT WINOLEAUTAPI Oleaut32$VariantClear(VARIANTARG *pvarg);

DECLSPEC_IMPORT WINOLEAPI Ole32$CoInitializeEx(LPVOID pvReserved, DWORD dwCoInit);
DECLSPEC_IMPORT WINOLEAPI Ole32$CoCreateInstance(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID *ppv);
DECLSPEC_IMPORT WINOLEAPI_(void) Ole32$CoUninitialize(void);

// domain\username from lookupsid
// the returned string MUST be freed using LocalFree
DWORD getUserDefaultSDDL(wchar_t **lpswzUserName, wchar_t **lpswzSDString) {
	DWORD dwErrorCode = ERROR_SUCCESS;
	HANDLE Token = NULL;
	SECURITY_DESCRIPTOR Sd = {0};
	PTOKEN_USER puser = NULL;
	DWORD RequiredSize = 0;
	DWORD UserSize = 0;
	wchar_t username[257] = {0};
	DWORD usernameSize = 257;
	wchar_t domainname[256] = {0};
	DWORD domainSize = 256;
	SID_NAME_USE junk = {0};
	TOKEN_DEFAULT_DACL* DefaultDacl = NULL;

	if (FALSE == Advapi32$OpenProcessToken((HANDLE)-1, TOKEN_QUERY, &Token)) {
		dwErrorCode = Kernel32$GetLastError();
		BadgerDispatch(g_dispatch, "[-] Error OpenProcessToken: %lX\n", dwErrorCode);
		goto getUserDefaultSDDL_end;
	}
	Advapi32$GetTokenInformation(Token, TokenDefaultDacl, NULL, 0, &RequiredSize);
	Advapi32$GetTokenInformation(Token, TokenUser, NULL, 0, &UserSize);

	DefaultDacl = (TOKEN_DEFAULT_DACL *)BadgerAlloc(RequiredSize);
	puser = (TOKEN_USER *)BadgerAlloc(UserSize);

	if (! Advapi32$GetTokenInformation(Token, TokenDefaultDacl, DefaultDacl, RequiredSize, &RequiredSize)) {
		dwErrorCode = Kernel32$GetLastError();
		BadgerDispatch(g_dispatch, "[-] Error GetTokenInformation: %lX\n", dwErrorCode);
		goto getUserDefaultSDDL_end;
	}
	if (! Advapi32$GetTokenInformation(Token, TokenUser, puser, UserSize, &UserSize)) {
		dwErrorCode = Kernel32$GetLastError();
		BadgerDispatch(g_dispatch, "[-] Error GetTokenInformation: %lX\n", dwErrorCode);
		goto getUserDefaultSDDL_end;
	}
	if (! Advapi32$InitializeSecurityDescriptor(&Sd, SECURITY_DESCRIPTOR_REVISION)) {
		dwErrorCode = Kernel32$GetLastError();
		BadgerDispatch(g_dispatch, "[-] Error InitializeSecurityDescriptor: %lX\n", dwErrorCode);
		goto getUserDefaultSDDL_end;
	}
	if (! Advapi32$SetSecurityDescriptorDacl(&Sd, TRUE, DefaultDacl->DefaultDacl, FALSE)) {
		dwErrorCode = Kernel32$GetLastError();
		BadgerDispatch(g_dispatch, "[-] Error SetSecurityDescriptorDacl: %lX\n", dwErrorCode);
		goto getUserDefaultSDDL_end;
	}

	if (! Advapi32$ConvertSecurityDescriptorToStringSecurityDescriptorW(&Sd,SDDL_REVISION_1, DACL_SECURITY_INFORMATION, lpswzSDString, NULL)) {
		dwErrorCode = Kernel32$GetLastError();
		BadgerDispatch(g_dispatch, "[-] Error SetSecurityDescriptorDacl: %lX\n", dwErrorCode);
		goto getUserDefaultSDDL_end;
	}

	// Get the username for the TokenUser
	if (! Advapi32$LookupAccountSidW(NULL, puser->User.Sid, username, &usernameSize, domainname, &domainSize, &junk)) {
		dwErrorCode = Kernel32$GetLastError();
		BadgerDispatch(g_dispatch, "[-] Error LookupAccountSidW: %lX\n", dwErrorCode);
		goto getUserDefaultSDDL_end;
	}

	*lpswzUserName = BadgerAlloc((usernameSize + domainSize) * 2 + 4);

	Msvcrt$wcsncat(*lpswzUserName, domainname, domainSize+1);
	(*lpswzUserName)[domainSize] = L'\\';
	Msvcrt$wcsncat(*lpswzUserName, username, usernameSize+domainSize+2);

getUserDefaultSDDL_end:

	if (ERROR_SUCCESS != dwErrorCode) {
		if (*lpswzSDString) {
			Kernel32$LocalFree(*lpswzSDString);
			*lpswzSDString = NULL;
		}
		if (*lpswzUserName) {
			BadgerFree((PVOID*)&*lpswzUserName);
		}
	}
	if (puser) {
		BadgerFree((PVOID*)&puser);
	}
	if (DefaultDacl) {
		BadgerFree((PVOID*)&DefaultDacl);
	}
	if (Token) {
		Kernel32$CloseHandle(Token);
		Token = NULL;
	}
	return dwErrorCode;
}

DWORD createTask(const wchar_t * server, wchar_t * taskpath, const wchar_t* xmldef, int mode, BOOL force) {
	HRESULT hr = S_OK;
	VARIANT Vserver;
	VARIANT VNull;
	VARIANT Vsddl;
	VARIANT Vthisuser;
	wchar_t *defaultSDDL = NULL;
	ITaskFolder *pCurFolder = NULL;
	ITaskFolder *pRootFolder = NULL;
	ITaskDefinition *pTaskDef = NULL;
	IRegisteredTask* pRegisteredTask = NULL;
	BSTR rootpath = NULL;
	BSTR BSTRtaskpath = NULL;
	BSTR BSTRtaskname = NULL;
	BSTR BSTRtaskxml = NULL;
	BSTR BSTRthisuser = NULL;
	BSTR BSTRsystem = NULL;
	wchar_t* taskname = NULL;
	wchar_t* taskpathpart = NULL;
	BOOL mustcreate = FALSE;
	TASK_STATE tstate = 0;
	TASK_LOGON_TYPE taskType = 0;	//(mode) ? TASK_LOGON_SERVICE_ACCOUNT : TASK_LOGON_INTERACTIVE_TOKEN;
	wchar_t * thisuser = NULL;
	VARIANT_BOOL isEnabled = 0;
	DATE taskdate = 0;
	IID CTaskScheduler = {0x0f87369f,0xa4e5,0x4cfc,{0xbd,0x3e,0x73,0xe6,0x15,0x45,0x72,0xdd}};
	IID IIDTaskService = {0x2faba4c7, 0x4da9, 0x4013, {0x96, 0x97, 0x20, 0xcc, 0x3f, 0xd4, 0x0f, 0x85}};
	ITaskService *pService = NULL;
	// Initialize variants
	Oleaut32$VariantInit(&Vserver);
	Oleaut32$VariantInit(&VNull);
	Oleaut32$VariantInit(&Vsddl);
	Oleaut32$VariantInit(&Vthisuser); // we don't clear this because we free both possible OLE strings

	// Initialize COM
	hr = Ole32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	if (FAILED(hr)) {
		BadgerDispatch(g_dispatch, "[-] Error CoInitializeEx: %lX\n", hr);
		goto createTask_end;
	}

	// Create System user string
	BSTRsystem = Oleaut32$SysAllocString(USER_SYSTEM_STRING);
	if (! BSTRsystem) {
		hr = ERROR_OUTOFMEMORY;
		BadgerDispatch(g_dispatch, "[-] Error SysAllocString: %lX\n", hr);
		goto createTask_end;
	}

	// Get an instance of the task scheduler
    hr = Ole32$CoCreateInstance(&CTaskScheduler, NULL, CLSCTX_INPROC_SERVER, &IIDTaskService, (void**)&pService); 
	if (FAILED(hr)) {
		BadgerDispatch(g_dispatch, "[-] Error CoCreateInstance: %lX", hr);
		goto createTask_end;
	}

	// Set up our variant for the server name if we need to
	Vserver.vt = VT_BSTR;
	Vserver.bstrVal = Oleaut32$SysAllocString(server);
	if (! Vserver.bstrVal) {
		hr = ERROR_OUTOFMEMORY;
		BadgerDispatch(g_dispatch, "[-] Error SysAllocString: %lX\n", hr);
		goto createTask_end;
	}

	// Connect to the server
	BadgerDispatch(g_dispatch, "[+] Connecting to \"%ls\"\n", Vserver.bstrVal);
	hr = pService->lpVtbl->Connect(pService, Vserver, VNull, VNull, VNull);
	if (FAILED(hr)) {
		BadgerDispatch(g_dispatch, "[-] Error connecting to server: %lX\n", hr);
		goto createTask_end;
	}

	rootpath = Oleaut32$SysAllocString(L"\\");
	if (! rootpath) {
		hr = ERROR_OUTOFMEMORY;
		BadgerDispatch(g_dispatch, "[-] Error SysAllocString: %lX\n", hr);
		goto createTask_end;
	}
	hr = pService->lpVtbl->GetFolder(pService, rootpath, &pRootFolder);
    if (FAILED(hr)) {
        BadgerDispatch(g_dispatch, "[-] Error getting task root folder: %lX\n", hr );
		goto createTask_end;
    }

	hr = (HRESULT)getUserDefaultSDDL(&thisuser, &defaultSDDL);
	if (ERROR_SUCCESS != hr) {
		BadgerDispatch(g_dispatch, "[-] Error getting the current user and default security descriptor: %lX\n", hr);
		goto createTask_end;
	}
	BadgerDispatch(g_dispatch, "[+] Extracted username and security descriptor\n");

	Vsddl.vt = VT_BSTR;
	Vsddl.bstrVal = Oleaut32$SysAllocString(defaultSDDL);
	if (! Vsddl.bstrVal) {
		hr = ERROR_OUTOFMEMORY;
		BadgerDispatch(g_dispatch, "[-] Error SysAllocString: %lX\n", hr);
		goto createTask_end;
	}
	
	BSTRthisuser = Oleaut32$SysAllocString(thisuser);
	if (! BSTRthisuser) {
		hr = ERROR_OUTOFMEMORY;
		BadgerDispatch(g_dispatch, "[-] Error SysAllocString: %lX\n", hr);
		goto createTask_end;
	}
	
	// Use the task XML passed in
	BSTRtaskxml = Oleaut32$SysAllocString(xmldef);
	if (! BSTRtaskxml) {
		hr = ERROR_OUTOFMEMORY;
		BadgerDispatch(g_dispatch, "[-] Error SysAllocString: %lX\n", hr);
		goto createTask_end;
	}

	// Validate the task only
	hr = pRootFolder->lpVtbl->RegisterTask(pRootFolder, NULL, BSTRtaskxml, TASK_VALIDATE_ONLY, VNull, VNull, 0, VNull, &pRegisteredTask);
	if (FAILED(hr)) {
		BadgerDispatch(g_dispatch, "[-] Error validating the XML task: %lX\n", hr);
		goto createTask_end;
	}
	BadgerDispatch(g_dispatch, "[+] Valitdated XML task\n");

	// Release the validation instance
	if (pRegisteredTask) {
		pRegisteredTask->lpVtbl->Release(pRegisteredTask);
		pRegisteredTask = NULL;
	}

	// Now we need to recursivly get or create the task path
	taskname = Msvcrt$wcsrchr(taskpath, L'\\');
	if (! taskname) {
		hr = ERROR_BAD_PATHNAME;
		BadgerDispatch(g_dispatch, "[-] Error locating \\ in your task path: %lX\n", hr);
		goto createTask_end;
	}

	taskname[0] = L'\0'; // null terminate our path to this point
	taskname += 1; // move past null
	BSTRtaskname = Oleaut32$SysAllocString(taskname);
	if (! BSTRtaskname) {
		hr = ERROR_OUTOFMEMORY;
		BadgerDispatch(g_dispatch, "[-] Error SysAllocString: %lX\n", hr);
		goto createTask_end;
	}
	// Loop through the full path name
	for(taskpathpart = Msvcrt$wcstok(taskpath, L"\\"); taskpathpart != NULL; taskpathpart = Msvcrt$wcstok(NULL, L"\\")) {
		if (mustcreate == FALSE) {
			BSTRtaskpath = Oleaut32$SysAllocString(taskpathpart);
			if (! BSTRtaskpath) {
				hr = ERROR_OUTOFMEMORY;
				BadgerDispatch(g_dispatch, "[-] Error SysAllocString: %lX\n", hr);
				goto createTask_end;
			}
			hr = pRootFolder->lpVtbl->GetFolder(pRootFolder, BSTRtaskpath, &pCurFolder);
			if (FAILED(hr)) {
				mustcreate = TRUE;
			} 
		}
		// Intentionally not an else, we want to start creating as soon as we fail
		if (mustcreate) {
			 // if this isn't null we just tried to get it, otherwise we need to aloc it for this token
			if (!BSTRtaskpath) {
				BSTRtaskpath = Oleaut32$SysAllocString(taskpathpart);
				if (! BSTRtaskpath) {
					hr = ERROR_OUTOFMEMORY;
					BadgerDispatch(g_dispatch, "[-] Error SysAllocString: %lX\n", hr);
					goto createTask_end;
				}
			}

			hr = pRootFolder->lpVtbl->CreateFolder(pRootFolder, BSTRtaskpath, Vsddl, &pCurFolder);
			if (FAILED(hr)) {
				BSTR errorpath = NULL;
				pRootFolder->lpVtbl->get_Path(pRootFolder, &errorpath);
				BadgerDispatch(g_dispatch, "[-] Error creating task folder %ls\\%ls: %lX\n", errorpath, BSTRtaskpath, hr);
				Oleaut32$SysFreeString(errorpath);
				goto createTask_end;
			} else {
				BSTR successpath = NULL;
				pRootFolder->lpVtbl->get_Path(pRootFolder, &successpath);
				BadgerDispatch(g_dispatch, "[+] Created task folder: %ls\\%ls\n", successpath, BSTRtaskpath);
				Oleaut32$SysFreeString(successpath);
			}
		} // end we mustcreate a folder

		pRootFolder->lpVtbl->Release(pRootFolder);
		pRootFolder = pCurFolder;
		if (BSTRtaskpath) {
			Oleaut32$SysFreeString(BSTRtaskpath);
			BSTRtaskpath = NULL;
		}
	} // end for loop creating task path

	// Set the task type and task user
	if (mode == SCHTASKS_USER) {
		Vthisuser.vt = VT_BSTR;
		Vthisuser.bstrVal = BSTRthisuser;
		taskType = TASK_LOGON_INTERACTIVE_TOKEN;
		BadgerDispatch(g_dispatch, "[+] Created task path for user: %ls\n", Vthisuser.bstrVal);
	} else if (mode == SCHTASKS_SYSTEM) {
		Vthisuser.vt = VT_BSTR;
		Vthisuser.bstrVal = BSTRsystem;
		taskType = TASK_LOGON_SERVICE_ACCOUNT;
		BadgerDispatch(g_dispatch, "[+] Created task path for user: %ls\n", Vthisuser.bstrVal);
	} else if (mode == SCHTASKS_XML_PRINCIPAL) {
		taskType = TASK_LOGON_NONE;
		BadgerDispatch(g_dispatch, "[+] Created task path for principal\n");
	} else {
		hr = ERROR_BAD_ARGUMENTS;
		BadgerDispatch(g_dispatch, "[-] Invalid mode (%d): %lX\n", mode, hr);
		goto createTask_end;
	}

	// Are we forcing the update/create or just trying to create?
	if (force) {
		hr = pRootFolder->lpVtbl->RegisterTask(pRootFolder, BSTRtaskname, BSTRtaskxml, TASK_CREATE_OR_UPDATE, Vthisuser, VNull, taskType, Vsddl, &pRegisteredTask);
		if (FAILED(hr)) {
			BadgerDispatch(g_dispatch, "[-] Error registering task: %lX\n", hr);
			goto createTask_end;
		}
	} else { 
		// First check to see if the task already exits
		hr = pRootFolder->lpVtbl->GetTask(pRootFolder, BSTRtaskname, &pRegisteredTask);
		if (SUCCEEDED(hr)) {
			hr = ERROR_ALREADY_EXISTS;
			BadgerDispatch(g_dispatch, "[-] Error task already exists: %lX\n", hr);
			goto createTask_end;
		}
		
		// The task does not exist, so we can continue
		hr = pRootFolder->lpVtbl->RegisterTask(pRootFolder, BSTRtaskname, BSTRtaskxml, TASK_CREATE, Vthisuser, VNull, taskType, Vsddl, &pRegisteredTask);
		if (FAILED(hr)) {
			BadgerDispatch(g_dispatch, "[-] Error registering task: %lX\n", hr);
			goto createTask_end;
		}
	}
	BadgerDispatch(g_dispatch, "[+] Success\n");

createTask_end:
	if (BSTRthisuser) {
		Oleaut32$SysFreeString(BSTRthisuser);
		BSTRthisuser = NULL;
	}
	if (BSTRsystem) {
		Oleaut32$SysFreeString(BSTRsystem);
		BSTRsystem = NULL;
	}
	if (pRegisteredTask) {
		pRegisteredTask->lpVtbl->Release(pRegisteredTask);
		pRegisteredTask = NULL;
	}
	if (BSTRtaskxml) {
		Oleaut32$SysFreeString(BSTRtaskxml);
		BSTRtaskxml = NULL;
	}
	if (BSTRtaskname) {
		Oleaut32$SysFreeString(BSTRtaskname);
		BSTRtaskname = NULL;
	}
	if (thisuser) {
		BadgerFree((PVOID*)&thisuser);
		thisuser = NULL;
	}
	if (defaultSDDL) {
		Kernel32$LocalFree(defaultSDDL);
		defaultSDDL = NULL;
	}
	if (pRootFolder && pRootFolder != pCurFolder) {
		pRootFolder->lpVtbl->Release(pRootFolder);
		pRootFolder = NULL;
	}
	if (pCurFolder) {
		pCurFolder->lpVtbl->Release(pCurFolder);
		pCurFolder = NULL;
	}
	if (BSTRtaskpath) {
		Oleaut32$SysFreeString(BSTRtaskpath);
		BSTRtaskpath = NULL;
	}
	if (pService) {
		pService->lpVtbl->Release(pService);
		pService = NULL;
	}
	if (rootpath) {
		Oleaut32$SysFreeString(rootpath);
		rootpath = NULL;
	}
	Oleaut32$VariantClear(&Vsddl);
	Oleaut32$VariantClear(&Vserver);
	Ole32$CoUninitialize();
	return (DWORD)hr;
}

VOID ConvertCharToWChar(char* charString, wchar_t** wcharString) {
    int size_needed = Kernel32$MultiByteToWideChar(CP_ACP, 0, charString, -1, NULL, 0);
    *wcharString = (wchar_t*) BadgerAlloc(size_needed * sizeof(wchar_t));
    if (*wcharString) {
        Kernel32$MultiByteToWideChar(CP_ACP, 0, charString, -1, *wcharString, size_needed);
    }
}

void coffee(char** argv, int argc, WCHAR** dispatch) {
    g_dispatch = dispatch;
    if (argc < 5) {
		BadgerDispatch(dispatch, "[!] Usage: schtasks_create.o <hostname> <taskpath> <user/system/principal> <bool:force>\n[!] NOTE: Configure XML task file using 'set_coffargs'\n");
        return;
    }
	WCHAR* wxmltask = NULL;
	WCHAR* whostname = NULL;
	WCHAR* wtaskpath = NULL;
	INT nMode = -1;
	BOOL bForce = FALSE;

	ConvertCharToWChar(argv[0], &wxmltask);
	ConvertCharToWChar(argv[1], &whostname);
	ConvertCharToWChar(argv[2], &wtaskpath);

	if (BadgerStrcmp(argv[3], "user") == 0) {
		nMode = SCHTASKS_USER;
	} else if (BadgerStrcmp(argv[3], "system") == 0) {
		nMode = SCHTASKS_SYSTEM;
	} else if (BadgerStrcmp(argv[3], "principal") == 0) {
		nMode = SCHTASKS_XML_PRINCIPAL;
	} else {
		BadgerDispatch(dispatch, "[-] Invalid usertype\n");
	}
	if (BadgerStrcmp(argv[4], "true") == 0) {
		bForce = TRUE;
	}
	BadgerDispatch(dispatch, "[+] Creating scheduled task:\n  - Hostname: %ls\n  - Task path: %ls\n  - Mode: %s\n  - Force: %s\n", whostname, wtaskpath, argv[3], (bForce ? "True" : "False"));
	createTask(whostname, wtaskpath, wxmltask, nMode, bForce);

	BadgerFree((PVOID*)&wxmltask);
	BadgerFree((PVOID*)&whostname);
	BadgerFree((PVOID*)&wtaskpath);
}