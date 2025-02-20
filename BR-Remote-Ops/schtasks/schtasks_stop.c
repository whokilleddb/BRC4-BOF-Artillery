#define _WIN32_DCOM
#include <windows.h>
#include <taskschd.h>
#include <sddl.h>
#include "../../badger_exports.h"

DECLSPEC_IMPORT WINOLEAUTAPI_(void) Oleaut32$VariantInit(VARIANTARG *pvarg);
DECLSPEC_IMPORT WINOLEAPI Ole32$CoInitializeEx(LPVOID pvReserved, DWORD dwCoInit);
DECLSPEC_IMPORT WINOLEAPI Ole32$CoCreateInstance(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID *ppv);
DECLSPEC_IMPORT WINOLEAUTAPI_(BSTR) Oleaut32$SysAllocString(const OLECHAR *);
DECLSPEC_IMPORT WINOLEAUTAPI_(void) Oleaut32$SysFreeString(BSTR);
DECLSPEC_IMPORT WINOLEAUTAPI Oleaut32$VariantClear(VARIANTARG *pvarg);

DECLSPEC_IMPORT WINOLEAPI Ole32$CoInitializeEx(LPVOID pvReserved, DWORD dwCoInit);
DECLSPEC_IMPORT WINOLEAPI_(void) Ole32$CoUninitialize(void);

DECLSPEC_IMPORT WINBASEAPI int WINAPI Kernel32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);

#ifndef TASK_RUN_FLAGS
typedef enum _TASK_RUN_FLAGS {
	TASK_RUN_NO_FLAGS	= 0,
	TASK_RUN_AS_SELF	= 0x1,
	TASK_RUN_IGNORE_CONSTRAINTS	= 0x2,
	TASK_RUN_USE_SESSION_ID	= 0x4,
	TASK_RUN_USER_SID	= 0x8
} TASK_RUN_FLAGS;
#endif 

DWORD stopTask(const wchar_t * server, const wchar_t * taskname) {
	HRESULT hr = S_OK;
	LONG flags = TASK_RUN_IGNORE_CONSTRAINTS;
	VARIANT Vserver;
	VARIANT VNull;
	ITaskFolder *pRootFolder = NULL;
	IRegisteredTask* pRegisteredTask = NULL;
	BSTR rootpath = NULL;
	BSTR taskpath = NULL;
	IID CTaskScheduler = {0x0f87369f,0xa4e5,0x4cfc,{0xbd,0x3e,0x73,0xe6,0x15,0x45,0x72,0xdd}};
	IID IIDTaskService = {0x2faba4c7, 0x4da9, 0x4013, {0x96, 0x97, 0x20, 0xcc, 0x3f, 0xd4, 0x0f, 0x85}};
	ITaskService *pService = NULL;
	// Initialize variants
	Oleaut32$VariantInit(&Vserver);
	Oleaut32$VariantInit(&VNull);

    // Initialize COM
	hr = Ole32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	if (FAILED(hr)) {
		BadgerDispatch(g_dispatch, "[-] Error CoInitializeEx: %lX\n", hr);
		goto stopTask_end;
	}

    hr = Ole32$CoCreateInstance(&CTaskScheduler, NULL, CLSCTX_INPROC_SERVER, &IIDTaskService, (void**)&pService ); 
	if (FAILED(hr)) {
		BadgerDispatch(g_dispatch, "[-] Error CoCreateInstance: %lX\n", hr);
		goto stopTask_end;
	}

	// Set up our variant for the server name if we need to
	Vserver.vt = VT_BSTR;
	Vserver.bstrVal = Oleaut32$SysAllocString(server);
	if (! Vserver.bstrVal) {
		hr = ERROR_OUTOFMEMORY;
		BadgerDispatch(g_dispatch, "[-] Error SysAllocString: %lX\n", hr);
		goto stopTask_end;
	}

	// Connect to the server
	// HRESULT Connect( VARIANT serverName, VARIANT user, VARIANT domain, VARIANT password );
    BadgerDispatch(g_dispatch, "[+] Connecting to \"%ls\"\n", Vserver.bstrVal);
	hr = pService->lpVtbl->Connect(pService, Vserver, VNull, VNull, VNull);
	if (FAILED(hr)) {
		BadgerDispatch(g_dispatch, "[-] Error connecting to server: %lX\n", hr);
		goto stopTask_end;
	}

	// Now we need to get the root folder 
	rootpath = Oleaut32$SysAllocString(L"\\");
	if (! rootpath) {
		hr = ERROR_OUTOFMEMORY;
		BadgerDispatch(g_dispatch, "[-] Error SysAllocString: %lX\n", hr);
		goto stopTask_end;
	}
	hr = pService->lpVtbl->GetFolder(pService, rootpath, &pRootFolder);
    if (FAILED(hr)) {
        BadgerDispatch(g_dispatch, "[-] Error accessing the root folder: %lX\n", hr);
		goto stopTask_end;
    }

	// Get the task name or current folder name
	taskpath = Oleaut32$SysAllocString(taskname);
	if (! taskpath) {
		hr = ERROR_OUTOFMEMORY;
        BadgerDispatch(g_dispatch, "[-] Error SysAllocString: %lX\n", hr);
		goto stopTask_end;
	}

	// Get a reference to the target task
	hr = pRootFolder->lpVtbl->GetTask(pRootFolder, taskpath, &pRegisteredTask);
	if (FAILED(hr)) {
        BadgerDispatch(g_dispatch, "[-] Error finding the task: %S: %lX\n", taskpath, hr);
        BadgerDispatch(g_dispatch, "[!] NOTE: You must specify the full path and name of the task\n");
		goto stopTask_end;
	}

	// Actually stop the task
	hr = pRegisteredTask->lpVtbl->Stop(pRegisteredTask, 0);
	if (FAILED(hr)) {
		BadgerDispatch(g_dispatch, "[-] Error stopping task: %S: %lX\n", taskpath, hr);
		goto stopTask_end;
	}

    BadgerDispatch(g_dispatch, "[+] Task stopped successfully\n");


stopTask_end:
	if (taskpath) {
		Oleaut32$SysFreeString(taskpath);
		taskpath = NULL;
	}
	if (rootpath) {
		Oleaut32$SysFreeString(rootpath);
		rootpath = NULL;
	}
	if (pRegisteredTask) {
		pRegisteredTask->lpVtbl->Release(pRegisteredTask);
		pRegisteredTask = NULL;
	}
	if (pRootFolder) {
		pRootFolder->lpVtbl->Release(pRootFolder);
		pRootFolder = NULL;
	}
	if (pService) {
		pService->lpVtbl->Release(pService);
		pService = NULL;
	}
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
    if (argc < 2) {
		BadgerDispatch(dispatch, "[!] Usage: schtasks_stop.o <hostname> <format:'foldername/taskname'>\n");
        return;
    }
    DWORD dwErrorCode = ERROR_SUCCESS;
    WCHAR* hostname = NULL;
    WCHAR* taskname = NULL;
    ConvertCharToWChar(argv[0], &hostname);
    ConvertCharToWChar(argv[1], &taskname);
    BadgerDispatch(g_dispatch, "[+] Stopping task '%ls' on '%ls'\n", taskname, hostname );
    stopTask(hostname, taskname);
    BadgerFree((PVOID*)&hostname);
    BadgerFree((PVOID*)&taskname);
}
