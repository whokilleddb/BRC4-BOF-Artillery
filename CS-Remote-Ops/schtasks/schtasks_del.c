#define _WIN32_DCOM
#include <windows.h>
#include <taskschd.h>
#include <sddl.h>
#include "../badger_exports.h"

DECLSPEC_IMPORT WINOLEAUTAPI_(void) Oleaut32$VariantInit(VARIANTARG *pvarg);
DECLSPEC_IMPORT WINOLEAPI Ole32$CoInitializeEx(LPVOID pvReserved, DWORD dwCoInit);
DECLSPEC_IMPORT WINOLEAPI Ole32$CoCreateInstance(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID *ppv);
DECLSPEC_IMPORT WINOLEAUTAPI_(BSTR) Oleaut32$SysAllocString(const OLECHAR *);
DECLSPEC_IMPORT WINOLEAUTAPI_(void) Oleaut32$SysFreeString(BSTR);
DECLSPEC_IMPORT WINOLEAUTAPI Oleaut32$VariantClear(VARIANTARG *pvarg);

DECLSPEC_IMPORT WINOLEAPI Ole32$CoInitializeEx(LPVOID pvReserved, DWORD dwCoInit);
DECLSPEC_IMPORT WINOLEAPI_(void) Ole32$CoUninitialize(void);

DECLSPEC_IMPORT WINBASEAPI int WINAPI Kernel32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);

DWORD deleteTask(WCHAR* server, WCHAR* taskname, BOOL isfolder) {
	HRESULT hr = S_OK;
	VARIANT Vserver;
	VARIANT VNull;
	ITaskFolder *pRootFolder = NULL;
	IRegisteredTask* pRegisteredTask = NULL;	
	BSTR rootpath = NULL;
	BSTR taskpath = NULL;
	IID CTaskScheduler = {0x0f87369f,0xa4e5,0x4cfc,{0xbd,0x3e,0x73,0xe6,0x15,0x45,0x72,0xdd}};
	IID IIDTaskService = {0x2faba4c7, 0x4da9, 0x4013, {0x96, 0x97, 0x20, 0xcc, 0x3f, 0xd4, 0x0f, 0x85}};
	ITaskService *pService = NULL;
	Oleaut32$VariantInit(&Vserver);
	Oleaut32$VariantInit(&VNull);

	hr = Ole32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	if (FAILED(hr)) {
		BadgerDispatch(g_dispatch, "[-] Error CoInitializeEx: %lX\n", hr);
		goto cleanUp;
	}
    hr = Ole32$CoCreateInstance(&CTaskScheduler, NULL, CLSCTX_INPROC_SERVER, &IIDTaskService, (void**)&pService); 
	if (FAILED(hr)) {
		BadgerDispatch(g_dispatch, "[-] Error CoCreateInstance: %lX\n", hr);
		goto cleanUp;
	}
	Vserver.vt = VT_BSTR;
	Vserver.bstrVal = Oleaut32$SysAllocString(server);
	if (! Vserver.bstrVal){
		hr = ERROR_OUTOFMEMORY;
		BadgerDispatch(g_dispatch, "[-] Error SysAllocString: %lX\n", hr);
		goto cleanUp;
	}
	hr = pService->lpVtbl->Connect(pService, Vserver, VNull, VNull, VNull);
	if (FAILED(hr)) {
		BadgerDispatch(g_dispatch, "[-] Error connecting to server: %lX\n", hr);
		goto cleanUp;
	}
	rootpath = Oleaut32$SysAllocString(L"\\");
	if (! rootpath) {
		hr = ERROR_OUTOFMEMORY;
		BadgerDispatch(g_dispatch, "[-] Error SysAllocString: %lX\n", hr);
		goto cleanUp;
	}
	hr = pService->lpVtbl->GetFolder(pService, rootpath, &pRootFolder);
    if (FAILED(hr)) {
        BadgerDispatch(g_dispatch, "[-] Error accessing root folder: %lX\n", hr);
		goto cleanUp;
    }
	taskpath = Oleaut32$SysAllocString(taskname);
	if (! taskpath) {
		hr = ERROR_OUTOFMEMORY;
		BadgerDispatch(g_dispatch, "[-] Error SysAllocString: %lX\n", hr);
		goto cleanUp;
	}
	if (isfolder) {
		hr = pRootFolder->lpVtbl->DeleteFolder(pRootFolder, taskpath, 0);
		if (FAILED(hr)) {
			BadgerDispatch(g_dispatch, "[-] Error deleting task folder %S: %lX\n", taskpath, hr);
			goto cleanUp;		
		}
		BadgerDispatch(g_dispatch, "[+] Deleted the task folder: %ls\n", taskpath);
	} else {
		hr = pRootFolder->lpVtbl->GetTask(pRootFolder, taskpath, &pRegisteredTask);
		if (FAILED(hr)) {
			BadgerDispatch(g_dispatch, "[-] Error fetching task task: %S: %lX\n", taskpath, hr);
			BadgerDispatch(g_dispatch, "[!] NOTE: When using delete, you must give the full path and name of the task\n");
			goto cleanUp;
		}
		hr = pRegisteredTask->lpVtbl->Stop(pRegisteredTask, 0);
		if (FAILED(hr)) {
			BadgerDispatch(g_dispatch, "[-] Error stopping task: %S: %lX\n", taskpath, hr);
			goto cleanUp;
		}
		pRegisteredTask->lpVtbl->Release(pRegisteredTask);
		pRegisteredTask = NULL;
		hr = pRootFolder->lpVtbl->DeleteTask(pRootFolder, taskpath, 0);
		if (FAILED(hr)) {
			BadgerDispatch(g_dispatch, "[-] Error deleting the task: %S: %lX\n", taskpath, hr);
			goto cleanUp;
		}
		BadgerDispatch(g_dispatch, "[+] Deleted the task: %S\n", taskpath);
	}
cleanUp:
	if (taskpath) {
		Oleaut32$SysFreeString(taskpath);
		taskpath = NULL;
	}
	if (rootpath) {
		Oleaut32$SysFreeString(rootpath);
		rootpath = NULL;
	}
	if (pRootFolder) {
		pRootFolder->lpVtbl->Release(pRootFolder);
		pRootFolder = NULL;
	}
	if (pRegisteredTask) {
		pRegisteredTask->lpVtbl->Release(pRegisteredTask);
		pRegisteredTask = NULL;
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
    if (argc < 3) {
		BadgerDispatch(dispatch, "[!] Usage: schtasks_del.o <folder/task> <hostname> <taskname/taskfolder>\n");
        return;
    }

	WCHAR *whostname = NULL;
	WCHAR *wtaskname_folder = NULL;
	BOOL isfolder = FALSE; // 0 = task, 1  = folder
	if (BadgerStrcmp(argv[0], "folder") == 0) {
		isfolder = TRUE;
	}
	ConvertCharToWChar(argv[1], &whostname);
	ConvertCharToWChar(argv[2], &wtaskname_folder);
	BadgerDispatch(dispatch, "[+] Deleting:\n  - Hostname: %ls\n  - %s: %ls\n  - Type: %s\n", whostname, ( isfolder ? "Taskfolder" : "Taskname"), wtaskname_folder, argv[0]);
	deleteTask(whostname, wtaskname_folder, isfolder);
	BadgerFree((PVOID*)&whostname);
	BadgerFree((PVOID*)&wtaskname_folder);
	BadgerFree((PVOID*)&wtaskname_folder);
}