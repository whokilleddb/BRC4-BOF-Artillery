#include <Windows.h>
#include <netfw.h>
#include "../badger_exports.h"

DECLSPEC_IMPORT void WINAPI OleAut32$SysFreeString(BSTR bstrString);
DECLSPEC_IMPORT BSTR WINAPI OleAut32$SysAllocString(const OLECHAR *psz);

DECLSPEC_IMPORT void WINAPI Ole32$CoUninitialize();
DECLSPEC_IMPORT HRESULT WINAPI Ole32$CoInitializeEx(LPVOID pvReserved, DWORD  dwCoInit);
DECLSPEC_IMPORT HRESULT WINAPI Ole32$CoCreateInstance(REFCLSID  rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID *ppv);

DECLSPEC_IMPORT DWORD WINAPI Kernel32$GetLastError();
DECLSPEC_IMPORT int WINAPI Kernel32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);

VOID ConvertCharToWChar(char* charString, wchar_t** wcharString) {
    int size_needed = Kernel32$MultiByteToWideChar(CP_ACP, 0, charString, -1, NULL, 0);
    *wcharString = (wchar_t*) BadgerAlloc(size_needed * sizeof(wchar_t));
    if (*wcharString) {
        Kernel32$MultiByteToWideChar(CP_ACP, 0, charString, -1, *wcharString, size_needed);
    }
}

HRESULT AddFirewallRule(BSTR ruleName, BSTR ruleDescription, BSTR ruleGroup, NET_FW_RULE_DIRECTION direction, BSTR localPorts, LONG protocol) {
    HRESULT hr = S_OK;
    INetFwPolicy2 *pNetFwPolicy2 = NULL;
    INetFwRules *pRules = NULL;
    INetFwRule *pRule = NULL;
	
    hr = Ole32$CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        BadgerDispatch(g_dispatch, "[-] Error CoInitializeEx %d\n", Kernel32$GetLastError());
        goto Cleanup;
    }
    IID CLSIDNetFwPolicy2 = {0xe2b3c97f, 0x6ae1, 0x41ac, {0x81, 0x7a, 0xf6, 0xf9, 0x21, 0x66, 0xd7, 0xdd}};
    IID IIDINetFwPolicy2 = {0x98325047, 0xc671, 0x4174, {0x8d, 0x81, 0xde, 0xfc, 0xd3, 0xf0, 0x31, 0x86}};
    hr = Ole32$CoCreateInstance(&CLSIDNetFwPolicy2, NULL, CLSCTX_INPROC_SERVER, &IIDINetFwPolicy2, (void**)&pNetFwPolicy2);
    if (FAILED(hr)) {
        BadgerDispatch(g_dispatch, "[-] Error CoCreateInstance of firewall setting manager object: %d\n", Kernel32$GetLastError());
        goto Cleanup;
    }
    hr = pNetFwPolicy2->lpVtbl->get_Rules(pNetFwPolicy2, &pRules);
    if (FAILED(hr)) {
        BadgerDispatch(g_dispatch, "[-] Error get_Rules: %d\n", Kernel32$GetLastError());
        goto Cleanup;
    }
    IID CLSIDNetFwRule = {0x2c5bc43e, 0x3369, 0x4c33, {0xab, 0x0c, 0xbe, 0x94, 0x69, 0x67, 0x7a, 0xf4}};
	IID IIDINetFwRule = {0xaf230d27, 0xbaba, 0x4e42, {0xac, 0xed, 0xf5, 0x24, 0xf2, 0x2c, 0xfc, 0xe2}};
    hr = Ole32$CoCreateInstance(&CLSIDNetFwRule, NULL, CLSCTX_INPROC_SERVER, &IIDINetFwRule, (void**)&pRule);
    if (FAILED(hr)) {
        BadgerDispatch(g_dispatch, "[-] Error CoCreateInstance of rule object: %d\n", Kernel32$GetLastError());
        goto Cleanup;
    }
    pRule->lpVtbl->put_Direction(pRule, direction);
    pRule->lpVtbl->put_Protocol(pRule, protocol);
    pRule->lpVtbl->put_LocalPorts(pRule, localPorts);
    pRule->lpVtbl->put_Action(pRule, NET_FW_ACTION_ALLOW);
    pRule->lpVtbl->put_Profiles(pRule, NET_FW_PROFILE2_ALL);
    pRule->lpVtbl->put_Name(pRule, ruleName);
    pRule->lpVtbl->put_Description(pRule, ruleDescription);
    pRule->lpVtbl->put_Grouping(pRule, ruleGroup);
    pRule->lpVtbl->put_Enabled(pRule, VARIANT_TRUE);
    hr = pRules->lpVtbl->Add(pRules, pRule);
    if (FAILED(hr)) {
        BadgerDispatch(g_dispatch, "[-] Error CoCreateInstance for adding rule to firewall: %d\n", Kernel32$GetLastError());
        goto Cleanup;
    }

Cleanup:
    if (pRule) pRule->lpVtbl->Release(pRule);
    if (pRules) pRules->lpVtbl->Release(pRules);
    if (pNetFwPolicy2) pNetFwPolicy2->lpVtbl->Release(pNetFwPolicy2);
    Ole32$CoUninitialize();
    return hr;
}

void coffee(char** argv, int argc, WCHAR** dispatch) {
    HRESULT hr;
    LONG protocol = NET_FW_IP_PROTOCOL_TCP;
    CHAR *directionOption = "in"; //in | out
    WCHAR *w_ruleName = NULL;
    WCHAR *w_ruleDescription = NULL;
    WCHAR *w_ruleGroup = NULL;
    WCHAR *w_localPorts = NULL;
    g_dispatch = dispatch;
    
    if (argc < 5) {
	BadgerDispatch(dispatch, "[!] Usage: AddFirewallRule.o <direction:in/out> <port> <rule_name> <group_name> <description>\n [!] Example: AddFirewallRule.o out 8080 MyRule MyGroup Allowing outbound traffic\n");
    }
    directionOption = argv[0];
    ConvertCharToWChar(argv[1], &w_localPorts);
    ConvertCharToWChar(argv[2], &w_ruleName);
    ConvertCharToWChar(argv[3], &w_ruleGroup);
    ConvertCharToWChar(argv[4], &w_ruleDescription);
    BSTR ruleName = OleAut32$SysAllocString(w_ruleName);
    BadgerDispatch(dispatch, "[*] Rule Name: %S\n", ruleName);
    BSTR ruleDescription = OleAut32$SysAllocString(w_ruleDescription);
    BadgerDispatch(dispatch, "[*] Rule Description: %S\n", ruleDescription);
    BSTR ruleGroup = OleAut32$SysAllocString(w_ruleGroup);
    BadgerDispatch(dispatch, "[*] Rule Group: %S\n", ruleGroup);
    BSTR localPorts = OleAut32$SysAllocString(w_localPorts);
    BadgerDispatch(dispatch, "[*] Local Port: %S\n", localPorts);
    if (BadgerStrcmp(directionOption, "in") == 0) {
	NET_FW_RULE_DIRECTION direction = NET_FW_RULE_DIR_IN;
	hr = AddFirewallRule(ruleName, ruleDescription, ruleGroup, direction, localPorts, protocol);
	if (SUCCEEDED(hr)) {
	    BadgerDispatch(dispatch, "[+] Inbound firewall rule added successfully.\n");
        }
        else {
	    BadgerDispatch(dispatch, "[-] Add failed: %lu\n", Kernel32$GetLastError());
        }
    } 
    else {
	NET_FW_RULE_DIRECTION direction = NET_FW_RULE_DIR_OUT;
	hr = AddFirewallRule(ruleName, ruleDescription, ruleGroup, direction, localPorts, protocol);
	if (SUCCEEDED(hr)) {
	    BadgerDispatch(dispatch, "[+] Outbound firewall rule added successfully.\n");
        }
        else {
	    BadgerDispatch(dispatch, "[-] Add failed: %lu\n", Kernel32$GetLastError());
        }
    }
    OleAut32$SysFreeString(ruleName);
    OleAut32$SysFreeString(ruleDescription);
    OleAut32$SysFreeString(ruleGroup);
    OleAut32$SysFreeString(localPorts);
    return;
}
