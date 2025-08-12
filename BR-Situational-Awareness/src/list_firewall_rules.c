#include "common.h"

// See: https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ics/c-enumerating-firewall-rules

#define NET_FW_IP_PROTOCOL_TCP_NAME L"TCP"
#define NET_FW_IP_PROTOCOL_UDP_NAME L"UDP"

#define NET_FW_RULE_DIR_IN_NAME L"In"
#define NET_FW_RULE_DIR_OUT_NAME L"Out"

#define NET_FW_RULE_ACTION_BLOCK_NAME L"Block"
#define NET_FW_RULE_ACTION_ALLOW_NAME L"Allow"

#define NET_FW_RULE_ENABLE_IN_NAME L"TRUE"
#define NET_FW_RULE_DISABLE_IN_NAME L"FALSE"

typedef struct ProfileMapElement {
        NET_FW_PROFILE_TYPE2 Id;
        LPCWSTR Name;
} ProfileMapElement;


void coffee(char** argv, int argc, WCHAR** dispatch) {
    g_dispatch = dispatch;

    HRESULT hrComInit = S_OK;
    HRESULT hr = S_OK;

    ULONG cFetched = 0;
    VARIANT var;

    IUnknown* pEnumerator;
    IEnumVARIANT* pVariant = NULL;

    INetFwPolicy2* pNetFwPolicy2 = NULL;
    INetFwRules* pFwRules = NULL;
    INetFwRule* pFwRule = NULL;

    hrComInit = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    long fwRuleCount;
}