#include <windows.h>
#include <stdio.h>
#include <oleauto.h>
#include <wchar.h>
#include <io.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <combaseapi.h>
#include <sddl.h>
#include <iads.h>
#include <wincrypt.h>
#include "certca.h"
#include "../badger_exports.h"

DECLSPEC_IMPORT HRESULT WINAPI Certcli$CAEnumFirstCA(IN LPCWSTR wszScope, IN DWORD dwFlags, OUT LPVOID * phCAInfo);
DECLSPEC_IMPORT HRESULT WINAPI Certcli$CAEnumNextCA(IN LPVOID hPrevCA, OUT LPVOID * phCAInfo);
DECLSPEC_IMPORT HRESULT WINAPI Certcli$CACloseCA(IN LPVOID hCA);
DECLSPEC_IMPORT DWORD WINAPI Certcli$CACountCAs(IN LPVOID hCAInfo);
DECLSPEC_IMPORT LPCWSTR WINAPI Certcli$CAGetDN(IN LPVOID hCAInfo);
DECLSPEC_IMPORT HRESULT WINAPI Certcli$CAGetCAProperty(IN LPVOID hCAInfo, IN LPCWSTR wszPropertyName, OUT PZPWSTR *pawszPropertyValue);
DECLSPEC_IMPORT HRESULT WINAPI Certcli$CAFreeCAProperty(IN LPVOID hCAInfo, IN PZPWSTR awszPropertyValue);
DECLSPEC_IMPORT HRESULT WINAPI Certcli$CAGetCAFlags(IN LPVOID hCAInfo, OUT DWORD  *pdwFlags);
DECLSPEC_IMPORT HRESULT WINAPI Certcli$CAGetCACertificate(IN LPVOID hCAInfo, OUT PCCERT_CONTEXT *ppCert);
DECLSPEC_IMPORT HRESULT WINAPI Certcli$CAGetCAExpiration(IN LPVOID hCAInfo, OUT DWORD * pdwExpiration, OUT DWORD * pdwUnits);
DECLSPEC_IMPORT HRESULT WINAPI Certcli$CAGetCASecurity(IN LPVOID hCAInfo, OUT PSECURITY_DESCRIPTOR * ppSD);
DECLSPEC_IMPORT HRESULT WINAPI Certcli$CAGetAccessRights(IN LPVOID hCAInfo, IN DWORD dwContext, OUT DWORD *pdwAccessRights);
DECLSPEC_IMPORT HRESULT WINAPI Certcli$CAEnumCertTypesForCA(IN LPVOID hCAInfo, IN DWORD dwFlags, OUT LPVOID * phCertType);
DECLSPEC_IMPORT HRESULT WINAPI Certcli$CAEnumCertTypes(IN DWORD dwFlags, OUT LPVOID * phCertType);
DECLSPEC_IMPORT HRESULT WINAPI Certcli$CAEnumNextCertType(IN LPVOID hPrevCertType, OUT LPVOID * phCertType);
DECLSPEC_IMPORT DWORD WINAPI Certcli$CACountCertTypes(IN LPVOID hCertType);
DECLSPEC_IMPORT HRESULT WINAPI Certcli$CACloseCertType(IN LPVOID hCertType);
DECLSPEC_IMPORT HRESULT WINAPI Certcli$CAGetCertTypeProperty(IN LPVOID hCertType, IN LPCWSTR wszPropertyName, OUT PZPWSTR *pawszPropertyValue);
DECLSPEC_IMPORT HRESULT WINAPI Certcli$CAGetCertTypePropertyEx(IN LPVOID hCertType, IN LPCWSTR wszPropertyName, OUT LPVOID *pPropertyValue);
DECLSPEC_IMPORT HRESULT WINAPI Certcli$CAFreeCertTypeProperty(IN LPVOID hCertType, IN PZPWSTR awszPropertyValue);
DECLSPEC_IMPORT HRESULT WINAPI Certcli$CAGetCertTypeExtensionsEx(IN LPVOID hCertType, IN DWORD dwFlags, IN LPVOID pParam, OUT PCERT_EXTENSIONS * ppCertExtensions);
DECLSPEC_IMPORT HRESULT WINAPI Certcli$CAFreeCertTypeExtensions(IN LPVOID hCertType, IN PCERT_EXTENSIONS pCertExtensions);
DECLSPEC_IMPORT HRESULT WINAPI Certcli$CAGetCertTypeFlagsEx(IN LPVOID hCertType, IN DWORD dwOption, OUT DWORD * pdwFlags);
DECLSPEC_IMPORT HRESULT WINAPI Certcli$CAGetCertTypeExpiration(IN LPVOID hCertType, OUT OPTIONAL FILETIME * pftExpiration, OUT OPTIONAL FILETIME * pftOverlap);
DECLSPEC_IMPORT HRESULT WINAPI Certcli$CACertTypeGetSecurity(IN LPVOID hCertType, OUT PSECURITY_DESCRIPTOR * ppSD);
DECLSPEC_IMPORT HRESULT WINAPI Certcli$caTranslateFileTimePeriodToPeriodUnits(IN FILETIME const *pftGMT, IN BOOL Flags, OUT DWORD *pcPeriodUnits, OUT LPVOID*prgPeriodUnits);
DECLSPEC_IMPORT HRESULT WINAPI Certcli$CAGetCertTypeAccessRights(IN LPVOID hCertType, IN DWORD dwContext, OUT DWORD *pdwAccessRights);

DECLSPEC_IMPORT PCCERT_CONTEXT WINAPI Crypt32$CertCreateCertificateContext(DWORD dwCertEncodingType, const BYTE *pbCertEncoded, DWORD cbCertEncoded);
DECLSPEC_IMPORT DWORD WINAPI Crypt32$CertGetNameStringW(PCCERT_CONTEXT pCertContext, DWORD dwType, DWORD dwFlags, void *pvTypePara, LPWSTR pszNameString, DWORD cchNameString);
DECLSPEC_IMPORT WINBOOL WINAPI Crypt32$CertGetCertificateContextProperty(PCCERT_CONTEXT pCertContext, DWORD dwPropId, void *pvData, DWORD *pcbData);
DECLSPEC_IMPORT WINBOOL WINAPI Crypt32$CertGetCertificateChain(HCERTCHAINENGINE hChainEngine, PCCERT_CONTEXT pCertContext, LPFILETIME pTime, HCERTSTORE hAdditionalStore, PCERT_CHAIN_PARA pChainPara, DWORD dwFlags, LPVOID pvReserved, PCCERT_CHAIN_CONTEXT *ppChainContext);
DECLSPEC_IMPORT VOID WINAPI Crypt32$CertFreeCertificateChain(PCCERT_CHAIN_CONTEXT pChainContext);
DECLSPEC_IMPORT WINIMPM WINBOOL WINAPI Crypt32$CertFreeCertificateContext(PCCERT_CONTEXT pCertContext);
DECLSPEC_IMPORT WINIMPM PCCRYPT_OID_INFO WINAPI Crypt32$CryptFindOIDInfo(DWORD dwKeyType, void *pvKey, DWORD dwGroupId);

DECLSPEC_IMPORT WINBASEAPI WINBOOL WINAPI Kernel32$FileTimeToSystemTime(CONST FILETIME *lpFileTime, LPSYSTEMTIME lpSystemTime);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI Kernel32$GetLastError();
DECLSPEC_IMPORT WINBASEAPI HLOCAL WINAPI Kernel32$LocalFree(HLOCAL hMem);
DECLSPEC_IMPORT WINBASEAPI HLOCAL WINAPI Kernel32$LocalAlloc(UINT uFlags, SIZE_T uBytes);
DECLSPEC_IMPORT WINBASEAPI int WINAPI Kernel32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);

DECLSPEC_IMPORT WINADVAPI WINBOOL WINAPI Advapi32$GetSecurityDescriptorOwner(PSECURITY_DESCRIPTOR pSecurityDescriptor, PSID *pOwner, LPBOOL lpbOwnerDefaulted);
DECLSPEC_IMPORT WINADVAPI WINBOOL WINAPI Advapi32$LookupAccountSidW(LPCWSTR lpSystemName, PSID Sid, LPWSTR Name, LPDWORD cchName, LPWSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse);
DECLSPEC_IMPORT WINADVAPI WINBOOL WINAPI Advapi32$ConvertSidToStringSidW(PSID Sid,LPWSTR *StringSid);
DECLSPEC_IMPORT WINADVAPI WINBOOL WINAPI Advapi32$GetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR pSecurityDescriptor, LPBOOL lpbDaclPresent, PACL *pDacl, LPBOOL lpbDaclDefaulted);
DECLSPEC_IMPORT WINADVAPI WINBOOL WINAPI Advapi32$GetAclInformation(PACL pAcl, LPVOID pAclInformation, DWORD nAclInformationLength, ACL_INFORMATION_CLASS dwAclInformationClass);
DECLSPEC_IMPORT WINADVAPI WINBOOL WINAPI Advapi32$GetAce(PACL pAcl, DWORD dwAceIndex, LPVOID *pAce);

DECLSPEC_IMPORT int Ole32$StringFromGUID2(REFGUID rguid, LPOLESTR lpsz, int cchMax);

DECLSPEC_IMPORT int __cdecl Msvcrt$memcmp(const void *_Buf1,const void *_Buf2,size_t _Size);
DECLSPEC_IMPORT int Msvcrt$sprintf(char *__stream, const char *__format, ...);

#define CHECK_RETURN_FALSE( function, return_value, result) \
	if (FALSE == return_value) \
	{ \
		result = Kernel32$GetLastError(); \
		BadgerDispatch(g_dispatch, "[-] Error %s: 0x%08lx\n", function, result); \
		goto fail; \
	}
#define CHECK_RETURN_FAIL( function, result ) \
	if (FAILED(result)) \
	{ \
		BadgerDispatch(g_dispatch, "[-] Error %s: 0x%08lx\n", function, result); \
		goto fail; \
	}
#define SAFE_CAFREECAPROPERTY( handle_ca, pointer_capropertyvaluearray ) \
	if (pointer_capropertyvaluearray) \
	{ \
		Certcli$CAFreeCAProperty(handle_ca, pointer_capropertyvaluearray); \
		pointer_capropertyvaluearray = NULL; \
	}
#define SAFE_CACLOSECA( handle_ca ) \
	if (handle_ca) \
	{ \
		Certcli$CACloseCA(handle_ca); \
		handle_ca = NULL; \
	}	
#define SAFE_CAFREECERTTYPEPROPERTY( handle_certtype, pointer_ctpropertyvaluearray ) \
	if (pointer_ctpropertyvaluearray) \
	{ \
		Certcli$CAFreeCertTypeProperty(handle_certtype, pointer_ctpropertyvaluearray); \
		pointer_ctpropertyvaluearray = NULL; \
	}
#define SAFE_CACLOSECERTTYPE( handle_certtype ) \
	if (handle_certtype) \
	{ \
		Certcli$CACloseCertType(handle_certtype); \
		handle_certtype = NULL; \
	}
#define SAFE_CERTFREECERTIFICATECHAIN( cert_chain_context ) \
	if(cert_chain_context) \
	{ \
		Crypt32$CertFreeCertificateChain(cert_chain_context); \
		cert_chain_context = NULL; \
	}	
#define SAFE_LOCAL_FREE( local_ptr ) \
	if (local_ptr) \
	{ \
		Kernel32$LocalFree(local_ptr); \
		local_ptr = NULL; \
	}

#define DEFINE_MY_GUID(name,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8) const GUID name = { l, w1, w2, { b1, b2, b3, b4, b5, b6, b7, b8 } }
DEFINE_MY_GUID(CertificateEnrollment,0x0e10c968,0x78fb,0x11d2,0x90,0xd4,0x00,0xc0,0x4f,0x79,0xdc,0x55);
DEFINE_MY_GUID(CertificateAutoEnrollment,0xa05b8cc2,0x17bc,0x4802,0xa7,0x10,0xe7,0xc1,0x5a,0xb8,0x66,0xa2);
DEFINE_MY_GUID(CertificateAll,0x00000000,0x0000,0x0000,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00);
DEFINE_MY_GUID(ManageCA,0x05000000,0x0015,0x0000,0xf9,0xbf,0xaa,0x22,0x07,0x95,0x8d,0xdd);

HRESULT adcs_enum(wchar_t* domain) {
	HRESULT	hr = S_OK;
	HCAINFO hCAInfo = NULL;
	HCAINFO hCAInfoNext = NULL;
	LPWSTR wszScope = domain;
	DWORD dwFlags = CA_FLAG_SCOPE_DNS;

	// get the first CA in the domain
	hr = Certcli$CAEnumFirstCA( wszScope, dwFlags, &hCAInfoNext );
	CHECK_RETURN_FAIL("CAEnumFirstCA", hr)
	// CountCAs
	if (! hCAInfoNext) {
		BadgerDispatch(g_dispatch, "[-] Found 0 CAs in the domain\n");
		goto fail;
	}
	BadgerDispatch(g_dispatch, "[+] Found %lu CAs in the domain\n", Certcli$CACountCAs(hCAInfoNext));

	// loop through CAs in the domain
	while (hCAInfoNext) {
		// free previous CA
		SAFE_CACLOSECA( hCAInfo );
		hCAInfo = hCAInfoNext;
		hCAInfoNext = NULL;
		// distinguished name
		BadgerDispatch(g_dispatch, "\n[+] Listing info for %S\n\n", Certcli$CAGetDN(hCAInfo));
		// list info for current CA
		hr = _adcs_enum_ca(hCAInfo);
		CHECK_RETURN_FAIL("_adcs_enum_ca", hr)
		// get the next CA in the domain
		hr = Certcli$CAEnumNextCA(hCAInfo, &hCAInfoNext);
		CHECK_RETURN_FAIL("CAEnumNextCA", hr)
	} // end loop through CAs in the domain
	hr = S_OK;
	//internal_printf("\n adcs_enum SUCCESS.\n");
fail:
	// free CA
	SAFE_CACLOSECA( hCAInfo )
	SAFE_CACLOSECA( hCAInfoNext )
	return hr;
} // end adcs_enum

HRESULT _adcs_enum_ca(HCAINFO hCAInfo) {
	HRESULT hr = S_OK;
	PZPWSTR awszPropertyValue = NULL;
	DWORD dwPropertyValueIndex = 0;
	DWORD dwFlags = 0;
	DWORD dwExpiration = 0;
	DWORD dwUnits = 0;
	PCCERT_CONTEXT pCert = NULL;
	PSECURITY_DESCRIPTOR pSD = NULL;
	HCERTTYPE hCertType = NULL;
	HCERTTYPE hCertTypeNext = NULL;

	// simple name of the CA
	hr = Certcli$CAGetCAProperty( hCAInfo, CA_PROP_NAME, &awszPropertyValue );
	CHECK_RETURN_FAIL("CAGetCAProperty(CA_PROP_NAME)", hr)
	BadgerDispatch(g_dispatch, "[+] Enterprise CA Name        : %ls\n", awszPropertyValue[dwPropertyValueIndex]);
	SAFE_CAFREECAPROPERTY( hCAInfo, awszPropertyValue )
	dwPropertyValueIndex = 0;

	// dns name of the machine
	hr = Certcli$CAGetCAProperty( hCAInfo, CA_PROP_DNSNAME, &awszPropertyValue );
	CHECK_RETURN_FAIL("CAGetCAProperty(CA_PROP_DNSNAME)", hr);
	BadgerDispatch(g_dispatch, "[+] DNS Hostname              : %ls\n", awszPropertyValue[dwPropertyValueIndex]);
	SAFE_CAFREECAPROPERTY( hCAInfo, awszPropertyValue )
	dwPropertyValueIndex = 0;

	// flags
	hr = Certcli$CAGetCAFlags( hCAInfo, &dwFlags );
	CHECK_RETURN_FAIL("CAGetCAFlags", hr)
	BadgerDispatch(g_dispatch, "[+] Flags                     :");
	if (CA_FLAG_NO_TEMPLATE_SUPPORT & dwFlags) {
		BadgerDispatch(g_dispatch, " NO_TEMPLATE_SUPPORT");
	}
	if (CA_FLAG_SUPPORTS_NT_AUTHENTICATION & dwFlags) {
		BadgerDispatch(g_dispatch, " SUPPORTS_NT_AUTHENTICATION");
	}
	if (CA_FLAG_CA_SUPPORTS_MANUAL_AUTHENTICATION & dwFlags) {
		BadgerDispatch(g_dispatch, " CA_SUPPORTS_MANUAL_AUTHENTICATION");
	}
	if (CA_FLAG_CA_SERVERTYPE_ADVANCED & dwFlags) {
		BadgerDispatch(g_dispatch, " CA_SERVERTYPE_ADVANCED");
	}
	BadgerDispatch(g_dispatch, "\n");

	// expiration
	hr = Certcli$CAGetCAExpiration( hCAInfo, &dwExpiration, &dwUnits );
	CHECK_RETURN_FAIL("CAGetCAExpiration", hr)
	BadgerDispatch(g_dispatch, "[+] Expiration                : %lu", dwExpiration);
	if (CA_UNITS_DAYS == dwUnits) {
		BadgerDispatch(g_dispatch, " days\n");
	} else if (CA_UNITS_WEEKS == dwUnits) {
		BadgerDispatch(g_dispatch, " weeks\n");
	} else if (CA_UNITS_MONTHS == dwUnits) {
		BadgerDispatch(g_dispatch, " months\n");
	} else if (CA_UNITS_YEARS == dwUnits) {
		BadgerDispatch(g_dispatch, " years\n");
	}

	// certificate
	hr = Certcli$CAGetCACertificate( hCAInfo, &pCert );
	CHECK_RETURN_FAIL("CAGetCACertificate", hr);
	BadgerDispatch(g_dispatch, "[+] CA Cert\n");
	hr = _adcs_enum_cert(pCert);
	CHECK_RETURN_FAIL("_adcs_enum_cert", hr);

	// permissions
	hr = Certcli$CAGetCASecurity( hCAInfo, &pSD );
	CHECK_RETURN_FAIL("CAGetCASecurity", hr);
	BadgerDispatch(g_dispatch, "[+] Permissions\n");
	hr = _adcs_enum_ca_permissions(pSD);
	CHECK_RETURN_FAIL("_adcs_enum_ca_permissions", hr);

	// get the first template on the CA
	hr = Certcli$CAEnumCertTypesForCA(hCAInfo, CT_ENUM_MACHINE_TYPES|CT_ENUM_USER_TYPES|CT_FLAG_NO_CACHE_LOOKUP, &hCertTypeNext);
	CHECK_RETURN_FAIL("CAEnumCertTypesForCA", hr)

	// CountCertTypes
	if (! hCertTypeNext) {
		BadgerDispatch(g_dispatch, "\n[-]Found 0 templates on the ca\n");
		goto fail;
	}
	BadgerDispatch(g_dispatch, "\n[+] Found %lu templates on the ca\n", Certcli$CACountCertTypes(hCertTypeNext));

	// loop through templates on the CA
	while (hCertTypeNext) {
		// free previous template
		SAFE_CACLOSECERTTYPE( hCertType );
		hCertType = hCertTypeNext;
		hCertTypeNext = NULL;

		// list info for current template
		hr = _adcs_enum_cert_type(hCertType);
		CHECK_RETURN_FAIL("_adcs_enum_cert_type", hr);
		// get the next template on the CA
		hr = Certcli$CAEnumNextCertType(hCertType, &hCertTypeNext);
		CHECK_RETURN_FAIL("CAEnumNextCertType", hr);
	} // end loop through templates on the CA
	hr = S_OK;
	//internal_printf("\n _adcs_enum_ca SUCCESS.\n");

fail:
	// free CA property
	SAFE_CAFREECAPROPERTY( hCAInfo, awszPropertyValue )
	// free certificate
	if (pCert) {
		Crypt32$CertFreeCertificateContext(pCert);
		pCert = NULL;
	}

	// free security descriptor
	SAFE_LOCAL_FREE(pSD);
	// free CertTypes
	SAFE_CACLOSECERTTYPE( hCertType )
	SAFE_CACLOSECERTTYPE( hCertTypeNext )
	return hr;
} // end _adcs_enum_ca

HRESULT _adcs_enum_cert(PCCERT_CONTEXT pCert) {
	HRESULT hr = S_OK;
	BOOL bReturn = TRUE;
	DWORD dwStrType = CERT_X500_NAME_STR;
	LPWSTR swzNameString = NULL;
	DWORD cchNameString = 0;
	PBYTE lpThumbprint = NULL;
	DWORD cThumbprint = 0;
	SYSTEMTIME systemTime;
	CERT_CHAIN_PARA chainPara;
	PCCERT_CHAIN_CONTEXT pCertChainContext = NULL;

	// subject name
	cchNameString = Crypt32$CertGetNameStringW( pCert, CERT_NAME_RDN_TYPE, 0, &dwStrType, swzNameString, cchNameString );
	swzNameString = BadgerAlloc(cchNameString*sizeof(WCHAR));
	if (1 == Crypt32$CertGetNameStringW( pCert, CERT_NAME_RDN_TYPE, 0, &dwStrType, swzNameString, cchNameString )) {
		hr = E_UNEXPECTED;
		BadgerDispatch(g_dispatch, "[-] Error CertGetNameStringW: 0x%08lx\n", hr);
		goto fail;
	}
	BadgerDispatch(g_dispatch, "  - Subject Name              : %ls\n", swzNameString);
	BadgerFree((PVOID*)&swzNameString);

	// thumbprint
	Crypt32$CertGetCertificateContextProperty(pCert, CERT_SHA1_HASH_PROP_ID, lpThumbprint, &cThumbprint);
	lpThumbprint = BadgerAlloc(cThumbprint);
	bReturn = Crypt32$CertGetCertificateContextProperty(pCert, CERT_SHA1_HASH_PROP_ID, lpThumbprint, &cThumbprint);
	CHECK_RETURN_FALSE("CertGetCertificateContextProperty(CERT_SHA1_HASH_PROP_ID)", bReturn, hr);
	BadgerDispatch(g_dispatch, "  - Thumbprint                : ");
	for (DWORD i=0; i<cThumbprint; i++) {
		BadgerDispatch(g_dispatch, "%02x", lpThumbprint[i]);
	}
	BadgerDispatch(g_dispatch, "\n");
	BadgerFree((PVOID*)&lpThumbprint);

	// serial number
	BadgerDispatch(g_dispatch, "  - Serial Number             : ");
	for (DWORD i=0; i<pCert->pCertInfo->SerialNumber.cbData; i++) {
		BadgerDispatch(g_dispatch, "%02x", pCert->pCertInfo->SerialNumber.pbData[i]);
	}
	BadgerDispatch(g_dispatch, "\n");

	// start date
	BadgerMemset(&systemTime, 0, sizeof(SYSTEMTIME));
	Kernel32$FileTimeToSystemTime(&(pCert->pCertInfo->NotBefore), &systemTime);
	BadgerDispatch(g_dispatch, "  - Start Date                : %hu/%hu/%hu %02hu:%02hu:%02hu\n", systemTime.wMonth, systemTime.wDay, systemTime.wYear, systemTime.wHour, systemTime.wMinute, systemTime.wSecond);

	// end date
	BadgerMemset(&systemTime, 0, sizeof(SYSTEMTIME));
	Kernel32$FileTimeToSystemTime(&(pCert->pCertInfo->NotAfter), &systemTime);
	BadgerDispatch(g_dispatch, "  - End Date                  : %hu/%hu/%hu %02hu:%02hu:%02hu\n", systemTime.wMonth, systemTime.wDay, systemTime.wYear, systemTime.wHour, systemTime.wMinute, systemTime.wSecond);

	// chain
	chainPara.cbSize = sizeof(CERT_CHAIN_PARA);
	chainPara.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
	chainPara.RequestedUsage.Usage.cUsageIdentifier = 0;
	chainPara.RequestedUsage.Usage.rgpszUsageIdentifier = NULL;
	bReturn = Crypt32$CertGetCertificateChain( NULL, pCert, NULL, NULL, &chainPara, 0, NULL, &pCertChainContext );
	CHECK_RETURN_FALSE("CertGetCertificateChain", bReturn, hr);
	BadgerDispatch(g_dispatch, "  - Chain                     :");
	for (DWORD i=0; i<pCertChainContext->cChain; i++) {
		for(DWORD j=0; j<pCertChainContext->rgpChain[i]->cElement; j++) {
			PCCERT_CONTEXT pChainCertContext = pCertChainContext->rgpChain[i]->rgpElement[j]->pCertContext;
			// subject name
			cchNameString = Crypt32$CertGetNameStringW( pChainCertContext, CERT_NAME_RDN_TYPE, 0, &dwStrType, swzNameString, cchNameString );
			swzNameString = BadgerAlloc(cchNameString*sizeof(WCHAR));
			if (1 == Crypt32$CertGetNameStringW( pChainCertContext, CERT_NAME_RDN_TYPE, 0, &dwStrType, swzNameString, cchNameString )) {
				hr = E_UNEXPECTED;
				BadgerDispatch(g_dispatch, "[-] Error CertGetNameStringW: 0x%08lx\n", hr);
				goto fail;
			}
			if (j!=0) {
				BadgerDispatch(g_dispatch, " >>");
			}
			BadgerDispatch(g_dispatch, " %ls", swzNameString);
			BadgerFree((PVOID*)&swzNameString);
		} // end for loop through PCERT_CHAIN_ELEMENT
		BadgerDispatch(g_dispatch, "\n");
	} // end for loop through PCERT_SIMPLE_CHAIN
	hr = S_OK;
	//BadgerDispatch(g_dispatch, "\n _adcs_enum_cert SUCCESS.\n");

fail:
	SAFE_CERTFREECERTIFICATECHAIN(pCertChainContext);
	BadgerFree((PVOID*)&swzNameString);
	BadgerFree((PVOID*)&lpThumbprint);
	return hr;
} // end _adcs_enum_cert

HRESULT _adcs_enum_ca_permissions(PSECURITY_DESCRIPTOR pSD) {
	HRESULT hr = S_OK;
	BOOL bReturn = TRUE;
	PSID pOwner = NULL;
	BOOL bOwnerDefaulted = TRUE;
	LPWSTR swzStringSid = NULL;
	WCHAR swzName[MAX_PATH];
	DWORD cchName = MAX_PATH;
	WCHAR swzDomainName[MAX_PATH];
	DWORD cchDomainName = MAX_PATH;
	BOOL bDaclPresent = TRUE;
	PACL pDacl = NULL;
	BOOL bDaclDefaulted = TRUE;
	ACL_SIZE_INFORMATION aclSizeInformation;
	SID_NAME_USE sidNameUse;

	// Get the owner
	bReturn = Advapi32$GetSecurityDescriptorOwner(pSD, &pOwner, &bOwnerDefaulted);
	CHECK_RETURN_FALSE("GetSecurityDescriptorOwner()", bReturn, hr);
	BadgerDispatch(g_dispatch, "  - Owner                     : ");
	cchName = MAX_PATH;
	BadgerMemset(swzName, 0, cchName*sizeof(WCHAR));
	cchDomainName = MAX_PATH;
	BadgerMemset(swzDomainName, 0, cchDomainName*sizeof(WCHAR));
	if (Advapi32$LookupAccountSidW(	NULL, pOwner, swzName, &cchName, swzDomainName, &cchDomainName, &sidNameUse )) {
		BadgerDispatch(g_dispatch, "%ls\\%ls", swzDomainName, swzName);
	} else {
		BadgerDispatch(g_dispatch, "N/A");
	}

	// Get the owner's SID
	if (Advapi32$ConvertSidToStringSidW(pOwner, &swzStringSid)) {
		BadgerDispatch(g_dispatch, " (%ls)\n", swzStringSid);
	} else {
		BadgerDispatch(g_dispatch, " (N/A)\n");
	}
	SAFE_LOCAL_FREE(swzStringSid);

	// Get the DACL
	bReturn = Advapi32$GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pDacl, &bDaclDefaulted);
	CHECK_RETURN_FALSE("GetSecurityDescriptorDacl", bReturn, hr);
	BadgerDispatch(g_dispatch, "  - Access Rights\n");
	if (! bDaclPresent) {
		BadgerDispatch(g_dispatch, "          N/A\n");
		goto fail;
	}

	// Loop through the ACEs in the ACL
	if (Advapi32$GetAclInformation( pDacl, &aclSizeInformation, sizeof(aclSizeInformation), AclSizeInformation)) {
		for(DWORD dwAceIndex=0; dwAceIndex<aclSizeInformation.AceCount; dwAceIndex++) {
			ACE_HEADER * pAceHeader = NULL;
			ACCESS_ALLOWED_ACE* pAce = NULL;
			ACCESS_ALLOWED_OBJECT_ACE* pAceObject = NULL;
			PSID pPrincipalSid = NULL;
			hr = E_UNEXPECTED;
			if (Advapi32$GetAce( pDacl, dwAceIndex, (LPVOID)&pAceHeader)) {
				pAceObject = (ACCESS_ALLOWED_OBJECT_ACE*)pAceHeader;
				pAce = (ACCESS_ALLOWED_ACE*)pAceHeader;
				int format_ACCESS_ALLOWED_OBJECT_ACE = 0;
				if (ACCESS_ALLOWED_OBJECT_ACE_TYPE == pAceHeader->AceType) {
					//internal_printf("        AceType: ACCESS_ALLOWED_OBJECT_ACE_TYPE\n");
					format_ACCESS_ALLOWED_OBJECT_ACE = 1;
					pPrincipalSid = (PSID)(&(pAceObject->InheritedObjectType)); 
				} else if (ACCESS_ALLOWED_ACE_TYPE == pAceHeader->AceType) { 
					//internal_printf("        AceType: ACCESS_ALLOWED_ACE_TYPE\n");
					pPrincipalSid = (PSID)(&(pAce->SidStart)); 
				} else {
					continue;
				}

				// Get the principal
				cchName = MAX_PATH;
				BadgerMemset(swzName, 0, cchName*sizeof(WCHAR));
				cchDomainName = MAX_PATH;
				BadgerMemset(swzDomainName, 0, cchDomainName*sizeof(WCHAR));
				if (FALSE == Advapi32$LookupAccountSidW( NULL, pPrincipalSid, swzName, &cchName, swzDomainName,	&cchDomainName,	&sidNameUse	)) {
					continue;
				}

				BadgerDispatch(g_dispatch, "    - Principal               : %ls\\%ls\n", swzDomainName, swzName);
				// pAceObject->Mask is always equal to pAce->Mask, not "perfect" but seems to work
				BadgerDispatch(g_dispatch, "    - Access mask             : %08X\n", pAceObject->Mask);
				BadgerDispatch(g_dispatch, "    - Flags                   : %08X\n", pAceObject->Flags);
					
				if (format_ACCESS_ALLOWED_OBJECT_ACE) {
					// Check if Enrollment permission
					if (ADS_RIGHT_DS_CONTROL_ACCESS & pAceObject->Mask) {
						if (ACE_OBJECT_TYPE_PRESENT & pAceObject->Flags) {
							OLECHAR szGuid[MAX_PATH];
							if ( Ole32$StringFromGUID2(&pAceObject->ObjectType, szGuid, MAX_PATH) ) {
								BadgerDispatch(g_dispatch, "    * Extended right          : %ls", szGuid);
							}
							if (
								(!Msvcrt$memcmp(&CertificateEnrollment, &pAceObject->ObjectType, sizeof (GUID))) ||
								(!Msvcrt$memcmp(&CertificateAutoEnrollment, &pAceObject->ObjectType, sizeof (GUID))) ||
								(!Msvcrt$memcmp(&CertificateAll, &pAceObject->ObjectType, sizeof (GUID)))
							) {
								BadgerDispatch(g_dispatch, " Enrollment Rights\n");
							} else if ((!Msvcrt$memcmp(&ManageCA, &pAceObject->ObjectType, sizeof (GUID)))) {
								BadgerDispatch(g_dispatch, " ManageCA Rights\n");
							} else {
								BadgerDispatch(g_dispatch, "\n");
							}
						} // end if ACE_OBJECT_TYPE_PRESENT
					} // end if ADS_RIGHT_DS_CONTROL_ACCESS
				}
				BOOL rightsPrinted = FALSE;
				// Check if ADS_RIGHT_GENERIC_ALL permission
				if (ADS_RIGHT_GENERIC_ALL & pAceObject->Mask) {
					if (! rightsPrinted) {
						BadgerDispatch(g_dispatch, "    - Other rights            : ");
						rightsPrinted = TRUE;
					}
					BadgerDispatch(g_dispatch, "Generic All Rights, ");
				} // end if ADS_RIGHT_GENERIC_ALL permission
				
				// Check if ADS_RIGHT_READ_CONTROL permission
				if ( (ADS_RIGHT_READ_CONTROL & pAceObject->Mask)) {
					if (! rightsPrinted) {
						BadgerDispatch(g_dispatch, "    - Other rights            : ");
						rightsPrinted = TRUE;
					}
					BadgerDispatch(g_dispatch, "Read Rights, ");
				} // end if ADS_RIGHT_READ_CONTROL permission

				// Check if ADS_RIGHT_WRITE_OWNER permission
				if ( (ADS_RIGHT_WRITE_OWNER & pAceObject->Mask)) {
					if (! rightsPrinted) {
						BadgerDispatch(g_dispatch, "    - Other rights            : ");
						rightsPrinted = TRUE;
					}
					BadgerDispatch(g_dispatch, "WriteOwner Rights, ");
				} // end if ADS_RIGHT_WRITE_OWNER permission
				
				// Check if ADS_RIGHT_WRITE_DAC permission
				if ( (ADS_RIGHT_WRITE_DAC & pAceObject->Mask)) {
					if (! rightsPrinted) {
						BadgerDispatch(g_dispatch, "    - Other rights            : ");
						rightsPrinted = TRUE;
					}
					BadgerDispatch(g_dispatch, "WriteDacl Rights, ");
				} // end if ADS_RIGHT_WRITE_DAC permission
				
				// Check if ADS_RIGHT_GENERIC_WRITE permission
				if ( (ADS_RIGHT_GENERIC_WRITE & pAceObject->Mask)) {
					if (! rightsPrinted) {
						BadgerDispatch(g_dispatch, "    - Other rights            : ");
						rightsPrinted = TRUE;
					}
					BadgerDispatch(g_dispatch, "WriteProperty All Rights, ");
				} // end if ADS_RIGHT_GENERIC_WRITE permission

				// Check if ADS_RIGHT_DS_WRITE_PROP permission
				if ( (ADS_RIGHT_DS_WRITE_PROP & pAceObject->Mask)) {
					if (format_ACCESS_ALLOWED_OBJECT_ACE) {
						if (! rightsPrinted) {
						BadgerDispatch(g_dispatch, "    - Other rights            : ");
						rightsPrinted = TRUE;
					}
						BadgerDispatch(g_dispatch, "WriteProperty Rights on ");
						OLECHAR szGuid[MAX_PATH];
						if ( Ole32$StringFromGUID2(&pAceObject->ObjectType, szGuid, MAX_PATH) ) {
							BadgerDispatch(g_dispatch, "%ls, ", szGuid);
						} else {
							BadgerDispatch(g_dispatch, "{ERROR}\n");
						}
					} else {
						// if ACCESS_OBJECT_ACE, there is no ACE_OBJECT_TYPE_PRESENT and ObjectType, so it's like a GENERIC_WRITE
						BadgerDispatch(g_dispatch, "WriteProperty All Rights");
					}
				} // end if ADS_RIGHT_DS_WRITE_PROP permission
				if (rightsPrinted) {
					BadgerDispatch(g_dispatch, "\n");
				}
			} // end if GetAce was successful
		} // end for loop through ACEs (AceCount)
	} // end else GetAclInformation was successful
	hr = S_OK;
	//internal_printf("\n _adcs_enum_ca_permissions SUCCESS.\n");
fail:
	return hr;
} // end _adcs_enum_ca_permissions

HRESULT _adcs_enum_cert_type(HCERTTYPE hCertType) {
	HRESULT hr = S_OK;
	PZPWSTR awszPropertyValue = NULL;
	DWORD dwPropertyValue = 0;
	DWORD dwPropertyValueIndex = 0;
	FILETIME ftExpiration;
	FILETIME ftOverlap;
	DWORD cPeriodUnits = 0;
	PERIODUNITS * prgPeriodUnits = NULL;
	PSECURITY_DESCRIPTOR pSD = NULL;
	CHAR szEKU[MAX_PATH];

	// Common name of the certificate type
	hr = Certcli$CAGetCertTypeProperty( hCertType, CERTTYPE_PROP_CN, &awszPropertyValue );
	CHECK_RETURN_FAIL("CAGetCertTypeProperty(CERTTYPE_PROP_CN)", hr);
	BadgerDispatch(g_dispatch, "  * Template Name             : %S\n", awszPropertyValue[dwPropertyValueIndex]);
	SAFE_CAFREECERTTYPEPROPERTY(hCertType, awszPropertyValue)
	dwPropertyValueIndex = 0;

	// The display name of a cert type retrieved from Crypt32 ( this accounts for the locale specific display names stored in OIDs)
	hr = Certcli$CAGetCertTypeProperty(hCertType, CERTTYPE_PROP_FRIENDLY_NAME, &awszPropertyValue);
	CHECK_RETURN_FAIL("CAGetCertTypeProperty(CERTTYPE_PROP_FRIENDLY_NAME)", hr);
	BadgerDispatch(g_dispatch, "  - Friendly Name             : %S\n", awszPropertyValue[dwPropertyValueIndex]);
	SAFE_CAFREECERTTYPEPROPERTY(hCertType, awszPropertyValue)
	dwPropertyValueIndex = 0;

	// The OID of this template
	hr = Certcli$CAGetCertTypeProperty(hCertType, CERTTYPE_PROP_OID, &awszPropertyValue);
	CHECK_RETURN_FAIL("CAGetCertTypeProperty(CERTTYPE_PROP_OID)", hr);
	BadgerDispatch(g_dispatch, "  - Template OID              : %S\n", awszPropertyValue[dwPropertyValueIndex]);
	SAFE_CAFREECERTTYPEPROPERTY(hCertType, awszPropertyValue)
	dwPropertyValueIndex = 0;

	// Validity Period
	BadgerMemset(&ftExpiration, 0, sizeof(ftExpiration));
	BadgerMemset(&ftOverlap, 0, sizeof(ftOverlap));
	hr = Certcli$CAGetCertTypeExpiration( hCertType, &ftExpiration, &ftOverlap );
	CHECK_RETURN_FAIL("CAGetCertTypeExpiration()", hr);
	hr = Certcli$caTranslateFileTimePeriodToPeriodUnits( &ftExpiration, TRUE, &cPeriodUnits, (LPVOID*)(&prgPeriodUnits) );
	CHECK_RETURN_FAIL("caTranslateFileTimePeriodToPeriodUnits()", hr);
	BadgerDispatch(g_dispatch, "  - Validity Period           : %ld ", prgPeriodUnits->lCount);
	if (ENUM_PERIOD_SECONDS == prgPeriodUnits->enumPeriod) {
		BadgerDispatch(g_dispatch, "seconds");
	} else if (ENUM_PERIOD_MINUTES == prgPeriodUnits->enumPeriod) {
		BadgerDispatch(g_dispatch, "minutes");
	} else if (ENUM_PERIOD_HOURS == prgPeriodUnits->enumPeriod) {
		BadgerDispatch(g_dispatch, "hours");
	} else if (ENUM_PERIOD_DAYS == prgPeriodUnits->enumPeriod) {
		BadgerDispatch(g_dispatch, "days");
	} else if (ENUM_PERIOD_WEEKS == prgPeriodUnits->enumPeriod) {
		BadgerDispatch(g_dispatch, "weeks");
	} else if (ENUM_PERIOD_MONTHS == prgPeriodUnits->enumPeriod) {
		BadgerDispatch(g_dispatch, "months");
	} else if (ENUM_PERIOD_YEARS == prgPeriodUnits->enumPeriod) {
		BadgerDispatch(g_dispatch, "years");
	}
	BadgerDispatch(g_dispatch, "\n");
	cPeriodUnits = 0;
	SAFE_LOCAL_FREE (prgPeriodUnits);
	prgPeriodUnits = NULL;
	hr = Certcli$caTranslateFileTimePeriodToPeriodUnits( &ftOverlap, TRUE, &cPeriodUnits, (LPVOID*)(&prgPeriodUnits) );
	CHECK_RETURN_FAIL("caTranslateFileTimePeriodToPeriodUnits()", hr);
	BadgerDispatch(g_dispatch, "  - Renewal Period            : %ld ", prgPeriodUnits->lCount);
	if (ENUM_PERIOD_SECONDS == prgPeriodUnits->enumPeriod) {
		BadgerDispatch(g_dispatch, "seconds");
	} else if (ENUM_PERIOD_MINUTES == prgPeriodUnits->enumPeriod) {
		BadgerDispatch(g_dispatch, "minutes");
	} else if (ENUM_PERIOD_HOURS == prgPeriodUnits->enumPeriod) {
		BadgerDispatch(g_dispatch, "hours");
	} else if (ENUM_PERIOD_DAYS == prgPeriodUnits->enumPeriod) {
		BadgerDispatch(g_dispatch, "days");
	} else if (ENUM_PERIOD_WEEKS == prgPeriodUnits->enumPeriod) {
		BadgerDispatch(g_dispatch, "weeks");
	} else if (ENUM_PERIOD_MONTHS == prgPeriodUnits->enumPeriod) {
		BadgerDispatch(g_dispatch, "months");
	} else if (ENUM_PERIOD_YEARS == prgPeriodUnits->enumPeriod) {
		BadgerDispatch(g_dispatch, "years");
	}
	BadgerDispatch(g_dispatch, "\n");
	SAFE_LOCAL_FREE (prgPeriodUnits);
	// Name Flags
	hr = Certcli$CAGetCertTypeFlagsEx( hCertType, CERTTYPE_SUBJECT_NAME_FLAG, &dwPropertyValue );
	CHECK_RETURN_FAIL("CAGetCertTypeFlagsEx(CERTTYPE_SUBJECT_NAME_FLAG)", hr);
	BadgerDispatch(g_dispatch, "  - Name Flags                :");
	if (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT & dwPropertyValue) {
		BadgerDispatch(g_dispatch, " ENROLLEE_SUPPLIES_SUBJECT");
	}
	if (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME & dwPropertyValue) {
		BadgerDispatch(g_dispatch, " ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME");
	}
	if (CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH & dwPropertyValue) {
		BadgerDispatch(g_dispatch, " SUBJECT_REQUIRE_DIRECTORY_PATH");
	}
	if (CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME & dwPropertyValue) {
		BadgerDispatch(g_dispatch, " SUBJECT_REQUIRE_COMMON_NAME");
	}
	if (CT_FLAG_SUBJECT_REQUIRE_EMAIL & dwPropertyValue) {
		BadgerDispatch(g_dispatch, " SUBJECT_REQUIRE_EMAIL");
	}
	if (CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN & dwPropertyValue) {
		BadgerDispatch(g_dispatch, " SUBJECT_REQUIRE_DNS_AS_CN");
	}
	if (CT_FLAG_SUBJECT_ALT_REQUIRE_DNS & dwPropertyValue) {
		BadgerDispatch(g_dispatch, " SUBJECT_ALT_REQUIRE_DNS");
	}
	if (CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL & dwPropertyValue) {
		BadgerDispatch(g_dispatch, " SUBJECT_ALT_REQUIRE_EMAIL");
	}
	if (CT_FLAG_SUBJECT_ALT_REQUIRE_UPN & dwPropertyValue) {
		BadgerDispatch(g_dispatch, " SUBJECT_ALT_REQUIRE_UPN");
	}
	if (CT_FLAG_SUBJECT_ALT_REQUIRE_DIRECTORY_GUID & dwPropertyValue) {
		BadgerDispatch(g_dispatch, " SUBJECT_ALT_REQUIRE_DIRECTORY_GUID");
	}
	if (CT_FLAG_SUBJECT_ALT_REQUIRE_SPN & dwPropertyValue) {
		BadgerDispatch(g_dispatch, " SUBJECT_ALT_REQUIRE_SPN");
	}
	if (CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS & dwPropertyValue) {
		BadgerDispatch(g_dispatch, " SUBJECT_ALT_REQUIRE_DOMAIN_DNS");
	}
	if (CT_FLAG_OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME & dwPropertyValue) {
		BadgerDispatch(g_dispatch, " OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME");
	}
	BadgerDispatch(g_dispatch, "\n");	
	dwPropertyValue = 0;

	// Enrollment Flags
	hr = Certcli$CAGetCertTypeFlagsEx( hCertType, CERTTYPE_ENROLLMENT_FLAG, &dwPropertyValue );
	CHECK_RETURN_FAIL("CAGetCertTypeFlagsEx(CERTTYPE_ENROLLMENT_FLAG)", hr);
	BadgerDispatch(g_dispatch, "  - Enrollment Flags          :");
	if (CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS & dwPropertyValue) {
		BadgerDispatch(g_dispatch, " INCLUDE_SYMMETRIC_ALGORITHMS");
	}
	if (CT_FLAG_PEND_ALL_REQUESTS & dwPropertyValue) {
		BadgerDispatch(g_dispatch, " PEND_ALL_REQUESTS");
	}
	if (CT_FLAG_PUBLISH_TO_KRA_CONTAINER & dwPropertyValue) {
		BadgerDispatch(g_dispatch, " PUBLISH_TO_KRA_CONTAINER");
	}
	if (CT_FLAG_PUBLISH_TO_DS & dwPropertyValue) {
		BadgerDispatch(g_dispatch, " PUBLISH_TO_DS");
	}
	if (CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE & dwPropertyValue) {
		BadgerDispatch(g_dispatch, " AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE");
	}
	if (CT_FLAG_AUTO_ENROLLMENT & dwPropertyValue) {
		BadgerDispatch(g_dispatch, " AUTO_ENROLLMENT");
	}
	if (CT_FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT & dwPropertyValue) {
		BadgerDispatch(g_dispatch, " PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT");
	}
	if (CT_FLAG_DOMAIN_AUTHENTICATION_NOT_REQUIRED & dwPropertyValue) {
		BadgerDispatch(g_dispatch, " DOMAIN_AUTHENTICATION_NOT_REQUIRED");
	}
	if (CT_FLAG_USER_INTERACTION_REQUIRED & dwPropertyValue) {
		BadgerDispatch(g_dispatch, " USER_INTERACTION_REQUIRED");
	}
	if (CT_FLAG_ADD_TEMPLATE_NAME & dwPropertyValue) {
		BadgerDispatch(g_dispatch, " ADD_TEMPLATE_NAME");
	}
	if (CT_FLAG_REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE & dwPropertyValue) {
		BadgerDispatch(g_dispatch, " REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE");
	}
	if (CT_FLAG_ALLOW_ENROLL_ON_BEHALF_OF & dwPropertyValue) {
		BadgerDispatch(g_dispatch, " ALLOW_ENROLL_ON_BEHALF_OF");
	}
	if (CT_FLAG_ADD_OCSP_NOCHECK & dwPropertyValue) {
		BadgerDispatch(g_dispatch, " ADD_OCSP_NOCHECK");
	}
	if (CT_FLAG_ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL & dwPropertyValue) {
		BadgerDispatch(g_dispatch, " ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL");
	}
	if (CT_FLAG_NOREVOCATIONINFOINISSUEDCERTS & dwPropertyValue) {
		BadgerDispatch(g_dispatch, " NOREVOCATIONINFOINISSUEDCERTS");
	}
	if (CT_FLAG_INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS & dwPropertyValue) {
		BadgerDispatch(g_dispatch, " INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS");
	}
	if (CT_FLAG_ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT & dwPropertyValue) {
		BadgerDispatch(g_dispatch, " ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT");
	}
	if (CT_FLAG_ISSUANCE_POLICIES_FROM_REQUEST & dwPropertyValue) {
		BadgerDispatch(g_dispatch, " ISSUANCE_POLICIES_FROM_REQUEST");
	}
	if (CT_FLAG_SKIP_AUTO_RENEWAL & dwPropertyValue) {
		BadgerDispatch(g_dispatch, " SKIP_AUTO_RENEWAL");
	}
	BadgerDispatch(g_dispatch, "\n");	
	dwPropertyValue = 0;	

	// The number of RA signatures required on a request referencing this template
	hr = Certcli$CAGetCertTypePropertyEx( hCertType, CERTTYPE_PROP_RA_SIGNATURE, (LPVOID)(&dwPropertyValue) );
	CHECK_RETURN_FAIL("CAGetCertTypeProperty(CERTTYPE_PROP_RA_SIGNATURE)", hr)
	BadgerDispatch(g_dispatch, "  - Signatures Required       : %lu\n", dwPropertyValue);
	dwPropertyValue = 0;

	// An array of extended key usage OIDs for a cert type
	hr = Certcli$CAGetCertTypeProperty( hCertType, CERTTYPE_PROP_EXTENDED_KEY_USAGE, &awszPropertyValue );
	if (FAILED(hr)) {
		if (CRYPT_E_NOT_FOUND != hr) {
			BadgerDispatch(g_dispatch, "[-] Error CAGetCertTypeProperty(CERTTYPE_PROP_EXTENDED_KEY_USAGE): 0x%08lx\n", hr);
			goto fail;
		} else {
			hr = S_OK;
		}
	}
	BadgerDispatch(g_dispatch, "  - Extended Key Usage        :");
	if ( (NULL == awszPropertyValue) || (NULL == awszPropertyValue[dwPropertyValueIndex]) )  { 
		BadgerDispatch(g_dispatch, " N/A"); 
	} else {
		while(awszPropertyValue[dwPropertyValueIndex]) {
			BadgerMemset(szEKU, 0, MAX_PATH);
			Msvcrt$sprintf(szEKU, "%ls", awszPropertyValue[dwPropertyValueIndex]);
			PCCRYPT_OID_INFO pCryptOidInfo = Crypt32$CryptFindOIDInfo( CRYPT_OID_INFO_OID_KEY, szEKU, 0 );
			if (0 != dwPropertyValueIndex) {
				BadgerDispatch(g_dispatch, ",");
			}
			if (pCryptOidInfo) {
				BadgerDispatch(g_dispatch, " %ls", pCryptOidInfo->pwszName);
			} else {
				BadgerDispatch(g_dispatch, " %ls", awszPropertyValue[dwPropertyValueIndex]);
			}
			dwPropertyValueIndex++;
		}
	}
	BadgerDispatch(g_dispatch, "\n");
	SAFE_CAFREECERTTYPEPROPERTY(hCertType, awszPropertyValue)
	dwPropertyValueIndex = 0;

	// permissions
	hr = Certcli$CACertTypeGetSecurity( hCertType, &pSD );
	CHECK_RETURN_FAIL("CACertTypeGetSecurity", hr);
	BadgerDispatch(g_dispatch, "  - Permissions               :\n");
	hr = _adcs_enum_cert_type_permissions(pSD);
	CHECK_RETURN_FAIL("_adcs_enum_cert_type_permissions", hr);
	BadgerDispatch(g_dispatch, "\n");
	hr = S_OK;
	//BadgerDispatch(g_dispatch, "\n _adcs_enum_cert_type SUCCESS.\n");

fail:
	// free security descriptor
	SAFE_LOCAL_FREE(pSD);
	SAFE_CAFREECERTTYPEPROPERTY(hCertType, awszPropertyValue)
	return hr;
} // end _adcs_enum_cert_type

HRESULT _adcs_enum_cert_type_permissions(PSECURITY_DESCRIPTOR pSD) {
	HRESULT hr = S_OK;
	BOOL bReturn = TRUE;
	PSID pOwner = NULL;
	BOOL bOwnerDefaulted = TRUE;
	LPWSTR swzStringSid = NULL;
	WCHAR swzName[MAX_PATH];
	DWORD cchName = MAX_PATH;
	WCHAR swzDomainName[MAX_PATH];
	DWORD cchDomainName = MAX_PATH;
	BOOL bDaclPresent = TRUE;
	PACL pDacl = NULL;
	BOOL bDaclDefaulted = TRUE;
	ACL_SIZE_INFORMATION aclSizeInformation;
	SID_NAME_USE sidNameUse;

	// Get the owner
	bReturn = Advapi32$GetSecurityDescriptorOwner(pSD, &pOwner, &bOwnerDefaulted);
	CHECK_RETURN_FALSE("CertGetCertificateChain()", bReturn, hr);
	BadgerDispatch(g_dispatch, "  - Owner                     : ");
	cchName = MAX_PATH;
	BadgerMemset(swzName, 0, cchName*sizeof(WCHAR));
	cchDomainName = MAX_PATH;
	BadgerMemset(swzDomainName, 0, cchDomainName*sizeof(WCHAR));
	if (Advapi32$LookupAccountSidW(	NULL, pOwner, swzName, &cchName, swzDomainName, &cchDomainName, &sidNameUse )) {
		BadgerDispatch(g_dispatch, "%ls\\%ls", swzDomainName, swzName);
	} else {
		BadgerDispatch(g_dispatch, "N/A");
	}

	// Get the owner's SID
	if (Advapi32$ConvertSidToStringSidW(pOwner, &swzStringSid)) {
		BadgerDispatch(g_dispatch, " (%ls)\n", swzStringSid);
	} else {
		BadgerDispatch(g_dispatch, " (N/A)\n");
	}
	SAFE_LOCAL_FREE(swzStringSid);

	// Get the DACL
	bReturn = Advapi32$GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pDacl, &bDaclDefaulted);
	CHECK_RETURN_FALSE("GetSecurityDescriptorDacl()", bReturn, hr);
	BadgerDispatch(g_dispatch, "  - Access Rights\n");
	if (FALSE == bDaclPresent) {
		BadgerDispatch(g_dispatch, "          N/A\n");
		goto fail;
	}

	// Loop through ACEs in ACL
	if ( Advapi32$GetAclInformation( pDacl, &aclSizeInformation, sizeof(aclSizeInformation), AclSizeInformation ) ) {
		for(DWORD dwAceIndex=0; dwAceIndex<aclSizeInformation.AceCount; dwAceIndex++) {
			ACE_HEADER * pAceHeader = NULL;
			ACCESS_ALLOWED_ACE* pAce = NULL;
			ACCESS_ALLOWED_OBJECT_ACE* pAceObject = NULL;
			PSID pPrincipalSid = NULL;
			hr = E_UNEXPECTED;

			if ( Advapi32$GetAce( pDacl, dwAceIndex, (LPVOID)&pAceHeader ) ) {
				pAceObject = (ACCESS_ALLOWED_OBJECT_ACE*)pAceHeader;
				pAce = (ACCESS_ALLOWED_ACE*)pAceHeader;
				int format_ACCESS_ALLOWED_OBJECT_ACE = 0;

				if (ACCESS_ALLOWED_OBJECT_ACE_TYPE == pAceHeader->AceType) { 
					//internal_printf("        AceType: ACCESS_ALLOWED_OBJECT_ACE_TYPE\n");
					format_ACCESS_ALLOWED_OBJECT_ACE = 1;
					pPrincipalSid = (PSID)(&(pAceObject->InheritedObjectType)); 
				} else if (ACCESS_ALLOWED_ACE_TYPE == pAceHeader->AceType) { 
					//internal_printf("        AceType: ACCESS_ALLOWED_ACE_TYPE\n");
					pPrincipalSid = (PSID)(&(pAce->SidStart)); 
				} else { 
					continue; 
				}

				// Get the principal
				cchName = MAX_PATH;
				BadgerMemset(swzName, 0, cchName*sizeof(WCHAR));
				cchDomainName = MAX_PATH;
				BadgerMemset(swzDomainName, 0, cchDomainName*sizeof(WCHAR));
				if (FALSE == Advapi32$LookupAccountSidW( NULL, pPrincipalSid, swzName, &cchName, swzDomainName,	&cchDomainName,	&sidNameUse	)) {
					continue;
				}
				
				BadgerDispatch(g_dispatch, "    - Principal               : %ls\\%ls\n", swzDomainName, swzName);
				// pAceObject->Mask is always equal to pAce->Mask, not "perfect" but seems to work
				BadgerDispatch(g_dispatch, "    - Access mask             : %08X\n", pAceObject->Mask);
				BOOL rightsPrinted = FALSE;

				if (format_ACCESS_ALLOWED_OBJECT_ACE) {
					// flags not defined in ACCESS_ALLOWED_ACE_TYPE
					BadgerDispatch(g_dispatch, "    - Flags                   : %08X\n", pAceObject->Flags);
					// Check if Enrollment permission
					if (ADS_RIGHT_DS_CONTROL_ACCESS & pAceObject->Mask) {
						if (ACE_OBJECT_TYPE_PRESENT & pAceObject->Flags) {
							if (
								(!Msvcrt$memcmp(&CertificateEnrollment, &pAceObject->ObjectType, sizeof (GUID))) ||
								(!Msvcrt$memcmp(&CertificateAutoEnrollment, &pAceObject->ObjectType, sizeof (GUID))) ||
								(!Msvcrt$memcmp(&CertificateAll, &pAceObject->ObjectType, sizeof (GUID)))
								) {
								BadgerDispatch(g_dispatch, "    - Rights                  : Enrollment Rights,");
								rightsPrinted = TRUE;
							}
						} // end if ACE_OBJECT_TYPE_PRESENT
					} // end if ADS_RIGHT_DS_CONTROL_ACCESS
				}
				
				// Check if ADS_RIGHT_GENERIC_ALL permission
				if (ADS_RIGHT_GENERIC_ALL & pAceObject->Mask) {
					if (! rightsPrinted) {
						BadgerDispatch(g_dispatch, "    - Other rights            : ");
						rightsPrinted = TRUE;
					}
					BadgerDispatch(g_dispatch, "All Rights, ");
				} // end if ADS_RIGHT_GENERIC_ALL permission
				
				// Check if ADS_RIGHT_WRITE_OWNER permission
				if ( (ADS_RIGHT_WRITE_OWNER & pAceObject->Mask)) {
					if (! rightsPrinted) {
						BadgerDispatch(g_dispatch, "    - Other rights            : ");
						rightsPrinted = TRUE;
					}
					BadgerDispatch(g_dispatch, "WriteOwner Rights, ");
				} // end if ADS_RIGHT_WRITE_OWNER permission
				
				// Check if ADS_RIGHT_WRITE_DAC permission
				if ( (ADS_RIGHT_WRITE_DAC & pAceObject->Mask) ) {
					if (! rightsPrinted) {
						BadgerDispatch(g_dispatch, "    - Other rights            : ");
						rightsPrinted = TRUE;
					}
					BadgerDispatch(g_dispatch, "WriteDacl Rights, ");
				} // end if ADS_RIGHT_WRITE_DAC permission
				
				
				// Check if ADS_RIGHT_GENERIC_WRITE permission
				if ( (ADS_RIGHT_GENERIC_WRITE & pAceObject->Mask) ) {
					if (! rightsPrinted) {
						BadgerDispatch(g_dispatch, "    - Other rights            : ");
						rightsPrinted = TRUE;
					}
					BadgerDispatch(g_dispatch, "WriteProperty Rights, ");
				} // end if ADS_RIGHT_GENERIC_WRITE permission

				// Check if ADS_RIGHT_DS_WRITE_PROP permission
				if ( (ADS_RIGHT_DS_WRITE_PROP & pAceObject->Mask)) {
					if (format_ACCESS_ALLOWED_OBJECT_ACE) {
						if (! rightsPrinted) {
							BadgerDispatch(g_dispatch, "    - Other rights            : ");
							rightsPrinted = TRUE;
						}
						BadgerDispatch(g_dispatch, "WriteProperty Rights on ");
						OLECHAR szGuid[MAX_PATH];
						if ( Ole32$StringFromGUID2(&pAceObject->ObjectType, szGuid, MAX_PATH) ) {
							BadgerDispatch(g_dispatch, "%ls\n", szGuid);
						} else {
							BadgerDispatch(g_dispatch, "{ERROR}\n");
						}
					} else {
						// if ACCESS_OBJECT_ACE, there is no ACE_OBJECT_TYPE_PRESENT and ObjectType, so it's like a GENERIC_WRITE
						if (! rightsPrinted) {
							BadgerDispatch(g_dispatch, "    - Other rights            : ");
							rightsPrinted = TRUE;
						}
						BadgerDispatch(g_dispatch, "WriteProperty All Rights\n");
					}
				} // end if ADS_RIGHT_DS_WRITE_PROP permission
			} // end if GetAce was successful
		} // end for loop through ACEs (AceCount)
	} // end else GetAclInformation was successful
	hr = S_OK;
	//internal_printf("\n _adcs_enum_cert_type_permissions SUCCESS.\n");
fail:
	return hr;
} // end _adcs_enum_cert_type_permissions

VOID ConvertCharToWChar(char* charString, wchar_t** wcharString) {
    int size_needed = Kernel32$MultiByteToWideChar(CP_ACP, 0, charString, -1, NULL, 0);
    *wcharString = (wchar_t*) BadgerAlloc(size_needed * sizeof(wchar_t));
    if (*wcharString) {
        Kernel32$MultiByteToWideChar(CP_ACP, 0, charString, -1, *wcharString, size_needed);
    }
}

void coffee(char **argv, int argc, WCHAR** dispatch) {
	g_dispatch = dispatch;
	if (argc != 1) {
		BadgerDispatch(dispatch, "[!] Usage: adcs_enum.o <domainName>\n[!] Eg.: adcs_enum.o darkvortex.corp\n");
		return;
	}

	HRESULT hr = S_OK;
	WCHAR *domain = NULL;
	ConvertCharToWChar(argv[0], &domain);
	hr = adcs_enum(domain);
	if (S_OK != hr) {
		BadgerDispatch(g_dispatch, "[-] Failed: 0x%08lx\n", hr);
	} else {
		BadgerDispatch(g_dispatch, "[+] Success\n");
	}
	BadgerFree((PVOID*)&domain);
};
