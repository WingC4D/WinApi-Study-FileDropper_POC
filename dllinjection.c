#include "dllinjection.h"

HANDLE FetchProcess(IN LPWSTR pProcessName, OUT PDWORD dwProcessId)
{	
	
	HANDLE hProcess = INVALID_HANDLE_VALUE;
	HANDLE hSnapshot;
	HANDLE hHeap;
	PROCESSENTRY32 pe32Process = { .dwSize = sizeof(PROCESSENTRY32) };
	
	if ((hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL)) == INVALID_HANDLE_VALUE) return hSnapshot;

	if (!(hHeap = GetProcessHeap())) goto _cleanup;
	
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
			wprintf(L"[i] Opened a HANDLE to process: \"%s\" | id: %d\n", local_temp, pe32Process.th32ProcessID);
			goto _cleanup; 
		}
	} while (Process32Next(hSnapshot, &pe32Process));

	printf("Failed To Find The Desired, pe32Process.\n");
_cleanup:	
	*dwProcessId = pe32Process.th32ProcessID;

	if (hHeap)HeapDestroy(hHeap);
	
	if (hSnapshot != INVALID_HANDLE_VALUE) CloseHandle(hSnapshot);

	return hProcess;
}






int inject_dll(void) 
{
	DWORD dwProcessId;
	LPWSTR szProcessname = L"calculatorapp.exe";
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapshot == INVALID_HANDLE_VALUE) return -1;
	PROCESSENTRY32 Process = { .dwSize = sizeof(PROCESSENTRY32) };
	if (!Process32First(hSnapshot, &Process)) {
		printf("failed!\nexiting with errorcode: %x\n", GetLastError());
		return -1;
	}
	WCHAR temp_1[MAX_PATH]; WCHAR temp_2[MAX_PATH];
	do {
			wprintf(L"[#] Name: %s id: %d\n", Process.szExeFile ,Process.th32ProcessID);
			WCHAR LowerName[MAX_PATH * 2];

			if (Process.szExeFile) {
				DWORD	dwSize = lstrlenW(Process.szExeFile);
				DWORD   i = 0;

				RtlSecureZeroMemory(LowerName, sizeof(LowerName));

				if (dwSize < MAX_PATH * 2) {

					for (; i < dwSize; i++)
						LowerName[i] = (WCHAR)tolower(Process.szExeFile[i]);

					LowerName[i++] = '\0';
				}
			}

			// If the lowercase'd pe32Process name matches the pe32Process we're looking for
			if (wcscmp(LowerName, szProcessname) == 0) {
				// Save the PID
				dwProcessId = Process.th32ProcessID;
				// Open a handle to the pe32Process
				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Process.th32ProcessID);
				if (Process.th32ProcessID == 0)
					printf("[!] OpenProcess Failed With Error : %d \n", GetLastError());

				break;
			}
	} while (Process32Next(hSnapshot, &Process));
	
	//while (Process32(hSnapshot, &pe32Process)) wprintf(L"[#] Name: %s id: %d\n",pe32Process.szExeFile ,pe32Process.th32ProcessID);
	return 0;
}