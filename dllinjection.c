#include "dllinjection.h"

#define _CRT_SECURE_NO_WARNNINGS

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

			// If the lowercase'd process name matches the process we're looking for
			if (wcscmp(LowerName, szProcessname) == 0) {
				// Save the PID
				dwProcessId = Process.th32ProcessID;
				// Open a handle to the process
				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Process.th32ProcessID);
				if (Process.th32ProcessID == 0)
					printf("[!] OpenProcess Failed With Error : %d \n", GetLastError());

				break;
			}
	} while (Process32Next(hSnapshot, &Process));
	
	//while (Process32(hSnapshot, &Process)) wprintf(L"[#] Name: %s id: %d\n",Process.szExeFile ,Process.th32ProcessID);
	return 0;
}