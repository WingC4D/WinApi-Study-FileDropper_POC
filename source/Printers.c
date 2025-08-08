#include "Printers.h"
#include "UserInput.h"
#include "Win32FindDataArray.h"
// Constructing a new data type that represents HelloWorld's function pointer.
typedef void(WINAPI* HelloWorldFunctionPointer)();

void PrintMemoryError(
	LPCWSTR pCFPoint
)
{
	wprintf(L"[X] Failed To Allocate Memory For %s!\nExiting With Error Code : % x\n", pCFPoint, GetLastError());
	return;
}

BOOL PrintProcesses() {

	DWORD		adwProcesses[1024 * 2],
		dwReturnLen1 = 0,
		dwReturnLen2 = 0;


	HANDLE		hProcess;
	HMODULE		hModule = NULL;

	WCHAR		szProc[MAX_PATH];

	// Get the array of PIDs
	if (!EnumProcesses(adwProcesses, sizeof(adwProcesses), &dwReturnLen1)) {
		printf("[!] EnumProcesses Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Calculating the number of elements in the array 
	DWORD dwNmbrOfPids = dwReturnLen1 / sizeof(DWORD);

	printf("[i] Number Of Processes Detected : %d \n", dwNmbrOfPids);

	for (int i = 0; i < dwNmbrOfPids; i++) {

		// If process is not NULL
		if (&adwProcesses[i] != NULL) {

			// Open a process handle 
			if ((hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, adwProcesses[i])) != NULL) {

				// If handle is valid
				// Get a handle of a module in the process 'hProcess'
				// The module handle is needed for 'GetModuleBaseName'
				if (!EnumProcessModules(hProcess, &hModule, sizeof(HMODULE), &dwReturnLen2)) {
					printf("[!] EnumProcessModules Failed [ At Pid: %d ] With Error : %d \n", adwProcesses[i], GetLastError());
				}
				else {
					// If EnumProcessModules succeeded
					// Get the name of 'hProcess' and save it in the 'szProc' variable 
					if (!GetModuleBaseName(hProcess, hModule, szProc, sizeof(szProc) / sizeof(WCHAR))) {
						printf("[!] GetModuleBaseName Failed [ At Pid: %d ] With Error : %d \n", adwProcesses[i], GetLastError());
					}
					else {
						// Printing the process name & its PID
						wprintf(L"[%0.3d] Process \"%s\" - Of Pid : %d \n", i, szProc, adwProcesses[i]);
					}
				}

				// Close process handle 
				CloseHandle(hProcess);
			}
		}

		// Iterate through the PIDs array  
	}

	return TRUE;
}

void PrintDrives(
	LPWSTR pPath
) 
{
	unsigned usArrayLength = (unsigned)wcslen(pPath);
	for (unsigned i = 0; i < usArrayLength; i++) 
	{	
		wprintf(L"[#] - %c\n", pPath[i]);
	}
	return;
}

void PrintCWD(
	LPWSTR pPath
)
{
	wprintf(L"Current Working Path: %s\n", pPath);
	return;
}

BOOL PrintUserName(
	void
) 
{
	WCHAR pUsername[MAX_PATH] = { L'\0' };
	LPDWORD pSizeOfUserName  = NULL;
	if (GetUserNameW(pUsername, pSizeOfUserName) == 0)
	{
		return FALSE;
	}
	wprintf(L"[#] Username: %s\n", pUsername);
	RtlSecureZeroMemory(pUsername, (wcslen(pUsername) + 1));//For Fun.
	return TRUE;
}

void PrintFilesArrayW(
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t
) 
{
	for(unsigned i = 0; i < pFiles_arr_t->count; i++)
	{
		wprintf(L"[%d] File Name: %s\n", i, pFiles_arr_t->pFilesArr[i].pFileName);
	}
}
