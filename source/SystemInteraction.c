#include "SystemInteraction.h"

//Automates Taking All System-Available Drive Letter And putting Them To A Path Buffer.
BOOL FetchDrives(LPWSTR pPath)
{
	DWORD dwDrivesBitMask = GetLogicalDrives();

	if (dwDrivesBitMask == 0) return FALSE;

	WCHAR base_wchar = L'A';

	unsigned drives_index = 0;

	for (WCHAR loop_index = 0; loop_index <= 26; loop_index++)
	{
		if (dwDrivesBitMask & (1 << loop_index)) {
			pPath[drives_index] = base_wchar + loop_index;
			drives_index++;
		}
	}
	pPath[drives_index] = L'\0';
	return TRUE;
}

LPWIN32_FIND_DATA_ARRAYW RefetchFilesArrayW(IN LPWSTR pPath, OUT LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t )
{
	FreeFileArray(pFiles_arr_t);
	return FetchFileArrayW(pPath);
}

LPWIN32_FIND_DATA_ARRAYW FetchFileArrayW(IN LPWSTR pPath)
{
	WIN32_FIND_DATAW find_data_t;
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t;
	USHORT i = 0;
	size_t sArraySize = 3;
	if (
		!(pFiles_arr_t = malloc(sArraySize * sizeof(WIN32_FIND_DATA_ARRAYW)))
		) return NULL;
	if (
		!(pFiles_arr_t->pFilesNames_arr = (PWIN32_FILE_IN_ARRAY)calloc(sArraySize, sizeof(WIN32_FILE_IN_ARRAY)))
		) return NULL;
	wcscat_s(pPath, MAX_PATH, L"*");

	if (
		(pFiles_arr_t->hBaseFile = FindFirstFileW(pPath, &find_data_t)) == INVALID_HANDLE_VALUE
		) return NULL;
	
	pPath[wcslen(pPath) - 1] = L'\0';
	
	while (FindNextFileW(pFiles_arr_t->hBaseFile, &find_data_t))
	{
		if (i == sArraySize / 2 && !FileBufferRoundUP(&sArraySize, &pFiles_arr_t->pFilesNames_arr)) return NULL;

		size_t sFileName = wcslen(find_data_t.cFileName);

		LPWSTR pFileName;
		if (!(pFileName = calloc(sFileName + 1, sizeof(WCHAR)))) return NULL;
		
		wcscpy_s(pFileName, sFileName + 1, find_data_t.cFileName);
		pFileName[sFileName] = '\0';
		pFiles_arr_t->pFilesNames_arr[i].pFileName = pFileName;
		pFiles_arr_t->pFilesNames_arr[i].index = i;
		i++;
	}
	pFiles_arr_t->count = i;
	return pFiles_arr_t;
}

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
		WCHAR local_temp[MAX_PATH] = { L'\0' };
		for (int i = 0; i < lstrlenW(pe32Process.szExeFile); i++)
		{
			local_temp[i] = (WCHAR)tolower(pe32Process.szExeFile[i]);
		}
		if (!wcscmp(local_temp, pProcessName))
		{
			hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32Process.th32ProcessID);
			wprintf(L"[i] Opened a HANDLE to process: \"%s\"\n[i] Process id: %d\n", local_temp, pe32Process.th32ProcessID);
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