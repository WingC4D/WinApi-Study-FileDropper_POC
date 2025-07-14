#include "main.h"




int main(void) 
{
	call();
	
	LPPAYLOAD pPayload = Test();
	
	if (pPayload == NULL) return -5;
	
	wprintf(L"[i] Payload in main: %s\n[i] Payload Heap Address: 0x%p\n[!] Encrypting Payload...\n", pPayload->pPayloadAddress, pPayload->pPayloadAddress);
	BYTE *pbKey[4] = {0xEFBEADDE};

	XorByInputKey(pPayload->pPayloadAddress, *pPayload->dwpPayloadSize, &pbKey, 4);

	wprintf(L"[i] Payload in main: %s\n[i] Payload Heap Address: 0x%p\n[!] Encrypting Payload...\n", pPayload->pPayloadAddress, pPayload->pPayloadAddress);

	WCHAR pPath[MAX_PATH] = { L'\0' };

	FetchDrives(pPath);
	
	if (pPath[0] == L'0')
	{
		printf("[X] Failed To Fetch Drives!\n[X] Exiting With Error Code: %x\n", GetLastError());
		return -1;
	}
	
	PrintDrives(pPath);
	
	while (!UserInputDrives(&pPath))
	{
		wprintf(
			L"[X] Wrong Input!\n"
		);
		PrintDrives(
			pPath
		);
	}
	
	PrintCWD(&pPath);
	
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t = FetchFileArrayW(&pPath);
	
	if (pFiles_arr_t == NULL) 
	{
		printf("[X] Folder Choosing || Printing Failed!\n[X] Exiting With Error Code : % x\n", GetLastError());
		return -2;
	}
	
	PrintFilesArrayW(pFiles_arr_t);
	
	while (!UserInputFolders(pPath, pFiles_arr_t)) {
		
		if (pFiles_arr_t == NULL) {
			printf("[!] No Files Under Current Folder.\n");
			break;
		}
		pFiles_arr_t = RefetchFilesArrayW(&pPath, pFiles_arr_t);
		if (pFiles_arr_t == NULL) {
			printf("[!] No Files Under Current Folder.\n");
			break;
		}
		PrintCWD(&pPath);
		PrintFilesArrayW(pFiles_arr_t);
	}
 	
	
	wprintf(L"File Name: %s", *pFiles_arr_t->pFiles_arr->file_data.cFileName);

	if (pFiles_arr_t->pFiles_arr->file_data.dwFileAttributes & FILE_ATTRIBUTE_NORMAL)
	{
		printf("[X] You Choose  !\n[X] Exiting With Error Code : % x\n", GetLastError());
		return -3;
	}
	
	if(pFiles_arr_t != NULL)FreeFileArray(pFiles_arr_t);
	HANDLE hFile = INVALID_HANDLE_VALUE;
			/*
		 * GENERIC_READ = 0x80000000
		 * GENERIC_WRITE = 0x40000000. (0d1073741824).
		 * GENERIC_READ | GENERIC_WRITE = 0xC0000000. (0d3221225472).
		 */
	
	hFile = CreateFileW(
		&pPath,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ,//(0d1).
		NULL, //(0d0).
		CREATE_ALWAYS, //(0d2).
		FILE_ATTRIBUTE_NORMAL,//(0x80 || 0d128).
		NULL 
	);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("[X] Failed To Fetch File Handle!\n[X] Exiting With Error Code: %x\n", GetLastError());
		return -4;
	}

	CloseHandle(hFile);
	printf("[#] Payload Created Successfully! :)\n");
	printf("[#] Press 'Enter' To Exit! :)");
	return 0;
}

