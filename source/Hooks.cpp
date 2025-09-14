#include <Hooks.h>

fnMessageBoxA g_pMessageBoxA = MessageBoxA;
namespace Anonymous
{
	 static BOOLEAN PrintDetourStatus
    (
        IN     DWORD dwDetourStatus
    )
    {
        printf("Detours Failed With ErrorCode: 0x%lx\n", dwDetourStatus);

        return FALSE;
    }

}


INT WINAPI HookedMessageBoxA
(
    HWND   hWindowHandle,
    LPCSTR lpEditedBodyText,
    LPCSTR lpEditedHeaderText,
    UINT   uiType
)
{
    printf("[!] Success! Hooked MessageBoxA!\n");

    printf("Intercepted Vars Are:\n\t1. %s\n\t2. %s\n", lpEditedHeaderText, lpEditedBodyText);

    return g_pMessageBoxA(nullptr, lpEditedBodyText, lpEditedHeaderText, uiType);
}



BOOLEAN HookWithVirtualAlloc
(
    IN     PVOID  pFunctionToHook,
    IN     PVOID  pAddressOfMyCode,
    IN     DWORD  sHookLength
)
{
    if (sHookLength < 5) return FALSE;

    DWORD    dwOldProtectionConstant  = NULL,
			 dwRelativeVirtualAddress = NULL,
			 dwFunctionStatus	      = NULL,
			 dwFileSize               = NULL;
    
    HANDLE   hProcess                 = INVALID_HANDLE_VALUE,
			 hHeap                    = INVALID_HANDLE_VALUE,
			 hFile                    = INVALID_HANDLE_VALUE;

	// OpenProcess(PROCESS_ALL_ACCESS, FALSE, 49176);
    HMODULE  hModule                  = nullptr;
    CHAR     lpFilePath[MAX_PATH]     = { };
    PBYTE    pFunctionData            = nullptr;

    if ((dwFunctionStatus = GetEnvironmentVariableA("WinDir", lpFilePath, MAX_PATH)) == NULL) return FALSE;

    if (strcat_s(lpFilePath, MAX_PATH, "\\System32\\kernel32.dll") != ERROR_SUCCESS) return FALSE;

    hModule = GetModuleHandleA(const_cast<LPCSTR>("kernel32.dll"));

    if (hModule == nullptr) return FALSE;

	hFile = CreateFileA(lpFilePath, GENERIC_READ, NULL, nullptr, OPEN_EXISTING, NULL, nullptr);

    if (hFile == nullptr || hFile == INVALID_HANDLE_VALUE) return  FALSE;

	if((dwFileSize = GetFileSize(hFile, nullptr))== NULL) return FALSE;

	hHeap = GetProcessHeap();

    if (hHeap == INVALID_HANDLE_VALUE || hHeap == nullptr) return FALSE;

    pFunctionData = static_cast<PBYTE>(HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwFileSize));

    if (pFunctionData == nullptr) return FALSE;

    ReadFile(hFile, pFunctionData, dwFileSize, &dwFunctionStatus, nullptr);

    if (dwFunctionStatus  !=  dwFileSize || pFunctionData == nullptr) return FALSE;

    if (VirtualProtect(pFunctionToHook, sHookLength, PAGE_READWRITE, &dwOldProtectionConstant) == FALSE) return FALSE;

    //ReadProcessMemory(GetCurrentProcess(), pFunctionToHook, )




    memset(pFunctionToHook, 0x90, sHookLength);

    dwRelativeVirtualAddress = static_cast<DWORD>(reinterpret_cast<DWORD64>(pAddressOfMyCode) - reinterpret_cast<DWORD64>(pFunctionToHook) - 0x05);

    if (VirtualProtect(pAddressOfMyCode, sHookLength, dwOldProtectionConstant, &dwOldProtectionConstant) == FALSE) return FALSE;

	return FALSE;
}

BOOLEAN HookLocalThreadUsingDetours
(
	IN     PVOID   fnFunctionToHook,
    IN     PVOID   pDetourFunction,
    IN     HANDLE  hThreadToHook
)
{
    if (fnFunctionToHook == nullptr || hThreadToHook == nullptr || hThreadToHook == INVALID_HANDLE_VALUE) return FALSE;

    DWORD dwDetoursStatus = NO_ERROR;

    if  ((dwDetoursStatus = DetourTransactionBegin()) != NO_ERROR) return Anonymous::PrintDetourStatus(dwDetoursStatus);

    if  ((dwDetoursStatus = DetourUpdateThread(hThreadToHook)) != NO_ERROR) return Anonymous::PrintDetourStatus(dwDetoursStatus);

    if  ((dwDetoursStatus = DetourAttach(reinterpret_cast<PVOID *>(&g_pMessageBoxA), pDetourFunction)) != NO_ERROR) return Anonymous::PrintDetourStatus(dwDetoursStatus);

    if  ((dwDetoursStatus = DetourTransactionCommit()) != NO_ERROR) return Anonymous::PrintDetourStatus(dwDetoursStatus);

	return TRUE;
}

BOOLEAN UnHookLocalThreadUsingDetours
(
    IN     PVOID   fnOriginalHookedFunction,
    IN     PVOID   pDetourFunction,
    IN     HANDLE  hThreadToUnHook
)
{
    if (fnOriginalHookedFunction == nullptr || pDetourFunction == nullptr || hThreadToUnHook== nullptr) return FALSE;

	DWORD dwDetoursStatus = NO_ERROR;

    if  ((dwDetoursStatus = DetourTransactionBegin()) != NO_ERROR) return Anonymous::PrintDetourStatus(dwDetoursStatus);

    if  ((dwDetoursStatus = DetourUpdateThread(hThreadToUnHook)) != NO_ERROR) return Anonymous::PrintDetourStatus(dwDetoursStatus);

    if  ((dwDetoursStatus = DetourDetach(reinterpret_cast<PVOID *>(&g_pMessageBoxA), pDetourFunction)) != NO_ERROR) return Anonymous::PrintDetourStatus(dwDetoursStatus);

    if  ((dwDetoursStatus = DetourTransactionCommit()) != NO_ERROR) return Anonymous::PrintDetourStatus(dwDetoursStatus);

    return TRUE;
}














/*
BOOLEAN FindProcessWithDesiredFunction
(
    IN     LPCWSTR lpFunctionName,
       OUT PHANDLE phProcess
)
{
    NTSTATUS					NtStatus         = 0;
    HANDLE                      hProcess_1       = INVALID_HANDLE_VALUE,
                                hHeap            = INVALID_HANDLE_VALUE;
    PPEB                        pPeb             = nullptr;
    PPEB_LDR_DATA               pLoaderDataTable = nullptr;
    PROCESS_BASIC_INFORMATION   ProcBasicInfo    = {};
    PLDR_DATA_TABLE_ENTRY       pLDREntry        = nullptr;
    PLIST_ENTRY					pLDRHeadEntry    = nullptr,
                                pLDRCurrentEntry = nullptr;
    fnNTQueryProcessInformation NtQueryProcInfo  = nullptr;
    DWORD                       dwTargetPID      = 0x00000000,
                                dwReturnLength   = 0x00000000;
    HMODULE                     hProcessModule   = nullptr;
    LPWSTR                      lpDllName        = nullptr;

    if ((hHeap = GetProcessHeap()) == INVALID_HANDLE_VALUE) return FALSE;

    if ((NtQueryProcInfo = reinterpret_cast<fnNTQueryProcessInformation>(GetProcAddress(GetModuleHandleW(L"NTDLL.dll"), "NtQueryInformationProcess"))) == nullptr) return FALSE;

    if ((pPeb = static_cast<PPEB>(HeapAlloc(hHeap,HEAP_ZERO_MEMORY,  sizeof(PEB)))) == nullptr) return FALSE;

    if ((pLoaderDataTable = static_cast<PPEB_LDR_DATA>(HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(PEB_LDR_DATA)))) == nullptr) return FALSE;

    FetchProcessHandleNtQuerySystemInformation(L"chrome.exe", &dwTargetPID, phProcess);

   if ((NtStatus = NtQueryProcInfo(
       *phProcess,
       ProcessBasicInformation,
       &ProcBasicInfo,
       sizeof(PROCESS_BASIC_INFORMATION),
       &dwReturnLength)) != 0x00) return  FALSE;

    ReadStructureFromProcess(*phProcess, ProcBasicInfo.PebBaseAddress, reinterpret_cast<PVOID *>(&pPeb),sizeof(PEB), hHeap);

    ReadStructureFromProcess(*phProcess, pPeb->Ldr, reinterpret_cast<PVOID *>(&pLoaderDataTable),sizeof(PEB_LDR_DATA), hHeap);

    pLDREntry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(pLoaderDataTable->InMemoryOrderModuleList.Flink);

    if ((pLDRHeadEntry = static_cast<PLIST_ENTRY>(HeapAlloc(hHeap, HEAP_ZERO_MEMORY,sizeof(LIST_ENTRY)))) == nullptr) return FALSE;

    ReadStructureFromProcess(*phProcess, pLoaderDataTable->InMemoryOrderModuleList.Flink, reinterpret_cast<PVOID*>(&pLDREntry), sizeof(PLDR_DATA_TABLE_ENTRY), hHeap);

    do
    {
        lpDllName = static_cast<LPWSTR>(HeapAlloc(hHeap, HEAP_ZERO_MEMORY, pLDREntry->FullDllName.Length + 1));


        pLDRCurrentEntry = static_cast<PLIST_ENTRY>(HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(LDR_DATA_TABLE_ENTRY)));

        ReadStructureFromProcess(*phProcess, pLDREntry->InMemoryOrderLinks.Flink, reinterpret_cast<PVOID *>(&pLDRCurrentEntry),sizeof(LDR_DATA_TABLE_ENTRY), hHeap);

        /*
        if (_wcsicmp(pLDREntry->FullDllName.Buffer, L"user32.dll") == 0)
        {
            hProcessModule = reinterpret_cast<HMODULE>(pLDREntry->Reserved2);

            break;
        }

        ReadStructureFromProcess(*phProcess, pLDREntry->FullDllName.Buffer, reinterpret_cast<PVOID*>(&lpDllName), pLDREntry->FullDllName.Length, hHeap);

        pLDRCurrentEntry = pLDRCurrentEntry->Blink;
    }
    while (pLDRCurrentEntry != pLDRHeadEntry);





    return TRUE;
}
*/