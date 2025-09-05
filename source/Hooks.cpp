#include <Hooks.h>

BOOLEAN HookWithVirtualAlloc
(
    IN     PVOID  pFunctionToHook,
    IN     PVOID  pAddressOfMyCode,
    IN     DWORD  sHookLength
)
{
    if (sHookLength < 5) return FALSE;

    DWORD dwOldProtectionConstant  = NULL,
		  dwRelativeVirtualAddress = NULL;

    HANDLE hProcess = INVALID_HANDLE_VALUE;// OpenProcess(PROCESS_ALL_ACCESS, FALSE, 49176);

    if (VirtualProtect(pFunctionToHook, sHookLength, PAGE_READWRITE, &dwOldProtectionConstant) == FALSE) return FALSE;

    memset(pFunctionToHook, static_cast<SIZE_T>(sHookLength), 0x90);

    dwRelativeVirtualAddress = reinterpret_cast<DWORD>(pAddressOfMyCode) - reinterpret_cast<DWORD>(pFunctionToHook) - 0x05;

    if (VirtualProtect(pAddressOfMyCode, sHookLength, dwOldProtectionConstant, &dwOldProtectionConstant) == FALSE) return FALSE;



	return FALSE;
}







void LogAndPrintLMBClick()
{
	
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