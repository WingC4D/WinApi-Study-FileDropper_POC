#include "rsrcPayloadTest.h"

LPPAYLOAD Test() 
{
	HRSRC   hRsrc            =  NULL ;
	
	HANDLE hHeap             = GetProcessHeap();

	LPPAYLOAD pPayload       = HeapAlloc(hHeap, 0, sizeof(LPPAYLOAD));
	
	HGLOBAL hGlobal          =  NULL ;
	
	DWORD dwPayloadSize      =  NULL ;
	
	
	

	hRsrc = FindResourceW(
		NULL,
		MAKEINTRESOURCEW(IDR_RCDATA1),
		RT_RCDATA
	);
	
	if (hRsrc == NULL) {
		wprintf(L"[X] FindResourceW Failed With Error Code: %x\n", GetLastError());
		return NULL;
	}
	
	hGlobal = LoadResource(
		NULL,
		hRsrc
	);
	
	if (hGlobal == NULL) {
		wprintf(L"[X] LoadResource Failed With Error Code: %x\n", GetLastError());
		return NULL;
	}
	
	PVOID pPayloadAddress = LockResource(hGlobal);

	if (pPayloadAddress == NULL) {
		wprintf(L"LockResource [X] Failed With Error Code: %x\n", GetLastError());
		return NULL;
	}

	DWORD sPayloadSize = SizeofResource(NULL, hRsrc);
	
	if (pPayload->dwpPayloadSize == NULL) {
		wprintf(L"[X] SizeofResource Failed With Error Code: %x\n", GetLastError());
		return NULL;
	}
	wprintf(L"[i] pPayloadAddress var : 0x%p \n", pPayloadAddress);
	
	pPayload->pPayloadAddress = malloc(wcslen(pPayload) * sizeof(WCHAR));
	
	memcpy(pPayload->pPayloadAddress, pPayloadAddress, sPayloadSize);
	
	if (pPayload->pPayloadAddress == NULL) return NULL;
	
	pPayload->dwpPayloadSize = HeapAlloc(hHeap, 0, sizeof(DWORD));

	memcpy(pPayload->dwpPayloadSize, &sPayloadSize, sizeof(DWORD));
	
	wprintf(L"[i] dwpPayloadSize var : %lu \n", *pPayload->dwpPayloadSize);
	
	return pPayload;
}