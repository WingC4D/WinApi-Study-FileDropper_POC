#include "rsrcPayloadTest.h"

PVOID Test() 
{
	HRSRC   hRsrc           = NULL;
	HGLOBAL hGlobal         = NULL;
	PVOID   pPayloadAddress = NULL;
	SIZE_T  sPayloadSize     = NULL;
	
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
	
	pPayloadAddress = LockResource(hGlobal);

	if (pPayloadAddress == NULL) {
		wprintf(L"LockResource [X] Failed With Error Code: %x\n", GetLastError());
		return NULL;
	}

	sPayloadSize = SizeofResource(NULL, hRsrc);
	
	if (sPayloadSize == NULL) {
		wprintf(L"[X] SizeofResource Failed With Error Code: %x\n", GetLastError());
		return NULL;
	}
	
	wprintf(L"[i] pPayloadAddress var : 0x%p \n", pPayloadAddress);
	wprintf(L"[i] sPayloadSize var : %lu \n", sPayloadSize);

	PVOID pPayload = HeapAlloc(GetProcessHeap(), 0, sPayloadSize);
	
	if (pPayload != NULL) memcpy(pPayload, pPayloadAddress, sPayloadSize);

	return pPayload;
}