#include "rsrcPayloadTest.h"

LPPAYLOAD Test()
{
	HRSRC   hRsrc = NULL;
	HANDLE hHeap = GetProcessHeap();
	
	HGLOBAL hGlobal = NULL;
	DWORD dwPayloadSize = NULL;

	unsigned char *pKey = "0xdeadbeef";

	hRsrc = FindResourceW(NULL,MAKEINTRESOURCEW(IDR_RCDATA1),RT_RCDATA);
	
	if (hRsrc == NULL) {
		wprintf(L"[X] FindResourceW Failed With Error Code: %x\n", GetLastError());
		return NULL;
	}
	
	hGlobal = LoadResource(NULL, hRsrc);
	
	if (hGlobal == NULL) {
		wprintf(L"[X] LoadResource Failed With Error Code: %x\n", GetLastError());
		return NULL;
	}
	
	PVOID pResource = LockResource(hGlobal);

	if (pResource == NULL) {
		wprintf(L"LockResource [X] Failed With Error Code: %x\n", GetLastError());
		return NULL;
	}

	LPPAYLOAD pPayload = HeapAlloc(hHeap, 0, sizeof(PAYLOAD));

	RC4CONTEXT Context = { NULL };

	pPayload->dwPayloadSize = SizeofResource(NULL, hRsrc);

	if (!pPayload->dwPayloadSize) {
		wprintf(L"[X] SizeofResource Failed With Error Code: %x\n", GetLastError());
		return NULL;
	}
	wprintf(L"[i] pPayloadAddress var : 0x%p \n", pResource);

	PVOID pPayloadCopy = HeapAlloc(hHeap, 0, pPayload->dwPayloadSize);

	memcpy(pPayloadCopy, pResource, pPayload->dwPayloadSize);

	RC4Init(&Context, pKey, strlen(pKey));

	pPayload->pPayloadAddress = malloc(wcslen(pPayload) + 1);

	wprintf(L"[i] Payload in main: %s\n[i] Payload Heap Address: 0x%p\n[!] Encrypting Payload...\n", pPayload->pPayloadAddress, pPayload->pPayloadAddress);

	RC4Encrypt(&Context, pPayloadCopy, pPayload->pPayloadAddress, pPayload->dwPayloadSize);

	if (pPayload->pPayloadAddress == NULL) return NULL;

	wprintf(L"[i] Payload in main: %s\n[i] Payload Heap Address: 0x%p\n[!] Decrypting Payload...\n", pPayload->pPayloadAddress, pPayload->pPayloadAddress);

	return pPayload;
}