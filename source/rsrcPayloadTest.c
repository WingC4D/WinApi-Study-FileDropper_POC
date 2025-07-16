#include "rsrcPayloadTest.h"

LPTEXT Test()
{
	HRSRC   hRsrc = NULL;
	HANDLE hHeap = GetProcessHeap();
	
	HGLOBAL hGlobal = NULL;
	DWORD sText = NULL;

	unsigned char *pKey[2049] = {'\0'};

	//printf("Please Enter A Key:\n");

	fgets(pKey, 2048, stdin);
	
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

	LPTEXT pText_t = HeapAlloc(hHeap, 0, sizeof(TEXT));

	Context Context = { NULL };

	pText_t->sText = SizeofResource(NULL, hRsrc);

	if (!pText_t->sText) {
		wprintf(L"[X] SizeofResource Failed With Error Code: %x\n", GetLastError());
		return NULL;
	}
	printf("[i] 0x%p \n", pResource);

	pText_t->pText = HeapAlloc(hHeap, 0, pText_t->sText);

	memcpy(pText_t->pText, pResource, pText_t->sText);

	//SystemFunction032(pKey, pText_t->pPayloadAddress, strlen(pKey), pText_t->dwPayloadSize);
	
	//rInit(&Context, pKey, strlen(pKey));

	pText_t->pText = malloc(pText_t->sText + 1);

	//printf("[i] Payload in Test: %s\n[i] Payload Heap Address: 0x%p\n[!] Encrypting Payload...\n", pText->pText, pText_t->pText);

	//rFin(&Context, pResource, pText_t->pText, pText_t->sText);

	if (pText_t->pText == NULL) return NULL;

	return pText_t;
}