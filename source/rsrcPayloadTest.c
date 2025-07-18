#include "rsrcPayloadTest.h"

PBYTE Test()
{
	UCHAR    pKey[KEYSIZE];
	UCHAR    pInitVec[IVSIZE];
	UCHAR    pInitVecCopy[IVSIZE];
	RESOURCE resource;
	
	if (!FetchResource(&resource)) { return NULL; }
	
	srand(time(NULL));
	GenerateRandomBytes(pKey, KEYSIZE);
	
	srand(time(NULL) ^ pKey[0]);            
	GenerateRandomBytes(pInitVec, IVSIZE);
	
	memcpy(pInitVecCopy, pInitVec, IVSIZE);
	
	StatusCheck(pInitVecCopy, pKey, resource.pAddress, resource.sSize,"Resource");
	
	PUCHAR rsrcText = malloc(resource.sSize);
	memcpy(rsrcText, resource.pAddress, resource.sSize);
	
	PUCHAR pCipherText;
	DWORD  sChiperText;

	if (!aInit(rsrcText, resource.sSize, pKey, pInitVecCopy, &pCipherText, &sChiperText)) { free(rsrcText); return NULL; }
	
	free(rsrcText);

	StatusCheck(pInitVecCopy, pKey, pCipherText, sChiperText,"CipherText");
	
	printf("[i] Heap Address: 0x%p\n[!] Encrypted!\n", pCipherText, pCipherText);

	PUCHAR pPlainText = malloc(sChiperText);
	DWORD  sPlainText = NULL;

	memcpy(pInitVecCopy, pInitVec, IVSIZE);

	aFin(pCipherText, sChiperText, pKey, pInitVecCopy, &pPlainText, &sPlainText);

	StatusCheck(pInitVecCopy, pKey, pPlainText, sPlainText, "PlainText");

	printf("[i] Heap Address: 0x%p\n[!] Decrypted!\n", pPlainText, pPlainText);
	
	if (pPlainText == NULL) { free(pPlainText); return NULL; }
	
	return pPlainText;
}


BOOL FetchResource(
	OUT PRESOURCE pResource_t
)
{
	HRSRC hRsrc = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_RCDATA1), RT_RCDATA);
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