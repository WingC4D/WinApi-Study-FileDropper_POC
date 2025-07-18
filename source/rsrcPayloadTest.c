#include "rsrcPayloadTest.h"

PBYTE Test()
{
	HRSRC   hRsrc = NULL;
	HANDLE hHeap = GetProcessHeap();
	
	HGLOBAL hGlobal = NULL;
	DWORD sResource = NULL;

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
	
	sResource = SizeofResource(NULL, hRsrc);
	if (!sResource) 
	{
		wprintf(L"[X] SizeofResource Failed With Error Code: %x\n", GetLastError());
		return NULL;
	}
	printf("[i] Resource: 0x%p\n", pResource);

	unsigned char *pText = malloc(sResource);

	memcpy(pText, (PBYTE)pResource, sResource);

	printf("[i] Payload in Test: %s\n[i] Payload Heap Address: 0x%p\n[!] Encrypted Payload!\n", pText, pText);
	

	unsigned char pKey[KEYSIZE];                    // KEYSIZE is 32 bytes
	unsigned char pInitVec[IVSIZE];                      // IVSIZE is 16 bytes

	srand(time(NULL));                      // The seed to generate the key. This is used to further randomize the key.
	GenerateRandomBytes(pKey, KEYSIZE);     // Generating a key with the helper function

	srand(time(NULL) ^ pKey[0]);            // The seed to generate the IV. Use the first byte of the key to add more randomness.
	GenerateRandomBytes(pInitVec, IVSIZE);       // Generating the IV with the helper function

	// Printing both key and IV onto the console 
	PrintHexData("pKey", pKey, KEYSIZE);
	PrintHexData("pIv", pInitVec, IVSIZE);
	PrintHexData("pText", pText, sResource);
	
	unsigned char *cText = NULL;
	DWORD scText = NULL;
	
	if (!aInit(pText, sResource, pKey, pInitVec, &cText, &scText)) return NULL;
	
	free(pText);

	PrintHexData("cText", cText, scText);
	
	printf("[i] Payload in Test: %s\n[i] Payload Heap Address: 0x%p\n[!] Encrypted Payload!\n", cText, cText);

	unsigned char *pTextCopy = NULL;
	
	PrintHexData("pKey", pKey, KEYSIZE);

	DWORD sText = NULL;

	aFin(cText, scText, pKey, pInitVec, &pTextCopy, &sText);

	//Here im Getting not The same data as in pText
	PrintHexData("pTextCopy", pTextCopy, sText);
	
	printf("[i] Payload in Test: %s\n[i] Payload Heap Address: 0x%p\n[!] Decrypted Payload!\n", pTextCopy, pTextCopy);
	
	if (pTextCopy == NULL) return NULL;
	free(pTextCopy);
	return pTextCopy;
}