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
	
	sResource = SizeofResource(NULL, hRsrc) + 1;
	if (!sResource) 
	{
		wprintf(L"[X] SizeofResource Failed With Error Code: %x\n", GetLastError());
		return NULL;
	}
	printf("[i] Resource: 0x%p\n", pResource);

	BYTE* pText = malloc(sResource);

	//pText_t->pText = HeapAlloc(hHeap, 0, sResource);
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

	// Defining two variables the output buffer and its respective size which will be used in SimpleEncryption
	//PVOID pCipherText = NULL;
	//DWORD dwCipherSize = NULL;
	PrintHexData("pText", pText, sResource);
	//pText_t->pText = HeapAlloc(GetProcessHeap(), 0, sResource);
	unsigned char *cText;
	DWORD scText = NULL;
	
	// Encrypting
	if (!aInit(pText, sResource, pKey, pInitVec, &cText, &scText)) return NULL;
	PrintHexData("cText", cText, scText);
	// Print the encrypted buffer as a hex array
	//if (!aInit(pTextCopy, sResource, pKey, pIv, &pText_t->pText, &sResource)) return "FAILED";
	
	printf("[i] Payload in Test: %s\n[i] Payload Heap Address: 0x%p\n[!] Encrypted Payload!\n", cText, cText);

	//SystemFunction032(pKey, pText_t->pPayloadAddress, strlen(pKey), pText_t->dwPayloadSize);
	
	//rInit(&Context, pKey, strlen(pKey));
	unsigned char *pTextCopy;
	PrintHexData("pKey", pKey, KEYSIZE);

	DWORD sText = NULL;

	aFin(cText, scText, pKey, pInitVec, &pTextCopy, &sText);
	

	PrintHexData("pTextCopy", pTextCopy, sText);
	
	//memcpy(pText_t->pText, pResource, sResource);
	
	printf("[i] Payload in Test: %s\n[i] Payload Heap Address: 0x%p\n[!] Decrypted Payload!\n", pTextCopy, pTextCopy);

	//size_t sTextCopy = 0;

	//aFin(pText_t->pText, sResource, pKey, pInitVec, &pTextCopy, &sTextCopy);

	//printf("[i] Payload in Test: %s\n[i] Payload Heap Address: 0x%p\n[!] Encrypting Payload...\n", pTextCopy, pTextCopy);


	//rFin(&Context, pResource, pText_t->pText, sResource);

	if (pTextCopy == NULL) return NULL;

	return pTextCopy;
}