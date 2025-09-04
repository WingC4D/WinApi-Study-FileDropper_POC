#include "Encryption.h"
//AES BCrypt encrypt wrapper
BOOL aInit(
IN	PVOID   pPText, 
IN	DWORD   sPText, 
IN	PBYTE   pKeyObj,
IN	PBYTE   pInitVec,
OUT	PVOID  *pCText,
OUT	DWORD  *psCText
)
{
	if (!pPText || ! sPText || !pKeyObj || !pInitVec) return FALSE;
	AEStruct AES_t = {
		.pKey     = pKeyObj,
		.pInitVec = pInitVec,
		.pPText   = pPText,
		.sPText   = sPText,
		.blEncrypt  = TRUE
	};	
	if (!InstallAes(&AES_t)) return FALSE;
	
	*pCText  = AES_t.pCText;
	*psCText = AES_t.sCText;

	return TRUE;
} 

//AES BCrypt decrypt wrapper
BOOL aFin(
	IN  PVOID  pCText,
	IN  DWORD  sCText,
	IN  PBYTE  pKeyObj,
	IN  PBYTE  pInitVec,
	OUT PVOID *pPText,
	OUT DWORD *spPText
) 
{
	if (!pCText || !sCText || !pKeyObj || !pInitVec) return FALSE;
	
	AEStruct AES_t = {
		.pKey     = pKeyObj,
		.pInitVec = pInitVec,
		.pCText   = pCText,
		.sCText   = sCText,
		.blEncrypt  = FALSE
	};


	if (!InstallAes(&AES_t)) return FALSE;

	*pPText  = AES_t.pPText;
	*spPText = AES_t.sPText;
	return TRUE;
}


BOOL InstallAes
(
	PAEStruct pA_t
)
{
	BCRYPT_ALG_HANDLE hAlgorithm = NULL;
	BCRYPT_KEY_HANDLE hKey       = NULL;

	DWORD cbResult = 0,
		  sBlock   = 0,
	      cbKeyObj = 0,
		  sOutText = 0;
	PBYTE pKeyObj  = NULL,
		  pOutText = NULL;

	BOOL     STATE = TRUE;
	
	
	NTSTATUS STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
	
	if (!AESSuccessCheck(&STATE, STATUS, "AlgorithmProvider")) goto _CleanUp;
	
	STATUS = BCryptGetProperty(
		hAlgorithm, 
		BCRYPT_OBJECT_LENGTH, 
		(PBYTE)&cbKeyObj, 
		sizeof(DWORD), 
		&cbResult, 
		0
	);
	
	if (!AESSuccessCheck(&STATE, STATUS, "BCryptGetProperty")) goto _CleanUp;
	
	STATUS = BCryptGetProperty(
		hAlgorithm, 
		BCRYPT_BLOCK_LENGTH, 
		(PBYTE)&sBlock, 
		sizeof(DWORD), 
		&cbResult, 
		0
	);
	
	if (!AESSuccessCheck(&STATE, STATUS,"BCryptGetProperty")) goto _CleanUp;
	
	if (sBlock != 16) { STATE = FALSE; goto _CleanUp; }
	
	HANDLE hHeap = GetProcessHeap();

	pKeyObj = (PBYTE)HeapAlloc(hHeap, 0, cbKeyObj);

	if (!pKeyObj) { STATE = FALSE; goto _CleanUp; }

	STATUS = BCryptSetProperty(
		hAlgorithm, 
		BCRYPT_CHAINING_MODE, 
		BCRYPT_CHAIN_MODE_CBC, 
		sizeof(BCRYPT_CHAIN_MODE_CBC), 
		0
	);
	
	if (!AESSuccessCheck(&STATE, STATUS, "SetProperty")) goto _CleanUp;

	STATUS = BCryptGenerateSymmetricKey(
		hAlgorithm, 
		&hKey, 
		pKeyObj, 
		cbKeyObj, 
		pA_t->pKey, 
		KEYSIZE, 
		0
	);
	
	if ( !AESSuccessCheck(&STATE, STATUS, "GenerateSymmetricKey") ) goto  _CleanUp;

	if (pA_t->blEncrypt) 
	{
		STATUS = BCryptEncrypt
		(
			hKey,
			pA_t->pPText,
			pA_t->sPText,
			NULL,
			pA_t->pInitVec,
			IVSIZE,
			NULL,
			0,
			&sOutText,
			BCRYPT_BLOCK_PADDING
		);

		if (!AESSuccessCheck(&STATE, STATUS, "Encrypt")) goto _CleanUp;

		pOutText = (PBYTE)HeapAlloc(hHeap, 0, sOutText);

		if (!pOutText) { STATE = FALSE; goto _CleanUp; }

		STATUS = BCryptEncrypt
		(
			hKey,
			pA_t->pPText,
			pA_t->sPText,
			NULL,
			pA_t->pInitVec,
			IVSIZE,
			pOutText,
			sOutText,
			&cbResult,
			BCRYPT_BLOCK_PADDING
		);
		if (!AESSuccessCheck(&STATE, STATUS, "Encrypt")) goto _CleanUp;
	
	}
	else
	{
		STATUS = BCryptDecrypt
		(
			hKey,
			pA_t->pCText,
			pA_t->sCText,
			NULL,
			pA_t->pInitVec,
			IVSIZE,
			NULL,
			0,
			&sOutText,
			BCRYPT_BLOCK_PADDING
		);
		
		if (!AESSuccessCheck(&STATE, STATUS, "Decrypt")) goto _CleanUp;

		pOutText = (PBYTE)HeapAlloc(hHeap, 0, sOutText);

		if (!pOutText) { STATE = FALSE; goto _CleanUp; }

		STATUS = BCryptDecrypt
		(
			hKey,
			pA_t->pCText,
			pA_t->sCText,
			NULL,
			pA_t->pInitVec,
			IVSIZE,
			pOutText,
			sOutText,
			&cbResult,
			BCRYPT_BLOCK_PADDING
		);

		if (!AESSuccessCheck(&STATE, STATUS, "Decrypt")) goto _CleanUp;
	}

_CleanUp: 
	if (hKey) { BCryptDestroyKey(hKey); }

	if (hAlgorithm) { BCryptCloseAlgorithmProvider(hAlgorithm, 0); }
	
	if (pKeyObj) { HeapFree(GetProcessHeap(), 0, pKeyObj); }
	
	if (!pA_t->blEncrypt) { goto _DecCleanUp; }
	
	if (pOutText && STATE) { pA_t->pCText = pOutText; pA_t->sCText = sOutText; }
	
	return STATE;

_DecCleanUp:
	if (pOutText && STATE) { pA_t->pPText = pOutText; pA_t->sPText = sOutText; }
	
	return STATE;
}

VOID PrintHexData(
	LPCSTR pName, 
	PBYTE  pData, 
	SIZE_T size
)
{
	printf("[i] %s[] = {", pName);

	for (int i = 0; i < size; i++) {
		if (i % 16 == 0) { printf("\n\t"); }

		if (i < size - 1) { printf("0x%0.2X ", pData[i]); }
		
		else printf("0x%0.2X ", pData[i]);
	}
	printf("};\n\n");
}


VOID GenerateRandomBytes(
	PBYTE pByte, 
	SIZE_T size
) 
{
	for (int i = 0; i < size; i++) pByte[i] = (BYTE)rand() % 0xFF;
	return;
}


BOOL AESSuccessCheck(PBOOL pSTATE, NTSTATUS STATUS, LPSTR function)
{
	if (!NT_SUCCESS(STATUS))
	{
		printf("[!] BCrypt%s Failed With Error: 0x%0.8X\n", function, STATUS);
		*pSTATE = FALSE;
	}
	return *pSTATE;
}

//RC4 Context rInit
BOOL rInit(
	pContext pContext_t, 
	unsigned char *pKey,
	size_t sKeyLength
)
{
	if (!pContext_t || !pKey) return FALSE;

	pContext_t->main_index = 0;
	pContext_t->swap_index = 0;


	unsigned short  MainIndexInit;
	unsigned short  SwapIndexInit;

	for (MainIndexInit = 0; MainIndexInit < 256; MainIndexInit++)
	{
		pContext_t->pKey[MainIndexInit] = (unsigned char)MainIndexInit;
	}

	for (MainIndexInit = 0, SwapIndexInit = 0; MainIndexInit < 256; MainIndexInit++)
	{
		SwapIndexInit = (
			SwapIndexInit + pContext_t->pKey[MainIndexInit] + pKey[MainIndexInit % sKeyLength]
			) % 256;

		unsigned char TempByteHolder = pContext_t->pKey[MainIndexInit];
		pContext_t->pKey[MainIndexInit] = pContext_t->pKey[SwapIndexInit];
		pContext_t->pKey[SwapIndexInit] = TempByteHolder;
	}
	return TRUE;
}

//RC4 D/Encrypt 
void rFin(
	pContext          pContext_t,
	unsigned char    *pInput,
	unsigned char    *pOutput,
	size_t            sLength
)
{	
	unsigned int   MainIndexFin       = pContext_t->main_index;
	unsigned int   SwapIndexFin       = pContext_t->swap_index;
	unsigned char *pKey               = pContext_t->pKey;

	//Core logic
	while (sLength > 0)
	{
		MainIndexFin = ( MainIndexFin + 1 ) % 256;

		SwapIndexFin = ( SwapIndexFin + pKey[MainIndexFin] ) % 256;
		
		unsigned char TempByteHolder = pKey[MainIndexFin];

		pKey[MainIndexFin] = pKey[SwapIndexFin];

		pKey[SwapIndexFin] = TempByteHolder;
		
		if (pInput && pOutput)
		{
			*pOutput = *pInput ^ pKey[(pKey[MainIndexFin] + pKey[SwapIndexFin]) % 256];

			pInput++; pOutput++;
		}

		sLength--;
	}

	pContext_t->main_index = MainIndexFin;
	pContext_t->swap_index = SwapIndexFin;
	
}

void xInit(byte *pShellcode, size_t sShellcode, byte *pKey, size_t sKey) {
	for (size_t i = 0, j = sKey; i < sShellcode; i++, j++) 
	{
		pShellcode[i] = pShellcode[i] ^ pKey[j % sKey];
	}
}

NTSTATUS SystemFunction032(
	byte *pKey, 
	byte *pData, 
	unsigned long sKey, 
	unsigned long sData
)
{
	USTRING data = {
		.pBuffer= pData,
		.Length = sData,
		.MaximumLength = sData
	};

	USTRING key = {
	.pBuffer = pKey,
	.Length = sKey,
	.MaximumLength = sKey
	};
	pfnSystem032 SystemFunction032 = (pfnSystem032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");
	
	NTSTATUS result = SystemFunction032(&data, &key);

	if (result != 0x0) {
		printf("[!] SystemFunction032 FAILED With Error: 0x%0.8X \n", result);
		return FALSE;
	}
	return TRUE;
}

NTSTATUS SystemFunction033(
	byte* pKey,
	byte* pData,
	unsigned long sKey,
	unsigned long sData
)
{
	USTRING data = {
		.pBuffer = pData,
		.Length = sData,
		.MaximumLength = sData
	};

	USTRING key = {
	.pBuffer = pKey,
	.Length = sKey,
	.MaximumLength = sKey
	};
	pfnSystem032 SystemFunction032 = (pfnSystem032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction033");

	NTSTATUS result = SystemFunction032(&data, &key);

	if (result != 0x0) {
		printf("[!] SystemFunction032 FAILED With Error: 0x%0.8X \n", result);
		return FALSE;
	}
	return TRUE;
}
