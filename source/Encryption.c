#include "Encryption.h"


//AES.WinNT init Wrapper
BOOL aInit(
IN	PVOID   pPText, 
IN	DWORD   sPText, 
IN	PBYTE   pKey,
IN	PBYTE   pInitVec,
OUT	PVOID  *pCText,
OUT	DWORD  *psCText
)
{
	if (!pPText || ! sPText || !pKey || !pInitVec) return FALSE;

	//intitalizing the AES Struct
	AEStruct A_t = {
		.pKey     = pKey,
		.pInitVec = pInitVec,
		.pPText   = pPText,
		.sPText   = sPText
	};
	
	if (!InstallAes(&A_t, TRUE)) return FALSE;
	
	*pCText  = A_t.pCText;
	*psCText = A_t.sCText;

	return TRUE;
} 

BOOL aFin(
	IN  PVOID  pCText,
	IN  DWORD  sCText,
	IN  PBYTE  pKey,
	IN  PBYTE  pInitVec,
	
	OUT PVOID *pPText,
	
	OUT DWORD *spPText
) 
{
	if (!pCText || !sCText || !pKey || !pInitVec) return FALSE;
	
	AEStruct A_t = {
		.pKey     = pKey,
		.pInitVec = pInitVec,
		.pCText   = pCText,
		.sCText   = sCText
	};


	if (!InstallAes(&A_t, FALSE)) return FALSE;

	*pPText  = A_t.pPText;
	*spPText = A_t.sPText;
	return TRUE;
}


BOOL InstallAes(
	PAEStruct pA_t, 
	BOOL Encrypt
)
{
	BOOL               STATE      = TRUE;
	BCRYPT_ALG_HANDLE  hAlgorithm = NULL;
	BCRYPT_KEY_HANDLE  hKey       = NULL;

	ULONG cbResult = NULL;
	DWORD sBlock   = NULL;

	DWORD cbKey = NULL;
	PBYTE pbKey = NULL;

	PBYTE    pbOUTText = NULL;
	DWORD    cbOutText = NULL;
	
	HANDLE hHeap = GetProcessHeap();
	
	//Algorithm init.
	NTSTATUS STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
	
	if (!AESSuccessCheck(&STATE, STATUS, "AlgorithmProvider")) goto _AECleanUp;

	//Getting the size of the key (pbKey).  
	STATUS = BCryptGetProperty(
		hAlgorithm, 
		BCRYPT_OBJECT_LENGTH, 
		(PBYTE)&cbKey, 
		sizeof(DWORD), 
		&cbResult, 
		0
	);
	
	if (!AESSuccessCheck(&STATE, STATUS, "BCryptGetProperty")) goto _AECleanUp;
	
	//Getting the block Size
	STATUS = BCryptGetProperty(
		hAlgorithm, 
		BCRYPT_BLOCK_LENGTH, 
		(PBYTE)&sBlock, 
		sizeof(DWORD), 
		&cbResult, 
		0
	);
	
	if (!AESSuccessCheck(&STATE, STATUS,"BCryptGetProperty")) goto _AECleanUp;
	
	if (sBlock != 16) { STATE = FALSE; goto _AECleanUp; }
	
	pbKey = (PBYTE)HeapAlloc(hHeap, 0, cbKey);

	if (!pbKey) { STATE = FALSE; goto _AECleanUp; }

	//Setting Block Cipher Mode to CBC. This uses a 32 byte key and a 16 byte IV.
	STATUS = BCryptSetProperty(
		hAlgorithm, 
		BCRYPT_CHAINING_MODE, 
		BCRYPT_CHAIN_MODE_CBC, 
		sizeof(BCRYPT_CHAIN_MODE_CBC), 
		0
	);
	
	if (!AESSuccessCheck(&STATE, STATUS, "SetProperty")) goto _AECleanUp;
	

	//Genrating Key for AES Struct.
	STATUS = BCryptGenerateSymmetricKey(
		hAlgorithm, 
		&hKey, 
		pbKey, 
		cbKey, 
		(PBYTE)pA_t->pKey, 
		KEYSIZE, 
		0
	);
	
	if ( !AESSuccessCheck( &STATE, STATUS, "GenerateSymmetricKey" ) ) goto  _AECleanUp;
	

	if (Encrypt) {
		//Retriving sizeof output buff
		STATUS = BCryptEncrypt(
			hKey,
			pA_t->pPText,
			pA_t->sPText,
			NULL,
			pA_t->pInitVec,
			IVSIZE,
			NULL,
			0,
			&cbOutText,//saving to here
			BCRYPT_BLOCK_PADDING
		);
		if (!AESSuccessCheck(&STATE, STATUS, "Encrypt")) goto _AECleanUp;

		pbOUTText = (PBYTE)HeapAlloc(hHeap, 0, cbOutText);
		if (!pbOUTText) { STATE = FALSE; goto _AECleanUp; }



		STATUS = BCryptEncrypt(
			hKey,
			pA_t->pPText,
			pA_t->sPText,
			NULL,
			pA_t->pInitVec,
			IVSIZE,
			pbOUTText,
			cbOutText,
			&cbResult,
			BCRYPT_BLOCK_PADDING
		);
		if (!AESSuccessCheck(&STATE, STATUS, "Encrypt")) goto _AECleanUp;
	
	}
	else
	{
		
		STATUS = BCryptDecrypt(
			hKey,
			(PUCHAR)pA_t->pCText,
			(ULONG)pA_t->sCText,
			NULL,
			pA_t->pInitVec,
			IVSIZE,
			NULL,
			0,
			&cbOutText,
			BCRYPT_BLOCK_PADDING
		);
		if (!AESSuccessCheck(&STATE, STATUS, "Decrypt")) goto _ADCleanUp;

		pbOUTText = (PBYTE)HeapAlloc(hHeap, 0, cbOutText);
		if (!pbOUTText) { STATE = FALSE; goto _AECleanUp; }


		STATUS = BCryptDecrypt(
			hKey,
			pA_t->pCText,
			pA_t->sCText,
			NULL,
			pA_t->pInitVec,
			IVSIZE,
			pbOUTText,
			cbOutText,
			&cbResult,
			BCRYPT_BLOCK_PADDING
		);
		if (!AESSuccessCheck(&STATE, STATUS, "Decrypt")) goto _ADCleanUp;
	}
	_AECleanUp: 
	

	if (hKey) BCryptDestroyKey(hKey);

	if (hAlgorithm) BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	
	if (pbKey) HeapFree(GetProcessHeap(), 0, pbKey);
	
	if (!Encrypt) goto _ADCleanUp;
	
	if (pbOUTText && STATE) {
		pA_t->pCText = pbOUTText;
		pA_t->sCText = cbOutText;
		HeapFree(GetProcessHeap(), 0, pbOUTText);
	}
	
	return STATE;

_ADCleanUp:

	if (pbOUTText && STATE) {
		pA_t->pPText = pbOUTText;
		pA_t->sPText = cbOutText;
		HeapFree(GetProcessHeap(), 0, pbOUTText);
	}

	return STATE;
}


// Print the input buffer as a hex char array
VOID PrintHexData(
	LPCSTR pName, 
	PBYTE  pData, 
	SIZE_T size
) {

	printf("unsigned char %s[] = {", pName);

	for (int i = 0; i < size; i++) {
		if (i % 16 == 0) printf("\n\t");

		if (i < size - 1) printf("0x%0.2X, ", pData[i]);
		
		else printf("0x%0.2X ", pData[i]);
		
	}
	printf("};\n\n\n");
}


VOID GenerateRandomBytes(
	PBYTE pByte, 
	SIZE_T size
) {
	for (int i = 0; i < size; i++) pByte[i] = (BYTE)rand() % 0xFF;
	return;
}


BOOL AESSuccessCheck(PBOOL pSTATE, NTSTATUS STATUS, LPSTR function)
{
	if (!NT_SUCCESS(STATUS))
	{
		printf("[!] BCrypt%s Failed With Error: 0x%0.8X\n", function, STATUS);
		pSTATE = FALSE;
	}
	return pSTATE;
}

//RC4 Context rInit
void rInit(
	pContext pContext_t, 
	unsigned char* pKey, 
	size_t sKeyLength
)
{
	if (!pContext_t || !pKey) return (void)ERROR_INVALID_PARAMETER;

	pContext_t->main_index = 0;
	pContext_t->swap_index = 0;


	unsigned int local_main_index;
	unsigned int local_swap_index;
	unsigned char temp_byte_holder;

	for (local_main_index = 0; local_main_index < 256; local_main_index++)
	{
		pContext_t->pKey[local_main_index] = local_main_index;
	}

	for (local_main_index = 0, local_swap_index = 0; local_main_index < 256; local_main_index++)
	{
		local_swap_index = (local_swap_index + pContext_t->pKey[local_main_index] + pKey[local_main_index % sKeyLength]) % 256;

		temp_byte_holder = pContext_t->pKey[local_main_index];
		pContext_t->pKey[local_main_index] = pContext_t->pKey[local_swap_index];
		pContext_t->pKey[local_swap_index] = temp_byte_holder;
	}

}

//RC4 D/Encrypt 
void rFin(
	pContext          pContext_t,
	unsigned char    *pInput,
	unsigned char    *pOutput,
	size_t            sLength
)
{	
	unsigned int   main_index       = pContext_t->main_index;
	unsigned int   swap_index       = pContext_t->swap_index;
	unsigned char *pKey             = pContext_t->pKey;
	unsigned char  temp_byte_holder = 0;

	//Core logic
	while (sLength > 0)
	{
		main_index = ( main_index + 1 ) % 256;

		swap_index = ( swap_index + pKey[main_index] ) % 256;
		
		temp_byte_holder = pKey[main_index];

		pKey[main_index] = pKey[swap_index];

		pKey[swap_index] = temp_byte_holder;
		
		if (pInput && pOutput)
		{
			*pOutput = *pInput ^ pKey[(pKey[main_index] + pKey[swap_index]) % 256];

			pInput++;
			pOutput++;
		}

		sLength--;
	}

	pContext_t->main_index = main_index;
	pContext_t->swap_index  = swap_index;
	
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
