#include "Encryption.h"

//AES.WinNT init Wrapper
BOOL aInit(
	PVOID  pCText, 
	DWORD  sCText, 
	PBYTE  pKey,
	PBYTE  pInitVec,
	PVOID  pPText,
	PDWORD psPText)
{
	if (!pCText || ! sCText || !pKey || !pInitVec) return FALSE;

	//intitalizing the AES Struct
	A A_t = {
		.pKey.    = pKey,
		.pInitVec = pInitVec,
		.pInText  = pCText,
		.sInText  = sCText
	};
	
	if (!InstallAesEncryption(&A_t)) return FALSE;
	
	pPText  = A_t.pOutText;
	psPText = A_t.sOutText;

	return TRUE;
} 


BOOL InstallAesEncryption(pA pA_t)
{
	BOOL               STATE      = TRUE;
	BCRYPT_ALG_HANDLE  hAlgorithm = NULL;
	BCRYPT_KEY_HANDLE  hKey       = NULL;

	ULONG cbresult = NULL;
	DWORD sBlock = NULL;

	DWORD cbKeyObject = NULL;
	PBYTE pbKeyObject

	PBYTE    pbCtext = NULL;
	DWORD    cbCText = NULL;
	NTSTATUS STATUS  = NULL;
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
	unsigned char *pInput,
	unsigned char       *pOutput,
	size_t               sPayloadLength
)
{	
	unsigned int   main_index       = pContext_t->main_index;
	unsigned int   swap_index       = pContext_t->swap_index;
	unsigned char *pKey             = pContext_t->pKey;
	unsigned char  temp_byte_holder = 0;

	//Core logic
	while (sPayloadLength > 0)
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

		sPayloadLength--;
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
	fnSystem032 SystemFunction032 = (fnSystem032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");
	
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
	fnSystem032 SystemFunction032 = (fnSystem032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction033");

	NTSTATUS result = SystemFunction032(&data, &key);

	if (result != 0x0) {
		printf("[!] SystemFunction032 FAILED With Error: 0x%0.8X \n", result);
		return FALSE;
	}
	return TRUE;
}
