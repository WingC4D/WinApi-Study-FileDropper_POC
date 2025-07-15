#include "Encryption.h"


VOID BasicStreamXor(IN PBYTE p_shellcode, IN SIZE_T s_shellcode, IN PBYTE p_key, IN SIZE_T s_key) {
	for (size_t i = 0, j = 0; i < s_shellcode; i++, j++) {
		if (j == s_key) {
			j = 0;
		}
		p_shellcode[i] = p_shellcode[i] ^ p_key[j];
	}
}

void RC4Init(PRC4CONTEXT pContext_t, unsigned char* pKey, size_t sKeyLength)
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


void RC4Encrypt(
	PRC4CONTEXT          pContext_t,
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