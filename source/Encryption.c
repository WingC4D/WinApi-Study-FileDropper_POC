#include "Encryption.h"


VOID XorByInputKey(IN PBYTE p_shellcode, IN SIZE_T s_shellcode, IN PBYTE p_key, IN SIZE_T s_key) {
	for (size_t i = 0, j = 0; i < s_shellcode; i++, j++) {
		if (j == s_key) {
			j = 0;
		}
		p_shellcode[i] = p_shellcode[i] ^ p_key[j];
	}
}

void RC4Init(PRC4CONTEXT context, const unsigned char* key, size_t length)
{
	unsigned int i;
	unsigned int j;
	unsigned char temp;

	// Check parameters
	if (context == NULL || key == NULL) return (void)ERROR_INVALID_PARAMETER;

	// Clear context
	context->main_index = 0;
	context->swap_index = 0;

	for (i = 0; i < 256; i++)
	{
		context->stream_key[i] = i;
	}

	
	for (i = 0, j = 0; i < 256; i++)
	{
		//Randomize the permutations using the supplied key
		j = (j + context->stream_key[i] + key[i % length]) % 256;

		//Swap the values of S[i] and S[j]
		temp = context->stream_key[i];
		context->stream_key[i] = context->stream_key[j];
		context->stream_key[j] = temp;
	}

}


void RC4Encrypt(
	PRC4CONTEXT          pContext_t,
	const unsigned char *pInput,
	unsigned char       *pOutput,
	size_t               sLength
)
{	
	unsigned int   main_index   = pContext_t->main_index;
	unsigned int   swap_index = pContext_t->swap_index;
	unsigned char *pKey   = pContext_t->stream_key;
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
			*pOutput = *pInput ^ pKey[
				(pKey[main_index] + pKey[swap_index]) % 256
			];

			pInput++;
			pOutput++;
		}

		sLength--;
	}

	pContext_t->main_index = main_index;
	pContext_t->swap_index  = swap_index;
	
}