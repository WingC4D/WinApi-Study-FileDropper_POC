#pragma once
#include <Windows.h>
class Payload 
{
    public:
        PBYTE  pData;
		HANDLE hAttachedProcessHandle,
			   hInjectedTread;
		SIZE_T sSize;
		DWORD  dwProtections;
        LPVOID lpExternalAddress,
			   lpLocalStompedFunction,
			   lpRemoteStompedFunction;

        enum error_codes : UCHAR
        {
            success,
            nullptrHandle,
            invalidHandle,
            nullptrPayload,
            nullptrInput,
            unknownPayloadSize,
            writeProcMemFailed,
            virtualProtectFailed,
            virtualProtectExFailed,
            memcpyFailed
        };

        error_codes InjectToRemoteProcWriteMem
		(
			IN     OPTIONAL HANDLE hTargetProcessHandle
        );

        error_codes StompLocalFunction
		(
            IN			LPVOID pTargetFunction
        );

        error_codes StompRemoteFunction
		(
			IN          LPVOID lpRemoteFunctionAddress
        );
         
    private:
        error_codes CheckHandleValidity
		(
            IN              HANDLE hCandidateHandle
        ) const
        {
            if (hCandidateHandle == nullptr && hAttachedProcessHandle == nullptr) return nullptrHandle;

            if (hCandidateHandle == INVALID_HANDLE_VALUE && (
                hAttachedProcessHandle == nullptr 
                || hAttachedProcessHandle == INVALID_HANDLE_VALUE)) return invalidHandle;

            return success;
        }

        error_codes CheckPayloadValidity
		(
			IN              VOID
        ) const
        {
            if (pData == nullptr) return nullptrPayload;

            if (sSize == NULL) return unknownPayloadSize;
 
        	return success;
        }
};