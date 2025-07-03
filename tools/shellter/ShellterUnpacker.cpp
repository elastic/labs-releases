#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <intrin.h>

#pragma intrinsic(_ReturnAddress)

// max decompressed size: 16MB
#define DECOMPRESS_MAX_SIZE (16 * 1024 * 1024)

extern "C" NTSTATUS NTAPI RtlDecompressBuffer(USHORT CompressionFormat, PUCHAR UncompressedBuffer, ULONG UncompressedBufferSize, PUCHAR CompressedBuffer, ULONG CompressedBufferSize, PULONG FinalUncompressedSize);

#pragma comment(lib, "ntdll.lib")

char *gpInputExeFileName = NULL;

BYTE *gpStage1 = NULL;
SIZE_T gqwStage1Size = 0;

// global vars used by ntdll!RtlDecompressBuffer hook
BYTE *gpExtractPE_StoredCompressedBuffer = NULL;
DWORD gdwExtractPE_StoredCompressedBufferSize = 0;
DWORD gdwExtractPE_StoredUncompressedBufferSize = 0;

// global vars used by ntdll!memcpy hook
DWORD gdwExtractPE_MemcpyCounter = 0;
BYTE *gpExtractPE_RawMemcpyBuffer = NULL;
DWORD gdwExtractPE_RawMemcpyBufferLength = 0;

BOOL VerifyProcess64Bit(HANDLE hProcess)
{
    SYSTEM_INFO SystemInfo;
    BOOL bWow64 = 0;

    // ensure this is a 64-bit OS
    GetNativeSystemInfo(&SystemInfo);
    if(SystemInfo.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64)
	{
		// error
        return 1;
    }

    if(IsWow64Process(hProcess, &bWow64) == 0)
	{
		// error
		return 1;
    }

	if(bWow64)
	{
		// wow64
		return 1;
	}

	// success
    return 0;
}

BOOL DumpOutput(char *pSuffix, VOID *pData, SIZE_T qwSize)
{
	char szFileName[512];
	FILE *pFile = NULL;

	memset(szFileName, 0, sizeof(szFileName));
	_snprintf(szFileName, sizeof(szFileName) - 1, "%s.%s", gpInputExeFileName, pSuffix);

	printf("Writing dump to %s...\n", szFileName);

	pFile = fopen(szFileName, "wb");
	if(pFile == NULL)
	{
		printf("Error: Failed to create output file\n");
		return 1;
	}

	fwrite(pData, qwSize, 1, pFile);
	fclose(pFile);

	return 0;
}

BYTE *FindPattern(BYTE *pSearchRegion, SIZE_T qwSearchRegionSize, BYTE *pPattern, BYTE *pFilter, SIZE_T qwPatternSize)
{
	BOOL bFoundSignature = 0;

	// validate sizes
	if(qwSearchRegionSize == 0 || qwPatternSize == 0 || qwPatternSize > qwSearchRegionSize)
	{
		return NULL;
	}

	for(SIZE_T i = 0; i < (qwSearchRegionSize - qwPatternSize) + 1; i++)
	{
		bFoundSignature = 1;
		for(SIZE_T ii = 0; ii < qwPatternSize; ii++)
		{
			if(pFilter)
			{
				if(pFilter[ii] == 0)
				{
					// skip this byte
					continue;
				}
			}

			if(pSearchRegion[i + ii] != pPattern[ii])
			{
				bFoundSignature = 0;
				break;
			}
		}

		if(bFoundSignature)
		{
			// found
			return &pSearchRegion[i];
		}
	}

	return NULL;
}

BOOL AesDecrypt(BYTE* pEncryptedData, DWORD dwEncryptedDataLength, BYTE* pKey, BYTE* pIV)
{
	HCRYPTPROV hProv = 0;
	HCRYPTKEY hKey = 0;
	DWORD dwMode = 0;
	struct
	{
		BLOBHEADER BlobHeader;
		DWORD dwKeyLength;
		BYTE bKeyData[16];
	} AesKeyData;

	// initialise
	if(CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) == 0)
	{
		return 1;
	}

	// import key
	memset(&AesKeyData, 0, sizeof(AesKeyData));
	AesKeyData.BlobHeader.bType = PLAINTEXTKEYBLOB;
	AesKeyData.BlobHeader.bVersion = CUR_BLOB_VERSION;
	AesKeyData.BlobHeader.reserved = 0;
	AesKeyData.BlobHeader.aiKeyAlg = CALG_AES_128;
	AesKeyData.dwKeyLength = 16;
	memcpy(AesKeyData.bKeyData, pKey, 16);
	if(CryptImportKey(hProv, (BYTE*)&AesKeyData, sizeof(AesKeyData), 0, 0, &hKey) == 0)
	{
		return 1;
	}

	// set mode
	dwMode = CRYPT_MODE_CBC;
	if(CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&dwMode, 0) == 0)
	{
		return 1;
	}

	// set iv
	if(CryptSetKeyParam(hKey, KP_IV, pIV, 0) == 0)
	{
		return 1;
	}

	// decrypt
	if(CryptDecrypt(hKey, 0, 0, 0, pEncryptedData, &dwEncryptedDataLength) == 0)
	{
		return 1;
	}

	CryptDestroyKey(hKey);
	CryptReleaseContext(hProv, 0);

	return 0;
}

BYTE *DecompressBuffer(VOID *pData, DWORD dwSize, DWORD *pdwDecompressedDataSize)
{
	BYTE *pDecompressedData = NULL;
	DWORD dwDecompressedDataBufferSize = 0;
	DWORD dwOutputSize = 0;

	// the payload may be compressed with LZNT1, attempt to decompress it
	dwDecompressedDataBufferSize = DECOMPRESS_MAX_SIZE;
	pDecompressedData = (BYTE*)malloc(dwDecompressedDataBufferSize);
	if(pDecompressedData == NULL)
	{
		return NULL;
	}

	if(RtlDecompressBuffer(COMPRESSION_FORMAT_LZNT1, pDecompressedData, dwDecompressedDataBufferSize, (BYTE*)pData, (DWORD)dwSize, &dwOutputSize) != 0)
	{
		return NULL;
	}

	// decompressed successfully
	*pdwDecompressedDataSize = dwOutputSize;

	return pDecompressedData;
}

BOOL ExtractStage1_CopyCode(HANDLE hProcess, VOID *pRIP)
{
	VOID *pCodeBase = NULL;
	SIZE_T qwCodeSize = 0;
	MEMORY_BASIC_INFORMATION MemoryBasicInfo;
	BYTE bEndOfDecryptionPattern[] =       { 0x48, 0x81, 0xEC, 0x78, 0x34, 0x00, 0x00, 0x90, 0x90, 0x90 };
	BYTE bEndOfDecryptionPatternFilter[] = {    1,    1,    1,    0,    0,    1,    1,    1,    1,    1 };
	BYTE *pEndOfDecryption = NULL;
	SIZE_T qwDecryptionCodeSize = 0;

	if(VirtualQueryEx(hProcess, pRIP, &MemoryBasicInfo, sizeof(MemoryBasicInfo)) == 0)
	{
		return 1;
	}
	pCodeBase = (BYTE*)MemoryBasicInfo.AllocationBase;
	if(VirtualQueryEx(hProcess, pCodeBase, &MemoryBasicInfo, sizeof(MemoryBasicInfo)) == 0)
	{
		return 1;
	}
	qwCodeSize = MemoryBasicInfo.RegionSize;

	// copy stage1 code to local process
	gpStage1 = (BYTE*)VirtualAlloc(NULL, qwCodeSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if(gpStage1 == NULL)
	{
		return 1;
	}
	gqwStage1Size = qwCodeSize;
	if(ReadProcessMemory(hProcess, pCodeBase, gpStage1, qwCodeSize, NULL) == 0)
	{
		return 1;
	}

	pEndOfDecryption = FindPattern(gpStage1, gqwStage1Size, bEndOfDecryptionPattern, bEndOfDecryptionPatternFilter, sizeof(bEndOfDecryptionPattern));
	if(pEndOfDecryption == NULL)
	{
		printf("Error: Failed to find pattern\n");
		return 1;
	}

	// replace self-decryption code with nops, the code has already been decrypted
	qwDecryptionCodeSize = (SIZE_T)((ULONG_PTR)pEndOfDecryption - (ULONG_PTR)gpStage1);
	memset(gpStage1, 0x90, qwDecryptionCodeSize);
	*gpStage1 = 0xE9;
	*(DWORD*)(gpStage1 + 1) = (DWORD)(qwDecryptionCodeSize - 5);

	return 0;
}

BOOL ExtractStage1_DebugProcess(PROCESS_INFORMATION *pProcessInfo)
{
	CONTEXT Context;
	DEBUG_EVENT DebugEvent;
	PROCESS_BASIC_INFORMATION ProcessBasicInfo;

	if(VerifyProcess64Bit(pProcessInfo->hProcess) != 0)
	{
		printf("Error: Target process must be 64-bit\n");
		return 1;
	}

	if(NtQueryInformationProcess(pProcessInfo->hProcess, ProcessBasicInformation, &ProcessBasicInfo, sizeof(ProcessBasicInfo), NULL) != 0)
	{
		return 1;
	}

	printf("Setting breakpoint...\n");

	memset(&Context, 0, sizeof(Context));
	Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if(GetThreadContext(pProcessInfo->hThread, &Context) == 0)
	{
		return 1;
	}
	Context.Dr0 = (ULONG_PTR)ProcessBasicInfo.PebBaseAddress + 0xFE0;
	Context.Dr7 = 0x90001;
	if(SetThreadContext(pProcessInfo->hThread, &Context) == 0)
	{
		return 1;
	}

	printf("Resuming process...\n");

	ResumeThread(pProcessInfo->hThread);

	printf("Waiting for exception, this may take a few seconds...\n");

	for(;;)
	{
		if(WaitForDebugEvent(&DebugEvent, INFINITE) == 0)
		{
			return 1;
		}

		if(DebugEvent.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
		{
			// finished
			break;
		}
		else if(DebugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
		{
			if(DebugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP)
			{
				// caught hardware breakpoint at PEB+0xFE0 - get the current region from RIP
				printf("Caught breakpoint\n");

				if(DebugEvent.dwThreadId != pProcessInfo->dwThreadId)
				{
					// unexpected thread ID
					return 1;
				}

				memset(&Context, 0, sizeof(Context));
				Context.ContextFlags = CONTEXT_ALL;
				if(GetThreadContext(pProcessInfo->hThread, &Context) == 0)
				{
					return 1;
				}

				printf("Extracting code...\n");

				if(ExtractStage1_CopyCode(pProcessInfo->hProcess, (VOID*)Context.Rip) != 0)
				{
					return 1;
				}

				// finished, terminate process
				TerminateProcess(pProcessInfo->hProcess, 0);
			}
		}

		ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
	}

	return 0;
}

BOOL ExtractStage1(char *pInputExe)
{
	STARTUPINFOA StartupInfo;
	PROCESS_INFORMATION ProcessInfo;
	BOOL bStatus = 0;

	printf("Launching process...\n");

	// launch suspended process
	memset((void*)&ProcessInfo, 0, sizeof(ProcessInfo));
	memset((void*)&StartupInfo, 0, sizeof(StartupInfo));
	StartupInfo.cb = sizeof(StartupInfo);
	if(CreateProcessA(NULL, pInputExe, NULL, NULL, 1, CREATE_NEW_CONSOLE | CREATE_SUSPENDED | DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &StartupInfo, &ProcessInfo) == 0)
	{
		printf("Error: Failed to launch process\n");
		return 1;
	}

	// debug the child process, extract stage1 payload
	bStatus = ExtractStage1_DebugProcess(&ProcessInfo);
	TerminateProcess(ProcessInfo.hProcess, 0);
	CloseHandle(ProcessInfo.hProcess);
	CloseHandle(ProcessInfo.hThread);
	if(bStatus != 0)
	{
		return 1;
	}

	return 0;
}

DWORD WINAPI Hook_RtlDecompressBuffer(USHORT CompressionFormat, PUCHAR UncompressedBuffer, ULONG UncompressedBufferSize, PUCHAR CompressedBuffer, ULONG CompressedBufferSize, PULONG FinalUncompressedSize)
{
	// store buffer
	gpExtractPE_StoredCompressedBuffer = CompressedBuffer;
	gdwExtractPE_StoredCompressedBufferSize = CompressedBufferSize;

	// store uncompressed size
	gdwExtractPE_StoredUncompressedBufferSize = UncompressedBufferSize;

	// terminate thread
	ExitThread(0);

	return 0;
}

void* Hook_memcpy(void *destination, const void *source, size_t num)
{
	VOID *pReturnAddr = NULL;
	MEMORY_BASIC_INFORMATION MemoryBasicInfo;

	// perform original memcpy
	for(size_t i = 0; i < num; i++)
	{
		*(BYTE*)((BYTE*)destination + i) = *(BYTE*)((BYTE*)source + i);
	}

	// check if this call originated from non-image-backed shellcode
	pReturnAddr = _ReturnAddress();
	VirtualQuery(pReturnAddr, &MemoryBasicInfo, sizeof(MemoryBasicInfo));
	if(MemoryBasicInfo.Type == MEM_PRIVATE)
	{
		// shellter always calls memcpy multiple times to map the PE:
		// memcpy(x, y, 4);
		// memcpy(x, y, 4);
		// memcpy(x, y, 4);
		// memcpy(x, y, 4);
		// memcpy(x, y, <PE_SIZE>); (encrypted block)
		// memcpy(x, y, <PE_SIZE>); (decrypted block) <<< this is what we want to capture.
		// however, if this binary uses shellter's compression feature, RtlDecompressBuffer will be called after the 5th memset but before the 6th.
		// in this case, RtlDecompressBuffer will handle the dump instead.
		gdwExtractPE_MemcpyCounter++;
		if(gdwExtractPE_MemcpyCounter == 6)
		{
			gpExtractPE_RawMemcpyBuffer = (BYTE*)source;
			gdwExtractPE_RawMemcpyBufferLength = (DWORD)num;

			// terminate thread
			ExitThread(0);
		}
	}

	return destination;
}

BOOL ExtractPE(VOID *pData, DWORD dwLength)
{
	BYTE *pPeLoaderCode = NULL;
	BYTE bHook[] = { 0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0xFF, 0xE0 };
	BYTE bOrigRtlDecompressBufferBytes[sizeof(bHook)];
	DWORD dwOrigProtect = 0;
	HANDLE hThread = NULL;
	VOID *pMemcpy = NULL;
	BYTE *pDecompressedData = NULL;
	DWORD dwOutputSize = 0;
	IMAGE_DOS_HEADER *pImageDosHeader = NULL;
	IMAGE_NT_HEADERS *pImageNtHeader = NULL;
	BOOL bFoundPE = 0;
	
	// copy data to executable region
	pPeLoaderCode = (BYTE*)VirtualAlloc(NULL, dwLength, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if(pPeLoaderCode == NULL)
	{
		printf("Error: Failed to allocate memory\n");
		return 1;
	}
	memcpy(pPeLoaderCode, pData, dwLength);

	printf("Hooking RtlDecompressBuffer...\n");

	// hook ntdll!RtlDecompressBuffer
	VirtualProtect(RtlDecompressBuffer, sizeof(bHook), PAGE_EXECUTE_READWRITE, &dwOrigProtect);
	*(DWORD64*)&bHook[2] = (DWORD64)Hook_RtlDecompressBuffer;
	memcpy(bOrigRtlDecompressBufferBytes, RtlDecompressBuffer, sizeof(bHook));
	memcpy(RtlDecompressBuffer, bHook, sizeof(bHook));
	
	// hook ntdll!memcpy
	pMemcpy = (DWORD(WINAPI*)(USHORT,PUCHAR,ULONG,PUCHAR,ULONG,PULONG))GetProcAddress(GetModuleHandleA("ntdll.dll"), "memcpy");
	if(pMemcpy == NULL)
	{
		printf("Error: Failed to find memcpy export\n");
		return 1;
	}
	VirtualProtect(pMemcpy, sizeof(bHook), PAGE_EXECUTE_READWRITE, &dwOrigProtect);
	*(DWORD64*)&bHook[2] = (DWORD64)Hook_memcpy;
	memcpy(pMemcpy, bHook, sizeof(bHook));
	
	// reset global ptrs
	gpExtractPE_StoredCompressedBuffer = NULL;
	gpExtractPE_RawMemcpyBuffer = NULL;

	printf("Creating thread...\n");

	// start executing code - it should eventually call RtlDecompressBuffer which gets intercepted by the hook above
	hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pPeLoaderCode, NULL, 0, NULL);
	if(hThread == NULL)
	{
		printf("Error: Failed to create thread\n");
		return 1;
	}

	printf("Waiting for thread to exit...\n");

	// wait for thread to exit
	if(WaitForSingleObject(hThread, 5000) != WAIT_OBJECT_0)
	{
		printf("Error: Thread timed-out\n");
		TerminateThread(hThread, 0);
		return 1;
	}

	printf("Thread exited\n");

	// check if a call to RtlDecompressBuffer was detected
	if(gpExtractPE_StoredCompressedBuffer != NULL)
	{
		printf("Payload is compressed\n");

		pDecompressedData = (BYTE*)malloc(gdwExtractPE_StoredUncompressedBufferSize);
		if(pDecompressedData == NULL)
		{
			printf("Error: Failed to allocate memory\n");
			return 1;
		}

		printf("Decompressing buffer...\n");

		// remove hook
		memcpy(RtlDecompressBuffer, bOrigRtlDecompressBufferBytes, sizeof(bOrigRtlDecompressBufferBytes));

		// decompress buffer
		if(RtlDecompressBuffer(COMPRESSION_FORMAT_LZNT1, pDecompressedData, gdwExtractPE_StoredUncompressedBufferSize, gpExtractPE_StoredCompressedBuffer, gdwExtractPE_StoredCompressedBufferSize, &dwOutputSize) != 0)
		{
			printf("Error: Failed to decompress data\n");
			return 1;
		}
	}
	else if(gpExtractPE_RawMemcpyBuffer != NULL)
	{
		// RtlDecompressBuffer wasn't called - this mean the payload isn't compressed, use the raw buffer captured from the memcpy hook instead
		printf("Payload is not compressed\n");

		pDecompressedData = gpExtractPE_RawMemcpyBuffer;
		dwOutputSize = gdwExtractPE_RawMemcpyBufferLength;
	}
	else
	{
		printf("Error: Failed to capture payload\n");
		return 1;
	}

	if(dwOutputSize < 1024)
	{
		printf("Error: Invalid data\n");
		return 1;
	}

	// the decompressed data contains a header with a filename, look for the start of the final PE
	bFoundPE = 0;
	for(DWORD i = 0; i < 512; i++)
	{
		// get dos header
		pImageDosHeader = (IMAGE_DOS_HEADER*)&pDecompressedData[i];
		if(pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			continue;
		}

		// get nt header
		pImageNtHeader = (IMAGE_NT_HEADERS*)((BYTE*)pImageDosHeader + pImageDosHeader->e_lfanew);
		if(pImageNtHeader->Signature != IMAGE_NT_SIGNATURE)
		{
			continue;
		}

		bFoundPE = 1;
		break;
	}

	if(bFoundPE == 0)
	{
		printf("Error: Failed to locate start of PE\n");
		return 1;
	}

	printf("Extracted PE payload successfully\n");

	// dump PE payload
	if(DumpOutput("final_pe_payload", pImageDosHeader, dwOutputSize - (DWORD)((ULONG_PTR)pImageDosHeader - (ULONG_PTR)pDecompressedData)) != 0)
	{
		return 1;
	}

	return 0;
}

VOID PrintFileTime(char *pFieldName, FILETIME *pFileTime)
{
	SYSTEMTIME SystemTime;
	DWORD dwMicroSeconds = 0;

	FileTimeToSystemTime(pFileTime, &SystemTime);
	dwMicroSeconds = (DWORD)((((DWORD64)pFileTime->dwHighDateTime << 32) + pFileTime->dwLowDateTime) % 10000000) / 10;

	printf("%s: %04u-%02u-%02u %02u:%02u:%02u.%06u\n", pFieldName, SystemTime.wYear, SystemTime.wMonth, SystemTime.wDay, SystemTime.wHour, SystemTime.wMinute, SystemTime.wSecond, dwMicroSeconds);
}

BOOL ExtractStage2()
{
	BYTE bStartOfConfigCodePattern[] =       { 0xFF, 0xC0, 0x89, 0x84, 0x24, 0x00, 0x00, 0x00, 0x00, 0xEB, 0xD7, 0xB8 };
	BYTE bStartOfConfigCodePatternFilter[] = {    1,    1,    1,    1,    1,    0,    0,    0,    0,    1,    1,    1 };
	BYTE *pStartOfConfigCode = NULL;
	BYTE bEndOfConfigCodePattern[] =       { 0x74, 0x0D, 0xC7, 0x84, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x0B };
	BYTE bEndOfConfigCodePatternFilter[] = {    1,    1,    1,    1,    1,    0,    0,    0,    0,    0,    0,    0,    0,    1,    1 };
	BYTE *pEndOfConfigCode = NULL;
	SIZE_T qwConfigCodeSize = 0;
	BYTE bPayloadSizePattern[] =       { 0xC7, 0x84, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x44, 0x24, 0x34 };
	BYTE bPayloadSizePatternFilter[] = {    1,    1,    1,    0,    0,    0,    0,    0,    0,    0,    0,    1,    1,    1,    1 };
	BYTE *pPayloadSize = NULL;
	BYTE bDateFieldStartPattern[] = { 0xC7, 0x84, 0x24, 0x70, 0x07, 0x00, 0x00 };
	BYTE *pDateFieldStart = NULL;
	BYTE bAesKeyStartPattern[] = { 0xC7, 0x84, 0x24, 0x60, 0x0B, 0x00, 0x00 };
	BYTE *pAesKeyStart = NULL;
	BYTE bStartOfEncryptedPayload[] =
	{
		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xCC, 0xCC, 0xCC, 0xCC, 0xC3,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	BYTE *pStage2EncryptedPayload = NULL;
	DWORD dwStage2PayloadSize = 0;
	BYTE bBlankKey[16];
	BYTE bStage2AesKey[16];
	BYTE bStage2AesIV[16];
	BYTE *pDecompressedData = NULL;
	DWORD dwDecompressedDataSize = 0;
	BYTE bStartOfPELoader[] = { 0x57, 0x31, 0xC0, 0xB9, 0x0A, 0x00, 0x00, 0x00 };
	FILETIME LicenseExpiryTime;
	FILETIME SelfDisarmTime;
	FILETIME InfectionStartTime;

	// find encrypted payload
	pStage2EncryptedPayload = FindPattern(gpStage1, gqwStage1Size, bStartOfEncryptedPayload, NULL, sizeof(bStartOfEncryptedPayload));
	if(pStage2EncryptedPayload == NULL)
	{
		printf("Error: Failed to find pattern (encrypted payload)\n");
		return 1;
	}
	pStage2EncryptedPayload += sizeof(bStartOfEncryptedPayload);

	// find start of config code
	pStartOfConfigCode = FindPattern(gpStage1, gqwStage1Size, bStartOfConfigCodePattern, bStartOfConfigCodePatternFilter, sizeof(bStartOfConfigCodePattern));
	if(pStartOfConfigCode == NULL)
	{
		printf("Error: Failed to find pattern (config start)\n");
		return 1;
	}
	pStartOfConfigCode += (sizeof(bStartOfConfigCodePattern) - 1);

	// find end of config code
	pEndOfConfigCode = FindPattern(gpStage1, gqwStage1Size, bEndOfConfigCodePattern, bEndOfConfigCodePatternFilter, sizeof(bEndOfConfigCodePattern));
	if(pEndOfConfigCode == NULL)
	{
		printf("Error: Failed to find pattern (config end)\n");
		return 1;
	}

	// ensure "start" pattern comes before "end" pattern
	if(pStartOfConfigCode > pEndOfConfigCode)
	{
		return 1;
	}
	qwConfigCodeSize = (SIZE_T)((ULONG_PTR)pEndOfConfigCode - (ULONG_PTR)pStartOfConfigCode);

	printf("Extracting dates...\n");

	pDateFieldStart = FindPattern(pStartOfConfigCode, qwConfigCodeSize, bDateFieldStartPattern, NULL, sizeof(bDateFieldStartPattern));
	if(pDateFieldStart == NULL)
	{
		printf("Error: Failed to find pattern (date fields)\n");
		return 1;
	}
	pDateFieldStart += sizeof(bDateFieldStartPattern);
	LicenseExpiryTime.dwLowDateTime = *(DWORD*)pDateFieldStart;
	LicenseExpiryTime.dwHighDateTime = *(DWORD*)(pDateFieldStart + 11);
	SelfDisarmTime.dwLowDateTime = *(DWORD*)(pDateFieldStart + 22);
	SelfDisarmTime.dwHighDateTime = *(DWORD*)(pDateFieldStart + 33);
	InfectionStartTime.dwLowDateTime = *(DWORD*)(pDateFieldStart + 44);
	InfectionStartTime.dwHighDateTime = *(DWORD*)(pDateFieldStart + 55);

	// print dates
	PrintFileTime("License expiry date  ", &LicenseExpiryTime);
	PrintFileTime("Self-disarm date     ", &SelfDisarmTime);
	PrintFileTime("Infection start date ", &InfectionStartTime);

	// find payload size
	pPayloadSize = FindPattern(pStartOfConfigCode, qwConfigCodeSize, bPayloadSizePattern, bPayloadSizePatternFilter, sizeof(bPayloadSizePattern));
	if(pPayloadSize == NULL)
	{
		printf("Error: Failed to find pattern (payload size)\n");
		return 1;
	}
	dwStage2PayloadSize = *(DWORD*)(pPayloadSize + 7);

	pAesKeyStart = FindPattern(pStartOfConfigCode, qwConfigCodeSize, bAesKeyStartPattern, NULL, sizeof(bAesKeyStartPattern));
	if(pAesKeyStart == NULL)
	{
		printf("Error: Failed to find pattern (AES key)\n");
		return 1;
	}
	pAesKeyStart += sizeof(bAesKeyStartPattern);
	*(DWORD*)&bStage2AesKey[0] = *(DWORD*)pAesKeyStart;
	*(DWORD*)&bStage2AesKey[4] = *(DWORD*)(pAesKeyStart + 11);
	*(DWORD*)&bStage2AesKey[8] = *(DWORD*)(pAesKeyStart + 22);
	*(DWORD*)&bStage2AesKey[12] = *(DWORD*)(pAesKeyStart + 33);
	*(DWORD*)&bStage2AesIV[0] = *(DWORD*)(pAesKeyStart + 44);
	*(DWORD*)&bStage2AesIV[4] = *(DWORD*)(pAesKeyStart + 55);
	*(DWORD*)&bStage2AesIV[8] = *(DWORD*)(pAesKeyStart + 66);
	*(DWORD*)&bStage2AesIV[12] = *(DWORD*)(pAesKeyStart + 77);

	// dump encrypted payload
	if(DumpOutput("stage2_encrypted", pStage2EncryptedPayload, dwStage2PayloadSize) != 0)
	{
		return 1;
	}

	memset(bBlankKey, 0, sizeof(bBlankKey));
	if(memcmp(bBlankKey, bStage2AesKey, sizeof(bStage2AesKey)) == 0 && memcmp(bBlankKey, bStage2AesIV, sizeof(bStage2AesIV)) == 0)
	{
		printf("Error: Embedded AES key is blank, unable to unpack\n");
		return 1;
	}

	printf("Stage2 payload size  : %u bytes\n", dwStage2PayloadSize);
	printf("Stage2 AES key       : ");
	for(DWORD i = 0; i < sizeof(bStage2AesKey); i++)
	{
		printf("%02X", bStage2AesKey[i]);
	}
	printf("\n");
	printf("Stage2 AES IV        : ");
	for(DWORD i = 0; i < sizeof(bStage2AesIV); i++)
	{
		printf("%02X", bStage2AesIV[i]);
	}
	printf("\n");

	printf("Decrypting...\n");

	// decrypt stage2
	if(AesDecrypt(pStage2EncryptedPayload, dwStage2PayloadSize, bStage2AesKey, bStage2AesIV) != 0)
	{
		printf("Error: Failed to decrypt\n");
		return 1;
	}

	if(DumpOutput("stage2_decrypted", pStage2EncryptedPayload, dwStage2PayloadSize) != 0)
	{
		return 1;
	}

	// check if the decrypted output contains the built-in PE loader
	if(memcmp(pStage2EncryptedPayload, bStartOfPELoader, sizeof(bStartOfPELoader)) == 0)
	{
		printf("Found PE loader\n");
		if(ExtractPE(pStage2EncryptedPayload, dwStage2PayloadSize) != 0)
		{
			return 1;
		}
	}
	else
	{
		// attempt to decompress (optional - may not be compressed)
		pDecompressedData = DecompressBuffer(pStage2EncryptedPayload, dwStage2PayloadSize, &dwDecompressedDataSize);
		if(pDecompressedData != NULL)
		{
			printf("Decompressed successfully\n");

			// decompressed successfully
			if(DumpOutput("stage2_decrypted_and_decompressed", pDecompressedData, dwDecompressedDataSize) != 0)
			{
				return 1;
			}

			// check if the decompressed output contains the built-in PE loader
			if(memcmp(pDecompressedData, bStartOfPELoader, sizeof(bStartOfPELoader)) == 0)
			{
				printf("Found PE loader\n");
				if(ExtractPE(pDecompressedData, dwDecompressedDataSize) != 0)
				{
					return 1;
				}
			}
		}
	}

	return 0;
}

BOOL CheckUserConfirmation()
{
	char szConfirm[16];
	char *pConfirmEnd = NULL;

	printf("Warning: This tool maps potentially malicious code into memory. This should only be run within a VM.\n");
	printf("Type \"confirm\" to continue: ");

	memset(szConfirm, 0, sizeof(szConfirm));
	fgets(szConfirm, sizeof(szConfirm) - 1, stdin);
	pConfirmEnd = strrchr(szConfirm, '\r');
	if(pConfirmEnd)
	{
		*pConfirmEnd = '\0';
	}
	pConfirmEnd = strrchr(szConfirm, '\n');
	if(pConfirmEnd)
	{
		*pConfirmEnd = '\0';
	}

	if(_stricmp(szConfirm, "confirm") != 0)
	{
		return 1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	BYTE *pStage1Data = NULL;
	DWORD dwStage1DataLength = 0;
	char *pInputExe = NULL;

	if(argc != 2)
	{
		printf("Usage: %s <input_exe>\n", argv[0]);
		return 1;
	}

	printf("\nShellter Payload Extractor\n");
	printf(" - Elastic Security Labs\n\n");

	if(CheckUserConfirmation() != 0)
	{
		printf("Exiting...\n");
		return 1;
	}

	printf("\nStarting...\n");

	// get target exe filename
	pInputExe = argv[1];
	gpInputExeFileName = strrchr(pInputExe, '\\');
	if(gpInputExeFileName == NULL)
	{
		gpInputExeFileName = pInputExe;
	}
	else
	{
		gpInputExeFileName++;
	}

	printf("Extracting stage1...\n");

	if(ExtractStage1(pInputExe) != 0)
	{
		printf("Error: Failed to extract stage1\n");
		return 1;
	}

	if(DumpOutput("stage1", gpStage1, gqwStage1Size) != 0)
	{
		return 1;
	}

	printf("Extracting stage2...\n");

	if(ExtractStage2() != 0)
	{
		printf("Error: Failed to extract stage2\n");
		return 1;
	}

	printf("Finished\n");

	return 0;
}
