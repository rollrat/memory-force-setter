/*************************************************************************
 *
 *                    ROLLRAT AUTO PERSONA VERBOTER LIBROFEX
 *
 *                         (C) Copyright 2009-2014
 *                                  rollrat
 *                           All Rights Reserved
 *
 *************************************************************************/

#ifndef __gtpget
#define __gtpget

#include <windows.h>
#include <tlhelp32.h>
#include <stdarg.h>
#include "ntstatus.h"

// ntdef.h에서 따옴.
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

#define ROUND_TO_PAGES(Size, PageSize)  (((ULONG_PTR)(Size) + PageSize - 1) & ~(PageSize - 1))
#define RVA_TO_ADDR(Mapping,Rva) ((PVOID)(((ULONG_PTR) (Mapping)) + (Rva)))

#define FASTCALL __fastcall

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemNextEventIdInformation,
	SystemEventIdsInformation,
	SystemCrashDumpInformation,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemPlugPlayBusInformation,
	SystemDockInformation,
	SystemProcessorSpeedInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef enum __PROCESS_INFORMATION_CLASS{
	ProcessBasicInformation,
	ProcessQuotaLimits,
	ProcessIoCounters,
	ProcessVmCounters,
	ProcessTimes,
	ProcessBasePriority,
	ProcessRaisePriority,
	ProcessDebugPort,
	ProcessExceptionPort,
	ProcessAccessToken,
	ProcessLdtInformation,
	ProcessLdtSize,
	ProcessDefaultHardErrorMode,
	ProcessIoPortHandlers,
	ProcessPooledUsageAndLimits,
	ProcessWorkingSetWatch,
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup,
	ProcessPriorityClass,
	ProcessWx86Information,
	ProcessHandleCount,
	ProcessAffinityMask,
	ProcessPriorityBoost,
	ProcessDeviceMap,
	ProcessSessionInformation,
	ProcessForegroundInformation,
	ProcessWow64Information,
	ProcessImageFileName,
	ProcessLUIDDeviceMapsEnabled,
	ProcessBreakOnTermination,
	ProcessDebugObjectHandle,
	ProcessDebugFlags,
	ProcessHandleTracing,
	ProcessIoPriority,
	ProcessExecuteFlags,
	ProcessResourceManagement,
	ProcessCookie,
	ProcessImageInformation,
	ProcessCycleTime,
	ProcessPagePriority,
	ProcessInstrumentationCallback,
	ProcessThreadStackAllocation,
	ProcessWorkingSetWatchEx,
	ProcessImageFileNameWin32,
	ProcessImageFileMapping,
	ProcessAffinityUpdateMode,
	ProcessMemoryAllocationMode,
	MaxProcessInfoClass,
} __PROCESS_INFORMATION_CLASS, *__PPROCESS_INFORMATION_CLASS;

typedef struct _ANSI_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PSTR  Buffer;
} ANSI_STRING, *PANSI_STRING;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG  Length;
	HANDLE  RootDirectory;
	PUNICODE_STRING  ObjectName;
	ULONG  Attributes;
	PVOID  SecurityDescriptor;
	PVOID  SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _CURDIR {
	UNICODE_STRING DosPath;
	HANDLE Handle;
} CURDIR, *PCURDIR;

typedef struct _VM_COUNTERS {
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG  PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
} VM_COUNTERS;

typedef struct _SYSTEM_THREAD_INFORMATION {
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	ULONG Priority;
	ULONG BasePriority;
	ULONG ContextSwitchCount;
	LONG State;
	LONG WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryDelta;
	ULONG ThreadCount;
	LARGE_INTEGER Reserved1[3];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ProcessName;
	ULONG BasePriority;
	HANDLE ProcessId;
	HANDLE InheritedFromProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR PageDirectoryBase;
	VM_COUNTERS VmCounters;
#if _WIN32_WINNT >= 0x500
	IO_COUNTERS IoCounters;
#endif
	SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef CONST OBJECT_ATTRIBUTES *PCOBJECT_ATTRIBUTES;
typedef struct _OBJECT_TYPE *POBJECT_TYPE;
typedef CCHAR KPROCESSOR_MODE;

typedef struct _OBJECT_HANDLE_INFORMATION {
	ULONG HandleAttributes;
	ACCESS_MASK GrantedAccess;
} OBJECT_HANDLE_INFORMATION, *POBJECT_HANDLE_INFORMATION;

typedef _Enum_is_bitflag_ enum _POOL_TYPE POOL_TYPE;
typedef struct _KPROCESS *PKPROCESS, *PRKPROCESS, *PEPROCESS;
typedef struct _ACCESS_STATE *PACCESS_STATE;

typedef enum _MODE {
	KernelMode,
	UserMode,
	MaximumMode
} MODE;

typedef struct _KAPC_STATE {
	LIST_ENTRY ApcListHead[MaximumMode];
	struct _KPROCESS *Process;
	union {
		UCHAR InProgressFlags;
		struct {
			BOOLEAN KernelApcInProgress : 1;
			BOOLEAN SpecialApcInProgress : 1;
		};
	};

	BOOLEAN KernelApcPending;
	BOOLEAN UserApcPending;
} KAPC_STATE, *PKAPC_STATE, *PRKAPC_STATE;

typedef _Enum_is_bitflag_ enum _POOL_TYPE {
	NonPagedPool,
	NonPagedPoolExecute = NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed = NonPagedPool + 2,
	DontUseThisType,
	NonPagedPoolCacheAligned = NonPagedPool + 4,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS = NonPagedPool + 6,
	MaxPoolType,

	//
	// Define base types for NonPaged (versus Paged) pool, for use in cracking
	// the underlying pool type.
	//

	NonPagedPoolBase = 0,
	NonPagedPoolBaseMustSucceed = NonPagedPoolBase + 2,
	NonPagedPoolBaseCacheAligned = NonPagedPoolBase + 4,
	NonPagedPoolBaseCacheAlignedMustS = NonPagedPoolBase + 6,

	//
	// Note these per session types are carefully chosen so that the appropriate
	// masking still applies as well as MaxPoolType above.
	//

	NonPagedPoolSession = 32,
	PagedPoolSession = NonPagedPoolSession + 1,
	NonPagedPoolMustSucceedSession = PagedPoolSession + 1,
	DontUseThisTypeSession = NonPagedPoolMustSucceedSession + 1,
	NonPagedPoolCacheAlignedSession = DontUseThisTypeSession + 1,
	PagedPoolCacheAlignedSession = NonPagedPoolCacheAlignedSession + 1,
	NonPagedPoolCacheAlignedMustSSession = PagedPoolCacheAlignedSession + 1,

	NonPagedPoolNx = 512,
	NonPagedPoolNxCacheAligned = NonPagedPoolNx + 4,
	NonPagedPoolSessionNx = NonPagedPoolNx + 32,

} _Enum_is_bitflag_ POOL_TYPE;

typedef
NTSTATUS(
NTAPI *
_ZwReadVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_In_ PVOID BaseAddress,
	_Out_opt_ PVOID Buffer,
	_In_ ULONG BufferLength,
	_Out_opt_ PULONG ReturnLength OPTIONAL
	);

typedef
NTSTATUS(
NTAPI *
_ZwWriteVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_In_ PVOID BaseAddress,
	_In_ PVOID Buffer,
	_In_ SIZE_T NumberOfBytesToWrite,
	_Out_opt_ PSIZE_T NumberOfBytesWritten
	);

typedef
NTSTATUS(
NTAPI *
_ZwOpenProcess)(
	_Out_opt_ PHANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ PCLIENT_ID ClientId OPTIONAL
	);

typedef
NTSTATUS(
NTAPI *
_ZwDuplicateObject)(
	_In_ HANDLE SourceProcessHandle,
	_In_ HANDLE SourceHandle,
	_In_opt_ HANDLE TargetProcessHandle,
	_Out_opt_ PHANDLE TargetHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ ULONG HandleAttritues,
	_In_ ULONG Options
	);

typedef
NTSTATUS(
NTAPI *
_ZwQuerySystemInformation)(
	_In_ HANDLE ProcessHandle,
	_In_ __PROCESS_INFORMATION_CLASS ProcessInformationClass,
	_Inout_ PVOID ProcessInformation,
	_In_ ULONG ProcessInformationLength,
	_Out_opt_ PULONG ReturnLength
	);

typedef
NTSTATUS(
NTAPI *
__ZwQuerySystemInformation)(
	_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Inout_ PVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength
	);

typedef
NTSTATUS(
NTAPI *
_ZwClose)(
	_In_ HANDLE hHandle
	);

typedef
NTSTATUS(
NTAPI *
_ObReferenceObjectByHandle)(
    _In_ HANDLE Handle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Out_ PVOID *Object,
    _Out_opt_ POBJECT_HANDLE_INFORMATION HandleInformation
	);

typedef
LONG_PTR(
FASTCALL *
_ObfDereferenceObject)(
    _In_ PVOID Object
    );

typedef
PVOID(
NTAPI *
_ExAllocatePoolWithTag)(
    _In_ __drv_strictTypeMatch(__drv_typeExpr) POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag
    );

typedef
VOID(
NTAPI *
_ExFreePoolWithTag)(
    _Pre_notnull_ __drv_freesMem(Mem) PVOID P,
    _In_ ULONG Tag
    );

typedef
BOOLEAN(
NTAPI *
_MmIsAddressValid)(
    _In_ PVOID VirtualAddress
    );

typedef
VOID(
NTAPI *
_ProbeForRead)(
    __in_data_source(USER_MODE) _In_reads_bytes_(Length) volatile VOID *Address,
    _In_ SIZE_T Length,
    _In_ ULONG Alignment
    );

typedef
VOID(
NTAPI *
_ProbeForWrite)(
    __in_data_source(USER_MODE) _Inout_updates_bytes_(Length) volatile VOID *Address,
    _In_ SIZE_T Length,
    _In_ ULONG Alignment
    );

typedef
VOID(
NTAPI *
_KeStackAttachProcess)(
    _Inout_ PRKPROCESS PROCESS,
    _Out_ PRKAPC_STATE ApcState
    );

typedef
VOID(
NTAPI *
_KeUnstackDetachProcess)(
    _In_ PRKAPC_STATE ApcState
    );

typedef
NTSTATUS(
NTAPI *
_PsLookupProcessByProcessId)(
    _In_ HANDLE ProcessId,
    _Outptr_ PEPROCESS *Process
    );

typedef
VOID(
NTAPI *
_RtlInitUnicodeString)(
    _Out_ PUNICODE_STRING DestinationString,
    _In_opt_z_ __drv_aliasesMem PCWSTR SourceString
    );

typedef
PVOID(
NTAPI *
_MmGetSystemRoutineAddress)(
    _In_ PUNICODE_STRING SystemRoutineName
    );

typedef
NTSTATUS(
NTAPI *
_ObOpenObjectByPointer)(
    _In_ PVOID Object,
    _In_ ULONG HandleAttributes,
    _In_opt_ PACCESS_STATE PassedAccessState,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Out_ PHANDLE Handle
    );

#define ExFreePool(a) ExFreePoolWithTag (a,0)
#define InitializeObjectAttributes( p, n, a, r, s ) { \
	(p)->Length = sizeof(OBJECT_ATTRIBUTES);          \
	(p)->RootDirectory = r;                             \
	(p)->Attributes = a;                                \
	(p)->ObjectName = n;                                \
	(p)->SecurityDescriptor = s;                        \
	(p)->SecurityQualityOfService = NULL;               \
	}
#define OBJ_INHERIT             0x00000002L
#define OBJ_PERMANENT           0x00000010L
#define OBJ_EXCLUSIVE           0x00000020L
#define OBJ_CASE_INSENSITIVE    0x00000040L
#define OBJ_OPENIF              0x00000080L
#define OBJ_OPENLINK            0x00000100L
#define OBJ_KERNEL_HANDLE       0x00000200L
#define OBJ_FORCE_ACCESS_CHECK  0x00000400L
#define OBJ_VALID_ATTRIBUTES    0x000007F2L

#define NonPagedPool NonPagedPoolNx
#define NonPagedPoolCacheAligned NonPagedPoolNxCacheAligned

#define RtlEqualMemory(Destination,Source,Length) (!memcmp((Destination),(Source),(Length)))
#define RtlMoveMemory(Destination,Source,Length) memmove((Destination),(Source),(Length))
#define RtlCopyMemory(Destination,Source,Length) memcpy((Destination),(Source),(Length))
#define RtlFillMemory(Destination,Length,Fill) memset((Destination),(Fill),(Length))
#define RtlZeroMemory(Destination,Length) memset((Destination),0,(Length))

#define CAST_INT(x)	(int)x

/***
*  @brief /프로세스 이름을 받아서 PID를 리턴함
*
*  @param szProcess_ProcessName
*/ // 0.9 추가.
DWORD FindProcess(char * szProcess)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 ProcessEntry32;

	if (hSnapshot)
	{
		ProcessEntry32.dwSize = sizeof(PROCESSENTRY32);

		while (Process32Next(hSnapshot, &ProcessEntry32))
		{
			if (strcmp(ProcessEntry32.szExeFile, szProcess) == 0)
				return ProcessEntry32.th32ProcessID;
		}
		CloseHandle(hSnapshot);
	}
	return 0;
}

/**
*  @brief /First Scan of process memory
*
*  @param pid_processid/dwDest_find value/size_Size/count_count of
*/ // 1.2 기능추가 : mbi읽기기능과 byte_read
PDWORD _$FirstScanOfProcess(DWORD pid, DWORD dwDest, DWORD dwSize, DWORD& count)
{
	SYSTEM_INFO sys_info;
	MEMORY_BASIC_INFORMATION mbi;
	DWORD vqAddr;
	DWORD lpfOldProtect;
	DWORD *byte_code = new DWORD[256 * dwSize];
	BYTE *parts = new BYTE[dwSize];
	HANDLE hProcess;

	if (!(hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, pid)))
		return NULL;

	if (!hProcess)
		return NULL;

	for (unsigned i = 0; i < dwSize; i++, dwDest /= 256)
		parts[i] = dwDest % 256;

	GetSystemInfo(&sys_info);
	vqAddr = (DWORD)sys_info.lpMinimumApplicationAddress;

	for (count = 0; vqAddr < (DWORD)sys_info.lpMaximumApplicationAddress;)
	{
		if (!VirtualQueryEx(hProcess, (LPVOID)vqAddr, &mbi, sizeof(mbi)) == sizeof(mbi))
			continue;
		if (!(mbi.Type == MEM_PRIVATE && mbi.State == MEM_COMMIT && mbi.RegionSize > 0))
			goto CAVECOURSE;

		BYTE * readmem = new BYTE[CAST_INT(mbi.RegionSize)];
		VirtualProtectEx(hProcess, mbi.BaseAddress, dwSize, PAGE_EXECUTE_READWRITE, &lpfOldProtect);

		if (!ReadProcessMemory(hProcess, mbi.BaseAddress, reinterpret_cast<LPVOID> (readmem), mbi.RegionSize, NULL))
			goto ENDVPE;

		for (int i = 0; i < CAST_INT(mbi.RegionSize); i++)
		{
			for (int j = 0; j < dwSize; j++)
			{
				if ((i + dwSize + 1) > CAST_INT(mbi.RegionSize))
					break;
				else if (readmem[i + j] != parts[j])
					break;
				else if (j == dwSize - 1)
				{
					if (count % 256 == 0)
						byte_code = (DWORD *)realloc(
						byte_code, dwSize * 256 * (count / 256 + 1)
						);
					byte_code[count] = (DWORD)mbi.BaseAddress + i;
					count++;
				}
			}
		}

	ENDVPE:
		VirtualProtectEx(hProcess, mbi.BaseAddress, dwSize, lpfOldProtect, NULL);
		delete readmem;
	CAVECOURSE:
		vqAddr = (DWORD)mbi.BaseAddress + (DWORD)mbi.RegionSize;
	}

	CloseHandle(hProcess);
	delete parts;
	return byte_code;
}


/**
*  @brief /First Scan of process memory
*
*  @param pid_processid/dwDest_find value/size_Size/count_count of
*/ // 1.1 변형추가 : Nt API
PDWORD _$FirstScanOfProcessWithNativeApi(DWORD pid, DWORD dwDest, DWORD dwSize, DWORD& count)
{
	SYSTEM_INFO sys_info;
	MEMORY_BASIC_INFORMATION mbi;
	DWORD vqAddr;
	DWORD lpfOldProtect;
	DWORD *byte_code = new DWORD[256 * dwSize];
	BYTE *parts = new BYTE[dwSize];
	HANDLE hProcess;
	_ZwReadVirtualMemory _ZwRVM =
		(_ZwReadVirtualMemory)GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwReadVirtualMemory");
	OBJECT_ATTRIBUTES ObjectAttributes;
	CLIENT_ID cid;
	cid.UniqueProcess = (HANDLE)pid;
	cid.UniqueThread = 0;

	InitializeObjectAttributes(&ObjectAttributes, NULL,
		OBJ_KERNEL_HANDLE, NULL, NULL);

	_ZwOpenProcess _ZwOP =
		(_ZwOpenProcess)GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwOpenProcess");
	_ZwClose _ZwC =
		(_ZwClose)GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwClose");


	_ZwOP(&hProcess, MAXIMUM_ALLOWED, &ObjectAttributes, &cid);

	/*if (!(hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, pid)))
		return NULL;*/

	if (!hProcess)
		return NULL;

	for (unsigned i = 0; i < dwSize; i++, dwDest /= 256)
		parts[i] = dwDest % 256;

	GetSystemInfo(&sys_info);
	vqAddr = (DWORD)sys_info.lpMinimumApplicationAddress;

	for (count = 0; vqAddr < (DWORD)sys_info.lpMaximumApplicationAddress;)
	{
		if (!VirtualQueryEx(hProcess, (LPVOID)vqAddr, &mbi, sizeof(mbi)) == sizeof(mbi))
			continue;
		if (!(mbi.Type == MEM_PRIVATE && mbi.State == MEM_COMMIT && mbi.RegionSize > 0))
			goto CAVECOURSE;

		BYTE * readmem = new BYTE[CAST_INT(mbi.RegionSize)];
		VirtualProtectEx(hProcess, mbi.BaseAddress, dwSize, PAGE_EXECUTE_READWRITE, &lpfOldProtect);

		_ZwRVM(hProcess, mbi.BaseAddress, reinterpret_cast<LPVOID> (readmem), mbi.RegionSize, NULL);

		for (int i = 0; i < CAST_INT(mbi.RegionSize); i++)
		{
			for (int j = 0; j < dwSize; j++)
			{
				if ((i + dwSize + 1) > CAST_INT(mbi.RegionSize))
					break;
				else if (readmem[i + j] != parts[j])
					break;
				else if (j == dwSize - 1)
				{
					if (count % 256 == 0)
						byte_code = (DWORD *)realloc(
						byte_code, dwSize * 256 * (count / 256 + 1)
						);
					byte_code[count] = (DWORD)mbi.BaseAddress + i;
					count++;
				}
			}
		}

		VirtualProtectEx(hProcess, mbi.BaseAddress, dwSize, lpfOldProtect, NULL);
		delete readmem;
	CAVECOURSE:
		vqAddr = (DWORD)mbi.BaseAddress + (DWORD)mbi.RegionSize;
	}

	_ZwC(hProcess);
	delete parts;
	return byte_code;
}

/**
*  @brief /Next Scan of process memory
*
*  @param pid_processid/pdwAddr_bytes array for address/dwDest_find value/dwSize_Size/count_count of
*/ // 1.0 첫 함수 변형
PDWORD _$NextScanOfProcess(DWORD pid, PDWORD pdwAddr, DWORD dwBySize, DWORD dwDest, DWORD dwSize, DWORD& count)
{
	SYSTEM_INFO sys_info;
	MEMORY_BASIC_INFORMATION mbi;
	DWORD vqAddr;
	DWORD lpfOldProtect;
	DWORD *byte_code = new DWORD[256 * dwSize];
	HANDLE hProcess;

	if (!(hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, pid)))
		return NULL;

	GetSystemInfo(&sys_info);
	vqAddr = pdwAddr[0];

	count = 0;

	for (int k = 0; k < dwBySize; vqAddr = pdwAddr[k++])
	{
		if (!VirtualQueryEx(hProcess, (LPVOID)vqAddr, &mbi, sizeof(mbi)) == sizeof(mbi))
			continue;
		if (!(mbi.Type == MEM_PRIVATE && mbi.State == MEM_COMMIT && mbi.RegionSize > 0))
			continue;

		DWORD readmem = 0;
		VirtualProtectEx(hProcess, (LPVOID)vqAddr, dwSize, PAGE_EXECUTE_READWRITE, &lpfOldProtect);

		if (!ReadProcessMemory(hProcess, (LPVOID)vqAddr, reinterpret_cast<LPVOID> (&readmem), sizeof(DWORD), NULL))
			goto ENDVPE;

		if (readmem == dwDest){
			if (count % 256 == 0)
				byte_code = (DWORD *)realloc(
				byte_code, dwSize * 256 * (count / 256 + 1)
				);
			byte_code[count] = vqAddr;
			count++;
		}

	ENDVPE:
		VirtualProtectEx(hProcess, (LPVOID)vqAddr, dwSize, lpfOldProtect, NULL);
	}

	CloseHandle(hProcess);
	return byte_code;
}


/**
*  @brief /Next Scan of process memory
*
*  @param pid_processid/pdwAddr_bytes array for address/dwDest_find value/dwSize_Size/count_count of
*/ // 1.1 변형추가 Nt API
PDWORD _$NextScanOfProcessWithNativeApi(DWORD pid, PDWORD pdwAddr, DWORD dwBySize, DWORD dwDest, DWORD dwSize, DWORD& count)
{
	SYSTEM_INFO sys_info;
	MEMORY_BASIC_INFORMATION mbi;
	DWORD vqAddr;
	DWORD lpfOldProtect;
	DWORD *byte_code = new DWORD[256 * dwSize];
	HANDLE hProcess;
	_ZwReadVirtualMemory _ZwRVM =
		(_ZwReadVirtualMemory)GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwReadVirtualMemory");
	OBJECT_ATTRIBUTES ObjectAttributes;
	CLIENT_ID cid;
	cid.UniqueProcess = (HANDLE)pid;
	cid.UniqueThread = 0;

	InitializeObjectAttributes(&ObjectAttributes, NULL,
		OBJ_KERNEL_HANDLE, NULL, NULL);

	_ZwOpenProcess _ZwOP =
		(_ZwOpenProcess)GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwOpenProcess");
	_ZwClose _ZwC =
		(_ZwClose)GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwClose");


	_ZwOP(&hProcess, MAXIMUM_ALLOWED, &ObjectAttributes, &cid);

	//if (!(hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, pid)))
	//	return NULL;

	if (!hProcess)
		return NULL;

	GetSystemInfo(&sys_info);
	vqAddr = pdwAddr[0];

	count = 0;

	for (int k = 0; k < dwBySize; vqAddr = pdwAddr[k++])
	{
		if (!VirtualQueryEx(hProcess, (LPVOID)vqAddr, &mbi, sizeof(mbi)) == sizeof(mbi))
			continue;
		if (!(mbi.Type == MEM_PRIVATE && mbi.State == MEM_COMMIT && mbi.RegionSize > 0))
			continue;

		DWORD readmem = 0;
		VirtualProtectEx(hProcess, (LPVOID)vqAddr, dwSize, PAGE_EXECUTE_READWRITE, &lpfOldProtect);

		_ZwRVM(hProcess, (LPVOID)vqAddr, reinterpret_cast<LPVOID> (&readmem), sizeof(DWORD), NULL);

		if (readmem == dwDest){
			if (count % 256 == 0)
				byte_code = (DWORD *)realloc(
				byte_code, dwSize * 256 * (count / 256 + 1)
				);
			byte_code[count] = vqAddr;
			count++;
		}

		VirtualProtectEx(hProcess, (LPVOID)vqAddr, dwSize, lpfOldProtect, NULL);
	}

	_ZwC(hProcess);
	return byte_code;
}

/***
*  @brief /메모리에 원하는 값을 씀.
*
*  @param hProcess 프로세스핸들 addr 주소 value 값 size 크기
*/ // 0.9 기능추가 : VirtualProtectEx
void _$WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID value, int size)
{
	DWORD lpfOldProtect;
	VirtualProtectEx(hProcess, lpBaseAddress, size, PAGE_EXECUTE_READWRITE, &lpfOldProtect);
	WriteProcessMemory(hProcess, lpBaseAddress, value, size, NULL);
	VirtualProtectEx(hProcess, lpBaseAddress, size, lpfOldProtect, NULL);
}

/***
*  @brief /메모리에 원하는 값을 씀.
*
*  @param hProcess 프로세스핸들 addr 주소 value 값 size 크기
*/ // 1.1 변형추가 Nt API
void _$WriteProcessMemoryWithNativeApi(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID value, int size)
{
	DWORD lpfOldProtect;
	_ZwWriteVirtualMemory _ZwRVM =
		(_ZwWriteVirtualMemory)GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwWriteVirtualMemory");
	VirtualProtectEx(hProcess, lpBaseAddress, size, PAGE_EXECUTE_READWRITE, &lpfOldProtect);
	_ZwRVM(hProcess, lpBaseAddress, (PVOID)value, size, NULL);
	VirtualProtectEx(hProcess, lpBaseAddress, size, lpfOldProtect, NULL);
}

/***
*  @brief /원하는 핸들을 복사함, 실제 핸들값을 얻음.
*
*  @param pid PID handle 원하는 핸들값
*/ // 0.9 시험추가, 1.6 삭제
HANDLE _$DupliateHandle(DWORD pid, HANDLE handle)
{
	/*_ZwDuplicateObject _ZwDO =
		(_ZwDuplicateObject)GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwDuplicateObject");
	_ZwDO(process, handle, INVALID_HANDLE_VALUE, &dup, 0, FALSE, DUPLICATE_SAME_ACCESS);*/
	return 0;
}

/***
*  @brief /망작
*
*  @param None
*/
void * _$PidBruteForce(int * size)
{
	DWORD *r_pid;
	DWORD *pid = new DWORD[16381];
	HANDLE hHandle, *t;
	OBJECT_ATTRIBUTES ObjectAttributes;
	CLIENT_ID cid;
	int g = 0;
	InitializeObjectAttributes(&ObjectAttributes, NULL,
		OBJ_KERNEL_HANDLE, NULL, NULL);
	_ZwOpenProcess _ZwOP =
		(_ZwOpenProcess)GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwOpenProcess");
	_ZwClose _ZwC =
		(_ZwClose)GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwClose");
	//_ZwDuplicateObject _ZwDO =
	//	(_ZwDuplicateObject)GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwDuplicateObject");

	for (int i = 0; i <= 0xffff; i += 4)
	{
		cid.UniqueProcess = (HANDLE)i;
		cid.UniqueThread = 0;
		_ZwOP(&hHandle, PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, &ObjectAttributes, &cid);
		if (hHandle == 0)
		{
			pid[g++] = (DWORD)i;
			_ZwC(hHandle);
		}
	}

	r_pid = new DWORD[g];
	for (int i = 0; i < g; i++)
		r_pid[i] = pid[i];
	delete[] pid;
	*size = g;
	return r_pid;
}

/***
*  @brief /get hidden pid list, with bruteforce.
*
*  @param None
*/ // 1.6 추가
void * _$HPidWithBruteForce(int * size)
{
	DWORD *r_pid;
	DWORD *pid = new DWORD[16381];
	HANDLE hHandle;
	OBJECT_ATTRIBUTES ObjectAttributes;
	CLIENT_ID cid;
	int g = 0;
	InitializeObjectAttributes(&ObjectAttributes, NULL,
		OBJ_KERNEL_HANDLE, NULL, NULL);
	_ZwOpenProcess _ZwOP =
		(_ZwOpenProcess)GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwOpenProcess");
	_ZwClose _ZwC =
		(_ZwClose)GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwClose");

	for (int i = 0x8; i <= 0xffff; i += 4)
	{
		cid.UniqueProcess = (HANDLE)i;
		cid.UniqueThread = 0;
		_ZwOP(&hHandle, MAXIMUM_ALLOWED, &ObjectAttributes, &cid);
						// PROCESS_QUERY_LIMITED_INFORMATION
		if (hHandle > 0)
		{
			pid[g++] = i;
			_ZwC(hHandle);
		}
	}

	r_pid = new DWORD[g];
	for (int i = 0; i < g; i++)
		r_pid[i] = pid[i];
	delete[] pid;
	*size = g;
	return r_pid;
}

/***
*  @brief /실패작 csrss ...
*
*  @param None
*/
void * _$HPidWithIm(int * size)
{
	HANDLE *r_pid;
	HANDLE *pid = new HANDLE[16381];
	PSYSTEM_PROCESS_INFORMATION spi = 0, spi_t;
	int g = 0;
	__ZwQuerySystemInformation _ZwQSI =
		(__ZwQuerySystemInformation)GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwQuerySystemInformation");

	_ZwQSI(SystemProcessInformation, spi, sizeof(SYSTEM_PROCESS_INFORMATION), 0);

	for (int j = 0;;)
	{
		spi_t = PSYSTEM_PROCESS_INFORMATION(&spi + j);
		j += spi_t->NextEntryDelta;
		pid[g++] = spi_t->ProcessId;
		if (spi_t->NextEntryDelta == 0)
			break;
	}

	r_pid = new HANDLE[g];
	for (int i = 0; i < g; i++)
		r_pid[i] = pid[i];
	delete[] pid;
	*size = g;
	return r_pid;
}

/***
*  @brief /get image file name
*
*  @param pid_PID
*/ // 1.6 추가
PUNICODE_STRING _$ReadProcessImageFileName(DWORD pid)
{
	HANDLE hHandle;
	OBJECT_ATTRIBUTES ObjectAttributes;
	CLIENT_ID cid;
	PUNICODE_STRING us;
	InitializeObjectAttributes(&ObjectAttributes, NULL,
		OBJ_KERNEL_HANDLE, NULL, NULL);
	_ZwOpenProcess _ZwOP =
		(_ZwOpenProcess)GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwOpenProcess");
	_ZwClose _ZwC =
		(_ZwClose)GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwClose");
	_ZwQuerySystemInformation _ZwQSI = 
		(_ZwQuerySystemInformation)GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwQuerySystemInformation");

	cid.UniqueProcess = (HANDLE)pid;
	cid.UniqueThread = 0;

	_ZwOP(&hHandle, MAXIMUM_ALLOWED, &ObjectAttributes, &cid);
	_ZwQSI(&hHandle, ProcessImageFileName, &us, sizeof(UNICODE_STRING), 0);
	_ZwC(hHandle);

	return us;
}

#endif