/*************************************************************************
 *
 *                    ROLLRAT AUTO PERSONA VERBOTER LIBROFEX
 *
 *************************************************************************/

#ifndef __tptpgd
#define __tptpgd

// ¿©±âÀÖ´Â ÄÚµåµéÁß ¾î¶² °ÍÀÌ¶óµµ º¹»ç, ¼öÁ¤ÇÏÁö ¸¶½Ê½Ã¿À.

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stddef.h>
#include <inttypes.h>
#include <tchar.h> 
#include <psapi.h> 
#include "gtpget.h"

#define RVA2OFFSET(TYPE, BASEADDR, RVA) ((TYPE)((DWORD)(BASEADDR) + (DWORD)(RVA)))
#define MAKEPTR RVA2OFFSET
#define STATUS_SUCCESS					(0x00000000L)

// http://blog.naver.com/artmedia0?Redirect=Log&logNo=60027642439
LPDWORD GetPointer2ProcAddress(HMODULE hModule, LPCSTR lpProcName) {
	PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS pNTHeader = RVA2OFFSET(PIMAGE_NT_HEADERS, pDOSHeader, pDOSHeader->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pExportDir = RVA2OFFSET(PIMAGE_EXPORT_DIRECTORY, hModule,
		pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	for (DWORD i = 0; i < pExportDir->NumberOfFunctions; i++) {
		LPDWORD pENT = RVA2OFFSET(LPDWORD, hModule, (LPDWORD)pExportDir->AddressOfNames + i);
		LPWORD pAONO = RVA2OFFSET(LPWORD, hModule, (LPWORD)pExportDir->AddressOfNameOrdinals + i);
		LPDWORD pAOF = RVA2OFFSET(LPDWORD, hModule, (LPDWORD)pExportDir->AddressOfFunctions + *pAONO);
		if (HIWORD(lpProcName))
			if (strcmp(RVA2OFFSET(LPCSTR, hModule, *pENT), lpProcName) == 0)
				return pAOF;
		else
			if (*pAONO == (WORD)lpProcName)
				return pAOF;
	}
	return NULL;
}

// ¸®¹ö½Ì ÇÙ½É¿ø¸®
bool HookExportedProc(HMODULE hModule, LPCSTR lpProcName, LPVOID* ppOldProcAddress, LPVOID pNewProcAddress) {
	LPDWORD pAddress = GetPointer2ProcAddress(hModule, lpProcName);
	if (pAddress == NULL)
		return false;

	*ppOldProcAddress = MAKEPTR(LPVOID*, hModule, *pAddress);

	DWORD dwProtect = PAGE_READWRITE;
	VirtualProtect(pAddress, sizeof(DWORD), dwProtect, &dwProtect);

	*pAddress = (DWORD)pNewProcAddress - (DWORD)hModule;
	VirtualProtect(pAddress, sizeof(DWORD), dwProtect, &dwProtect);

	return true;
}

// ¸®¹ö½Ì ÇÙ½É¿ø¸®
BOOL SetPrivilege(HANDLE hHandle, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp;
	HANDLE hToken;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&hToken))
		return FALSE;

	if (!LookupPrivilegeValue(NULL,           // lookup privilege on local system
		lpszPrivilege,  // privilege to lookup 
		&luid))        // receives LUID of privilege
		return FALSE;

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	if (!AdjustTokenPrivileges(hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
		return FALSE;

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
		return FALSE;

	return TRUE;
}

// ¸®¹ö½Ì ÇÙ½É¿ø¸®
BOOL InjectDll(DWORD dwPID, LPCTSTR szDllPath)
{
	HANDLE hProcess = NULL, hThread = NULL;
	HMODULE hMod = NULL;
	LPVOID pRemoteBuf = NULL;
	DWORD dwBufSize = (DWORD)(strlen(szDllPath) + 1) * sizeof(TCHAR);
	LPTHREAD_START_ROUTINE pThreadProc;

	if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)))
		return FALSE;

	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);

	WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllPath, dwBufSize, NULL);

	hMod = GetModuleHandle(TEXT("kernel32.dll"));
	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryW");

	hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);
	CloseHandle(hProcess);

	return TRUE;
}

// ¸®¹ö½Ì ÇÙ½É¿ø¸®
BOOL InjectDll2(HANDLE hProcess, LPCTSTR szDllName)
{
	HANDLE hThread;
	LPVOID pRemoteBuf;
	DWORD dwBufSize = (DWORD)(strlen(szDllName) + 1) * sizeof(TCHAR);
	FARPROC pThreadProc;

	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize,
		MEM_COMMIT, PAGE_READWRITE);
	if (pRemoteBuf == NULL)
		return FALSE;

	WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllName,
		dwBufSize, NULL);

	pThreadProc = GetProcAddress(GetModuleHandleA("kernel32.dll"),
		"LoadLibraryW");
	hThread = CreateRemoteThread(hProcess, NULL, 0,
		(LPTHREAD_START_ROUTINE)pThreadProc,
		pRemoteBuf, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);

	VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);

	CloseHandle(hThread);

	return TRUE;
}

// ¸®¹ö½Ì ÇÙ½É¿ø¸®
BOOL EjectDll(DWORD dwPID, LPCTSTR szDllName)
{
	BOOL bMore = FALSE, bFound = FALSE;
	HANDLE hSnapshot, hProcess, hThread;
	HMODULE hModule = NULL;
	MODULEENTRY32 me = { sizeof(me) };
	LPTHREAD_START_ROUTINE pThreadProc;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);

	bMore = Module32First(hSnapshot, &me);
	for (; bMore; bMore = Module32Next(hSnapshot, &me))
	{
		if (!strcmp((LPCTSTR)me.szModule, szDllName) ||
			!strcmp((LPCTSTR)me.szExePath, szDllName))
		{
			bFound = TRUE;
			break;
		}
	}

	if (!bFound)
	{
		CloseHandle(hSnapshot);
		return FALSE;
	}

	if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)))
		return FALSE;

	hModule = GetModuleHandle(TEXT("kernel32.dll"));
	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hModule, "FreeLibrary");
	hThread = CreateRemoteThread(hProcess, NULL, 0,
		pThreadProc, me.modBaseAddr,
		0, NULL);
	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);
	CloseHandle(hProcess);
	CloseHandle(hSnapshot);

	return TRUE;
}

// ¸®¹ö½Ì ÇÙ½É¿ø¸®
// 0 ÀÎÁ§Æ®, 1 ÀÌÁ§Æ®
BOOL InjectAllProcess(int nMode, LPCTSTR szDllPath)
{
	DWORD                   dwPID = 0;
	HANDLE                  hSnapShot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32          pe;

	pe.dwSize = sizeof(PROCESSENTRY32);
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);

	Process32First(hSnapShot, &pe);
	do
	{
		dwPID = pe.th32ProcessID;

		if (dwPID < 100)
			continue;

		if (nMode == 0)
			InjectDll(dwPID, szDllPath);
		else
			EjectDll(dwPID, szDllPath);
	} while (Process32Next(hSnapShot, &pe));

	CloseHandle(hSnapShot);

	return TRUE;
}

// ¸®¹ö½Ì ÇÙ½É¿ø¸®
DWORD _EnableNTPrivilege(LPCTSTR szPrivilege, DWORD dwState)
{
	DWORD dwRtn = 0;
	HANDLE hToken;
	if (OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		LUID luid;
		if (LookupPrivilegeValue(NULL, szPrivilege, &luid))
		{
			BYTE t1[sizeof(TOKEN_PRIVILEGES) + sizeof(LUID_AND_ATTRIBUTES)];
			BYTE t2[sizeof(TOKEN_PRIVILEGES) + sizeof(LUID_AND_ATTRIBUTES)];
			DWORD cbTP = sizeof(TOKEN_PRIVILEGES) + sizeof (LUID_AND_ATTRIBUTES);

			PTOKEN_PRIVILEGES pTP = (PTOKEN_PRIVILEGES)t1;
			PTOKEN_PRIVILEGES pPrevTP = (PTOKEN_PRIVILEGES)t2;

			pTP->PrivilegeCount = 1;
			pTP->Privileges[0].Luid = luid;
			pTP->Privileges[0].Attributes = dwState;

			if (AdjustTokenPrivileges(hToken, FALSE, pTP, cbTP, pPrevTP, &cbTP))
				dwRtn = pPrevTP->Privileges[0].Attributes;
		}

	    CloseHandle(hToken);
	}

	return dwRtn;
}

typedef NTSTATUS(WINAPI *PFZWQUERYSYSTEMINFORMATION)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength);

typedef BOOL(WINAPI *PFCREATEPROCESSA)(
	LPCTSTR lpApplicationName,
	LPTSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCTSTR lpCurrentDirectory,
	LPSTARTUPINFO lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	);

typedef BOOL(WINAPI *PFCREATEPROCESSW)(
	LPCTSTR lpApplicationName,
	LPTSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCTSTR lpCurrentDirectory,
	LPSTARTUPINFO lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	);

BYTE g_pOrgZwQSI[5] = { 0, };
PWSTR target = 0;
LPCTSTR target_mod = 0;

// ¸®¹ö½Ì ÇÙ½É¿ø¸®
BOOL hook_by_code(LPCSTR szDllName, LPCSTR szFuncName, PROC pfnNew, PBYTE pOrgBytes)
{
	FARPROC pFunc;
	DWORD dwOldProtect, dwAddress;
	BYTE pBuf[5] = { 0xE9, 0, };
	PBYTE pByte;

	pFunc = (FARPROC)GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
	pByte = (PBYTE)pFunc;
	if (pByte[0] == 0xE9)
		return FALSE;

	VirtualProtect((LPVOID)pFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	memcpy(pOrgBytes, pFunc, 5);

	dwAddress = (DWORD)pfnNew - (DWORD)pFunc - 5;
	memcpy(&pBuf[1], &dwAddress, 4);

	memcpy(pFunc, pBuf, 5);

	VirtualProtect((LPVOID)pFunc, 5, dwOldProtect, &dwOldProtect);

	return TRUE;
}

// ¸®¹ö½Ì ÇÙ½É¿ø¸®
BOOL hook_by_hotpatch(LPCSTR szDllName, LPCSTR szFuncName, PROC pfnNew)
{
	FARPROC pFunc;
	DWORD dwOldProtect, dwAddress;
	BYTE pBuf[5] = { 0xE9, 0, };
	BYTE pBuf2[2] = { 0xEB, 0xF9 };
	PBYTE pByte;

	pFunc = (FARPROC)GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
	pByte = (PBYTE)pFunc;
	if (pByte[0] == 0xEB)
		return FALSE;

	VirtualProtect((LPVOID)((DWORD)pFunc - 5), 7, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	// 1. NOP (0x90)
	dwAddress = (DWORD)pfnNew - (DWORD)pFunc;
	memcpy(&pBuf[1], &dwAddress, 4);
	memcpy((LPVOID)((DWORD)pFunc - 5), pBuf, 5);

	// 2. MOV EDI, EDI (0x8BFF)
	memcpy(pFunc, pBuf2, 2);

	VirtualProtect((LPVOID)((DWORD)pFunc - 5), 7, dwOldProtect, &dwOldProtect);

	return TRUE;
}

// ¸®¹ö½Ì ÇÙ½É¿ø¸®
BOOL hook_by_codeex(HANDLE hHandle, LPCSTR szDllName, LPCSTR szFuncName, PROC pfnNew, PBYTE pOrgBytes)
{
	FARPROC pFunc;
	DWORD dwOldProtect, dwAddress;
	BYTE pBuf[5] = { 0xE9, 0, };
	PBYTE pByte;

	pFunc = (FARPROC)GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
	pByte = (PBYTE)pFunc;
	if (pByte[0] == 0xE9)
		return FALSE;

	VirtualProtectEx(hHandle, (LPVOID)pFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	memcpy(pOrgBytes, pFunc, 5);

	dwAddress = (DWORD)pfnNew - (DWORD)pFunc - 5;
	memcpy(&pBuf[1], &dwAddress, 4);

	memcpy(pFunc, pBuf, 5);

	VirtualProtectEx(hHandle, (LPVOID)pFunc, 5, dwOldProtect, &dwOldProtect);

	return TRUE;
}

// ¸®¹ö½Ì ÇÙ½É¿ø¸®
BOOL hook_by_hotpatchex(HANDLE hHandle, LPCSTR szDllName, LPCSTR szFuncName, PROC pfnNew)
{
	FARPROC pFunc;
	DWORD dwOldProtect, dwAddress;
	BYTE pBuf[5] = { 0xE9, 0, };
	BYTE pBuf2[2] = { 0xEB, 0xF9 };
	PBYTE pByte;

	pFunc = (FARPROC)GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
	pByte = (PBYTE)pFunc;
	if (pByte[0] == 0xEB)
		return FALSE;

	VirtualProtectEx(hHandle, (LPVOID)((DWORD)pFunc - 5), 7, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	// 1. NOP (0x90)
	dwAddress = (DWORD)pfnNew - (DWORD)pFunc;
	memcpy(&pBuf[1], &dwAddress, 4);
	memcpy((LPVOID)((DWORD)pFunc - 5), pBuf, 5);

	// 2. MOV EDI, EDI (0x8BFF)
	memcpy(pFunc, pBuf2, 2);

	VirtualProtectEx(hHandle, (LPVOID)((DWORD)pFunc - 5), 7, dwOldProtect, &dwOldProtect);

	return TRUE;
}

// ¸®¹ö½Ì ÇÙ½É¿ø¸®
BOOL unhook_by_code(LPCSTR szDllName, LPCSTR szFuncName, PBYTE pOrgBytes)
{
	FARPROC pFunc;
	DWORD dwOldProtect;
	PBYTE pByte;

	pFunc = (FARPROC)GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
	pByte = (PBYTE)pFunc;
	if (pByte[0] != 0xE9)
		return FALSE;

	VirtualProtect((LPVOID)pFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	memcpy(pFunc, pOrgBytes, 5);

	VirtualProtect((LPVOID)pFunc, 5, dwOldProtect, &dwOldProtect);

	return TRUE;
}

// ¸®¹ö½Ì ÇÙ½É¿ø¸®
BOOL unhook_by_codeex(HANDLE hHandle, LPCSTR szDllName, LPCSTR szFuncName, PBYTE pOrgBytes)
{
	FARPROC pFunc;
	DWORD dwOldProtect;
	PBYTE pByte;

	pFunc = (FARPROC)GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
	pByte = (PBYTE)pFunc;
	if (pByte[0] != 0xE9)
		return FALSE;

	VirtualProtectEx(hHandle, (LPVOID)pFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	memcpy(pFunc, pOrgBytes, 5);

	VirtualProtectEx(hHandle, (LPVOID)pFunc, 5, dwOldProtect, &dwOldProtect);

	return TRUE;
}

// ¸®¹ö½Ì ÇÙ½É¿ø¸®
BOOL unhook_by_hotpatch(LPCSTR szDllName, LPCSTR szFuncName)
{
	FARPROC pFunc;
	DWORD dwOldProtect;
	PBYTE pByte;
	BYTE pBuf[5] = { 0x90, 0x90, 0x90, 0x90, 0x90 };
	BYTE pBuf2[2] = { 0x8B, 0xFF };


	pFunc = (FARPROC)GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
	pByte = (PBYTE)pFunc;
	if (pByte[0] != 0xEB)
		return FALSE;

	VirtualProtect((LPVOID)pFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	// 1. NOP (0x90)
	memcpy((LPVOID)((DWORD)pFunc - 5), pBuf, 5);

	// 2. MOV EDI, EDI (0x8BFF)
	memcpy(pFunc, pBuf2, 2);

	VirtualProtect((LPVOID)pFunc, 5, dwOldProtect, &dwOldProtect);

	return TRUE;
}

// ¸®¹ö½Ì ÇÙ½É¿ø¸®
BOOL unhook_by_hotpatchex(HANDLE hHandle, LPCSTR szDllName, LPCSTR szFuncName)
{
	FARPROC pFunc;
	DWORD dwOldProtect;
	PBYTE pByte;
	BYTE pBuf[5] = { 0x90, 0x90, 0x90, 0x90, 0x90 };
	BYTE pBuf2[2] = { 0x8B, 0xFF };


	pFunc = (FARPROC)GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
	pByte = (PBYTE)pFunc;
	if (pByte[0] != 0xEB)
		return FALSE;

	VirtualProtectEx(hHandle, (LPVOID)pFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	// 1. NOP (0x90)
	memcpy((LPVOID)((DWORD)pFunc - 5), pBuf, 5);

	// 2. MOV EDI, EDI (0x8BFF)
	memcpy(pFunc, pBuf2, 2);

	VirtualProtectEx(hHandle, (LPVOID)pFunc, 5, dwOldProtect, &dwOldProtect);

	return TRUE;
}

// ¸®¹ö½Ì ÇÙ½É¿ø¸®
// ÀÌ°Ç dll¿ë
//NTSTATUS WINAPI NewZwQuerySystemInformation(
//	SYSTEM_INFORMATION_CLASS SystemInformationClass,
//	PVOID SystemInformation,
//	ULONG SystemInformationLength,
//	PULONG ReturnLength)
//{
//	NTSTATUS status;
//	FARPROC pFunc;
//	PSYSTEM_PROCESS_INFORMATION pCur, pPrev;
//	char szProcName[MAX_PATH] = { 0, };
//
//	unhook_by_code("ntdll.dll", "ZwQuerySystemInformation", g_pOrgZwQSI);
//
//	pFunc = GetProcAddress(GetModuleHandleA("ntdll.dll"),
//		"ZwQuerySystemInformation");
//	status = ((PFZWQUERYSYSTEMINFORMATION)pFunc)
//		(SystemInformationClass, SystemInformation,
//		SystemInformationLength, ReturnLength);
//
//	if (status != STATUS_SUCCESS)
//		goto __NTQUERYSYSTEMINFORMATION_END;
//
//	if (SystemInformationClass == SystemProcessInformation)
//	{
//		pCur = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
//
//		while (TRUE)
//		{
//			if (pCur->Reserved2[1] != NULL)
//			{
//				if (!_wcsicmp((PWSTR)pCur->Reserved2[1], target))
//				{
//					if (pCur->NextEntryOffset == 0)
//						pPrev->NextEntryOffset = 0;
//					else
//						pPrev->NextEntryOffset += pCur->NextEntryOffset;
//				}
//				else
//					pPrev = pCur;
//			}
//
//			if (pCur->NextEntryOffset == 0)
//				break;
//
//			pCur = (PSYSTEM_PROCESS_INFORMATION)((ULONG)pCur + pCur->NextEntryOffset);
//		}
//	}
//
//__NTQUERYSYSTEMINFORMATION_END:
//
//	hook_by_code("ntdll.dll", "ZwQuerySystemInformation",
//		(PROC)NewZwQuerySystemInformation, g_pOrgZwQSI);
//
//	return status;
//}

// http://stackoverflow.com/questions/18729137/how-to-get-the-handle-id-from-process-hwnd-programmaticaly
HMODULE getModulePid(DWORD processID, char* searchStr){ // gets the module by the module name from an explicit process

	HANDLE hProcess;
	HMODULE hMods[1024];
	TCHAR szModName[MAX_PATH];
	DWORD cbNeeded;

	if (hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID))
	{
		if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
		{
			unsigned int k;
			for (k = 0; k < (cbNeeded / sizeof(HMODULE)); ++k)
			{
				if (GetModuleFileNameEx(hProcess, hMods[k], szModName, sizeof(szModName) / sizeof(TCHAR)))
				{

					//printf( "fess pid: %u modname: %s\n", processID, szModName );

					if (strstr(szModName, searchStr))
					{
						printf("pid: &#37;u modname: %s\n", processID, szModName);
						CloseHandle(hProcess);
						return hMods[k];
					}
				}
			}//for
		}
	}
	CloseHandle(hProcess);
	return NULL;
}

HMODULE getModule(char* searchStr){ // gets the module by the modul name from all processes
	DWORD aProcesses[1024], cbNeeded, cProcesses;

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) return NULL;
	cProcesses = cbNeeded / sizeof(DWORD);

	HMODULE hmodule;
	unsigned int i;
	for (i = 0; i < cProcesses; ++i)
	{
		if (hmodule = getModulePid(aProcesses[i], searchStr))
		{
			return hmodule;
		}
	}
	return NULL;
}

// ¸®¹ö½Ì ÇÙ½É¿ø¸®
BOOL WINAPI NewCreateProcessA(
	LPCTSTR lpApplicationName,
	LPTSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCTSTR lpCurrentDirectory,
	LPSTARTUPINFO lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	)
{
	BOOL bRet;
	FARPROC pFunc;

	pFunc = GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateProcessA");
	pFunc = (FARPROC)((DWORD)pFunc + 2);
	bRet = ((PFCREATEPROCESSA)pFunc)(lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation);

	if (bRet)
		InjectDll2(lpProcessInformation->hProcess, target_mod);

	return bRet;
}

// ¸®¹ö½Ì ÇÙ½É¿ø¸®
BOOL WINAPI NewCreateProcessW(
	LPCTSTR lpApplicationName,
	LPTSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCTSTR lpCurrentDirectory,
	LPSTARTUPINFO lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	)
{
	BOOL bRet;
	FARPROC pFunc;

	pFunc = GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateProcessW");
	pFunc = (FARPROC)((DWORD)pFunc + 2);
	bRet = ((PFCREATEPROCESSW)pFunc)(lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation);

	if (bRet)
		InjectDll2(lpProcessInformation->hProcess, target_mod);

	return bRet;
}

// ¸®¹ö½Ì ÇÙ½É¿ø¸®
BOOL hook_iat(HMODULE hMod, HANDLE hHandle, LPCSTR szDllName, PROC pfnOrg, PROC pfnNew)
{
	LPCSTR szLibName;
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc;
	PIMAGE_THUNK_DATA pThunk;
	DWORD dwOldProtect, dwRVA;
	PBYTE pAddr;

	pAddr = (PBYTE)hMod;
	pAddr += *((DWORD*)&pAddr[0x3C]);
	dwRVA = *((DWORD*)&pAddr[0x80]);
	pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)hMod + dwRVA);

	for (; pImportDesc->Name; pImportDesc++)
	{
		szLibName = (LPCSTR)((DWORD)hMod + pImportDesc->Name);
		if (!_stricmp(szLibName, szDllName))
		{
			pThunk = (PIMAGE_THUNK_DATA)((DWORD)hMod +
				pImportDesc->FirstThunk);

			for (; pThunk->u1.Function; pThunk++)
			{
				if (pThunk->u1.Function == (DWORD)pfnOrg)
				{
					VirtualProtectEx(hHandle, (LPVOID)&pThunk->u1.Function,
						4,
						PAGE_EXECUTE_READWRITE,
						&dwOldProtect);
					pThunk->u1.Function = (DWORD)pfnNew;
					VirtualProtectEx(hHandle, (LPVOID)&pThunk->u1.Function,
						4,
						dwOldProtect,
						&dwOldProtect);

					return TRUE;
				}
			}
		}
	}

	return FALSE;
}

#endif