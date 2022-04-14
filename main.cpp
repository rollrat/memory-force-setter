#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include "tptpgd.h"
#include "gtpget.h"

// 초기버전 0.9(1.20) ~ 현재버전 1.6(2.14)

FARPROC g_pOrgFunc = NULL;

int main()
{
START:
	int menu, size;
	DWORD *Result = 0;
	DWORD pid, value, count, address;
	HANDLE hHandle;
	char t[128];
	char *mod, *func, *mod1, *func1;
	DWORD tx;
	HMODULE module;
	OBJECT_ATTRIBUTES ObjectAttributes;
	CLIENT_ID cid;
	LPVOID* temp;
	InitializeObjectAttributes(&ObjectAttributes, NULL,
		OBJ_KERNEL_HANDLE, NULL, NULL);
	_ZwOpenProcess _ZwOP =
		(_ZwOpenProcess)GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwOpenProcess");
	_ZwClose _ZwC =
		(_ZwClose)GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwClose");

	printf("           %%--------------------------------------------------%%\n");
	printf("           |ROLLRAT SOFTWARE MEMORIES FORCE SETTER  LAST V 1.7|\n");
	printf("           |--------------------------------------------------|\n");
	printf("           |If you want to more information Then Visit My Blog|\n");
	printf("           |Or Send E-Mail(rollrat@naver.com) === RollRat APVL|\n");
	printf("           %%--------------------------------------------------%%\n\n");

	printf("   1. ScanProcessByName  2. ScanProcessById (!Caution to 1) 3. Native API Scan\nChoose : ");
	scanf_s("%d", &menu);

	switch (menu)
	{
	case 1:
		//
		// 프로세스 이름으로 pid를 얻어온다.
		//
		printf("Process Name : ");
		scanf_s("%s", &t, 128);
		pid = FindProcess(t);
		break;
	case 2:
		//
		// 그냥 pid를 읽어온다.
		//
		printf("Process Pid : ");
		scanf_s("%d", &pid);
		break;
	case 3:
		goto STKL;
	case 4:
		goto KTTL;
	case 5:
		goto LGTL;
	}

	printf("Scan for what : ");
	scanf_s("%d", &value);

	//
	//	FirstScan을 시작함.
	//
	Result = _$FirstScanOfProcess(pid, value, 4, count);

	printf("\n           <Address>\n");
	for (int i = 0; i < count; i++)
		printf("%X\n", Result[i]);
	printf("Result : %d times match.\n", count);

	for (;;){
		printf("\n1. Patch All Address  2. Scan Next Address  3. Patch Specific Addres 4. Exit\n");
		printf("Command : ");
		scanf_s("%d", &menu);

		switch (menu)
		{
		case 1:
			printf("Wirte Memory Value : ");
			scanf_s("%d", &value);

			hHandle = OpenProcess(MAXIMUM_ALLOWED, FALSE, pid);
			for (int i = 0; i < count; i++)
				_$WriteProcessMemory(hHandle, (LPVOID)Result[i], (LPCVOID)&value, 4);
			CloseHandle(hHandle);
			break;
		case 2:
			printf("Scan for : ");
			scanf_s("%d", &value);

			Result = _$NextScanOfProcess(pid, Result, count, value, 4, count);

			printf("\n           <Address>\n");
			for (int i = 0; i < count; i++)
				printf("%X\n", Result[i]);
			printf("Result : %d times match.\n", count);
			break;
		case 3:
			printf(" -> Address : ");
			scanf_s("%X", &address);

			printf(" -> Wirte Memory Value : ");
			scanf_s("%d", &value);

			hHandle = OpenProcess(MAXIMUM_ALLOWED, FALSE, pid);
			_$WriteProcessMemory(hHandle, (LPVOID)address, (LPCVOID)&value, 4);
			CloseHandle(hHandle);
			break;
		case 4:
			return 0;
			break;
		}

	}

	return 0;
STKL: // Native API를 이용하는 채널

	printf("OK\n");

	printf("Process Pid : ");
	scanf_s("%d", &pid);
	printf("\n1. Scan Generic  2. Scan with Native API  3. Scan with IPC 4. Dup Handle\nCommand : ");
	scanf_s("%d", &menu);

	cid.UniqueProcess = (HANDLE)pid;
	cid.UniqueThread = 0;

	switch (menu)
	{
	case 1:
		//
		// 처음으로 돌아간다.
		//
		goto START;
		break;
	case 2:
		//
		// 그대로 계속진행한다.
		//
		break;
	case 3:
		//
		// 아직 구현않함. (1.3에 추가예정)
		//
		goto STKL;
		break;
	case 4:
		//
		// 아직 구현않함. (함수는 구현함)
		//
		goto STKL;
		break;
	}
	//
	//	무엇을 검색할 것인가? 참고로 DWORD만 됨.
	//
	printf("Scan for what : ");
	scanf_s("%d", &value);

	//
	//	FirstScan을 시작함.
	//
	Result = _$FirstScanOfProcessWithNativeApi(pid, value, 4, count);

	printf("\n           <Address>\n");
	for (int i = 0; i < count; i++)
		printf("%X\n", Result[i]);
	printf("Result : %d times match.\n", count);

	for (;;){
		printf("\n1. Patch All Address  2. Scan Next Address  3. Patch Specific Addres 4. Exit\n");
		printf("Command : ");
		scanf_s("%d", &menu);

		switch (menu)
		{
		case 1:
			printf("Wirte Memory Value : ");
			scanf_s("%d", &value);

			_ZwOP(&hHandle, MAXIMUM_ALLOWED, &ObjectAttributes, &cid);
			for (int i = 0; i < count; i++)
				_$WriteProcessMemoryWithNativeApi(hHandle, (LPVOID)Result[i], (LPCVOID)&value, 4);
			_ZwC(hHandle);
			break;
		case 2:
			printf("Scan for : ");
			scanf_s("%d", &value);

			Result = _$NextScanOfProcessWithNativeApi(pid, Result, count, value, 4, count);

			printf("\n           <Address>\n");
			for (int i = 0; i < count; i++)
				printf("%X\n", Result[i]);
			printf("Result : %d times match.\n", count);
			break;
		case 3:
			printf(" -> Address : ");
			scanf_s("%X", &address);

			printf(" -> Wirte Memory Value : ");
			scanf_s("%d", &value);

			_ZwOP(&hHandle, MAXIMUM_ALLOWED, &ObjectAttributes, &cid);
			_$WriteProcessMemoryWithNativeApi(hHandle, (LPVOID)address, (LPCVOID)&value, 4);
			_ZwC(hHandle);
			break;
		case 4:
			return 0;
			break;
		}

	}
KTTL:

	system("cls");

	printf("           %%------------------------------------------------%%\n");
	printf("           |ROLLRAT SOFTWARE API HOOKING MANAGER VERSION 1.1|\n");
	printf("           %%------------------------------------------------%%\n\n");

	printf("1. Inject  2. Eject\nCommand : ");
	scanf_s("%d", &menu);

	printf("Process Pid : ");
	scanf_s("%d", &pid);

	cid.UniqueProcess = (HANDLE)pid;
	cid.UniqueThread = 0;

	printf("Dll Path : ");
	scanf_s("%s", &t, 128);

	_EnableNTPrivilege(SE_DEBUG_NAME, SE_PRIVILEGE_ENABLED);
/*
	if (!SetPrivilege(cid.UniqueProcess, SE_DEBUG_NAME, TRUE))
		return 1;*/

	switch (menu)
	{
	case 1:
		printf("1. Inject  2. All Process Inject\nCommand : ");
		scanf_s("%d", &menu);

		if (menu == 1)
		{
			if (InjectDll(pid, t))
				printf("success");
			else
				printf("failed");
		}
		else if (menu == 2)
		{
			if (InjectAllProcess(0, t))
				printf("success");
			else
				printf("failed");
		}
		break;
	case 2:
		printf("1. Eject  2. All Process Eject\nCommand : ");
		scanf_s("%d", &menu);

		if (menu == 1)
		{
			if (EjectDll(pid, t))
				printf("success");
			else
				printf("failed");
		}
		else if (menu == 2)
		{
			if (InjectAllProcess(1, t))
				printf("success");
			else
				printf("failed");
		}
		break;
	}
	
	goto START;
LGTL:

	printf("ok...\n");
	Result = (DWORD *)_$HPidWithBruteForce(&size);
	for (int i = 0; i < size; i++)
		printf("%d\n", Result[i]);

	goto START;
	return 0;
}


int main2()
{
START:
	int menu, size;
	DWORD *Result = 0;
	DWORD pid, value, count, address;
	HANDLE hHandle;
	char *t;
	char *mod, *func, *mod1, *func1;
	DWORD tx;
	HMODULE module;
	OBJECT_ATTRIBUTES ObjectAttributes;
	CLIENT_ID cid;
	LPVOID* temp;
	InitializeObjectAttributes(&ObjectAttributes, NULL,
		OBJ_KERNEL_HANDLE, NULL, NULL);
	_ZwOpenProcess _ZwOP =
		(_ZwOpenProcess)GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwOpenProcess");
	_ZwClose _ZwC =
		(_ZwClose)GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwClose");

	printf("           %%--------------------------------------------------%%\n");
	printf("           |ROLLRAT SOFTWARE MEMORIES FORCE SETTER VERSION 1.6|\n");
	printf("           |--------------------------------------------------|\n");
	printf("           |If you want to more information Then Visit My Blog|\n");
	printf("           |Or Send E-Mail(rollrat@naver.com) === RollRat APVL|\n");
	printf("           %%--------------------------------------------------%%\n\n");

	printf("Process Name : ");
	scanf_s("%s", &t, 128);
	pid = FindProcess(t);

	cid.UniqueProcess = (HANDLE)pid;
	cid.UniqueThread = 0;

	printf("OK\n");

	printf("Process Pid : ");
	scanf_s("%d", &pid);
	printf("\n1. Scan Generic  2. Scan with Native API\nCommand : ");
	scanf_s("%d", &menu);

	//
	//	무엇을 검색할 것인가? 참고로 DWORD만 됨.
	//
	printf("Scan for what : ");
	scanf_s("%d", &value);

	//
	//	FirstScan을 시작함.
	//
	Result = _$FirstScanOfProcessWithNativeApi(pid, value, 4, count);

	printf("\n           <Address>\n");
	for (int i = 0; i < count; i++)
		printf("%X\n", Result[i]);
	printf("Result : %d times match.\n", count);

	for (;;){
		printf("\n1. Patch All Address  2. Scan Next Address  3. Patch Specific Addres 4. Exit\n");
		printf("Command : ");
		scanf_s("%d", &menu);

		switch (menu)
		{
		case 1:
			printf("Wirte Memory Value : ");
			scanf_s("%d", &value);

			_ZwOP(&hHandle, MAXIMUM_ALLOWED, &ObjectAttributes, &cid);
			for (int i = 0; i < count; i++)
				_$WriteProcessMemoryWithNativeApi(hHandle, (LPVOID)Result[i], (LPCVOID)&value, 4);
			_ZwC(hHandle);
			break;
		case 2:
			printf("Scan for : ");
			scanf_s("%d", &value);

			Result = _$NextScanOfProcessWithNativeApi(pid, Result, count, value, 4, count);

			printf("\n           <Address>\n");
			for (int i = 0; i < count; i++)
				printf("%X\n", Result[i]);
			printf("Result : %d times match.\n", count);
			break;
		case 3:
			printf(" -> Address : ");
			scanf_s("%X", &address);

			printf(" -> Wirte Memory Value : ");
			scanf_s("%d", &value);

			_ZwOP(&hHandle, MAXIMUM_ALLOWED, &ObjectAttributes, &cid);
			_$WriteProcessMemoryWithNativeApi(hHandle, (LPVOID)address, (LPCVOID)&value, 4);
			_ZwC(hHandle);
			break;
		case 4:
			return 0;
			break;
		}

	}
}