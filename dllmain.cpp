#include "stdafx.h"
#include <iostream>
#include "mem.h"
#include <WinSock2.h>
#include "proc.h"


void hexDump(void* addr, int len)
{
	int i;
	unsigned char buff[500];
	unsigned char* pc = (unsigned char*)addr;
	// Process every byte in the data.
	for (i = 0; i < len; i++) {
		// Multiple of 16 means new line (with line offset).

		if ((i % 16) == 0) {
			// Just don't print ASCII for the zeroth line.
			if (i != 0)
				printf("  %s\n", buff);

			// Output the offset.
			std::cout << (int*)addr + 16 << " : ";
		}

		// Now the hex code for the specific character.
		printf(" %02x", pc[i]);

		// And store a printable ASCII character for later.
		if ((pc[i] < 0x20) || (pc[i] > 0x7e)) {
			buff[i % 16] = '.';
		}
		else {
			buff[i % 16] = pc[i];
		}

		buff[(i % 16) + 1] = '\0';
	}

	// Pad out last line if not exactly 16 characters.
	while ((i % 16) != 0) {
		printf("   ");
		i++;
	}

	// And print the final ASCII bit.
	printf("  %s\n", buff);
}

typedef BOOL(__thiscall* _myFunc2)(int This, int* a2, int a3);
_myFunc2 myFunc2;

BOOL __fastcall Hook1(int This, int EDX, int* a2, int a3)
{
	char i;
	int e;
	int c;
	unsigned char* pc = (unsigned char*)a2;

	if ((int)a2 > 0x18 )
	{
		if (GetAsyncKeyState(VK_RETURN))
		{
			for (i = 0; i < 50; i++)
			{
				printf("%x :", pc + (16 * i));
				for (e = 0; e < 16; ++e)
				{
					printf("%02x ", pc[e + (16 * i)]);
				}
				printf("\t");
				for (c = 0; c < 16; ++c)
				{
					printf("%c", pc[c + (16 * i)]);
				}
				printf("\n");
			}
			printf("\n===================================================================\n");
		}
	}

	return myFunc2(This, a2, a3);
}


DWORD WINAPI HThread(HMODULE hModule)
{
	//Create Console
	AllocConsole();
	FILE* f;
	freopen_s(&f, "CONOUT$", "w", stdout);

	uintptr_t xaddr = GetModuleBaseAddress(0, L"engine.dll");
	myFunc2 = (_myFunc2)(xaddr + 0x225790);
	myFunc2 = (_myFunc2)mem::TrampHook32((BYTE*)myFunc2, (BYTE*)Hook1, 5);

	//x0r = (_x0r)(xaddr + 0x1016D170); 
	//x0r = (_x0r)mem::TrampHook32((BYTE*)x0r, (BYTE*)myx0, 5);

	//osend = (tsend)GetProcAddress(GetModuleHandle(L"ws2_32.dll"), "sendto");
	//osend = (tsend)mem::TrampHook32((BYTE*)osend, (BYTE*)hsend, 5);
	while (true)
	{

	}
	fclose(f);
	FreeConsole();	
	FreeLibraryAndExitThread(hModule, 0);
	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		CloseHandle(CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)HThread, hModule, 0, nullptr));
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
