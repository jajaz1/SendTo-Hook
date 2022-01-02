#include "stdafx.h"
#include "mem.h"
#include <iostream>


void mem::Patch(BYTE* dst, BYTE* src, unsigned int size)
{
	DWORD oldprotect;
	VirtualProtect(dst, size, PAGE_EXECUTE_READWRITE, &oldprotect);

	memcpy(dst, src, size);
	VirtualProtect(dst, size, oldprotect, &oldprotect);
}

void mem::PatchEx(BYTE* dst, BYTE* src, unsigned int size, HANDLE hProcess)
{
	DWORD oldprotect;
	VirtualProtectEx(hProcess, dst, size, PAGE_EXECUTE_READWRITE, &oldprotect);
	WriteProcessMemory(hProcess, dst, src, size, nullptr);
	VirtualProtectEx(hProcess, dst, size, oldprotect, &oldprotect);
}

void mem::Nop(BYTE* dst, unsigned int size)
{
	DWORD oldprotect;
	VirtualProtect(dst, size, PAGE_EXECUTE_READWRITE, &oldprotect);
	memset(dst, 0x90, size);
	VirtualProtect(dst, size, oldprotect, &oldprotect);
}

void mem::NopEx(BYTE* dst, unsigned int size, HANDLE hProcess)
{
	BYTE* nopArray = new BYTE[size];
	memset(nopArray, 0x90, size);

	PatchEx(dst, nopArray, size, hProcess);
	delete[] nopArray;
}

uintptr_t mem::FindDMAAddy(uintptr_t ptr, std::vector<unsigned int> offsets)
{
	uintptr_t addr = ptr;
	for (unsigned int i = 0; i < offsets.size(); ++i)
	{
		addr = *(uintptr_t*)addr;
		addr += offsets[i];
	}
	return addr;
}
bool mem::Detour32(BYTE* src, BYTE* dst, const uintptr_t len)
{
	if (len < 5)
	{
		return false;
	}

	DWORD curProtection;
	VirtualProtect(src, len, PAGE_EXECUTE_READWRITE, &curProtection);
	uintptr_t relativeAddress = dst - src - 5;
	*src = 0xE9;
	*(uintptr_t*)(src + 1) = relativeAddress;
	//*(src + 5) = 0x90;
	VirtualProtect(src, len, curProtection, &curProtection);
	return true;
}
BYTE* mem::TrampHook32(BYTE* src, BYTE* dst, uintptr_t len)
{
	//len = 6;
	if (len < 5)
	{
		return 0;
	}
	BYTE* gateway = (BYTE*)VirtualAlloc(0, 10, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memcpy_s(gateway, len, src, len);

	uintptr_t gateRelativeAddr = src - gateway - 5;

	*(gateway + len) = 0xE9;

	//ворованные байты + адрес возврата
	*(uintptr_t*)(uintptr_t)(gateway + len + 1) = gateRelativeAddr;

	Detour32(src, dst, len);

	return gateway;
}