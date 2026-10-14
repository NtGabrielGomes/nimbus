#include "InlineHook.h"
#include <cstring>

namespace
{
	constexpr SIZE_T STUB_SIZE = 11;
	constexpr SIZE_T PATCH_SIZE = 12;
	constexpr SIZE_T MAX_HOOKS = 8;

	constexpr BYTE STUB_PROLOGUE[] = { 0x4C, 0x8B, 0xD1, 0xB8 };

	struct HookEntry
	{
		LPVOID function;
		LPVOID trampoline;
		BYTE original[PATCH_SIZE];
		bool active;
	};

	HookEntry g_entries[MAX_HOOKS] = {};

	HookEntry* FindEntry(LPVOID function)
	{
		for (HookEntry& entry : g_entries)
			if (entry.active && entry.function == function)
				return &entry;
		return nullptr;
	}

	LPVOID ResolveNtdllFunction(LPCSTR lpFunctionName)
	{
		const HMODULE ntdll = GetModuleHandleA("ntdll.dll");
		return ntdll != nullptr ? (LPVOID)GetProcAddress(ntdll, lpFunctionName) : nullptr;
	}
}

LPVOID InlineHook::Hook(LPCSTR lpFunctionName, LPVOID lpHookFunction)
{
	LPVOID function = ResolveNtdllFunction(lpFunctionName);
	if (function == nullptr || FindEntry(function) != nullptr)
		return nullptr;

	const BYTE* stub = (const BYTE*)function;
	if (memcmp(stub, STUB_PROLOGUE, sizeof(STUB_PROLOGUE)) != 0)
		return nullptr;

	const DWORD syscallNumber = *(const DWORD*)(stub + 4);

	const LPVOID trampoline = VirtualAlloc(nullptr, 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (trampoline == nullptr)
		return nullptr;

	BYTE stubCopy[STUB_SIZE] = { 0x4C, 0x8B, 0xD1, 0xB8 };
	memcpy(stubCopy + 4, &syscallNumber, sizeof(syscallNumber));
	stubCopy[8] = 0x0F;
	stubCopy[9] = 0x05;
	stubCopy[10] = 0xC3;
	memcpy(trampoline, stubCopy, STUB_SIZE);

	BYTE patch[PATCH_SIZE] = { 0x48, 0xB8 };
	memcpy(patch + 2, &lpHookFunction, sizeof(lpHookFunction));
	patch[10] = 0xFF;
	patch[11] = 0xE0;

	HookEntry* entry = nullptr;
	for (HookEntry& candidate : g_entries)
		if (!candidate.active)
		{
			entry = &candidate;
			break;
		}
	if (entry == nullptr)
	{
		VirtualFree(trampoline, 0, MEM_RELEASE);
		return nullptr;
	}

	DWORD oldProtect = 0;
	if (!VirtualProtect(function, PATCH_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect))
	{
		VirtualFree(trampoline, 0, MEM_RELEASE);
		return nullptr;
	}

	entry->function = function;
	entry->trampoline = trampoline;
	memcpy(entry->original, stub, PATCH_SIZE);
	entry->active = true;

	memcpy(function, patch, PATCH_SIZE);
	VirtualProtect(function, PATCH_SIZE, oldProtect, &oldProtect);
	FlushInstructionCache(GetCurrentProcess(), function, PATCH_SIZE);

	return trampoline;
}

bool InlineHook::Unhook(LPCSTR lpFunctionName)
{
	const LPVOID function = ResolveNtdllFunction(lpFunctionName);
	HookEntry* entry = function != nullptr ? FindEntry(function) : nullptr;
	if (entry == nullptr)
		return false;

	DWORD oldProtect = 0;
	if (VirtualProtect(entry->function, PATCH_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect))
	{
		memcpy(entry->function, entry->original, PATCH_SIZE);
		VirtualProtect(entry->function, PATCH_SIZE, oldProtect, &oldProtect);
		FlushInstructionCache(GetCurrentProcess(), entry->function, PATCH_SIZE);
	}

	VirtualFree(entry->trampoline, 0, MEM_RELEASE);
	entry->active = false;
	entry->function = nullptr;
	entry->trampoline = nullptr;
	return true;
}
