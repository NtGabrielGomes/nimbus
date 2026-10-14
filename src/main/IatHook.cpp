#include "IatHook.h"

namespace
{

	LPVOID HookImport(DWORD_PTR imageBase, LPCSTR lpModuleName, LPCSTR lpFunctionName, const LPVOID lpFunction)
	{
		if (imageBase == 0)
			return nullptr;

		const auto lpImageDosHeader = (PIMAGE_DOS_HEADER)imageBase;
		const auto lpImageNtHeader = (PIMAGE_NT_HEADERS)(imageBase + lpImageDosHeader->e_lfanew);

		const IMAGE_DATA_DIRECTORY& ImportDataDirectory = lpImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		if (ImportDataDirectory.VirtualAddress == 0)
			return nullptr;

		for (auto lpImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(imageBase + ImportDataDirectory.VirtualAddress);
			lpImportDescriptor->Name != 0; ++lpImportDescriptor)
		{
			const auto lpCurrentModuleName = (LPCSTR)(imageBase + lpImportDescriptor->Name);
			if (_stricmp(lpCurrentModuleName, lpModuleName) != 0)
				continue;

			if (lpImportDescriptor->OriginalFirstThunk == 0)
				continue;

			auto lpOriginalThunk = (PIMAGE_THUNK_DATA)(imageBase + lpImportDescriptor->OriginalFirstThunk);
			auto lpIatThunk = (PIMAGE_THUNK_DATA)(imageBase + lpImportDescriptor->FirstThunk);

			for (; lpOriginalThunk->u1.AddressOfData != 0; ++lpOriginalThunk, ++lpIatThunk)
			{
				if (lpOriginalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
					continue;

				const auto lpImportData = (PIMAGE_IMPORT_BY_NAME)(imageBase + lpOriginalThunk->u1.AddressOfData);
				if (strcmp(lpFunctionName, lpImportData->Name) != 0)
					continue;

				const LPVOID lpOrgFunction = (LPVOID)lpIatThunk->u1.Function;

				DWORD dwOldProtect = 0;
				if (!VirtualProtect(lpIatThunk, sizeof(*lpIatThunk), PAGE_READWRITE, &dwOldProtect))
					return nullptr;

				lpIatThunk->u1.Function = (DWORD_PTR)lpFunction;
				VirtualProtect(lpIatThunk, sizeof(*lpIatThunk), dwOldProtect, &dwOldProtect);

				return lpOrgFunction;
			}
		}

		return nullptr;
	}
}

LPVOID Iat::Hook(LPCSTR lpModuleName, LPCSTR lpFunctionName, const LPVOID lpFunction, LPCSTR lpTargetModuleName)
{
	return HookImport((DWORD_PTR)GetModuleHandleA(lpTargetModuleName), lpModuleName, lpFunctionName, lpFunction);
}

LPVOID Iat::Hook(LPCSTR lpModuleName, LPCSTR lpFunctionName, const LPVOID lpFunction)
{

	return HookImport((DWORD_PTR)GetModuleHandleW(nullptr), lpModuleName, lpFunctionName, lpFunction);
}
