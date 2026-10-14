#include <windows.h>

namespace
{
	struct RawUnicodeString
	{
		USHORT Length;
		USHORT MaximumLength;
		PWCH Buffer;
	};

#pragma pack(push, 8)
	struct LdrEntry
	{
		LIST_ENTRY InLoadOrderLinks;
		LIST_ENTRY InMemoryOrderLinks;
		LIST_ENTRY InInitializationOrderLinks;
		PVOID DllBase;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		RawUnicodeString FullDllName;
		RawUnicodeString BaseDllName;
	};
#pragma pack(pop)

	DWORD Ror13(DWORD value)
	{
		return (value >> 13) | (value << 19);
	}

	// Position independence rules (the bootstrap copy runs BEFORE relocations
	// are applied): no switch statements, no CRT calls, volatile memory
	// access so the compiler cannot turn the loops into memcpy.
	void CopyBytes(volatile LPBYTE destination, const LPBYTE source, SIZE_T length)
	{
		for (SIZE_T i = 0; i < length; ++i)
			destination[i] = source[i];
	}

	DWORD HashWideLowercase(const wchar_t* name, USHORT lengthBytes)
	{
		DWORD hash = 0;
		for (USHORT i = 0; i < lengthBytes / sizeof(wchar_t); ++i)
		{
			hash = Ror13(hash);
			wchar_t c = name[i];
			if (c >= L'A' && c <= L'Z')
				c = c + (L'a' - L'A');
			hash = hash + (DWORD)c;
		}
		return hash;
	}

	DWORD HashAnsi(const char* name)
	{
		DWORD hash = 0;
		for (const char* c = name; *c; ++c)
		{
			hash = Ror13(hash);
			hash = hash + (DWORD)(UCHAR)*c;
		}
		return hash;
	}

	// Walks the export table of a module and returns the function address for
	// a hashed name, or null. Forwarded exports are not resolved.
	PVOID FindExport(const void* dllBase, DWORD functionNameHash)
	{
		if (dllBase == nullptr)
			return nullptr;

		const BYTE* base = (const BYTE*)dllBase;
		const auto dosHeader = (const IMAGE_DOS_HEADER*)base;
		if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			return nullptr;

		const auto ntHeaders = (const IMAGE_NT_HEADERS*)(base + dosHeader->e_lfanew);
		const DWORD exportRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		if (exportRva == 0)
			return nullptr;

		const auto exportDirectory = (const IMAGE_EXPORT_DIRECTORY*)(base + exportRva);
		const DWORD* names = (const DWORD*)(base + exportDirectory->AddressOfNames);
		const DWORD* functions = (const DWORD*)(base + exportDirectory->AddressOfFunctions);
		const WORD* ordinals = (const WORD*)(base + exportDirectory->AddressOfNameOrdinals);

		for (DWORD i = 0; i < exportDirectory->NumberOfNames; ++i)
		{
			if (HashAnsi((const char*)(base + names[i])) == functionNameHash)
			{
				const DWORD functionRva = functions[ordinals[i]];
				if (functionRva >= exportRva && functionRva < exportRva + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
					return nullptr;
				return (PVOID)(base + functionRva);
			}
		}

		return nullptr;
	}

	PVOID PebGetProcAddress(DWORD moduleNameHash, DWORD functionNameHash)
	{
		const BYTE* peb = (const BYTE*)__readgsqword(0x60);
		const BYTE* ldr = *(const BYTE* const*)(peb + 0x18);
		const LIST_ENTRY* head = (const LIST_ENTRY*)(ldr + 0x10);

		for (const LIST_ENTRY* link = head->Flink; link != head; link = link->Flink)
		{
			const auto entry = (const LdrEntry*)link;
			if (HashWideLowercase(entry->BaseDllName.Buffer, entry->BaseDllName.Length) == moduleNameHash)
				return FindExport(entry->DllBase, functionNameHash);
		}

		return nullptr;
	}

	DWORD SectionProtection(DWORD characteristics)
	{
		if (characteristics & IMAGE_SCN_MEM_EXECUTE)
			return PAGE_EXECUTE_READWRITE;
		if (characteristics & IMAGE_SCN_MEM_WRITE)
			return PAGE_READWRITE;
		return PAGE_READONLY;
	}
}

extern "C" __declspec(dllexport) DWORD WINAPI ReflectiveDllMain(LPBYTE bootstrapImage)
{
	typedef NTSTATUS(NTAPI* NtFlushInstructionCache_t)(HANDLE, PVOID, ULONG);
	typedef HMODULE(WINAPI* LoadLibraryA_t)(LPCSTR);
	typedef FARPROC(WINAPI* GetProcAddress_t)(HMODULE, LPCSTR);
	typedef LPVOID(WINAPI* VirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
	typedef BOOL(WINAPI* VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
	typedef BOOL(WINAPI* DllMain_t)(HINSTANCE, DWORD, LPVOID);

	const NtFlushInstructionCache_t ntFlushInstructionCache =
		(NtFlushInstructionCache_t)PebGetProcAddress(0xcef6e822, 0x534c0ab8);
	const LoadLibraryA_t loadLibraryA =
		(LoadLibraryA_t)PebGetProcAddress(0x8fecd63f, 0xec0e4e8e);
	const GetProcAddress_t getProcAddress =
		(GetProcAddress_t)PebGetProcAddress(0x8fecd63f, 0x7c0dfcaa);
	const VirtualAlloc_t virtualAlloc =
		(VirtualAlloc_t)PebGetProcAddress(0x8fecd63f, 0x91afca54);
	const VirtualProtect_t virtualProtect =
		(VirtualProtect_t)PebGetProcAddress(0x8fecd63f, 0x7946c61b);

	if (!ntFlushInstructionCache || !loadLibraryA || !getProcAddress || !virtualAlloc || !virtualProtect)
		return 0;

	const LPBYTE dllBase = bootstrapImage;
	const auto dosHeader = (const IMAGE_DOS_HEADER*)dllBase;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return 0;

	const auto ntHeaders = (PIMAGE_NT_HEADERS)(dllBase + dosHeader->e_lfanew);

	const LPBYTE image = (LPBYTE)virtualAlloc(nullptr, ntHeaders->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (image == nullptr)
		return 0;

	CopyBytes(image, dllBase, ntHeaders->OptionalHeader.SizeOfHeaders);

	const auto sections = (PIMAGE_SECTION_HEADER)((LPBYTE)&ntHeaders->OptionalHeader + ntHeaders->FileHeader.SizeOfOptionalHeader);
	for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
		CopyBytes(image + sections[i].VirtualAddress, dllBase + sections[i].PointerToRawData, sections[i].SizeOfRawData);

	const DWORD relocRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	if (relocRva != 0)
	{
		const UINT_PTR delta = (UINT_PTR)(image - ntHeaders->OptionalHeader.ImageBase);

		for (auto relocation = (PIMAGE_BASE_RELOCATION)(image + relocRva); relocation->SizeOfBlock; relocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)relocation + relocation->SizeOfBlock))
		{
			const LPBYTE page = image + relocation->VirtualAddress;
			const WORD* offsets = (const WORD*)((LPBYTE)relocation + sizeof(IMAGE_BASE_RELOCATION));

			for (DWORD i = 0; i < (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); ++i)
			{
				const WORD type = offsets[i] >> 12;
				const WORD offset = offsets[i] & 0xFFF;
				if (type == IMAGE_REL_BASED_DIR64)
					*(UINT_PTR*)(page + offset) += delta;
				else if (type == IMAGE_REL_BASED_HIGHLOW)
					*(DWORD*)(page + offset) += (DWORD)delta;
			}
		}
	}

	const DWORD importRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (importRva != 0)
	{
		for (auto descriptor = (PIMAGE_IMPORT_DESCRIPTOR)(image + importRva); descriptor->Name; ++descriptor)
		{
			const LPBYTE module = (LPBYTE)loadLibraryA((LPCSTR)(image + descriptor->Name));
			if (module == nullptr)
				continue;

			if (descriptor->OriginalFirstThunk == 0)
				continue;

			auto originalThunk = (PIMAGE_THUNK_DATA)(image + descriptor->OriginalFirstThunk);
			UINT_PTR* addressTable = (UINT_PTR*)(image + descriptor->FirstThunk);

			for (; originalThunk->u1.AddressOfData; ++originalThunk, ++addressTable)
			{
				if (originalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
					continue;

				const auto importByName = (PIMAGE_IMPORT_BY_NAME)(image + originalThunk->u1.AddressOfData);
				*addressTable = (UINT_PTR)getProcAddress((HMODULE)module, (LPCSTR)importByName->Name);
			}
		}
	}

	DWORD oldProtect = 0;
	for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
	{
		const SIZE_T size = i + 1 < ntHeaders->FileHeader.NumberOfSections
			? sections[i + 1].VirtualAddress - sections[i].VirtualAddress
			: ntHeaders->OptionalHeader.SizeOfImage - sections[i].VirtualAddress;
		if (!virtualProtect(image + sections[i].VirtualAddress, size, SectionProtection(sections[i].Characteristics), &oldProtect))
			return 0;
	}

	const auto dllMain = (DllMain_t)(image + ntHeaders->OptionalHeader.AddressOfEntryPoint);

	ntFlushInstructionCache((HANDLE)-1, nullptr, 0);

	// The bootstrap image is deliberately NOT freed: the caller (this very
	// function) still lives there until it returns.
	return dllMain((HINSTANCE)image, DLL_PROCESS_ATTACH, bootstrapImage) != FALSE ? 1 : 0;
}
