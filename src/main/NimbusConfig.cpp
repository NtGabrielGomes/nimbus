#include "NimbusConfig.h"

namespace
{
	const wchar_t* const BUILTIN_MARKER = L"nimbus";
	const wchar_t* const CONFIG_KEY = L"SOFTWARE\\nimbus_config";

	NimbusConfig::Snapshot* volatile g_current = nullptr;

	NimbusConfig::Snapshot* LoadSnapshot()
	{
		NimbusConfig::Snapshot* snapshot = (NimbusConfig::Snapshot*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(NimbusConfig::Snapshot));

		HKEY key = nullptr;
		if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, CONFIG_KEY, 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS)
			return snapshot;

		WCHAR names[8192];
		WCHAR paths[8192];
		DWORD namesSize = sizeof(names);
		DWORD pathsSize = sizeof(paths);
		WCHAR pids[1024];
		WCHAR ports[1024];
		DWORD pidsSize = sizeof(pids);
		DWORD portsSize = sizeof(ports);

		if (RegQueryValueExW(key, L"Names", nullptr, nullptr, (LPBYTE)names, &namesSize) != ERROR_SUCCESS) namesSize = 2, names[0] = 0, names[1] = 0;
		if (RegQueryValueExW(key, L"Paths", nullptr, nullptr, (LPBYTE)paths, &pathsSize) != ERROR_SUCCESS) pathsSize = 2, paths[0] = 0, paths[1] = 0;
		if (RegQueryValueExW(key, L"Pids", nullptr, nullptr, (LPBYTE)pids, &pidsSize) != ERROR_SUCCESS) pidsSize = 2, pids[0] = 0, pids[1] = 0;
		if (RegQueryValueExW(key, L"Ports", nullptr, nullptr, (LPBYTE)ports, &portsSize) != ERROR_SUCCESS) portsSize = 2, ports[0] = 0, ports[1] = 0;

		RegCloseKey(key);

		const HANDLE heap = GetProcessHeap();

		snapshot->names = (LPWSTR)HeapAlloc(heap, 0, namesSize);
		snapshot->paths = (LPWSTR)HeapAlloc(heap, 0, pathsSize);
		if (snapshot->names) CopyMemory(snapshot->names, names, namesSize);
		if (snapshot->paths) CopyMemory(snapshot->paths, paths, pathsSize);

		for (LPWSTR cursor = pids; *cursor; cursor += lstrlenW(cursor) + 1)
			++snapshot->pidCount;
		for (LPWSTR cursor = ports; *cursor; cursor += lstrlenW(cursor) + 1)
			++snapshot->portCount;

		snapshot->pids = (DWORD*)HeapAlloc(heap, 0, snapshot->pidCount * sizeof(DWORD));
		snapshot->ports = (USHORT*)HeapAlloc(heap, 0, snapshot->portCount * sizeof(USHORT));

		DWORD pidIndex = 0;
		for (LPWSTR cursor = pids; *cursor; cursor += lstrlenW(cursor) + 1)
			if (snapshot->pids) snapshot->pids[pidIndex++] = (DWORD)wcstoul(cursor, nullptr, 10);

		DWORD portIndex = 0;
		for (LPWSTR cursor = ports; *cursor; cursor += lstrlenW(cursor) + 1)
		{
			const unsigned long value = wcstoul(cursor, nullptr, 10);
			if (value > 0 && value <= 0xFFFF && snapshot->ports)
				snapshot->ports[portIndex++] = (USHORT)value;
		}
		if (snapshot->ports) snapshot->portCount = portIndex;

		return snapshot;
	}

	void FreeSnapshot(NimbusConfig::Snapshot* snapshot)
	{
		const HANDLE heap = GetProcessHeap();
		if (snapshot->names) HeapFree(heap, 0, snapshot->names);
		if (snapshot->paths) HeapFree(heap, 0, snapshot->paths);
		if (snapshot->pids) HeapFree(heap, 0, snapshot->pids);
		if (snapshot->ports) HeapFree(heap, 0, snapshot->ports);
		HeapFree(heap, 0, snapshot);
	}

	bool SnapshotsEqual(const NimbusConfig::Snapshot& a, const NimbusConfig::Snapshot& b)
	{
		if (a.pidCount != b.pidCount || a.portCount != b.portCount)
			return false;
		if ((a.names == nullptr) != (b.names == nullptr)) return false;
		if (a.names && b.names && lstrcmpiW(a.names, b.names) != 0) return false;
		if ((a.paths == nullptr) != (b.paths == nullptr)) return false;
		if (a.paths && b.paths && lstrcmpiW(a.paths, b.paths) != 0) return false;
		for (DWORD i = 0; i < a.pidCount; ++i)
			if (a.pids[i] != b.pids[i]) return false;
		for (DWORD i = 0; i < a.portCount; ++i)
			if (a.ports[i] != b.ports[i]) return false;
		return true;
	}

	DWORD WINAPI RefreshThread(LPVOID)
	{
		NimbusConfig::Snapshot* current = LoadSnapshot();
		g_current = current;

		for (;;)
		{
			Sleep(1000);

			NimbusConfig::Snapshot* next = LoadSnapshot();
			if (SnapshotsEqual(*current, *next))
			{
				FreeSnapshot(next);
			}
			else
			{
				const NimbusConfig::Snapshot* previous = current;
				current = next;
				g_current = current;

				// Readers may still walk the previous snapshot; retain it for
				// one short grace period before releasing it.
				Sleep(50);
				FreeSnapshot((NimbusConfig::Snapshot*)previous);
			}
		}
	}

	bool ContainsSubstring(const wchar_t* haystack, size_t haystackLength, const wchar_t* needle)
	{
		const size_t needleLength = lstrlenW(needle);
		for (size_t i = 0; haystack && i + needleLength <= haystackLength; ++i)
		{
			size_t j = 0;
			while (j < needleLength)
			{
				wchar_t a = haystack[i + j];
				wchar_t b = needle[j];
				if (a >= L'A' && a <= L'Z') a = a + (L'a' - L'A');
				if (b >= L'A' && b <= L'Z') b = b + (L'a' - L'A');
				if (a != b) break;
				++j;
			}
			if (j == needleLength)
				return true;
		}
		return false;
	}

	bool EqualsCaseInsensitive(const wchar_t* a, size_t aLength, const wchar_t* b)
	{
		if ((size_t)lstrlenW(b) != aLength)
			return false;
		for (size_t i = 0; i < aLength; ++i)
		{
			wchar_t x = a[i];
			wchar_t y = b[i];
			if (x >= L'A' && x <= L'Z') x = x + (L'a' - L'A');
			if (y >= L'A' && y <= L'Z') y = y + (L'a' - L'A');
			if (x != y)
				return false;
		}
		return true;
	}

	const NimbusConfig::Snapshot& Current()
	{
		if (const NimbusConfig::Snapshot* snapshot = g_current)
			return *snapshot;

		static const NimbusConfig::Snapshot empty = {};
		return empty;
	}
}

void NimbusConfig::StartRefreshThread()
{
	if (g_current != nullptr)
		return;

	if (const HANDLE thread = CreateThread(nullptr, 0, RefreshThread, nullptr, 0, nullptr))
		CloseHandle(thread);
}

bool NimbusConfig::IsHiddenName(const wchar_t* name, size_t nameLength)
{
	if (name == nullptr)
		return false;

	if (ContainsSubstring(name, nameLength, BUILTIN_MARKER))
		return true;

	const Snapshot& snapshot = Current();
	if (snapshot.names == nullptr)
		return false;

	for (LPWSTR entry = snapshot.names; *entry; entry += lstrlenW(entry) + 1)
		if (ContainsSubstring(name, nameLength, entry))
			return true;

	return false;
}

bool NimbusConfig::IsHiddenPid(DWORD pid)
{
	const Snapshot& snapshot = Current();
	for (DWORD i = 0; i < snapshot.pidCount; ++i)
		if (snapshot.pids[i] == pid)
			return true;

	return false;
}

bool NimbusConfig::IsHiddenPort(DWORD localPortNetworkOrder, DWORD remotePortNetworkOrder)
{
	const Snapshot& snapshot = Current();
	for (DWORD i = 0; i < snapshot.portCount; ++i)
	{
		const USHORT port = snapshot.ports[i];
		const DWORD portNetworkOrder = ((DWORD)((port & 0xFF) << 8) | ((port >> 8) & 0xFF));
		if (portNetworkOrder == localPortNetworkOrder || portNetworkOrder == remotePortNetworkOrder)
			return true;
	}

	return false;
}

bool NimbusConfig::IsHiddenItemPath(const wchar_t* directoryPath, const wchar_t* name, size_t nameLength)
{
	if (directoryPath == nullptr || name == nullptr)
		return false;

	const Snapshot& snapshot = Current();
	if (snapshot.paths == nullptr)
		return false;

	wchar_t item[MAX_PATH * 2];
	size_t itemLength = 0;

	const size_t directoryLength = lstrlenW(directoryPath);
	if (directoryLength >= MAX_PATH)
		return false;
	CopyMemory(item, directoryPath, directoryLength * sizeof(wchar_t));
	itemLength = directoryLength;
	if (itemLength == 0 || item[itemLength - 1] != L'\\')
		item[itemLength++] = L'\\';
	if (itemLength + nameLength >= MAX_PATH * 2)
		return false;
	CopyMemory(item + itemLength, name, nameLength * sizeof(wchar_t));
	itemLength += nameLength;
	item[itemLength] = L'\0';

	for (LPWSTR entry = snapshot.paths; *entry; entry += lstrlenW(entry) + 1)
	{
		const size_t entryLength = lstrlenW(entry);
		if (entryLength > 0 && entry[entryLength - 1] == L'\\')
		{
			if (itemLength >= entryLength && EqualsCaseInsensitive(item, entryLength, entry))
				return true;
		}
		else if (EqualsCaseInsensitive(item, itemLength, entry))
		{
			return true;
		}
	}

	return false;
}

bool NimbusConfig::HasPathRules()
{
	const Snapshot& snapshot = Current();
	return snapshot.paths != nullptr && snapshot.paths[0] != L'\0';
}
