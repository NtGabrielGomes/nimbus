#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winsvc.h>
#include <iphlpapi.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "../main/WinStruct.h"

extern "C" __declspec(dllimport) NTSTATUS NTAPI NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
extern "C" __declspec(dllimport) NTSTATUS NTAPI NtQueryDirectoryFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS, BOOLEAN, PUNICODE_STRING, BOOLEAN);
extern "C" __declspec(dllimport) NTSTATUS NTAPI NtEnumerateKey(HANDLE, ULONG, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG);
extern "C" __declspec(dllimport) NTSTATUS NTAPI NtEnumerateValueKey(HANDLE, ULONG, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG);
extern "C" __declspec(dllimport) NTSTATUS NTAPI NtQueryKey(HANDLE, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG);

static const NTSTATUS STATUS_INFO_LENGTH_MISMATCH = (NTSTATUS)0xC0000004L;

static int g_failures = 0;
static int g_checks = 0;
static FILE* g_log = nullptr;

static void Check(bool ok, const char* what, const std::string& detail = std::string())
{
	++g_checks;
	if (!ok)
		++g_failures;

	char line[1024];
	if (detail.empty())
		snprintf(line, sizeof(line), "[%s] %s", ok ? "PASS" : "FAIL", what);
	else
		snprintf(line, sizeof(line), "[%s] %s (%s)", ok ? "PASS" : "FAIL", what, detail.c_str());

	printf("%s\r\n", line);
	if (g_log != nullptr)
	{
		fprintf(g_log, "%s\n", line);
		fflush(g_log);
	}
}

static std::string Narrow(const std::wstring& text)
{
	std::string out;
	out.reserve(text.size());
	for (wchar_t c : text)
		out.push_back(c < 128 ? (char)c : '?');
	return out;
}

static std::string Hex(NTSTATUS status)
{
	char buffer[16];
	snprintf(buffer, sizeof(buffer), "0x%08lX", (unsigned long)status);
	return buffer;
}

static bool ContainsMark(const wchar_t* name, size_t nameLength)
{
	const size_t markLength = wcslen(L"nimbus");
	for (size_t i = 0; name != nullptr && i + markLength <= nameLength; ++i)
	{
		size_t j = 0;
		while (j < markLength)
		{
			wchar_t a = name[i + j];
			wchar_t b = L"nimbus"[j];
			if (a >= L'A' && a <= L'Z') a = a + (L'a' - L'A');
			if (b >= L'A' && b <= L'Z') b = b + (L'a' - L'A');
			if (a != b)
				break;
			++j;
		}
		if (j == markLength)
			return true;
	}
	return false;
}

static bool ContainsMark(const wchar_t* name)
{
	return name != nullptr && ContainsMark(name, wcslen(name));
}

static std::wstring DirectoryOfCurrentModule()
{
	wchar_t modulePath[MAX_PATH] = {};
	if (GetModuleFileNameW(nullptr, modulePath, MAX_PATH) == 0)
		return std::wstring();
	const std::wstring path(modulePath);
	const size_t lastSlash = path.find_last_of(L"\\/");
	return lastSlash == std::wstring::npos ? std::wstring() : path.substr(0, lastSlash + 1);
}

static std::wstring JoinPaths(const std::wstring& a, const std::wstring& b)
{
	if (a.empty() || a.back() == L'\\')
		return a + b;
	return a + L"\\" + b;
}

static int FinishAndReport()
{
	char line[256];
	snprintf(line, sizeof(line), "==== %d checks, %d failures ====", g_checks, g_failures);
	printf("%s\r\n", line);
	if (g_log != nullptr)
	{
		fprintf(g_log, "%s\n", line);
		fclose(g_log);
	}
	return g_failures != 0 ? 1 : 0;
}

static int RunProbe()
{
	WSADATA wsa = {};
	WSAStartup(MAKEWORD(2, 2), &wsa);

	sockaddr_in addr = {};
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");

	const SOCKET tcp = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	addr.sin_port = htons(44441);
	bind(tcp, (sockaddr*)&addr, sizeof(addr));
	listen(tcp, 1);

	const SOCKET udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	addr.sin_port = htons(44442);
	bind(udp, (sockaddr*)&addr, sizeof(addr));

	Sleep(25000);
	return 0;
}

static void TestProcessHiding(HANDLE probeProcess, DWORD probePid)
{
	Check(WaitForSingleObject(probeProcess, 0) == WAIT_TIMEOUT, "probe process alive (precheck)");

	ULONG bufferSize = 1 << 20;
	std::vector<BYTE> buffer(bufferSize);
	ULONG returnLength = 0;
	NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
	for (int attempt = 0; attempt < 6 && status == STATUS_INFO_LENGTH_MISMATCH; ++attempt)
	{
		status = NtQuerySystemInformation(_SYSTEM_INFORMATION_CLASS::SystemProcessInformation, buffer.data(), bufferSize, &returnLength);
		if (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			bufferSize *= 2;
			buffer.resize(bufferSize);
		}
	}

	if (status != 0)
	{
		Check(false, "process list: NtQuerySystemInformation", "status " + Hex(status));
		return;
	}

	std::wstring leaked;
	auto entry = (PSYSTEM_PROCESS_INFORMATION)buffer.data();
	for (;;)
	{
		if (ContainsMark(entry->ImageName.Buffer, entry->ImageName.Length / sizeof(WCHAR)))
		{
			leaked.assign(entry->ImageName.Buffer ? entry->ImageName.Buffer : L"(unnamed)");
			break;
		}
		if (entry->NextEntryOffset == 0)
			break;
		entry = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)entry + entry->NextEntryOffset);
	}

	Check(leaked.empty(), "process list hides marker", leaked.empty() ? "probe pid " + std::to_string(probePid) : Narrow(leaked));
}

template <typename T>
static void CollectNames(const BYTE* info, size_t bytes, std::vector<std::wstring>& names)
{
	const BYTE* record = info;
	while (true)
	{
		const auto typed = (const T*)record;
		names.emplace_back(typed->FileName, typed->FileNameLength / sizeof(WCHAR));
		if (typed->NextEntryOffset == 0)
			break;
		record += typed->NextEntryOffset;
		if ((size_t)(record - info) >= bytes)
			break;
	}
	(void)bytes;
}

static bool QueryDirectoryByClass(const std::wstring& path, FILE_INFORMATION_CLASS infoClass, std::vector<std::wstring>& names)
{
	const HANDLE directory = CreateFileW(
		path.c_str(), FILE_LIST_DIRECTORY,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);

	if (directory == INVALID_HANDLE_VALUE)
		return false;

	wchar_t patternBuffer[] = L"*";
	UNICODE_STRING pattern = {};
	pattern.Buffer = patternBuffer;
	pattern.Length = 2;
	pattern.MaximumLength = 4;

	BYTE info[8192];
	IO_STATUS_BLOCK ioStatus = {};
	const NTSTATUS status = NtQueryDirectoryFile(
		directory, nullptr, nullptr, nullptr, &ioStatus, info, sizeof(info),
		infoClass, FALSE, &pattern, FALSE);

	CloseHandle(directory);

	if (status != 0)
		return false;

	const size_t bytes = (size_t)ioStatus.Information;
	switch (infoClass)
	{
	case FILE_INFORMATION_CLASS::FileDirectoryInformation:
		CollectNames<FILE_DIRECTORY_INFORMATION>(info, bytes, names); break;
	case FILE_INFORMATION_CLASS::FileFullDirectoryInformation:
		CollectNames<FILE_FULL_DIR_INFORMATION>(info, bytes, names); break;
	case FILE_INFORMATION_CLASS::FileBothDirectoryInformation:
		CollectNames<FILE_BOTH_DIR_INFORMATION>(info, bytes, names); break;
	case FILE_INFORMATION_CLASS::FileIdBothDirectoryInformation:
		CollectNames<FILE_ID_BOTH_DIR_INFORMATION>(info, bytes, names); break;
	case FILE_INFORMATION_CLASS::FileIdExtdDirectoryInformation:
		CollectNames<FILE_ID_EXTD_DIR_INFORMATION>(info, bytes, names); break;
	default:
		break;
	}
	return true;
}

static void TestDirectoryHiding(const std::wstring& base)
{
	const std::wstring dir = JoinPaths(base, L"nimbus_rk_test");
	const std::wstring allHiddenDir = JoinPaths(base, L"nimbus_rk_all");

	CreateDirectoryW(dir.c_str(), nullptr);
	CreateDirectoryW(allHiddenDir.c_str(), nullptr);

	HANDLE file = CreateFileW(JoinPaths(dir, L"nimbus_a.txt").c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
	file = CreateFileW(JoinPaths(dir, L"normal.txt").c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
	file = CreateFileW(JoinPaths(allHiddenDir, L"nimbus_only.txt").c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (file != INVALID_HANDLE_VALUE) CloseHandle(file);

	const struct { FILE_INFORMATION_CLASS infoClass; const char* label; } classes[] = {
		{ FILE_INFORMATION_CLASS::FileDirectoryInformation, "FileDirectoryInformation" },
		{ FILE_INFORMATION_CLASS::FileFullDirectoryInformation, "FileFullDirectoryInformation" },
		{ FILE_INFORMATION_CLASS::FileBothDirectoryInformation, "FileBothDirectoryInformation" },
		{ FILE_INFORMATION_CLASS::FileIdBothDirectoryInformation, "FileIdBothDirectoryInformation" },
		{ FILE_INFORMATION_CLASS::FileIdExtdDirectoryInformation, "FileIdExtdDirectoryInformation" },
	};

	for (const auto& variant : classes)
	{
		std::vector<std::wstring> names;
		const bool gotEntries = QueryDirectoryByClass(dir, variant.infoClass, names);

		bool sawNormal = false, sawHidden = false;
		for (const auto& name : names)
		{
			if (name == L"normal.txt") sawNormal = true;
			if (ContainsMark(name.c_str())) sawHidden = true;
		}

		Check(gotEntries && sawNormal && !sawHidden, (std::string("dir listing hides marker: ") + variant.label).c_str(),
			sawHidden ? "marker leaked" : (sawNormal ? "" : "normal.txt missing"));
	}

	{
		std::vector<std::wstring> names;
		BYTE scratch[64];
		wchar_t patternBuffer[] = L"*";
		UNICODE_STRING pattern = {};
		pattern.Buffer = patternBuffer;
		pattern.Length = 2;
		pattern.MaximumLength = 4;
		IO_STATUS_BLOCK ioStatus = {};

		const HANDLE directory = CreateFileW(allHiddenDir.c_str(), FILE_LIST_DIRECTORY,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
		const NTSTATUS rawStatus = directory != INVALID_HANDLE_VALUE
			? NtQueryDirectoryFile(directory, nullptr, nullptr, nullptr, &ioStatus, scratch, sizeof(scratch),
				FILE_INFORMATION_CLASS::FileIdBothDirectoryInformation, FALSE, &pattern, FALSE)
			: (NTSTATUS)0xDEAD0002L;
		if (directory != INVALID_HANDLE_VALUE) CloseHandle(directory);

		std::string leaked;
		for (const auto& n : names)
			if (n != L"." && n != L"..")
				leaked += " " + Narrow(n);
		Check(leaked.empty(), "all-hidden dir reports empty result", leaked.empty() ? ("raw=" + Hex(rawStatus)) : "leaked:" + leaked);
	}

	{
	WIN32_FIND_DATAW findData = {};
	bool sawHidden = false;
	const HANDLE find = FindFirstFileW(JoinPaths(base, L"*").c_str(), &findData);
		if (find != INVALID_HANDLE_VALUE)
		{
			do
			{
				if (ContainsMark(findData.cFileName))
					sawHidden = true;
			} while (FindNextFileW(find, &findData));
			FindClose(find);
		}
		Check(!sawHidden, "FindFirstFileW root listing hides marker dirs");
	}

	{
		WIN32_FIND_DATAW findData = {};
		bool sawNormal = false, sawHidden = false;
		std::string names;
		const HANDLE find = FindFirstFileW(JoinPaths(dir, L"*").c_str(), &findData);
		if (find == INVALID_HANDLE_VALUE)
		{
			Check(false, "FindFirstFileW pattern listing filtered", "GetLastError=" + std::to_string(GetLastError()));
		}
		else
		{
			do
			{
				if (wcscmp(findData.cFileName, L"normal.txt") == 0) sawNormal = true;
				if (ContainsMark(findData.cFileName)) sawHidden = true;
				names += " " + Narrow(findData.cFileName);
			} while (FindNextFileW(find, &findData));
			FindClose(find);
			Check(sawNormal && !sawHidden, "FindFirstFileW pattern listing filtered", names);
		}
	}
}

static void TestRegistryHiding()
{
	const wchar_t* parentName = L"Software\\zz_nimbus_rk_test";
	HKEY parent = nullptr;
	if (RegCreateKeyExW(HKEY_CURRENT_USER, parentName, 0, nullptr, REG_OPTION_VOLATILE,
		KEY_ALL_ACCESS, nullptr, &parent, nullptr) != ERROR_SUCCESS)
	{
		Check(false, "registry: test key created");
		return;
	}
	Check(true, "registry: test key created");

	HKEY sub = nullptr;
	RegCreateKeyExW(parent, L"nimbus_child", 0, nullptr, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, nullptr, &sub, nullptr);
	if (sub) RegCloseKey(sub);
	RegCreateKeyExW(parent, L"normal_child", 0, nullptr, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, nullptr, &sub, nullptr);
	if (sub) RegCloseKey(sub);
	RegSetValueExW(parent, L"nimbus_val", 0, REG_DWORD, (const BYTE*)parentName, sizeof(DWORD));
	RegSetValueExW(parent, L"normal_val", 0, REG_DWORD, (const BYTE*)parentName, sizeof(DWORD));

	{
		BYTE buffer[2048];
		ULONG length = 0;
		const NTSTATUS status = NtQueryKey(parent, KEY_INFORMATION_CLASS::KeyFullInformation, buffer, sizeof(buffer), &length);
		if (status == 0)
		{
			const auto info = (PKEY_FULL_INFORMATION)buffer;
			Check(info->SubKeys == 1, "NtQueryKey SubKeys adjusted", std::to_string(info->SubKeys));
			Check(info->Values == 1, "NtQueryKey Values adjusted", std::to_string(info->Values));
		}
		else
		{
			Check(false, "NtQueryKey", "status " + Hex(status));
		}
	}

	{
		bool sawNormal = false, sawHidden = false;
		BYTE buffer[2048];
		for (ULONG index = 0;; ++index)
		{
			ULONG length = 0;
			const NTSTATUS status = NtEnumerateKey(parent, index, KEY_INFORMATION_CLASS::KeyBasicInformation, buffer, sizeof(buffer), &length);
			if (status != 0)
				break;
			const auto info = (PKEY_BASIC_INFORMATION)buffer;
			const std::wstring name(info->Name, info->NameLength / sizeof(WCHAR));
			if (name == L"normal_child") sawNormal = true;
			if (ContainsMark(info->Name, info->NameLength / sizeof(WCHAR))) sawHidden = true;
		}
		Check(sawNormal && !sawHidden, "NtEnumerateKey hides marker subkey");
	}

	{
		bool sawNormal = false, sawHidden = false;
		BYTE buffer[2048];
		for (ULONG index = 0;; ++index)
		{
			ULONG length = 0;
			const NTSTATUS status = NtEnumerateValueKey(parent, index, KEY_VALUE_INFORMATION_CLASS::KeyValueBasicInformation, buffer, sizeof(buffer), &length);
			if (status != 0)
				break;
			const auto info = (PKEY_VALUE_BASIC_INFORMATION)buffer;
			const std::wstring name(info->Name, info->NameLength / sizeof(WCHAR));
			if (name == L"normal_val") sawNormal = true;
			if (ContainsMark(info->Name, info->NameLength / sizeof(WCHAR))) sawHidden = true;
		}
		Check(sawNormal && !sawHidden, "NtEnumerateValueKey hides marker value");
	}

	RegCloseKey(parent);
	RegDeleteTreeW(HKEY_CURRENT_USER, parentName);
}

static void TestServiceHiding()
{
	const SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE | SC_MANAGER_ENUMERATE_SERVICE);
	if (scm == nullptr)
	{
		printf("[SKIP] service hiding (not elevated)\r\n");
		if (g_log != nullptr) fprintf(g_log, "[SKIP] service hiding (not elevated)\n");
		return;
	}

	const SC_HANDLE hidden = CreateServiceW(scm, L"nimbus_svc_probe", nullptr, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
		SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, L"C:\\Windows\\System32\\cmd.exe", nullptr, nullptr, nullptr, nullptr, nullptr);
	const SC_HANDLE normal = CreateServiceW(scm, L"zz_rk_normal_probe", nullptr, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
		SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, L"C:\\Windows\\System32\\cmd.exe", nullptr, nullptr, nullptr, nullptr, nullptr);

	if (hidden == nullptr || normal == nullptr)
	{
		Check(false, "service: probe services created", "CreateServiceW failed");
		if (hidden) { DeleteService(hidden); CloseServiceHandle(hidden); }
		if (normal) { DeleteService(normal); CloseServiceHandle(normal); }
		CloseServiceHandle(scm);
		return;
	}

	bool sawNormal = false, sawHidden = false;
	DWORD bytesNeeded = 0, serviceCount = 0, resumeHandle = 0;
	BYTE buffer[64 * 1024];
	if (EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32_OWN_PROCESS, SERVICE_STATE_ALL,
		buffer, sizeof(buffer), &bytesNeeded, &serviceCount, &resumeHandle, nullptr))
	{
		const auto services = (const ENUM_SERVICE_STATUS_PROCESSW*)buffer;
		for (DWORD i = 0; i < serviceCount; ++i)
		{
			if (wcscmp(services[i].lpServiceName, L"zz_rk_normal_probe") == 0) sawNormal = true;
			if (ContainsMark(services[i].lpServiceName)) sawHidden = true;
		}
		Check(sawNormal && !sawHidden, "EnumServicesStatusExW hides marker service");
	}
	else
	{
		Check(false, "EnumServicesStatusExW", "call failed");
	}

	DeleteService(hidden);
	DeleteService(normal);
	CloseServiceHandle(hidden);
	CloseServiceHandle(normal);
	CloseServiceHandle(scm);
}

static void TestNetworkHiding(DWORD probePid)
{

	sockaddr_in addr = {};
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr.sin_port = htons(44443);
	const SOCKET self = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	bind(self, (sockaddr*)&addr, sizeof(addr));
	listen(self, 1);

	ULONG bufferSize = 128 * 1024;
	std::vector<BYTE> buffer(bufferSize);
	DWORD result = ERROR_INSUFFICIENT_BUFFER;
	for (int attempt = 0; attempt < 4 && result == ERROR_INSUFFICIENT_BUFFER; ++attempt)
	{
		result = GetExtendedTcpTable(buffer.data(), &bufferSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
		if (result == ERROR_INSUFFICIENT_BUFFER)
		{
			bufferSize *= 2;
			buffer.resize(bufferSize);
		}
	}

	if (result != NO_ERROR)
	{
		Check(false, "GetExtendedTcpTable", "error " + std::to_string(result));
	}
	else
	{
		const auto table = (const MIB_TCPTABLE_OWNER_PID*)buffer.data();
		bool sawSelf = false, sawProbe = false;
		for (DWORD i = 0; i < table->dwNumEntries; ++i)
		{
			if (table->table[i].dwOwningPid == GetCurrentProcessId()) sawSelf = true;
			if (table->table[i].dwOwningPid == probePid) sawProbe = true;
		}
		Check(sawSelf && !sawProbe, "TCP table hides marker process rows", sawProbe ? "probe row leaked" : "");
	}

	bufferSize = 128 * 1024;
	buffer.assign(bufferSize, 0);
	result = GetExtendedUdpTable(buffer.data(), &bufferSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
	if (result == NO_ERROR)
	{
		const auto table = (const MIB_UDPTABLE_OWNER_PID*)buffer.data();
		bool sawProbe = false;
		for (DWORD i = 0; i < table->dwNumEntries; ++i)
			if (table->table[i].dwOwningPid == probePid) sawProbe = true;
		Check(!sawProbe, "UDP table hides marker process rows");
	}
	else
	{
		Check(false, "GetExtendedUdpTable", "error " + std::to_string(result));
	}

	closesocket(self);
}

static void WriteConfigMultiString(const wchar_t* valueName, const std::wstring& doubleNullTerminated)
{
	HKEY key = nullptr;
	if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\nimbus_config", 0, nullptr,
		REG_OPTION_VOLATILE, KEY_SET_VALUE, nullptr, &key, nullptr) == ERROR_SUCCESS)
	{
		RegSetValueExW(key, valueName, 0, REG_MULTI_SZ,
			(const BYTE*)doubleNullTerminated.c_str(),
			(DWORD)((doubleNullTerminated.size() + 1) * sizeof(wchar_t)));
		RegCloseKey(key);
	}
}

static void Stage(const char* name);

static void TestConfigRules(const std::wstring& base)
{
	Stage("config");

	HANDLE file = CreateFileW(JoinPaths(base, L"zz_marked_file.txt").c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
	file = CreateFileW(JoinPaths(base, L"zz_secret.txt").c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (file != INVALID_HANDLE_VALUE) CloseHandle(file);

	sockaddr_in addr = {};
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr.sin_port = htons(44445);
	const SOCKET self = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	bind(self, (sockaddr*)&addr, sizeof(addr));
	listen(self, 1);

	WriteConfigMultiString(L"Names", std::wstring(L"zz_marked") + L'\0');
	WriteConfigMultiString(L"Paths", std::wstring(L"C:\\nimbus_test\\zz_secret.txt") + L'\0');
	WriteConfigMultiString(L"Pids", std::to_wstring(GetCurrentProcessId()) + L'\0');
	WriteConfigMultiString(L"Ports", std::wstring(L"44445") + L'\0');

	Sleep(7000);

	{
		std::vector<std::wstring> names;
		QueryDirectoryByClass(base, FILE_INFORMATION_CLASS::FileIdBothDirectoryInformation, names);
		bool sawMarked = false, sawSecret = false;
		for (const auto& n : names)
		{
			if (n == L"zz_marked_file.txt") sawMarked = true;
			if (n == L"zz_secret.txt") sawSecret = true;
		}
		Check(!sawMarked, "config Names rule hides file");
		Check(!sawSecret, "config Paths rule hides file");
	}

	{
		ULONG bufferSize = 1 << 20;
		std::vector<BYTE> buffer(bufferSize);
		ULONG returnLength = 0;
		if (NtQuerySystemInformation(_SYSTEM_INFORMATION_CLASS::SystemProcessInformation, buffer.data(), bufferSize, &returnLength) == 0)
		{
			bool sawSelf = false;
			auto entry = (PSYSTEM_PROCESS_INFORMATION)buffer.data();
			for (;;)
			{
				if ((DWORD)(DWORD_PTR)entry->UniqueProcessId == GetCurrentProcessId())
				{
					sawSelf = true;
					break;
				}
				if (entry->NextEntryOffset == 0)
					break;
				entry = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)entry + entry->NextEntryOffset);
			}
			Check(!sawSelf, "config Pids rule hides own process");
		}
	}

	{
		ULONG bufferSize = 128 * 1024;
		std::vector<BYTE> buffer(bufferSize);
		if (GetExtendedTcpTable(buffer.data(), &bufferSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
		{
			const auto table = (const MIB_TCPTABLE_OWNER_PID*)buffer.data();
			bool sawPort = false;
			for (DWORD i = 0; i < table->dwNumEntries; ++i)
				if (table->table[i].dwOwningPid == GetCurrentProcessId()) sawPort = true;
			Check(!sawPort, "config Ports rule hides TCP listener");
		}
	}

	RegDeleteKeyW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\nimbus_config");
	Sleep(7000);

	closesocket(self);
	DeleteFileW(JoinPaths(base, L"zz_marked_file.txt").c_str());
	DeleteFileW(JoinPaths(base, L"zz_secret.txt").c_str());
}

static void Stage(const char* name)
{
	if (g_log != nullptr)
	{
		fprintf(g_log, "-- %s\n", name);
		fflush(g_log);
	}
}

int wmain(int argc, wchar_t* argv[])
{
	Stage("probe-check");
	if (argc > 1 && wcscmp(argv[1], L"--probe") == 0)
		return RunProbe();

	Stage("open-log");
	if (argc > 1)
		g_log = _wfopen(argv[1], L"w");

	Stage("wsa");
	WSADATA wsa = {};
	WSAStartup(MAKEWORD(2, 2), &wsa);

	Stage("paths");
	const std::wstring base = DirectoryOfCurrentModule();

	Stage("load-dll");
	const HMODULE dll = LoadLibraryW(JoinPaths(base, L"nimbus_src.dll").c_str());
	if (dll == nullptr)
	{
		Check(false, "nimbus_src.dll loaded", "LoadLibraryW failed");
		return FinishAndReport();
	}
	Check(true, "nimbus_src.dll loaded");
	Sleep(1500);
	Stage("hooks-wait");
	Stage("inline-diag");
	{

		const char* names[] = { "NtQuerySystemInformation", "NtQueryDirectoryFile", "NtQueryDirectoryFileEx" };
		char line[256];
		for (const char* fn : names)
		{
			const auto address = (const BYTE*)GetProcAddress(GetModuleHandleA("ntdll.dll"), fn);
			snprintf(line, sizeof(line), "[diag] %s: %02X %02X %02X %02X", fn,
				address[0], address[1], address[2], address[3]);
			printf("%s\r\n", line);
			if (g_log != nullptr) { fprintf(g_log, "%s\n", line); fflush(g_log); }
		}

		BYTE basic[64] = {};
		ULONG basicLen = 0;
		const NTSTATUS canary = NtQuerySystemInformation(_SYSTEM_INFORMATION_CLASS::SystemBasicInformation, basic, sizeof(basic), &basicLen);
		snprintf(line, sizeof(line), "[diag] canary status=%s", Hex(canary).c_str());
		printf("%s\r\n", line);
		if (g_log != nullptr) { fprintf(g_log, "%s\n", line); fflush(g_log); }
	}

	STARTUPINFOW si {};
	si.cb = sizeof(si);
	PROCESS_INFORMATION pi = {};
	const std::wstring probePath = JoinPaths(base, L"nimbus_probe.exe");
	std::wstring commandLine = L"\"" + probePath + L"\" --probe";

	if (!CopyFileW(JoinPaths(base, L"test.exe").c_str(), probePath.c_str(), FALSE))
	{
		Check(false, "probe created", "CopyFileW failed");
		return FinishAndReport();
	}

	if (!CreateProcessW(probePath.c_str(), commandLine.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi))
	{
		Check(false, "probe started", "CreateProcessW failed");
		return FinishAndReport();
	}

	Sleep(1500);

	TestProcessHiding(pi.hProcess, pi.dwProcessId);
	TestDirectoryHiding(base);
	TestRegistryHiding();
	TestServiceHiding();
	TestNetworkHiding(pi.dwProcessId);
	TestConfigRules(base);

	TerminateProcess(pi.hProcess, 0);
	WaitForSingleObject(pi.hProcess, 5000);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	DeleteFileW(JoinPaths(base, L"nimbus_rk_test\\nimbus_a.txt").c_str());
	DeleteFileW(JoinPaths(base, L"nimbus_rk_test\\normal.txt").c_str());
	DeleteFileW(JoinPaths(base, L"nimbus_rk_all\\nimbus_only.txt").c_str());
	RemoveDirectoryW(JoinPaths(base, L"nimbus_rk_test").c_str());
	RemoveDirectoryW(JoinPaths(base, L"nimbus_rk_all").c_str());
	DeleteFileW(probePath.c_str());

	WSACleanup();
	return FinishAndReport();
}
