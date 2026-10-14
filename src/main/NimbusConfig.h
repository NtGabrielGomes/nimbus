#ifndef NIMBUS_CONFIG_H
#define NIMBUS_CONFIG_H

#include <windows.h>

namespace NimbusConfig
{
	struct Snapshot
	{
		LPWSTR names;
		LPWSTR paths;
		DWORD* pids;
		DWORD pidCount;
		USHORT* ports;
		DWORD portCount;
	};

	void StartRefreshThread();
	bool IsHiddenName(const wchar_t* name, size_t nameLength);
	bool IsHiddenPid(DWORD pid);
	bool IsHiddenPort(DWORD localPortNetworkOrder, DWORD remotePortNetworkOrder);
	bool IsHiddenItemPath(const wchar_t* directoryPath, const wchar_t* name, size_t nameLength);
	bool HasPathRules();
}

#endif
