#ifndef INLINE_HOOK_H
#define INLINE_HOOK_H

#include <windows.h>

namespace InlineHook
{
	LPVOID Hook(LPCSTR functionName, LPVOID hookFunction);
	bool Unhook(LPCSTR functionName);
}

#endif
