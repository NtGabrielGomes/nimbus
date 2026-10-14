#ifndef IAT_HOOK_H
#define IAT_HOOK_H

#include <windows.h>

namespace Iat
{
	LPVOID Hook(LPCSTR moduleName, LPCSTR functionName, const LPVOID hookFunction, LPCSTR targetModuleName);
	LPVOID Hook(LPCSTR moduleName, LPCSTR functionName, const LPVOID hookFunction);
}

#endif
