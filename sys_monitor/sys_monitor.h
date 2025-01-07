#pragma once
#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <DbgHelp.h>
#pragma comment(lib, "dbghelp")



namespace sys_monitor
{
	bool init();
}