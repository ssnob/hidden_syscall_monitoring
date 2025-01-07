#pragma once
#include <Windows.h>
#include <vector>
#include <mutex>
#include <unordered_map>
#include <DbgHelp.h>
#include <Psapi.h>

namespace page_guard_hook
{
	void register_guard(unsigned __int64 address, unsigned __int32 region_size);
	void install_handler();
};

