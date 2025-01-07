#include "NtAllocateVirtualMemory_Hook.h"
#include "page_guard_hook.h"

NTSTATUS NtAllocateVirtualMemory_Hook::hook(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
{
	const auto result = reinterpret_cast<decltype(&NtAllocateVirtualMemory_Hook::hook)>(NtAllocateVirtualMemory_Hook::original_function)(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);

	if (Protect == PAGE_EXECUTE_READWRITE && BaseAddress && RegionSize)
	{
		page_guard_hook::register_guard(reinterpret_cast<unsigned __int64>(*BaseAddress), *RegionSize);
	}

	return result;
}
