#pragma once
#include <Windows.h>
#include <stdio.h>
#include <intrin.h>
#include <thread>
#include <shared_mutex>
#include <atomic>
#include <mutex>

typedef LONG NTSTATUS;

namespace NtAllocateVirtualMemory_Hook
{
	inline unsigned __int64 original_function;

	NTSTATUS hook(
		HANDLE    ProcessHandle,
		PVOID* BaseAddress,
		ULONG_PTR ZeroBits,
		PSIZE_T   RegionSize,
		ULONG     AllocationType,
		ULONG     Protect
	);
};

