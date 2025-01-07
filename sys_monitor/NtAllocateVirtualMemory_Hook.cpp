/*
   Copyright 2025 ssnob

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

	   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include "NtAllocateVirtualMemory_Hook.h"
#include "page_guard_hook.h"
#ifdef PAGE_GUARD_HOOK
NTSTATUS NtAllocateVirtualMemory_Hook::hook(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
{
	const auto result = reinterpret_cast<decltype(&NtAllocateVirtualMemory_Hook::hook)>(NtAllocateVirtualMemory_Hook::original_function)(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);

	if (Protect == PAGE_EXECUTE_READWRITE && BaseAddress && RegionSize && result == 0)
	{
		// page guard memory that wants to be executed
		page_guard_hook::register_guard(reinterpret_cast<unsigned __int64>(*BaseAddress), *RegionSize);
	}

	return result;
}
#endif