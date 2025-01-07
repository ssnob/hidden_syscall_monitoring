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

#include "NtProtectVirtualMemory_Hook.h"
#include "page_guard_hook.h"

#ifdef EXCEPTION_HOOK

NTSTATUS NtProtectVirtualMemory_Hook::hook(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtection, PULONG OldProtection)
{
	NTSTATUS result = 0;

	if (NewProtection == PAGE_EXECUTE_READWRITE && BaseAddress && RegionSize && OldProtection && result == 0)
	{
		// not the best way, but this lets us know its us changing the memory and not the game
		if (OldProtection != reinterpret_cast<PULONG>(1337))
		{
			// PAGE_READWRITE so that the memory will throw an exception on execution
			result = reinterpret_cast<decltype(&NtProtectVirtualMemory_Hook::hook)>(NtProtectVirtualMemory_Hook::original_function)(ProcessHandle, BaseAddress, RegionSize, PAGE_READWRITE, OldProtection);
			const auto page_address = reinterpret_cast<unsigned __int64>(*BaseAddress);
		}
		else
		{
			// just a temp variable because NtProtectVirtualMemory returns an error if OldProtection isnt a valid pointer
			ULONG fake_old;
			result = reinterpret_cast<decltype(&NtProtectVirtualMemory_Hook::hook)>(NtProtectVirtualMemory_Hook::original_function)(ProcessHandle, BaseAddress, RegionSize, NewProtection, &fake_old);
		}
	}
	else
	{
		// call original
		result = reinterpret_cast<decltype(&NtProtectVirtualMemory_Hook::hook)>(NtProtectVirtualMemory_Hook::original_function)(ProcessHandle, BaseAddress, RegionSize, NewProtection, OldProtection);
	}

	return result;
}

#endif