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

#include "sys_monitor.h"
#include "util.h"
#include "NtAllocateVirtualMemory_Hook.h"
#include "page_guard_hook.h"

namespace sys_monitor
{
	// a hook is created on NtAllocateVirtualMemory
	bool init()
	{
		// mov    r10,rcx
		// mov    eax, <syscall index>
		// syscall
		// ret
		unsigned char original_instructions[] = 
		{ 
			0x49, 0x89, 0xCA, 
			0xB8, 0x00, 0x00, 0x00, 0x00, 
			0x0F, 0x05, 
			0xC3 
		};

		// mov rax, <jmp_location>
		// jmp rax
		unsigned char hook_stub[] =
		{
			0x48, 0xB8, 0x4C, 0x9C, 0x8C, 0xDA, 0xC1, 0xFC, 0x03, 0x00,
			0xFF, 0xE0
		};

		const auto ntdll = LoadLibraryA("ntdll");
		const auto NtAllocateVirtualMemory = reinterpret_cast<unsigned __int64>(GetProcAddress(ntdll, "NtAllocateVirtualMemory"));

		// setup the original stub with the correct syscall index
		*reinterpret_cast<DWORD*>(&original_instructions[4]) = util::get_syscall_index(NtAllocateVirtualMemory);

		// allocate original stub
		const void* original_stub_location = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!original_stub_location)
		{
			return false;
		}
		
		// write the original stub into the process
		memcpy(const_cast<void*>(original_stub_location), original_instructions, sizeof(original_instructions));

		// store it
		NtAllocateVirtualMemory_Hook::original_function = reinterpret_cast<unsigned __int64>(original_stub_location);

		// setup the hook stub to jump to our hook
		*reinterpret_cast<unsigned __int64*>(&hook_stub[2]) = reinterpret_cast<unsigned __int64>(&NtAllocateVirtualMemory_Hook::hook);

		// allocate the hook stub
		const void* hook_stub_location = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!hook_stub_location)
		{
			return false;
		}

		// write the hook stub
		memcpy(const_cast<void*>(hook_stub_location), hook_stub, sizeof(hook_stub));

		// overwrite NtAllocateVirtualMemory
		DWORD old;
		if (!VirtualProtect(reinterpret_cast<void*>(NtAllocateVirtualMemory), 0x1000, PAGE_EXECUTE_READWRITE, &old))
		{
			return false;
		}

		// write in the hook
		memcpy(reinterpret_cast<void*>(NtAllocateVirtualMemory), hook_stub_location, sizeof(hook_stub));

		// restore protections
		VirtualProtect(reinterpret_cast<void*>(NtAllocateVirtualMemory), 0x1000, old, &old);

		// install the exception handler
		page_guard_hook::install_handler();

		// init sym
		SymSetOptions(SYMOPT_UNDNAME);
		if (!SymInitialize(reinterpret_cast<HANDLE>(-1), nullptr, TRUE)) // invade process required for UNDNAME
		{
			printf("SymInitialize failed\n");
			return false;
		}
		return true;
	}
};