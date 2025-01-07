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


#include "page_guard_hook.h"
#include "sig_scan.h"

struct guarded_page_t
{
	unsigned __int64 virtual_address;
	unsigned __int32 region_size;
};

std::mutex register_mutex;
std::vector<guarded_page_t> guarded_pages;

LONG WINAPI guard_UnhandledExceptionFilter(EXCEPTION_POINTERS* ex);

bool guard_memory(unsigned __int64 address, unsigned __int32 region_size)
{
	// get the original protection
	MEMORY_BASIC_INFORMATION mbi;
	if (!VirtualQuery(reinterpret_cast<void*>(address), &mbi, sizeof(mbi)))
	{
		printf("failed to query memory: %p\n", address);
		return false;
	}

	DWORD old;
	if (!VirtualProtect(reinterpret_cast<void*>(address), region_size, mbi.Protect | PAGE_GUARD, &old))
	{
		printf("failed to adjust memory protection for: %p\n", address);
		return false;
	}

	return true;
}


void page_guard_hook::register_guard(unsigned __int64 address, unsigned __int32 region_size)
{
	std::lock_guard<std::mutex> lock(register_mutex);
	guarded_pages.push_back({ address, region_size });

	if (!guard_memory(address, region_size))
	{
		printf("failed to guard memory: %p\n", address);
	}
}

void page_guard_hook::install_handler()
{
	AddVectoredExceptionHandler(TRUE, guard_UnhandledExceptionFilter);
}

// called under both the single step and page guard violation handlers
// this is because we can't guarentee which one will have the exception address of mov r10, rcx 
// because we are constantly swapping between instructions
bool search_for_syscall_stub(unsigned __int64 start, CONTEXT* context_record)
{
	const auto instructions = reinterpret_cast<unsigned char*>(start);

	// 4c 8b d1
	// mov r10, rcx
	if (instructions[0] == 0x4C && instructions[1] == 0x8B && instructions[2] == 0xD1)
	{		
		__int32 syscall_index = -1;
		__int32* address_of_syscall_index = nullptr;

		// cods stub does a jmp + x, but this is here just incase 
		if (instructions[3] == 0xB8) // mov eax, 0x0000000
		{
			syscall_index = *reinterpret_cast<unsigned __int32*>(&instructions[4]);
			address_of_syscall_index = reinterpret_cast<__int32*>(&instructions[4]);
		}
		else if (instructions[3] == 0xEB)
		{
			// cod only uses a __int8 jmp index
			const auto jmp_index = instructions[4];

			// resolve where its jumping to
			const auto jmp_start = reinterpret_cast<unsigned __int64>(&instructions[3]);
			const auto resolved_address = jmp_start + jmp_index + 2; // 0xEB, 0x0, 2 bytes rva

			// read instructions
			const auto resolved_instructions = reinterpret_cast<unsigned char*>(resolved_address);
			if (resolved_instructions[0] == 0xB8)
			{
				syscall_index = *reinterpret_cast<unsigned __int32*>(&resolved_instructions[1]);
				address_of_syscall_index = reinterpret_cast<__int32*>(&resolved_instructions[1]);
			}	
		}

		if (syscall_index != -1)
		{
			// figure out what the actual syscall is here
			// mov r10, rcx
			// mov eax, 0x0000000
			unsigned char search_bytes[] =
			{
				0x4C, 0x8B, 0xD1,
				0xB8, 0x00, 0x00, 0x00, 0x00
			};

			// add the syscall index to our stub
			*reinterpret_cast<unsigned __int32*>(&search_bytes[4]) = syscall_index;

			// search ntdll for the syscall stub
			const auto result = sig_scan::find_signature(reinterpret_cast<unsigned __int64>(LoadLibraryA("ntdll")), search_bytes, sizeof(search_bytes));

			BYTE symbol_buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME]{ 0 };
			PSYMBOL_INFO symbol_info = reinterpret_cast<PSYMBOL_INFO>(symbol_buffer);
			symbol_info->SizeOfStruct = sizeof(SYMBOL_INFO);
			symbol_info->MaxNameLen = MAX_SYM_NAME;

			if (SymFromAddr(reinterpret_cast<HANDLE>(-1), result, NULL, symbol_info))
			{
				printf("SYSCALL: %s (%p) [index: %x]\n", symbol_info->Name, result, syscall_index);

				CONTEXT ctx_copy = *context_record;

				std::vector<STACKFRAME64> frames;

				STACKFRAME64 stack_frame = {};
				stack_frame.AddrPC.Offset = ctx_copy.Rip;
				stack_frame.AddrPC.Mode = AddrModeFlat;
				stack_frame.AddrFrame.Offset = ctx_copy.Rsp;
				stack_frame.AddrFrame.Mode = AddrModeFlat;
				stack_frame.AddrStack.Offset = ctx_copy.Rsp;
				stack_frame.AddrStack.Mode = AddrModeFlat;

				HANDLE process = GetCurrentProcess();
				HANDLE thread = GetCurrentThread();

				// walk the stack to figure out where this was called from
				while (StackWalk64(
					IMAGE_FILE_MACHINE_AMD64,
					process,
					thread,
					&stack_frame,
					&ctx_copy,
					NULL,
					SymFunctionTableAccess64,
					SymGetModuleBase64,
					NULL))
				{
					// end of stack
					if (stack_frame.AddrPC.Offset == 0)
						break;

					frames.push_back(stack_frame);

				};

				// print it out
				for (auto& stack_frame : frames)
				{
					wchar_t module_name[512];
					memset(module_name, 0, sizeof(module_name));

					HMODULE module;
					RtlPcToFileHeader(reinterpret_cast<PVOID>(stack_frame.AddrPC.Offset), reinterpret_cast<PVOID*>(&module));

					if (GetModuleBaseNameW(reinterpret_cast<HANDLE>(-1), module, module_name, sizeof(module_name)))
					{
						const auto module_base = reinterpret_cast<unsigned __int64>(GetModuleHandleW(module_name));
						const auto rva = stack_frame.AddrPC.Offset - module_base;

						if (module) // nullptr if RtlPcToFileHeader failed to find
						{
							printf("%ws!0x%p\n", module_name, rva);
						}
						else
						{
							printf("0x%p\n", stack_frame.AddrPC.Offset);
						}
					}
				}

			}
			else
			{
				printf("Failed to find syscall %p (index: %x)\n", result, syscall_index);
			}

			// example modification of syscall index
			// in our case this will prevent NtTerminateProcess
			if (address_of_syscall_index)
			{
				*address_of_syscall_index = 0;
			}

			return true;
		}
	}
	return false;
}

// rip, page
std::unordered_map<unsigned __int64, guarded_page_t> guarded_page_restore;
LONG WINAPI guard_UnhandledExceptionFilter(EXCEPTION_POINTERS* ex)
{
	const auto return_address = *reinterpret_cast<unsigned __int64*>(ex->ContextRecord->Rsp);
	const auto exception_address = ex->ExceptionRecord->ExceptionAddress;

#ifdef PAGE_GUARD_HOOK

	if (ex->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
	{
		guarded_page_t page_to_restore{ 0, 0 };

		for (const auto& page : guarded_pages)
		{
			if (return_address >= page.virtual_address && return_address <= page.virtual_address + page.region_size)
			{
				page_to_restore.virtual_address = page.virtual_address;
				page_to_restore.region_size = page.region_size;
				break;
			}
		}

		//printf("STATUS_GUARD_PAGE_VIOLATION: %p\n", ex->ContextRecord->Rsp);

		guarded_page_restore[return_address] = page_to_restore;

		if (search_for_syscall_stub(reinterpret_cast<unsigned __int64>(ex->ExceptionRecord->ExceptionAddress), ex->ContextRecord))
		{
			printf("[PAGE GUARD HOOK] FOUND SYSCALL AT: %p\n", reinterpret_cast<unsigned __int64>(ex->ExceptionRecord->ExceptionAddress));
		}

		// enable single step, windows removes PAGE_GUARD after the exception has been fired, so we need to restore it
		ex->ContextRecord->EFlags |= 0x100;
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	if (ex->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
	{
		if (guarded_page_restore.find(return_address) != guarded_page_restore.end())
		{
			if (search_for_syscall_stub(reinterpret_cast<unsigned __int64>(ex->ExceptionRecord->ExceptionAddress), ex->ContextRecord))
			{
				printf("[PAGE GUARD HOOK] FOUND SYSCALL AT: %p\n", reinterpret_cast<unsigned __int64>(ex->ExceptionRecord->ExceptionAddress));
			}

			// guard the memory after we mess with it to prevent recursion
			const auto page_to_restore = guarded_page_restore[return_address];
			if (page_to_restore.virtual_address)
			{
				if (!guard_memory(page_to_restore.virtual_address, page_to_restore.region_size))
				{
					printf("failed to guard memory: %p\n", page_to_restore.virtual_address);
				}
			}

		}

		return EXCEPTION_CONTINUE_EXECUTION;
	}
#endif // PAGE_GUARD_HOOK

#ifdef EXCEPTION_HOOK
	if (ex->ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION)
	{
		const auto access_type = ex->ExceptionRecord->ExceptionInformation[0];

		if (access_type == 8) // execute attempt (dep violation)
		{
			MEMORY_BASIC_INFORMATION mbi;
			if (!VirtualQuery(reinterpret_cast<void*>(exception_address), &mbi, sizeof(mbi)))
			{
				printf("Failed to query access violation!\n");
				return EXCEPTION_CONTINUE_SEARCH;
			}

			if (mbi.Protect == PAGE_READWRITE)
			{
				// restore the execute permission
				DWORD old;
				if (!VirtualProtect(exception_address, mbi.RegionSize, PAGE_EXECUTE_READWRITE, reinterpret_cast<PDWORD>(1337)))
				{
					printf("Failed to restore protection\n");
				}

				if (search_for_syscall_stub(reinterpret_cast<unsigned __int64>(exception_address), ex->ContextRecord))
				{
					printf("[EXCEPTION HOOK] FOUND SYSCALL AT: %p\n", exception_address);
				}
			}

			return EXCEPTION_CONTINUE_EXECUTION;
		}

		// we don't know about this access violation
		return EXCEPTION_CONTINUE_SEARCH;
	}
#endif

	return EXCEPTION_CONTINUE_SEARCH;
}