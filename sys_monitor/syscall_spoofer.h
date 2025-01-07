#pragma once
#include <Windows.h>
#include "util.h"

#include "text_section_code.h"

#define _BYTE  __int8
#define _WORD  __int16
#define _DWORD int
#define _QWORD __int64


namespace syscall_spoofer
{
	__forceinline __int64 get_syscall_instruction_address(unsigned __int64 func)
	{
		const auto distance = 12288LL;
	LABEL_1798:
		const auto starting_distance = __rdtsc() % (distance - 3);
		auto ntdll_exported_func = (char*)func;

		__int64 syscall_instruction_spot = 0;
		for (syscall_instruction_spot = 0LL; ; ++syscall_instruction_spot)
		{
			if (starting_distance + syscall_instruction_spot >= distance)
				goto LABEL_1798;
			if (ntdll_exported_func[syscall_instruction_spot + 1 + starting_distance] == 5
				&& (unsigned __int8)ntdll_exported_func[syscall_instruction_spot + 2 + starting_distance] == 195
				&& ntdll_exported_func[syscall_instruction_spot + starting_distance] == 15)
			{
				break;
			}
		}

		return (unsigned __int64)&ntdll_exported_func[syscall_instruction_spot + starting_distance];
	}

	__forceinline void* generate_syscall_stub_text(unsigned __int64 syscall_instrucion, const int syscall_index, void** base, int* size)
	{
		if (base == nullptr || size == nullptr)
		{
			return nullptr;
		}

		*size = sizeof(large_code_block);

		auto offset = rand() % (*size - 0x40);

		volatile __int64 syscall_stub_memory = (__int64)large_code_block;

		const auto func_NtProtectVirtualMemory = reinterpret_cast<NTSTATUS(*)(HANDLE ProcessHandle, PVOID * BaseAddress, PSIZE_T RegionSize, ULONG NewProtection, PULONG OldProtection)>(GetProcAddress(LoadLibraryA("ntdll"), "NtProtectVirtualMemory"));
		auto region_size = sizeof(large_code_block);
		ULONG old_protection;
		func_NtProtectVirtualMemory(reinterpret_cast<HANDLE>(-1), (PVOID*)(&syscall_stub_memory), reinterpret_cast<PSIZE_T>(&region_size), PAGE_EXECUTE_READWRITE, &old_protection);

		*(_QWORD*)(syscall_stub_memory + offset + 28LL) = (__int64)syscall_instrucion;
		*(_QWORD*)(syscall_stub_memory + offset + 20LL) = 0x63B4B73DD1E509A9LL;
		*(_QWORD*)(syscall_stub_memory + offset + 20LL) ^= 0x7FA6B73DD1E72C56uLL;
		*(_DWORD*)(syscall_stub_memory + offset + 12LL) = syscall_index;
		*(_DWORD*)(syscall_stub_memory + offset + 8LL) = -997864955;
		*(_DWORD*)(syscall_stub_memory + offset + 8LL) ^= 0x7CEB6A07u;
		*(_DWORD*)(syscall_stub_memory + offset) = -1006268688;
		*(_DWORD*)(syscall_stub_memory + offset) ^= 0x62ADC0BFu;
		*(_DWORD*)(syscall_stub_memory + offset + 4LL) = -1637542171;
		*(_DWORD*)(syscall_stub_memory + offset + 4LL) ^= 0x75B49DA9u;
		*(_DWORD*)(syscall_stub_memory + offset + 16LL) = 109211239;
		*(_DWORD*)(syscall_stub_memory + offset + 16LL) ^= 0xBBCA6C8C;

		*base = (void*)syscall_stub_memory;
		return (void*)(syscall_stub_memory + offset + 4LL);
	}

	__forceinline void* generate_syscall_stub_alloc(unsigned __int64 syscall_instrucion, const int syscall_index, void** base, int* size)
	{
		if (base == nullptr || size == nullptr)
		{
			return nullptr;
		}

		*size = 0x4096;

		auto offset = rand() % (*size - 0x40);

		volatile __int64 syscall_stub_memory = (__int64)VirtualAlloc(nullptr, 0x4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		*(_QWORD*)(syscall_stub_memory + offset + 28LL) = (__int64)syscall_instrucion;
		*(_QWORD*)(syscall_stub_memory + offset + 20LL) = 0x63B4B73DD1E509A9LL;
		*(_QWORD*)(syscall_stub_memory + offset + 20LL) ^= 0x7FA6B73DD1E72C56uLL;
		*(_DWORD*)(syscall_stub_memory + offset + 12LL) = syscall_index;
		*(_DWORD*)(syscall_stub_memory + offset + 8LL) = -997864955;
		*(_DWORD*)(syscall_stub_memory + offset + 8LL) ^= 0x7CEB6A07u;
		*(_DWORD*)(syscall_stub_memory + offset) = -1006268688;
		*(_DWORD*)(syscall_stub_memory + offset) ^= 0x62ADC0BFu;
		*(_DWORD*)(syscall_stub_memory + offset + 4LL) = -1637542171;
		*(_DWORD*)(syscall_stub_memory + offset + 4LL) ^= 0x75B49DA9u;
		*(_DWORD*)(syscall_stub_memory + offset + 16LL) = 109211239;
		*(_DWORD*)(syscall_stub_memory + offset + 16LL) ^= 0xBBCA6C8C;

		*base = (void*)syscall_stub_memory;
		return (void*)(syscall_stub_memory + offset + 4LL);
	}

	__forceinline void free_syscall_stub(void* base, int size)
	{
		memset(base, 0, size);
		VirtualFree(base, 0, MEM_RELEASE);
	} 

	template<typename... Params>
	__forceinline NTSTATUS spoof_syscall(unsigned __int64 exported_ntdll_function, unsigned __int64 function_to_call, Params... params)
	{
		void* base_address_of_stub = nullptr;
		int stub_size = 0;

		const auto nt_syscall_instruction = get_syscall_instruction_address(exported_ntdll_function);
		const auto syscall_index = util::get_syscall_index(function_to_call);
		void* stub = nullptr; 
		NTSTATUS result = 0;

		// first use the allocated .text section
		stub = generate_syscall_stub_text(nt_syscall_instruction, syscall_index, &base_address_of_stub, &stub_size);
		result = reinterpret_cast<NTSTATUS(__fastcall*)(Params...)>(stub)(params...);

		// then just for testing purposes we will allocate our own memory
		stub = generate_syscall_stub_alloc(nt_syscall_instruction, syscall_index, &base_address_of_stub, &stub_size);
		result = reinterpret_cast<NTSTATUS(__fastcall*)(Params...)>(stub)(params...);
		
		free_syscall_stub(base_address_of_stub, stub_size);

		return result;
	}

};

