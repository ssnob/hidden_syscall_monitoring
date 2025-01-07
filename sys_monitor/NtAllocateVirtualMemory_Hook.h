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

