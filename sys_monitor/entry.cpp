// entry.cpp : This file contains the 'main' function. Program execution begins and ends there.

#include <Windows.h>
#include <stdio.h>

#include "sys_monitor.h"
#include "syscall_spoofer.h"

int main(int argc, char** argv)
{
	sys_monitor::init();

	while (true)
	{
		const auto syassasd = (unsigned __int64)GetProcAddress(LoadLibraryA("ntdll"), "NtTerminateProcess");
		const auto spoof_start = (unsigned __int64)GetProcAddress(LoadLibraryA("ntdll"), "NtOpenFile");
		syscall_spoofer::spoof_syscall(spoof_start, syassasd, (HANDLE)-1, 1337);

		Sleep(5000);
	}

	getchar();
	return 0;
}  