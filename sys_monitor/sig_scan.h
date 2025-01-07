#pragma once
#include <Windows.h>

namespace sig_scan
{
	unsigned __int64 find_signature(unsigned __int64 start, unsigned __int32 size, unsigned char* bytes, unsigned __int32 byte_size);
	unsigned __int64 find_signature(unsigned __int64 start, unsigned char* bytes, unsigned __int32 byte_size);
};

