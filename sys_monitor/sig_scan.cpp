#include "sig_scan.h"

unsigned __int64 sig_scan::find_signature(unsigned __int64 start, unsigned __int32 size, unsigned char* bytes, unsigned __int32 byte_size)
{
    for (unsigned __int32 i = 0; i < size - byte_size; i++)
    {
        bool found = true;
        for (int j = 0; j < byte_size; j++)
        {
            const auto start_bytes = reinterpret_cast<unsigned char*>(start);
            if (start_bytes[i + j] != bytes[j])
            {
                if (bytes[j] != '\?')
                {
                    found = false;
                }
            }       
        }

        if (found)
        {
            return start + i;
        }
    }

    return 0;
}

unsigned __int64 sig_scan::find_signature(unsigned __int64 start, unsigned char* bytes, unsigned __int32 byte_size)
{
    IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(start);
    IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(start + dos->e_lfanew);

    return sig_scan::find_signature(start, nt->OptionalHeader.SizeOfImage, bytes, byte_size);
}
