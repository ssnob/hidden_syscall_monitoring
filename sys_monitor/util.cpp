#include "util.h"

unsigned __int32 util::get_syscall_index(unsigned __int64 syscall_func)
{
    return *(unsigned __int32*)&reinterpret_cast<char*>(syscall_func)[4];

}
