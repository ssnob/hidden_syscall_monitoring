#pragma once

// this is what would be used for the game
#define EXCEPTION_HOOK

// this will catch things that use virtual alloc for their syscall stub
#define PAGE_GUARD_HOOK