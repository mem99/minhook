/*
 *  MinHook - The Minimalistic API Hooking Library for x64/x86
 *  Copyright (C) 2009-2017 Tsuda Kageyu.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 *  TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 *  PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER
 *  OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 *  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#pragma once
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <syscall.h>
#include <sys/mman.h>

#define gettid() syscall(SYS_gettid)
#define tgkill(__tgid, __tid, __signal) syscall(SYS_tgkill, __tgid, __tid, __signal)

// Size of each memory block. (= size of one page)
#define MEMORY_BLOCK_SIZE (uintptr_t)sysconf(_SC_PAGESIZE)

// Size of each memory slot.
#if defined(_M_X64) || defined(__x86_64__)
    #define MEMORY_SLOT_SIZE 64
#else
    #define MEMORY_SLOT_SIZE 32
#endif

typedef struct _MEMORY_INFORMATION {
    void           *BaseAddress;
    uint64_t        RegionSize;
    unsigned long   Protection;
    unsigned long   State;
} MEMORY_INFORMATION, *PMEMORY_INFORMATION;

void   InitializeBuffer();
void   UninitializeBuffer();
void  *AllocateBuffer(void *pOrigin);
void   FreeBuffer(void *pBuffer);
int    QueryAddress(void *pAddress, PMEMORY_INFORMATION pBuffer);
int    IsExecutableAddress(void *pAddress);
