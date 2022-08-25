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

#include "buffer.h"

// Max range for seeking a memory block. (= 1024MB)
#define MAX_MEMORY_RANGE 0x40000000

// Memory protection flags to check the executable address.
#define PAGE_EXECUTE_FLAGS \
    (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

// Memory slot.
typedef struct _MEMORY_SLOT
{
    union
    {
        struct _MEMORY_SLOT *pNext;
        uint8_t buffer[MEMORY_SLOT_SIZE];
    };
} MEMORY_SLOT, *PMEMORY_SLOT;

// Memory block info. Placed at the head of each block.
typedef struct _MEMORY_BLOCK
{
    struct _MEMORY_BLOCK *pNext;
    PMEMORY_SLOT pFree;         // First element of the free slot list.
    unsigned int usedCount;
} MEMORY_BLOCK, *PMEMORY_BLOCK;

//-------------------------------------------------------------------------
// Global Variables:
//-------------------------------------------------------------------------

// First element of the memory block list.
PMEMORY_BLOCK g_pMemoryBlocks;

//-------------------------------------------------------------------------
void InitializeBuffer()
{
    // Nothing to do for now.
}

//-------------------------------------------------------------------------
void UninitializeBuffer()
{
    PMEMORY_BLOCK pBlock = g_pMemoryBlocks;
    g_pMemoryBlocks = NULL;

    while (pBlock)
    {
        PMEMORY_BLOCK pNext = pBlock->pNext;
        munmap(pBlock, MEMORY_BLOCK_SIZE);
        pBlock = pNext;
    }
}

//-------------------------------------------------------------------------
#if defined(_M_X64) || defined(__x86_64__)
static void *FindPrevFreeRegion(void *pAddress, void *pMinAddr)
{
    uintptr_t tryAddr = (uintptr_t)pAddress, minAddr = (uintptr_t)pMinAddr;

    FILE *fpMaps = fopen("/proc/self/maps", "r");
    if (fpMaps)
    {
        char line[PATH_MAX + 74];
        uintptr_t baseAddress = 0, lastEndAddress = 0;

        while (fgets(line, sizeof(line), fpMaps))
        {
            uintptr_t endAddress = 0;
            sscanf(line, "%lx-%lx", &baseAddress, &endAddress);

            if (endAddress < minAddr)
                continue;

            if (baseAddress > tryAddr)
                break;

            if (baseAddress == lastEndAddress) {
                lastEndAddress = endAddress;
                continue;
            }

            if (lastEndAddress && baseAddress - lastEndAddress >= MEMORY_BLOCK_SIZE)
                return (void*)lastEndAddress;

            lastEndAddress = endAddress;
        }

        fclose(fpMaps);
    }

    return NULL;
}
#endif

//-------------------------------------------------------------------------
#if defined(_M_X64) || defined(__x86_64__)
void *FindNextFreeRegion(void *pAddress, void *pMaxAddr)
{
    uintptr_t tryAddr = (uintptr_t)pAddress, maxAddr = (uintptr_t)pMaxAddr;

    FILE *fpMaps = fopen("/proc/self/maps", "r");
    if (fpMaps)
    {
        char line[PATH_MAX + 74];
        uintptr_t baseAddress = 0, lastEndAddress = 0;

        while (fgets(line, sizeof(line), fpMaps))
        {
            uintptr_t endAddress = 0;
            sscanf(line, "%lx-%lx", &baseAddress, &endAddress);

            if (baseAddress < tryAddr)
                continue;

            if (baseAddress > maxAddr)
                break;

            if (baseAddress == lastEndAddress) {
                lastEndAddress = endAddress;
                continue;
            }

            if (lastEndAddress && baseAddress - lastEndAddress >= MEMORY_BLOCK_SIZE)
                return (void*)lastEndAddress;

            lastEndAddress = endAddress;
        }

        fclose(fpMaps);
    }

    return NULL;
}
#endif

//-------------------------------------------------------------------------
static inline void *AllocPage(void *lpAddress, size_t dwSize, unsigned long flType, unsigned long flProtect)
{
    void *address = mmap(lpAddress, dwSize, flProtect, flType, -1, 0);
    return address == MAP_FAILED ? NULL : address;
}

//-------------------------------------------------------------------------
static PMEMORY_BLOCK GetMemoryBlock(void *pOrigin)
{
    PMEMORY_BLOCK pBlock;
#if defined(_M_X64) || defined(__x86_64__)
    uintptr_t minAddr = MEMORY_BLOCK_SIZE;
    uintptr_t maxAddr = 1ull << 47;

    // pOrigin ± 512MB
    if ((uintptr_t)pOrigin > MAX_MEMORY_RANGE && minAddr < (uintptr_t)pOrigin - MAX_MEMORY_RANGE)
        minAddr = (uintptr_t)pOrigin - MAX_MEMORY_RANGE;

    if (maxAddr > (uintptr_t)pOrigin + MAX_MEMORY_RANGE)
        maxAddr = (uintptr_t)pOrigin + MAX_MEMORY_RANGE;

    // Make room for MEMORY_BLOCK_SIZE bytes.
    maxAddr -= MEMORY_BLOCK_SIZE - 1;
#endif

    // Look the registered blocks for a reachable one.
    for (pBlock = g_pMemoryBlocks; pBlock != NULL; pBlock = pBlock->pNext)
    {
#if defined(_M_X64) || defined(__x86_64__)
        // Ignore the blocks too far.
        if ((uintptr_t)pBlock < minAddr || (uintptr_t)pBlock >= maxAddr)
            continue;
#endif
        // The block has at least one unused slot.
        if (pBlock->pFree != NULL)
            return pBlock;
    }

#if defined(_M_X64) || defined(__x86_64__)
    // Alloc a new block above if not found.
    {
        void* pAlloc = pOrigin;
        while ((uintptr_t)pAlloc >= minAddr)
        {
            pAlloc = FindPrevFreeRegion(pAlloc, (void*)minAddr);
            if (pAlloc == NULL)
                break;

            pBlock = (PMEMORY_BLOCK)AllocPage(
                pAlloc, MEMORY_BLOCK_SIZE, MAP_PRIVATE | MAP_ANONYMOUS, PROT_READ | PROT_WRITE | PROT_EXEC);
            if (pBlock != NULL)
                break;
        }
    }

    // Alloc a new block below if not found.
    if (pBlock == NULL)
    {
        void* pAlloc = pOrigin;
        while ((uintptr_t)pAlloc <= maxAddr)
        {
            pAlloc = FindNextFreeRegion(pAlloc, (void*)maxAddr);
            if (pAlloc == NULL)
                break;

            pBlock = (PMEMORY_BLOCK)AllocPage(
                pAlloc, MEMORY_BLOCK_SIZE, MAP_PRIVATE | MAP_ANONYMOUS, PROT_READ | PROT_WRITE | PROT_EXEC);
            if (pBlock != NULL)
                break;
        }
    }
#else
    // In x86 mode, a memory block can be placed anywhere.
    pBlock = (PMEMORY_BLOCK)AllocPage(
        NULL, MEMORY_BLOCK_SIZE, MAP_PRIVATE | MAP_ANONYMOUS, PROT_READ | PROT_WRITE | PROT_EXEC);
#endif

    if (pBlock != NULL)
    {
        // Build a linked list of all the slots.
        PMEMORY_SLOT pSlot = (PMEMORY_SLOT)pBlock + 1;
        pBlock->pFree = NULL;
        pBlock->usedCount = 0;
        do
        {
            pSlot->pNext = pBlock->pFree;
            pBlock->pFree = pSlot;
            pSlot++;
        } while ((uintptr_t)pSlot - (uintptr_t)pBlock <= MEMORY_BLOCK_SIZE - MEMORY_SLOT_SIZE);

        pBlock->pNext = g_pMemoryBlocks;
        g_pMemoryBlocks = pBlock;
    }

    return pBlock;
}

//-------------------------------------------------------------------------
void *AllocateBuffer(void *pOrigin)
{
    PMEMORY_SLOT  pSlot;
    PMEMORY_BLOCK pBlock = GetMemoryBlock(pOrigin);
    if (pBlock == NULL)
        return NULL;

    // Remove an unused slot from the list.
    pSlot = pBlock->pFree;
    pBlock->pFree = pSlot->pNext;
    pBlock->usedCount++;
#ifdef _DEBUG
    // Fill the slot with INT3 for debugging.
    memset(pSlot, 0xCC, sizeof(MEMORY_SLOT));
#endif
    return pSlot;
}

//-------------------------------------------------------------------------
void FreeBuffer(void *pBuffer)
{
    PMEMORY_BLOCK pBlock = g_pMemoryBlocks;
    PMEMORY_BLOCK pPrev = NULL;
    uintptr_t pTargetBlock = ((uintptr_t)pBuffer / MEMORY_BLOCK_SIZE) * MEMORY_BLOCK_SIZE;

    while (pBlock != NULL)
    {
        if ((uintptr_t)pBlock == pTargetBlock)
        {
            PMEMORY_SLOT pSlot = (PMEMORY_SLOT)pBuffer;
#ifdef _DEBUG
            // Clear the released slot for debugging.
            memset(pSlot, 0x00, sizeof(MEMORY_SLOT));
#endif
            // Restore the released slot to the list.
            pSlot->pNext = pBlock->pFree;
            pBlock->pFree = pSlot;
            pBlock->usedCount--;

            // Free if unused.
            if (pBlock->usedCount == 0)
            {
                if (pPrev)
                    pPrev->pNext = pBlock->pNext;
                else
                    g_pMemoryBlocks = pBlock->pNext;

                munmap(pBlock, MEMORY_BLOCK_SIZE);
            }

            break;
        }

        pPrev = pBlock;
        pBlock = pBlock->pNext;
    }
}

//-------------------------------------------------------------------------
int QueryAddress(void *pAddress, PMEMORY_INFORMATION pBuffer)
{
    memset(pBuffer, 0, sizeof(MEMORY_INFORMATION));
    size_t final;
    uintptr_t address = (uintptr_t)pAddress;
    FILE *fpMaps = fopen("/proc/self/maps", "r");
    if (fpMaps)
    {
        char line[PATH_MAX + 74];
        __u_long baseAddress = 0, endAddress = 0;
        char perm[4];

        while (fgets(line, sizeof(line), fpMaps))
        {
            sscanf(line, "%lx-%lx %s", &baseAddress, &endAddress, perm);
            if (baseAddress <= address) {
                if (endAddress >= address) {
                    pBuffer->BaseAddress = (void*)baseAddress;
                    pBuffer->RegionSize = endAddress - baseAddress;
                    if (perm[0] == 'r')
                        pBuffer->Protection |= PROT_READ;
                    if (perm[1] == 'w')
                        pBuffer->Protection |= PROT_WRITE;
                    if (perm[2] == 'x')
                        pBuffer->Protection |= PROT_EXEC;
                    if (perm[3] == 'p')
                        pBuffer->State = MAP_PRIVATE;
                    final = sizeof(void*) + sizeof(unsigned long) * 2;
                    break;
                }
            }
        }

        fclose(fpMaps);
    }

    return final;
}

//-------------------------------------------------------------------------
int IsExecutableAddress(void *pAddress)
{
    MEMORY_INFORMATION mi;
    QueryAddress(pAddress, &mi);

    return (mi.Protection & PROT_EXEC);
}
