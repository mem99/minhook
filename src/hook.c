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

#include <dlfcn.h>
#include <limits.h>

#include "../include/MinHook.h"
#include "buffer.h"
#include "trampoline.h"

#ifndef ARRAYSIZE
    #define ARRAYSIZE(A) (sizeof(A)/sizeof((A)[0]))
#endif

// Initial capacity of the HOOK_ENTRY buffer.
#define INITIAL_HOOK_CAPACITY   32

// Initial capacity of the thread IDs buffer.
#define INITIAL_THREAD_CAPACITY 128

// Special hook position values.
#define INVALID_HOOK_POS UINT_MAX
#define ALL_HOOKS_POS    UINT_MAX

// Freeze() action argument defines.
#define ACTION_DISABLE      0
#define ACTION_ENABLE       1
#define ACTION_APPLY_QUEUED 2

// Hook information.
typedef struct _HOOK_ENTRY
{
    void*    pTarget;             // Address of the target function.
    void*    pDetour;             // Address of the detour or relay function.
    void*    pTrampoline;         // Address of the trampoline function.
    uint8_t  backup[8];           // Original prologue of the target function.

    uint8_t  patchAbove  : 1;     // Uses the hot patch area.
    uint8_t  isEnabled   : 1;     // Enabled.
    uint8_t  queueEnable : 1;     // Queued for enabling/disabling when != isEnabled.

    unsigned int   nIP : 4;             // Count of the instruction boundaries.
    uint8_t        oldIPs[8];           // Instruction boundaries of the target function.
    uint8_t        newIPs[8];           // Instruction boundaries of the trampoline function.
} HOOK_ENTRY, *PHOOK_ENTRY;

// Suspended threads for Freeze()/Unfreeze().
typedef struct _FROZEN_THREADS
{
    unsigned long  *pItems;         // Data heap
    unsigned int    capacity;       // Size of allocated data heap, items
    unsigned int    size;           // Actual number of data items
} FROZEN_THREADS, *PFROZEN_THREADS;

//-------------------------------------------------------------------------
// Global Variables:
//-------------------------------------------------------------------------

// Spin lock flag for EnterSpinLock()/LeaveSpinLock().
volatile long g_isLocked = 0;

// Hook entries.
struct
{
    PHOOK_ENTRY     pItems;     // Data heap
    unsigned int    capacity;   // Size of allocated data heap, items
    unsigned int    size;       // Actual number of data items
} g_hooks;

//-------------------------------------------------------------------------
// Returns INVALID_HOOK_POS if not found.
static unsigned int FindHookEntry(void *pTarget)
{
    unsigned int i;
    for (i = 0; i < g_hooks.size; ++i)
    {
        if ((uintptr_t)pTarget == (uintptr_t)g_hooks.pItems[i].pTarget)
            return i;
    }

    return INVALID_HOOK_POS;
}

//-------------------------------------------------------------------------
static PHOOK_ENTRY AddHookEntry()
{
    if (g_hooks.pItems == NULL)
    {
        g_hooks.capacity = INITIAL_HOOK_CAPACITY;
        g_hooks.pItems = (PHOOK_ENTRY)malloc(g_hooks.capacity * sizeof(HOOK_ENTRY));
        if (g_hooks.pItems == NULL)
            return NULL;
    }
    else if (g_hooks.size >= g_hooks.capacity)
    {
        PHOOK_ENTRY p = (PHOOK_ENTRY)realloc(g_hooks.pItems, (g_hooks.capacity * 2) * sizeof(HOOK_ENTRY));
        if (p == NULL)
            return NULL;

        g_hooks.capacity *= 2;
        g_hooks.pItems = p;
    }

    return &g_hooks.pItems[g_hooks.size++];
}

//-------------------------------------------------------------------------
static void DeleteHookEntry(unsigned int pos)
{
    if (pos < g_hooks.size - 1)
        g_hooks.pItems[pos] = g_hooks.pItems[g_hooks.size - 1];

    g_hooks.size--;

    if (g_hooks.capacity / 2 >= INITIAL_HOOK_CAPACITY && g_hooks.capacity / 2 >= g_hooks.size)
    {
        PHOOK_ENTRY p = (PHOOK_ENTRY)realloc(g_hooks.pItems, (g_hooks.capacity / 2) * sizeof(HOOK_ENTRY));
        if (p == NULL)
            return;

        g_hooks.capacity /= 2;
        g_hooks.pItems = p;
    }
}

//-------------------------------------------------------------------------
static uintptr_t FindOldIP(PHOOK_ENTRY pHook, uintptr_t ip)
{
    unsigned int i;

    if (pHook->patchAbove && ip == ((uintptr_t)pHook->pTarget - sizeof(JMP_REL)))
        return (uintptr_t)pHook->pTarget;

    for (i = 0; i < pHook->nIP; ++i)
    {
        if (ip == ((uintptr_t)pHook->pTrampoline + pHook->newIPs[i]))
            return (uintptr_t)pHook->pTarget + pHook->oldIPs[i];
    }

#if defined(_M_X64) || defined(__x86_64__)
    // Check relay function.
    if (ip == (uintptr_t)pHook->pDetour)
        return (uintptr_t)pHook->pTarget;
#endif

    return 0;
}

//-------------------------------------------------------------------------
static uintptr_t FindNewIP(PHOOK_ENTRY pHook, uintptr_t ip)
{
    unsigned int i;
    for (i = 0; i < pHook->nIP; ++i)
    {
        if (ip == ((uintptr_t)pHook->pTarget + pHook->oldIPs[i]))
            return (uintptr_t)pHook->pTrampoline + pHook->newIPs[i];
    }

    return 0;
}

//-------------------------------------------------------------------------
static void ProcessThreadIPs(void */*hThread*/, unsigned int /*pos*/, unsigned int /*action*/)
{
    // If the thread suspended in the overwritten area,
    // move IP to the proper address.
/*
    CONTEXT c;
#if defined(_M_X64) || defined(__x86_64__)
    DWORD64 *pIP = &c.Rip;
#else
    DWORD   *pIP = &c.Eip;
#endif
    UINT count;

    c.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(hThread, &c))
        return;

    if (pos == ALL_HOOKS_POS)
    {
        pos = 0;
        count = g_hooks.size;
    }
    else
    {
        count = pos + 1;
    }

    for (; pos < count; ++pos)
    {
        PHOOK_ENTRY pHook = &g_hooks.pItems[pos];
        BOOL        enable;
        uintptr_t   ip;

        switch (action)
        {
        case ACTION_DISABLE:
            enable = FALSE;
            break;

        case ACTION_ENABLE:
            enable = TRUE;
            break;

        default: // ACTION_APPLY_QUEUED
            enable = pHook->queueEnable;
            break;
        }
        if (pHook->isEnabled == enable)
            continue;

        if (enable)
            ip = FindNewIP(pHook, *pIP);
        else
            ip = FindOldIP(pHook, *pIP);

        if (ip != 0)
        {
            *pIP = ip;
            SetThreadContext(hThread, &c);
        }
    }*/
}

//-------------------------------------------------------------------------
static int EnumerateThreads(PFROZEN_THREADS pThreads)
{
    int succeeded = 0;
    __pid_t currentThreadId = gettid();

    DIR *taskDir = opendir("/proc/self/task");
    if (taskDir)
    {
        succeeded = 1;
        struct dirent *entry;
        while (( entry = readdir(taskDir) ))
        {
            if (entry->d_name[0] == '.')
                continue;

            __pid_t threadId = atoi(entry->d_name);
            if (threadId != currentThreadId)
            {
                if (pThreads->pItems == NULL)
                {
                    pThreads->capacity = INITIAL_THREAD_CAPACITY;
                    pThreads->pItems
                            = (unsigned long*)malloc(pThreads->capacity * sizeof(unsigned long));
                    if (pThreads->pItems == NULL)
                    {
                        succeeded = 0;
                        break;
                    }
                }
                else if (pThreads->size >= pThreads->capacity)
                {
                    pThreads->capacity *= 2;
                    unsigned long* p = (unsigned long*)realloc(pThreads->pItems, pThreads->capacity * sizeof(unsigned long));
                    if (p == NULL)
                    {
                        succeeded = 0;
                        break;
                    }

                    pThreads->pItems = p;
                }
                pThreads->pItems[pThreads->size++] = threadId;
            }
        }

        if (pThreads->size)
        {
            //            if (succeeded && errno != 0)
            //                succeeded = FALSE;

            if (!succeeded && pThreads->pItems != NULL)
            {
                free(pThreads->pItems);
                pThreads->pItems = NULL;
            }
        }
        closedir(taskDir);
    }

    return succeeded;
}

//-------------------------------------------------------------------------
static MH_STATUS Freeze(PFROZEN_THREADS pThreads, unsigned int pos, unsigned int action)
{
    MH_STATUS status = MH_OK;

    pThreads->pItems   = NULL;
    pThreads->capacity = 0;
    pThreads->size     = 0;
    if (!EnumerateThreads(pThreads))
    {
        status = MH_ERROR_MEMORY_ALLOC;
    }
    else if (pThreads->pItems != NULL)
    {
        unsigned int i;
        for (i = 0; i < pThreads->size; ++i)
        {
//            HANDLE hThread = OpenThread(THREAD_ACCESS, FALSE, pThreads->pItems[i]);
//            if (hThread != NULL)
//            {
//                SuspendThread(hThread);
//                ProcessThreadIPs(hThread, pos, action);
//                CloseHandle(hThread);
//            }
        }
    }

    return status;
}

//-------------------------------------------------------------------------
static void Unfreeze(PFROZEN_THREADS pThreads)
{
    if (pThreads->pItems != NULL)
    {
        unsigned int i;
        for (i = 0; i < pThreads->size; ++i)
        {
//            HANDLE hThread = OpenThread(THREAD_ACCESS, FALSE, pThreads->pItems[i]);
//            if (hThread != NULL)
//            {
//                ResumeThread(hThread);
//                CloseHandle(hThread);
//            }
        }

        free(pThreads->pItems);
    }
}

static int ProtectRegion(void *lpAddress, size_t dwSize, unsigned long flNewProtect, unsigned long *lpflOldProtect)
{
    if (lpflOldProtect) {
        MEMORY_INFORMATION mbi;
        QueryAddress(lpAddress, &mbi);
        *lpflOldProtect = mbi.Protection;
    }

    void *pageAddress = (void*)((unsigned long)lpAddress & (~(MEMORY_BLOCK_SIZE - 1)));
    int result = mprotect(pageAddress, dwSize, flNewProtect);
    return result == -1 ? 0 : 1;
}

//-------------------------------------------------------------------------
static MH_STATUS EnableHookLL(unsigned int pos, int enable)
{
    PHOOK_ENTRY pHook = &g_hooks.pItems[pos];
    unsigned long  oldProtect;
    size_t patchSize    = sizeof(JMP_REL);
    unsigned char *pPatchTarget = (unsigned char*)pHook->pTarget;

    if (pHook->patchAbove)
    {
        pPatchTarget -= sizeof(JMP_REL);
        patchSize    += sizeof(JMP_REL_SHORT);
    }

    if (!ProtectRegion(pPatchTarget, patchSize, PROT_READ | PROT_WRITE | PROT_EXEC, &oldProtect))
        return MH_ERROR_MEMORY_PROTECT;

    if (enable)
    {
        PJMP_REL pJmp = (PJMP_REL)pPatchTarget;
        pJmp->opcode = 0xE9;
        pJmp->operand = (uint32_t)((unsigned char*)pHook->pDetour - (pPatchTarget + sizeof(JMP_REL)));

        if (pHook->patchAbove)
        {
            PJMP_REL_SHORT pShortJmp = (PJMP_REL_SHORT)pHook->pTarget;
            pShortJmp->opcode = 0xEB;
            pShortJmp->operand = (uint8_t)(0 - (sizeof(JMP_REL_SHORT) + sizeof(JMP_REL)));
        }
    }
    else
    {
        if (pHook->patchAbove)
            memcpy(pPatchTarget, pHook->backup, sizeof(JMP_REL) + sizeof(JMP_REL_SHORT));
        else
            memcpy(pPatchTarget, pHook->backup, sizeof(JMP_REL));
    }

    ProtectRegion(pPatchTarget, patchSize, oldProtect, NULL);

    // Just-in-case measure.
    // GCC: void __builtin___clear_cache (char *begin, char *end)
    __builtin___clear_cache(pPatchTarget, (uint8_t*)((intptr_t)pPatchTarget + (intptr_t)patchSize));

    pHook->isEnabled   = enable;
    pHook->queueEnable = enable;

    return MH_OK;
}

//-------------------------------------------------------------------------
static MH_STATUS EnableAllHooksLL(int enable)
{
    MH_STATUS status = MH_OK;
    unsigned int i, first = INVALID_HOOK_POS;

    for (i = 0; i < g_hooks.size; ++i)
    {
        if (g_hooks.pItems[i].isEnabled != enable)
        {
            first = i;
            break;
        }
    }

    if (first != INVALID_HOOK_POS)
    {
        FROZEN_THREADS threads;
        status = Freeze(&threads, ALL_HOOKS_POS, enable ? ACTION_ENABLE : ACTION_DISABLE);
        if (status == MH_OK)
        {
            for (i = first; i < g_hooks.size; ++i)
            {
                if (g_hooks.pItems[i].isEnabled != enable)
                {
                    status = EnableHookLL(i, enable);
                    if (status != MH_OK)
                        break;
                }
            }

            Unfreeze(&threads);
        }
    }

    return status;
}

//-------------------------------------------------------------------------
static void EnterSpinLock()
{
    size_t spinCount = 0;

    // Wait until the flag is FALSE.
    // GCC = type __sync_val_compare_and_swap (type *ptr, type comperand, type exchange, ...)
    while (__sync_val_compare_and_swap(&g_isLocked, 0, 1) != 0)
    {
        // No need to generate a memory barrier here, since InterlockedCompareExchange()
        // generates a full memory barrier itself.

        // Prevent the loop from being too busy.
        if (spinCount < 32)
            usleep(0);
        else
            usleep(1000);

        spinCount++;
    }
}

//-------------------------------------------------------------------------
static void LeaveSpinLock()
{
    // No need to generate a memory barrier here, since InterlockedExchange()
    // generates a full memory barrier itself.

    // GCC = type __sync_lock_test_and_set (type *ptr, type value, ...)
    __sync_lock_test_and_set(&g_isLocked, 0);
}

//-------------------------------------------------------------------------
MH_STATUS MH_Initialize()
{
    return MH_OK;
}

//-------------------------------------------------------------------------
MH_STATUS MH_Uninitialize()
{
    MH_STATUS status = MH_OK;

    EnterSpinLock();

    status = EnableAllHooksLL(0);
    if (status == MH_OK)
    {
        // Free the internal function buffer.

        UninitializeBuffer();

        free(g_hooks.pItems);

        g_hooks.pItems   = NULL;
        g_hooks.capacity = 0;
        g_hooks.size     = 0;
    }

    LeaveSpinLock();

    return status;
}

//-------------------------------------------------------------------------
MH_STATUS MH_CreateHook(void *pTarget, void *pDetour, void **ppOriginal)
{
    MH_STATUS status = MH_OK;

    EnterSpinLock();

    if (IsExecutableAddress(pTarget) && IsExecutableAddress(pDetour))
    {
        unsigned int pos = FindHookEntry(pTarget);
        if (pos == INVALID_HOOK_POS)
        {
            void *pBuffer = AllocateBuffer(pTarget);
            if (pBuffer != NULL)
            {
                TRAMPOLINE ct;

                ct.pTarget     = pTarget;
                ct.pDetour     = pDetour;
                ct.pTrampoline = pBuffer;
                if (CreateTrampolineFunction(&ct))
                {
                    PHOOK_ENTRY pHook = AddHookEntry();
                    if (pHook != NULL)
                    {
                        pHook->pTarget     = ct.pTarget;
#if defined(_M_X64) || defined(__x86_64__)
                        pHook->pDetour     = ct.pRelay;
#else
                        pHook->pDetour     = ct.pDetour;
#endif
                        pHook->pTrampoline = ct.pTrampoline;
                        pHook->patchAbove  = ct.patchAbove;
                        pHook->isEnabled   = 0;
                        pHook->queueEnable = 0;
                        pHook->nIP         = ct.nIP;
                        memcpy(pHook->oldIPs, ct.oldIPs, ARRAYSIZE(ct.oldIPs));
                        memcpy(pHook->newIPs, ct.newIPs, ARRAYSIZE(ct.newIPs));

                        // Back up the target function.

                        if (ct.patchAbove)
                        {
                            memcpy(
                                        pHook->backup,
                                        (unsigned char*)pTarget - sizeof(JMP_REL),
                                        sizeof(JMP_REL) + sizeof(JMP_REL_SHORT));
                        }
                        else
                        {
                            memcpy(pHook->backup, pTarget, sizeof(JMP_REL));
                        }

                        if (ppOriginal != NULL)
                            *ppOriginal = pHook->pTrampoline;
                    }
                    else
                    {
                        status = MH_ERROR_MEMORY_ALLOC;
                    }
                }
                else
                {
                    status = MH_ERROR_UNSUPPORTED_FUNCTION;
                }

                if (status != MH_OK)
                {
                    FreeBuffer(pBuffer);
                }
            }
            else
            {
                status = MH_ERROR_MEMORY_ALLOC;
            }
        }
        else
        {
            status = MH_ERROR_ALREADY_CREATED;
        }
    }
    else
    {
        status = MH_ERROR_NOT_EXECUTABLE;
    }

    LeaveSpinLock();

    return status;
}

//-------------------------------------------------------------------------
MH_STATUS MH_RemoveHook(void *pTarget)
{
    MH_STATUS status = MH_OK;

    EnterSpinLock();

    unsigned int pos = FindHookEntry(pTarget);
    if (pos != INVALID_HOOK_POS)
    {
        if (g_hooks.pItems[pos].isEnabled)
        {
            FROZEN_THREADS threads;
            status = Freeze(&threads, pos, ACTION_DISABLE);
            if (status == MH_OK)
            {
                status = EnableHookLL(pos, 0);

                Unfreeze(&threads);
            }
        }

        if (status == MH_OK)
        {
            FreeBuffer(g_hooks.pItems[pos].pTrampoline);
            DeleteHookEntry(pos);
        }
    }
    else
    {
        status = MH_ERROR_NOT_CREATED;
    }

    LeaveSpinLock();

    return status;
}

//-------------------------------------------------------------------------
static MH_STATUS EnableHook(void* pTarget, int enable)
{
    MH_STATUS status = MH_OK;

    EnterSpinLock();

    if (pTarget == MH_ALL_HOOKS)
    {
        status = EnableAllHooksLL(enable);
    }
    else
    {
        unsigned int pos = FindHookEntry(pTarget);
        if (pos != INVALID_HOOK_POS)
        {
            if (g_hooks.pItems[pos].isEnabled != enable)
            {
                FROZEN_THREADS threads;
                status = Freeze(&threads, pos, ACTION_ENABLE);
                if (status == MH_OK)
                {
                    status = EnableHookLL(pos, enable);

                    Unfreeze(&threads);
                }
            }
            else
            {
                status = enable ? MH_ERROR_ENABLED : MH_ERROR_DISABLED;
            }
        }
        else
        {
            status = MH_ERROR_NOT_CREATED;
        }
    }

    LeaveSpinLock();

    return status;
}

//-------------------------------------------------------------------------
MH_STATUS MH_EnableHook(void *pTarget)
{
    return EnableHook(pTarget, 1);
}

//-------------------------------------------------------------------------
MH_STATUS MH_DisableHook(void *pTarget)
{
    return EnableHook(pTarget, 0);
}

//-------------------------------------------------------------------------
static MH_STATUS QueueHook(void* pTarget, int queueEnable)
{
    MH_STATUS status = MH_OK;

    EnterSpinLock();

    if (pTarget == MH_ALL_HOOKS)
    {
        unsigned int i;
        for (i = 0; i < g_hooks.size; ++i)
            g_hooks.pItems[i].queueEnable = queueEnable;
    }
    else
    {
        unsigned int pos = FindHookEntry(pTarget);
        if (pos != INVALID_HOOK_POS)
        {
            g_hooks.pItems[pos].queueEnable = queueEnable;
        }
        else
        {
            status = MH_ERROR_NOT_CREATED;
        }
    }

    LeaveSpinLock();

    return status;
}

//-------------------------------------------------------------------------
MH_STATUS MH_QueueEnableHook(void *pTarget)
{
    return QueueHook(pTarget, 1);
}

//-------------------------------------------------------------------------
MH_STATUS MH_QueueDisableHook(void *pTarget)
{
    return QueueHook(pTarget, 0);
}

//-------------------------------------------------------------------------
MH_STATUS MH_ApplyQueued()
{
    MH_STATUS status = MH_OK;
    unsigned int i, first = INVALID_HOOK_POS;

    EnterSpinLock();

    for (i = 0; i < g_hooks.size; ++i)
    {
        if (g_hooks.pItems[i].isEnabled != g_hooks.pItems[i].queueEnable)
        {
            first = i;
            break;
        }
    }

    if (first != INVALID_HOOK_POS)
    {
        FROZEN_THREADS threads;
        status = Freeze(&threads, ALL_HOOKS_POS, ACTION_APPLY_QUEUED);
        if (status == MH_OK)
        {
            for (i = first; i < g_hooks.size; ++i)
            {
                PHOOK_ENTRY pHook = &g_hooks.pItems[i];
                if (pHook->isEnabled != pHook->queueEnable)
                {
                    status = EnableHookLL(i, pHook->queueEnable);
                    if (status != MH_OK)
                        break;
                }
            }

            Unfreeze(&threads);
        }
    }

    LeaveSpinLock();

    return status;
}

//-------------------------------------------------------------------------
MH_STATUS MH_CreateHookApiEx(
    const __WCHAR_TYPE__ * pszModule, const char * pszProcName, void *pDetour,
    void **ppOriginal, void **ppTarget)
{
    void *hModule;
    void *pTarget;

    char path_cstr[PATH_MAX];
    wcstombs(path_cstr, pszModule, sizeof(path_cstr));
    hModule = dlopen(path_cstr, RTLD_NOW | RTLD_NOLOAD | RTLD_NODELETE);
    if (hModule == NULL)
        return MH_ERROR_MODULE_NOT_FOUND;

    pTarget = (void*)dlsym(hModule, pszProcName);
    dlclose(hModule); // Should we make the user close the handle?
    if (pTarget == NULL)
        return MH_ERROR_FUNCTION_NOT_FOUND;

    if(ppTarget != NULL)
        *ppTarget = pTarget;

    return MH_CreateHook(pTarget, pDetour, ppOriginal);
}

//-------------------------------------------------------------------------
MH_STATUS MH_CreateHookApi(
    const __WCHAR_TYPE__ * pszModule, const char * pszProcName, void *pDetour, void **ppOriginal)
{
   return MH_CreateHookApiEx(pszModule, pszProcName, pDetour, ppOriginal, NULL);
}

//-------------------------------------------------------------------------
const char * MH_StatusToString(MH_STATUS status)
{
#define MH_ST2STR(x)    \
    case x:             \
        return #x;

    switch (status) {
        MH_ST2STR(MH_UNKNOWN)
        MH_ST2STR(MH_OK)
        MH_ST2STR(MH_ERROR_ALREADY_INITIALIZED)
//        MH_ST2STR(MH_ERROR_NOT_INITIALIZED)
        MH_ST2STR(MH_ERROR_ALREADY_CREATED)
        MH_ST2STR(MH_ERROR_NOT_CREATED)
        MH_ST2STR(MH_ERROR_ENABLED)
        MH_ST2STR(MH_ERROR_DISABLED)
        MH_ST2STR(MH_ERROR_NOT_EXECUTABLE)
        MH_ST2STR(MH_ERROR_UNSUPPORTED_FUNCTION)
        MH_ST2STR(MH_ERROR_MEMORY_ALLOC)
        MH_ST2STR(MH_ERROR_MEMORY_PROTECT)
        MH_ST2STR(MH_ERROR_MODULE_NOT_FOUND)
        MH_ST2STR(MH_ERROR_FUNCTION_NOT_FOUND)
    }

#undef MH_ST2STR

    return "(unknown)";
}
