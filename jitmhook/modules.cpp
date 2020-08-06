/* Copyright (C) 2020 FireEye, Inc. All Rights Reserved. */ 

#include "modules.h"
#include "tlhelp32.h"
#include "vector"

#define MYBUFSIZE 0x200
using std::vector;


HMODULE FindModuleByNameWithSnapshot(const char *pszName)
{
    DWORD dwPID = GetCurrentProcessId();
    HANDLE hSnapshot = INVALID_HANDLE_VALUE;
    MODULEENTRY32 me = { 0 };

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return false;

    me.dwSize = sizeof(MODULEENTRY32);
    if (!Module32First(hSnapshot, &me))
    {
        CloseHandle(hSnapshot);
        return false;
    }

    ModuleInfo modinfo = { 0 };
    ModuleInfo *mod = NULL;
    HMODULE result = NULL;
    do {
        if (strstr(me.szExePath, pszName))
        {
            result = me.hModule;
            break;
        }
    } while (Module32Next(hSnapshot, &me));
    return result;
}


BOOL CheckHeaders(PBYTE _h1, PBYTE _h2, DWORD nMaxSize)
{
    PIMAGE_DOS_HEADER pMZ1 = (PIMAGE_DOS_HEADER)_h1;
    PIMAGE_DOS_HEADER pMZ2 = (PIMAGE_DOS_HEADER)_h2;

    if (memcmp(pMZ1, pMZ2, sizeof(IMAGE_DOS_HEADER)) != 0)
    {
        return false;
    }

    PIMAGE_NT_HEADERS pPE1 = (PIMAGE_NT_HEADERS)((PBYTE)_h1 + pMZ1->e_lfanew);
    PIMAGE_NT_HEADERS pPE2 = (PIMAGE_NT_HEADERS)((PBYTE)_h2 + pMZ2->e_lfanew);

    if (pPE1->FileHeader.NumberOfSections != pPE2->FileHeader.NumberOfSections ||
        pPE1->FileHeader.TimeDateStamp != pPE2->FileHeader.TimeDateStamp ||
        pPE1->FileHeader.Characteristics != pPE2->FileHeader.Characteristics ||
        pPE1->FileHeader.SizeOfOptionalHeader != pPE2->FileHeader.SizeOfOptionalHeader ||
        pPE1->OptionalHeader.CheckSum != pPE2->OptionalHeader.CheckSum ||
        pPE1->OptionalHeader.SizeOfHeaders != pPE2->OptionalHeader.SizeOfHeaders ||
        pPE1->OptionalHeader.AddressOfEntryPoint != pPE2->OptionalHeader.AddressOfEntryPoint
        ) return false;
    return true;
}

/**
 * Scan the current process memory page (starting at 0x1000) and look for a page that contains
 * a valid MZ/PE header. It then perform some basic validation to make sure most fields match 
 * the same version on disk.
 */
HMODULE FindModuleByNameWithMemScan(const char *pszFilename)
{
    HMODULE hModule = NULL;
    DWORD nPageSize = 0x1000;
    DWORD nBytes = 0;
    DWORD nFileSizeHigh = 0;
    HANDLE hFile = CreateFileA(
        pszFilename,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);

    if (INVALID_HANDLE_VALUE == hFile)
    {
        printf("[E] - Failed to open file %s for reading\n", pszFilename);
        return NULL;
    }

    DWORD nFileSizeLow = GetFileSize(hFile, &nFileSizeHigh);
    if (nFileSizeLow < MYBUFSIZE)
    {
        printf("[E] - Invalid file. File too small!\n");
        CloseHandle(hFile);
        return NULL;
    }

    BYTE pHdr[MYBUFSIZE] = { 0 };
    if (!ReadFile(hFile, pHdr, MYBUFSIZE, &nBytes, NULL))
        return NULL;

    PIMAGE_DOS_HEADER pMZ = (PIMAGE_DOS_HEADER)(pHdr);
    PIMAGE_NT_HEADERS pPE = (PIMAGE_NT_HEADERS)((DWORD)pHdr + pMZ->e_lfanew);
    DWORD nHeaderSize = pPE->OptionalHeader.SizeOfHeaders;
    DWORD nSize = nHeaderSize > 0x100 ? 0x100 : nHeaderSize;
    BOOL bDone = FALSE;
    DWORD nMemEnd = 0x8000000;
    DWORD nMem = 0x1000;
    while (!bDone)
    {
        if (nMem >= nMemEnd) break;
        MEMORY_BASIC_INFORMATION mem = { 0 };
        if (VirtualQuery((LPVOID)nMem, &mem, sizeof(mem)) != 0)
        {
            if (mem.State == MEM_COMMIT && mem.RegionSize >= nSize)
            {
                if (!IsBadReadPtr(mem.BaseAddress, nSize))
                {
                    PWORD pMemHdr = (PWORD)(mem.BaseAddress);
                    if (*pMemHdr == 0x5A4D)
                    {
                        if (CheckHeaders((PBYTE)(mem.BaseAddress), pHdr, nSize))
                        {
                            // found it!
                            hModule = (HMODULE)mem.BaseAddress;
                            bDone = TRUE;
                        }
                    }
                }
                nMem += mem.RegionSize;
            }
            else
            {
                nMem += mem.RegionSize;
            }
        }
        else
        {
            nMem += nPageSize;
        }
    }
    return hModule;
}


/**
 * Find a module by name.
 * - It first tries FindModuleByNameWithSnapshot() to use CreateToolhelp32Snapshot()
 *   to find a matching module. This call is likely to fail because .NET assembly
 *   loaded by the .NET runtime does not appear in the list
 * - It falls back to FindModuleByNameWithMemScan() to do a scan of the current
 *   process memory.
 */
HMODULE FindModuleByName(const char *pszName)
{
    HMODULE hModule = FindModuleByNameWithSnapshot(pszName);
    if (hModule)
        return hModule;

    return FindModuleByNameWithMemScan(pszName);
}


