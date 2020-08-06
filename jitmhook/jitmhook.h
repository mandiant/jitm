/* Copyright (C) 2020 FireEye, Inc. All Rights Reserved. */ 
#pragma once

#include <Windows.h>
#include "corinfo.h"
#include "corjit.h"
#include <stdio.h>
#include <string>
#include <sstream>
#include <iostream>
#include <fstream>
#include <vector>
#include <map>

#pragma pack(push, 1)
typedef struct _Trampoline {
    BYTE    mov = 0xB8;
    DWORD   dst = 0x41414141;
    BYTE    jmps[2] = { 0xFF, 0xE0 };
    BYTE    nops[2] = { 0x90, 0x90 };
} Trampoline;
#pragma pack(pop)

typedef int(__stdcall *PCompileMethod)(
    uintptr_t thisptr, ICorJitInfo *comp, CORINFO_METHOD_INFO *info,
    unsigned flags, BYTE **nativeEntry, ULONG *nativeSizeOfCode);

typedef struct _JITVtable
{
    PCompileMethod compileMethod;
} JITVtable, PJitVtable;

typedef struct _JIT
{
    JITVtable vtbl;
} JIT;
typedef JIT *(__stdcall *PGetJit)();

typedef struct _Method
{
    DWORD               nToken;
    std::vector<BYTE>   RawBody;
    std::vector<BYTE>   RawHeader;
    std::string         sHeader;
    std::string         sBody;
} Method, *PMethod;
