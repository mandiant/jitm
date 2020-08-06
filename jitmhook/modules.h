/* Copyright (C) 2020 FireEye, Inc. All Rights Reserved. */ 

#pragma once
#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <string>


typedef struct _ModduleInfo
{
    CHAR    name[MAX_PATH];
    DWORD   nStart;
    DWORD   nEnd;
    DWORD   nLength;
} ModuleInfo, *PModuleInfo;


HMODULE     FindModuleByName(const char *);
