/*
 * Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
 *
 * CDNet -- A C implementation to parse the .NET medatadata from a PE file
 */
#pragma once
#include "windows.h"
#include <string>
#include <vector>
#include <map>
#include <stdio.h>
#include <iostream>


#define IMAGE_DIRECTORY_CLR_INDEX    14

#define DNT_Module                  0
#define DNT_TypeRef                 1
#define DNT_TypeDef                 2
#define DNT_Field                   4
#define DNT_MethodDef               6
#define DNT_Param                   8
#define DNT_InterfaceImpl           9
#define DNT_MemberRef               10
#define DNT_Constant                11
#define DNT_CustomAttribute         12
#define DNT_FieldMarshal            13
#define DNT_DeclSecurity            14
#define DNT_ClassLayout             15
#define DNT_FieldLayout             16
#define DNT_StandAloneSig           17
#define DNT_EventMap                18
#define DNT_Event                   20
#define DNT_PropertyMap             21
#define DNT_Property                23
#define DNT_MethodSemantics         24
#define DNT_MethodImpl              25
#define DNT_ModuleRef               26
#define DNT_TypeSpec                27
#define DNT_ImplMap                 28
#define DNT_FieldRVA                29
#define DNT_Assembly                32
#define DNT_AssemblyProcessor       33
#define DNT_AssemblyOS              34
#define DNT_AssemblyRef             35
#define DNT_AssemblyRefProcessor    36
#define DNT_AssemblyRefOS           37
#define DNT_File                    38
#define DNT_ExportedType            39
#define DNT_ManifestResource        40
#define DNT_NestedClass             41
#define DNT_GenericParam            42
#define DNT_MethodSpec              43
#define DNT_GenericParamConstraint  44

#define DNT_Module_Name                 "DNT_Module"
#define DNT_TypeRef_Name                "DNT_TypeRef"
#define DNT_TypeDef_Name                "DNT_TypeDef"
#define DNT_Field_Name                  "DNT_Field"
#define DNT_MethodDef_Name              "DNT_MethodDef"
#define DNT_Param_Name                  "DNT_Param"
#define DNT_InterfaceImpl_Name          "DNT_InterfaceImpl"
#define DNT_MemberRef_Name              "DNT_MemberRef"
#define DNT_Constant_Name               "DNT_Constant"
#define DNT_CustomAttribute_Name        "DNT_CustomAttribute"
#define DNT_FieldMarshal_Name           "DNT_FieldMarshal"
#define DNT_DeclSecurity_Name           "DNT_DeclSecurity"
#define DNT_ClassLayout_Name            "DNT_ClassLayout"
#define DNT_FieldLayout_Name            "DNT_FieldLayout"
#define DNT_StandAloneSig_Name          "DNT_StandAloneSig"
#define DNT_EventMap_Name               "DNT_EventMap"
#define DNT_Event_Name                  "DNT_Event"
#define DNT_PropertyMap_Name            "DNT_PropertyMap"
#define DNT_Property_Name               "DNT_Property"
#define DNT_MethodSemantics_Name        "DNT_MethodSemantics"
#define DNT_MethodImpl_Name             "DNT_MethodImpl"
#define DNT_ModuleRef_Name              "DNT_ModuleRef"
#define DNT_TypeSpec_Name               "DNT_TypeSpec"
#define DNT_ImplMap_Name                "DNT_ImplMap"
#define DNT_FieldRVA_Name               "DNT_FieldRVA"
#define DNT_Assembly_Name               "DNT_Assembly"
#define DNT_AssemblyProcessor_Name      "DNT_AssemblyProcessor"
#define DNT_AssemblyOS_Name             "DNT_AssemblyOS"
#define DNT_AssemblyRef_Name            "DNT_AssemblyRef"
#define DNT_AssemblyRefProcessor_Name   "DNT_AssemblyRefProcessor"
#define DNT_AssemblyRefOS_Name          "DNT_AssemblyRefOS"
#define DNT_File_Name                   "DNT_File"
#define DNT_ExportedType_Name           "DNT_ExportedType"
#define DNT_ManifestResource_Name       "DNT_ManifestResource"
#define DNT_NestedClass_Name            "DNT_NestedClass"
#define DNT_GenericParam_Name           "DNT_GenericParam"
#define DNT_MethodSpec_Name             "DNT_MethodSpec"
#define DNT_GenericParamConstraint_Name "DNT_GenericParamConstraint"

#pragma pack(push, 1)
typedef struct _DNetDirectory
{
    DWORD   cb;
    WORD    nMajor;
    WORD    nMinor;
    DWORD   nMetaDataRVA;
    DWORD   nMetaDataSize;
    BOOL Load(HANDLE hFile, DWORD nOffset)
    {
        DWORD nBytes = 0;
        if (INVALID_SET_FILE_POINTER == SetFilePointer(hFile, nOffset, 0, FILE_BEGIN))
        {
            return FALSE;
        }
        if (!ReadFile(hFile, this, sizeof(_DNetDirectory), &nBytes, NULL))
            return FALSE;
        return TRUE;
    }
} DNetDirectory, *PDNetDirectory;

typedef struct _DNetMetaDataHeader
{
    DWORD   nSignature;
    WORD    nMajor;
    WORD    nMinor;
    DWORD   nReserved;
    DWORD   nVersionLength;
    WORD    nFlags;
    WORD    nNumberOfStreams;
} DNetMetaDataHeader, *PDNetMetaDataHeader;

typedef struct _MetaDataHeader
{
    DNetMetaDataHeader    info;
    std::string            sVersion;
    DWORD Size()
    {
        SIZE_T nSize = sVersion.size();
        SIZE_T nBlocks = nSize / sizeof(DWORD) + 1;
        return sizeof(info) + nBlocks * sizeof(DWORD);
    }

    BOOL Load(HANDLE hFile, DWORD nOffset = 0)
    {
        DWORD nBytes = 0;
        if (INVALID_SET_FILE_POINTER == SetFilePointer(hFile, nOffset, 0, FILE_BEGIN))
            return FALSE;
        if (!ReadFile(hFile, &info, sizeof(_DNetMetaDataHeader) - sizeof(WORD) * 2, &nBytes, NULL))
            return FALSE;
        BOOL bDone = FALSE;
        CHAR s[MAX_PATH] = { 0 };
        if (!ReadFile(hFile, s, info.nVersionLength, &nBytes, NULL))
            return FALSE;
        if (!ReadFile(hFile, &(this->info.nFlags), sizeof(WORD), &nBytes, NULL))
            return FALSE;
        if (!ReadFile(hFile, &(this->info.nNumberOfStreams), sizeof(WORD), &nBytes, NULL))
            return FALSE;
        this->sVersion.assign(s);
        return TRUE;
    }
} MetaDataHeader, *PMetaDataHeader;

typedef struct _DNetStreamInfo
{
    DWORD    nOffset;
    DWORD    nSize;
} DNetStreamInfo, *PDNetStreamInfo;

typedef struct _StreamInfo
{
    DNetStreamInfo  info;
    std::string     sName;   
    DWORD Size()
    {
        SIZE_T nSize = sName.size();
        SIZE_T nBlocks = nSize / sizeof(DWORD) + 1;
        return sizeof(DNetStreamInfo) + nBlocks * sizeof(DWORD);
    }

    BOOL Load(HANDLE hFile, DWORD nOffset)
    {
        this->sName.clear();
        DWORD nBytes = 0;
        if (INVALID_SET_FILE_POINTER == SetFilePointer(hFile, nOffset, 0, FILE_BEGIN))
            return FALSE;
        if (!ReadFile(hFile, &info, sizeof(_DNetStreamInfo), &nBytes, NULL))
            return FALSE;
        BOOL bDone = FALSE;
        CHAR _s[2] = { 0 };
        while (!bDone)
        {
            if (!ReadFile(hFile, &_s, sizeof(CHAR), &nBytes, NULL))
                return FALSE;
            if (strlen(_s) == 0) {
                bDone = TRUE;
                break;
            }
            this->sName.append(_s);
        }
        return TRUE;
    }

    BOOL Copy(_StreamInfo* that)
    {
        this->info.nOffset = that->info.nOffset;
        this->info.nSize = that->info.nSize;
        this->sName.assign(that->sName.c_str(), that->sName.size());
        return TRUE;
    }
} StreamInfo, *PStreamInfo;

typedef struct _DNetTablesHeader
{
    DWORD    nReserved_1;
    BYTE     nMajorVersion;
    BYTE     nMinorVersion;
    BYTE     nHeapOffsetSizes;
    BYTE     nReserved_2;
    DWORD    nMaskValidLow;
    DWORD    nMaskValidHigh;
    DWORD    nMaskSortedLow;
    DWORD    nMaskSortedHigh;

    BOOL Load(HANDLE hFile, DWORD nOffset)
    {
        DWORD nBytes = 0;
        if (INVALID_SET_FILE_POINTER == SetFilePointer(hFile, nOffset, 0, FILE_BEGIN))
            return FALSE;
        if (!ReadFile(hFile, this, sizeof(_DNetTablesHeader), &nBytes, NULL))
            return FALSE;
        return TRUE;
    }

    DWORD Size()
    {
        return sizeof(_DNetTablesHeader);
    }
} DNetTablesHeader;

typedef struct _Row
{
    virtual BOOL    Load(HANDLE, DWORD) = 0;
    virtual DWORD   Size() = 0;
} Row, *PRow;

typedef struct _DNetTableRow_Module : Row
{
    typedef struct __DNetTableRow_Module
    {
        WORD  nGeneration;
        DWORD nNameRVA;
        WORD  nMVID;
        WORD  nEncId;
        WORD  nEncBaseId;
    } __INTERNAL;
    WORD    nGeneration;
    DWORD   nNameRVA;
    WORD    nMVID;
    WORD    nEncId;
    WORD    nEncBaseId;

    DWORD Size() { return sizeof(__INTERNAL); }
    BOOL Load(HANDLE hFile, DWORD nOffset)
    {
        __INTERNAL data = { 0 };
        DWORD nBytes;
        if (INVALID_SET_FILE_POINTER == SetFilePointer(hFile, nOffset, 0, FILE_BEGIN))
            return FALSE;
        if (!ReadFile(hFile, &data, sizeof data, &nBytes, NULL))
            return FALSE;

        this->nGeneration = data.nGeneration;
        this->nNameRVA = data.nNameRVA;
        this->nEncId = data.nEncId;
        this->nEncBaseId = data.nEncBaseId;
        this->nMVID = data.nMVID;
        return TRUE;
    }
} DNetTableRow_Module, *PDNetTableRow_Module;

typedef struct _DNetTableRow_TypeRef : Row
{
    typedef struct __DNetTableRow_TypeRef
    {
        WORD    nResolutionScope;
        DWORD   nNameRVA;
        DWORD   nNamespace;
    } __INTERNAL;
    WORD    nResolutionScope;
    DWORD   nNameRVA;
    DWORD   nNamespace;

    DWORD Size() { return sizeof(__INTERNAL); }
    BOOL Load(HANDLE hFile, DWORD nOffset)
    {
        __INTERNAL data = { 0 };
        DWORD nBytes = 0;
        if (INVALID_SET_FILE_POINTER == SetFilePointer(hFile, nOffset, 0, FILE_BEGIN))
            return FALSE;
        if (!ReadFile(hFile, &data, sizeof(data), &nBytes, NULL))
            return FALSE;

        this->nResolutionScope = data.nResolutionScope;
        this->nNameRVA = data.nNameRVA;
        this->nNamespace = data.nNamespace;
        return TRUE;
    }


} DNetTableRow_TypeRef, *PDNetTableRow_TypeRef;


typedef struct _DNetTableRow_TypeDef : Row
{
    typedef struct __DNetTableRow_TypeDef
    {
        DWORD   nFlags;
        DWORD   nNameRVA;
        DWORD   nNamespace;
        WORD    nExtends;
        WORD    nFieldList;
        WORD    nMethodList;
    } __INTERNAL;
    DWORD   nFlags;
    DWORD   nNameRVA;
    DWORD   nNamespace;
    WORD    nExtends;
    WORD    nFieldList;
    WORD    nMethodList;

    DWORD Size() { return sizeof(__INTERNAL); }
    BOOL Load(HANDLE hFile, DWORD nOffset)
    {
        __INTERNAL data;
        DWORD nBytes = 0;
        if (INVALID_SET_FILE_POINTER == SetFilePointer(hFile, nOffset, 0, FILE_BEGIN))
            return FALSE;
        if (!ReadFile(hFile, &data, sizeof(data), &nBytes, NULL))
            return FALSE;

        this->nFlags = data.nFlags;
        this->nNameRVA = data.nNameRVA;
        this->nNamespace = data.nNamespace;
        this->nExtends = data.nExtends;
        this->nFieldList = data.nFieldList;
        this->nMethodList = data.nMethodList;
        return TRUE;
    }
} DNetTableRow_TypeDef, *PDNetTableRowTypeDef;


typedef struct _DNetTableRow_Field : Row
{
    typedef struct __DNetTableRow_Field
    {
        WORD    nFlags;
        DWORD   nNameRVA;
        WORD    nSignature;
    } __INTERNAL;
    WORD    nFlags;
    DWORD   nNameRVA;
    WORD    nSignature;
    DWORD Size() { return sizeof(__INTERNAL); }
    BOOL Load(HANDLE hFile, DWORD nOffset)
    {
        __INTERNAL data;
        DWORD nBytes = 0;
        if (INVALID_SET_FILE_POINTER == SetFilePointer(hFile, nOffset, 0, FILE_BEGIN))
            return FALSE;
        if (!ReadFile(hFile, &data, sizeof(data), &nBytes, NULL))
            return FALSE;

        this->nFlags = data.nFlags;
        this->nNameRVA = data.nNameRVA;
        this->nSignature = data.nSignature;
        return TRUE;
    }
} DNetTableRow_Field, *PDNetTableRow_Field;


typedef struct _DNetTableRow_MethodDef : Row
{
    typedef struct __DNetTableRow_MethodDef
    {
        DWORD   nRVA;
        WORD    nImplFlags;
        WORD    nFlags;
        DWORD   nNameRVA;
        WORD    nSignature;
        WORD    nParamList;
    } __INTERNAL;
    DWORD   nRVA;
    WORD    nImplFlags;
    WORD    nFlags;
    DWORD   nNameRVA;
    WORD    nSignature;
    WORD    nParamList;
    DWORD   nMID;
    DWORD   nToken;

    DWORD Size() { return sizeof(__INTERNAL); }
    BOOL Load(HANDLE hFile, DWORD nOffset)
    {
        __INTERNAL data;
        DWORD nBytes = 0;
        if (INVALID_SET_FILE_POINTER == SetFilePointer(hFile, nOffset, 0, FILE_BEGIN))
            return FALSE;
        if (!ReadFile(hFile, &data, sizeof(data), &nBytes, NULL))
            return FALSE;

        this->nRVA = data.nRVA;
        this->nImplFlags = data.nImplFlags;
        this->nFlags = data.nFlags;
        this->nNameRVA = data.nNameRVA;
        this->nSignature = data.nSignature;
        this->nParamList = data.nParamList;
        return TRUE;
    }
} MethodDef, *PMethodDef, DNetTableRow_MethodDef, *PDNetTableRow_MethodDef;


typedef struct _SectionInfo
{
    std::string  sName;
    DWORD        nVirtualAddress;
    DWORD        nVirtualSize;
    DWORD        nRawAddress;
    DWORD        nRawSize;
} SectionInfo;

typedef struct _CDNet
{
    std::string                    sFilename;
    std::vector <DWORD>            DNTypes;
    std::map<DWORD, std::string>   DNTNames;
    std::vector <MethodDef *>      Methods;
    std::vector <SectionInfo *>    Sections;


    BOOL            Initialize(const char *);
    BOOL            Parse();
    BOOL            LoadTablesInfo(HANDLE, DWORD, DWORD, DWORD);
    MethodDef*      FindMethodDefByToken(DWORD);
    DWORD           GetSectionOffsetByRVA(DWORD);
    DWORD           GetFileOffsetByRVA(DWORD);
    SectionInfo*    GetSectionByRVA(DWORD);
} CDNet, *PCDNet;
#pragma pack(pop)


__inline DWORD        MIDToToken(DWORD nMID) { return 0x6000000 + nMID; }
__inline DWORD        TokenToMID(DWORD nToken) { return nToken & 0xFFFFFF; }
