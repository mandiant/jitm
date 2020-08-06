/*
 * Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
 *
 * CDNet -- A C implementation to parse the .NET medatadata from a PE file
 */

#include "CDNet.h"

#include <stdio.h>
#include <iostream>


BOOL _CDNet::Initialize(const char *pszFilename)
{
    this->DNTypes = {
        DNT_Module,
        DNT_TypeRef,
        DNT_TypeDef,
        DNT_Field,
        DNT_MethodDef,
        DNT_Param,
        DNT_InterfaceImpl,
        DNT_MemberRef,
        DNT_Constant,
        DNT_CustomAttribute,
        DNT_FieldMarshal,
        DNT_DeclSecurity,
        DNT_ClassLayout,
        DNT_FieldLayout,
        DNT_StandAloneSig,
        DNT_EventMap,
        DNT_Event,
        DNT_PropertyMap,
        DNT_Property,
        DNT_MethodSemantics,
        DNT_MethodImpl,
        DNT_ModuleRef,
        DNT_TypeSpec,
        DNT_ImplMap,
        DNT_FieldRVA,
        DNT_Assembly,
        DNT_AssemblyProcessor,
        DNT_AssemblyOS,
        DNT_AssemblyRef,
        DNT_AssemblyRefProcessor,
        DNT_AssemblyRefOS,
        DNT_File,
        DNT_ExportedType,
        DNT_ManifestResource,
        DNT_NestedClass,
        DNT_GenericParam,
        DNT_MethodSpec,
        DNT_GenericParamConstraint,
    };

    this->DNTNames.insert(std::pair<DWORD, std::string>(DNT_Module, DNT_Module_Name));
    this->DNTNames.insert(std::pair<DWORD, std::string>(DNT_TypeRef, DNT_TypeRef_Name));
    this->DNTNames.insert(std::pair<DWORD, std::string>(DNT_TypeDef, DNT_TypeDef_Name));
    this->DNTNames.insert(std::pair<DWORD, std::string>(DNT_Field, DNT_Field_Name));
    this->DNTNames.insert(std::pair<DWORD, std::string>(DNT_MethodDef, DNT_MethodDef_Name));
    this->DNTNames.insert(std::pair<DWORD, std::string>(DNT_Param, DNT_Param_Name));
    this->DNTNames.insert(std::pair<DWORD, std::string>(DNT_InterfaceImpl, DNT_InterfaceImpl_Name));
    this->DNTNames.insert(std::pair<DWORD, std::string>(DNT_MemberRef, DNT_MemberRef_Name));
    this->DNTNames.insert(std::pair<DWORD, std::string>(DNT_Constant, DNT_Constant_Name));
    this->DNTNames.insert(std::pair<DWORD, std::string>(DNT_CustomAttribute, DNT_CustomAttribute_Name));
    this->DNTNames.insert(std::pair<DWORD, std::string>(DNT_FieldMarshal, DNT_FieldMarshal_Name));
    this->DNTNames.insert(std::pair<DWORD, std::string>(DNT_DeclSecurity, DNT_DeclSecurity_Name));
    this->DNTNames.insert(std::pair<DWORD, std::string>(DNT_ClassLayout, DNT_ClassLayout_Name));
    this->DNTNames.insert(std::pair<DWORD, std::string>(DNT_FieldLayout, DNT_FieldLayout_Name));
    this->DNTNames.insert(std::pair<DWORD, std::string>(DNT_StandAloneSig, DNT_StandAloneSig_Name));
    this->DNTNames.insert(std::pair<DWORD, std::string>(DNT_EventMap, DNT_EventMap_Name));
    this->DNTNames.insert(std::pair<DWORD, std::string>(DNT_Event, DNT_Event_Name));
    this->DNTNames.insert(std::pair<DWORD, std::string>(DNT_PropertyMap, DNT_PropertyMap_Name));
    this->DNTNames.insert(std::pair<DWORD, std::string>(DNT_Property, DNT_Property_Name));
    this->DNTNames.insert(std::pair<DWORD, std::string>(DNT_MethodSemantics, DNT_MethodSemantics_Name));
    this->DNTNames.insert(std::pair<DWORD, std::string>(DNT_MethodImpl, DNT_MethodImpl_Name));
    this->DNTNames.insert(std::pair<DWORD, std::string>(DNT_ModuleRef, DNT_ModuleRef_Name));
    this->DNTNames.insert(std::pair<DWORD, std::string>(DNT_TypeSpec, DNT_TypeSpec_Name));
    this->DNTNames.insert(std::pair<DWORD, std::string>(DNT_ImplMap, DNT_ImplMap_Name));
    this->DNTNames.insert(std::pair<DWORD, std::string>(DNT_FieldRVA, DNT_FieldRVA_Name));
    this->DNTNames.insert(std::pair<DWORD, std::string>(DNT_Assembly, DNT_Assembly_Name));
    this->DNTNames.insert(std::pair<DWORD, std::string>(DNT_AssemblyProcessor, DNT_AssemblyProcessor_Name));
    this->DNTNames.insert(std::pair<DWORD, std::string>(DNT_AssemblyOS, DNT_AssemblyOS_Name));
    this->DNTNames.insert(std::pair<DWORD, std::string>(DNT_AssemblyRef, DNT_AssemblyRef_Name));
    this->DNTNames.insert(std::pair<DWORD, std::string>(DNT_AssemblyRefProcessor, DNT_AssemblyRefProcessor_Name));
    this->DNTNames.insert(std::pair<DWORD, std::string>(DNT_AssemblyRefOS, DNT_AssemblyRefOS_Name));
    this->DNTNames.insert(std::pair<DWORD, std::string>(DNT_File, DNT_File_Name));
    this->DNTNames.insert(std::pair<DWORD, std::string>(DNT_ExportedType, DNT_ExportedType_Name));
    this->DNTNames.insert(std::pair<DWORD, std::string>(DNT_ManifestResource, DNT_ManifestResource_Name));
    this->DNTNames.insert(std::pair<DWORD, std::string>(DNT_NestedClass, DNT_NestedClass_Name));
    this->DNTNames.insert(std::pair<DWORD, std::string>(DNT_GenericParam, DNT_GenericParam_Name));
    this->DNTNames.insert(std::pair<DWORD, std::string>(DNT_MethodSpec, DNT_MethodSpec_Name));
    this->DNTNames.insert(std::pair<DWORD, std::string>(DNT_GenericParamConstraint, DNT_GenericParamConstraint_Name));

    this->sFilename.assign(pszFilename);
    this->Methods.clear();
    return TRUE;
}

/**
 * Parse the PE file and fill out the .NET metadata
 */
BOOL _CDNet::Parse()
{
    HANDLE hFile = CreateFileA(this->sFilename.c_str(), GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, 0, NULL);
    if (INVALID_HANDLE_VALUE == hFile)
        return FALSE;

    DWORD nBytesRead;

    IMAGE_DOS_HEADER oMZ = { 0 };
    if (INVALID_SET_FILE_POINTER == SetFilePointer(hFile, 0, 0, FILE_BEGIN))
        return FALSE;
    if (!ReadFile(hFile, &oMZ, sizeof(oMZ), &nBytesRead, NULL))
        return FALSE;

    IMAGE_NT_HEADERS oNT;
    if (INVALID_SET_FILE_POINTER == SetFilePointer(hFile, oMZ.e_lfanew, 0, FILE_BEGIN))
        return FALSE;
    if (!ReadFile(hFile, &oNT, sizeof(oNT), &nBytesRead, NULL))
        return FALSE;


    // Parse the section header
    IMAGE_SECTION_HEADER SectionHeader = { 0 };
    for (int i = 0; i < oNT.FileHeader.NumberOfSections; ++i)
    {
        if (!ReadFile(hFile, &SectionHeader, sizeof(SectionHeader), &nBytesRead, NULL))
            return FALSE;
        SectionInfo *psection = new SectionInfo();
        psection->sName.assign((char *)SectionHeader.Name);
        psection->nVirtualAddress = SectionHeader.VirtualAddress;
        psection->nVirtualSize = SectionHeader.Misc.VirtualSize;
        psection->nRawAddress = SectionHeader.PointerToRawData;
        psection->nRawSize = SectionHeader.SizeOfRawData;
        this->Sections.push_back(psection);
    }

    PIMAGE_DATA_DIRECTORY pCLR = &(oNT.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_CLR_INDEX]);
    if (pCLR->Size == 0 || pCLR->VirtualAddress == NULL)
    {
        std::cerr << "[*] Invalid PE file: Missing CLR Runtime directory entry" << std::endl;
        return FALSE;
    }

    // Load the .NET metadata directory
    DWORD nDirectoryBaseOffset = this->GetFileOffsetByRVA(pCLR->VirtualAddress);
    DNetDirectory dnd = { 0 };
    if (!dnd.Load(hFile, nDirectoryBaseOffset))
    {
        std::cerr << "[!] Failed to load .NET metadirectory" << std::endl;
        return FALSE;
    }

    // Load the .NET metadata
    DWORD nDNetMetaDataOffset = this->GetFileOffsetByRVA(dnd.nMetaDataRVA);
    std::cout << "[*] MetaDataOffset: 0x" << std::hex << nDNetMetaDataOffset << std::endl;
    MetaDataHeader mdhdr = { 0 };
    if (!mdhdr.Load(hFile, nDNetMetaDataOffset))
    {
        std::cerr << "[!] Failed to load .NET metadata header" << std::endl;
        return FALSE;
    }

    std::cout << "[*]  .NET meta data header loaded: "
        << ", signature: 0x" << std::hex << mdhdr.info.nSignature
        << ", nNumbrOfStreams: 0x" << mdhdr.info.nNumberOfStreams
        << ", version: " << mdhdr.sVersion.c_str()
        << std::dec << std::endl;

    DWORD nStartOfStreams = nDNetMetaDataOffset + mdhdr.Size();
    DWORD nCurrentStreamOffset = nStartOfStreams;
    StreamInfo siMainStream = { 0 };
    // Load the .NET streams
    for (unsigned int i = 0; i < mdhdr.info.nNumberOfStreams; i++)
    {
        StreamInfo  si = { 0 };
        si.Load(hFile, nCurrentStreamOffset);
        std::cout << "[d]  .NET Stream: " << si.sName << std::hex
            << ", offset: 0x" << si.info.nOffset
            << ", size: 0x" << si.info.nSize
            << std::dec << std::endl;
        if (i == 0) siMainStream.Copy(&si);
        nCurrentStreamOffset += si.Size();
    }

    DWORD nMainStreamOffset = nCurrentStreamOffset;
    DNetTablesHeader thdr = { 0 };
    if (!thdr.Load(hFile, nMainStreamOffset))
    {
        std::cerr << "[!] Failed to load the .NET Tables header" << std::endl;
        return FALSE;
    }

    DWORD nStartOfNumberOfRows = nMainStreamOffset + thdr.Size();

    return this->LoadTablesInfo(hFile, nStartOfNumberOfRows,
        thdr.nMaskValidLow, thdr.nMaskValidHigh);
}

// Check if a token is valid based on a 64bit mask
BOOL _IsTokenTypeValid(DWORD nTokenType, DWORD nMaskLow, DWORD nMaskHigh)
{
    DWORD nMask = nTokenType > 31 ? nMaskHigh : nMaskLow;
    return ((1 << nTokenType) & nMask) != 0;
}


/**
 * Load the Token Tables from the main stream. However, we only load upto
 * the MethodDef table and ignore the rest. 
 */

BOOL _CDNet::LoadTablesInfo(
    HANDLE  hFile,
    DWORD   nStartOfNumberOfRows,
    DWORD   nMaskLow,
    DWORD   nMaskHigh)
{
    std::cout << "[*] Loading tables info..." << std::endl;
    DWORD nBytes;
    typedef struct _TableInfo
    {
        DWORD nTokenType;
        std::string sName;
        DWORD nNumberOfRows;
    } TableInfo, *PTableInfo;

    std::vector<PTableInfo> Tables;
    for (std::vector<DWORD>::iterator it = this->DNTypes.begin(); it != this->DNTypes.end(); ++it)
    {
        DWORD nTokenType = (*it);
        if (_IsTokenTypeValid(nTokenType, nMaskLow, nMaskHigh))
        {
            PTableInfo ti = new TableInfo();
            ti->nTokenType = nTokenType;
            std::string sTypeName = this->DNTNames.find(nTokenType)->second;
            ti->sName.assign(sTypeName.c_str(), sTypeName.size());
            Tables.push_back(ti);
        }
    }

    DWORD nCount = 0;
    for (std::vector<PTableInfo>::iterator it = Tables.begin(); it != Tables.end(); ++it)
    {
        DWORD nNumberOfRows = 0;
        DWORD nOffset = nStartOfNumberOfRows + nCount * sizeof(DWORD);
        if (!ReadFile(hFile, &nNumberOfRows, sizeof(DWORD), &nBytes, NULL))
            return FALSE;
        (*it)->nNumberOfRows = nNumberOfRows;
        nCount += 1;
    }

    DWORD nStartOfTablesData = nStartOfNumberOfRows + nCount * sizeof(DWORD);
    DWORD nCurrentOffset = nStartOfTablesData;
    for (unsigned int i = 0; i < Tables.size(); ++i)
    {
        PTableInfo ti = Tables.at(i);
        DWORD nTokenType = ti->nTokenType;
        for (unsigned int j = 1; j < ti->nNumberOfRows+1; ++j)
        {
            PRow row = NULL;
            switch (nTokenType)
            {
            case DNT_Module:
                row = (PRow) new DNetTableRow_Module();
                break;
            case DNT_TypeRef:
                row = (PRow) new DNetTableRow_TypeRef();
                break;
            case DNT_TypeDef:
                row = (PRow) new DNetTableRow_TypeDef();
                break;
            case DNT_Field:
                row = (PRow) new DNetTableRow_Field();
                break;
            case DNT_MethodDef:
                row = (PRow) new DNetTableRow_MethodDef();
                break;
            default:
                row = NULL;
                break;
            }

            if (row && row->Load(hFile, nCurrentOffset))
            {
                nCurrentOffset += row->Size();

                if (nTokenType == DNT_MethodDef)
                {
                    PMethodDef pMethod = (PMethodDef)row;
                    pMethod->nMID = j;
                    pMethod->nToken = MIDToToken(pMethod->nMID);
                    this->Methods.push_back(pMethod);
                }
                else
                {
                    delete row;
                }
            }
        }
    }

    // cleanup stuffs
    while (!Tables.empty())
    {
        PTableInfo ti = Tables.back();
        Tables.pop_back();
        delete ti;
    }
    return this->Methods.size() > 0;
}

SectionInfo *_CDNet::GetSectionByRVA(DWORD nRVA)
{
    std::vector<SectionInfo*>::iterator it;
    for (it = this->Sections.begin(); it != this->Sections.end(); ++it)
    {
        SectionInfo *psection = *it;
        if (psection->nVirtualAddress <= nRVA &&
            nRVA <= (psection->nVirtualAddress + psection->nVirtualSize))
        {
            return psection;
        }
    }
    return NULL;
}


DWORD _CDNet::GetSectionOffsetByRVA(DWORD nRVA)
{
    SectionInfo *psection = this->GetSectionByRVA(nRVA);
    if (!psection)
        return -1;

    return nRVA - psection->nVirtualAddress;
}


DWORD _CDNet::GetFileOffsetByRVA(DWORD nRVA)
{
    SectionInfo *psection = this->GetSectionByRVA(nRVA);
    if (!psection)
    {
        printf("FAILED TO FIND section by RVA: 0x%x\n", nRVA);
        return -1;
    }
    DWORD nSectionOffset = this->GetSectionOffsetByRVA(nRVA);
    if (nSectionOffset == -1)
        return -1;
    return psection->nRawAddress + nSectionOffset;
}


MethodDef *_CDNet::FindMethodDefByToken(DWORD nToken)
{
    std::vector<MethodDef *>::iterator it;
    for (it = this->Methods.begin(); it != this->Methods.end(); ++it)
    {
        if ((*it)->nToken == nToken)
            return *it;
    }
    return NULL;
}
