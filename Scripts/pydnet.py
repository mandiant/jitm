'''
Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

Python implementation to pase PE .NET metadata. Unfortunatley, I can not find
any thing in Python to do that.

This is a work in progress. Currently, the module only parse upto the
MethodDef table, and only save the content of the Method table. All other
.NET metadata is ignored/thrown away
'''

import pefile
import struct
import logging
from vstruct import VStruct, primitives as vp

DWORD_SIZE                  = 4

DNT_Module                  = 0
DNT_TypeRef                 = 1
DNT_TypeDef                 = 2
DNT_Field                   = 4
DNT_MethodDef               = 6
DNT_Param                   = 8
DNT_InterfaceImpl           = 9
DNT_MemberRef               = 10
DNT_Constant                = 11
DNT_CustomAttribute         = 12
DNT_FieldMarshal            = 13
DNT_DeclSecurity            = 14
DNT_ClassLayout             = 15
DNT_FieldLayout             = 16
DNT_StandAloneSig           = 17
DNT_EventMap                = 18
DNT_Event                   = 20
DNT_PropertyMap             = 21
DNT_Property                = 23
DNT_MethodSemantics         = 24
DNT_MethodImpl              = 25
DNT_ModuleRef               = 26
DNT_TypeSpec                = 27
DNT_ImplMap                 = 28
DNT_FieldRVA                = 29
DNT_Assembly                = 32
DNT_AssemblyProcessor       = 33
DNT_AssemblyOS              = 34
DNT_AssemblyRef             = 35
DNT_AssemblyRefProcessor    = 36
DNT_AssemblyRefOS           = 37
DNT_File                    = 38
DNT_ExportedType            = 39
DNT_ManifestResource        = 40
DNT_NestedClass             = 41
DNT_GenericParam            = 42
DNT_MethodSpec              = 43
DNT_GenericParamConstraint  = 44

DNT_Types = [
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
]

DNT_Names = {
    DNT_Module:                     'DNT_Module',
    DNT_TypeRef:                    'DNT_TypeRef',
    DNT_TypeDef:                    'DNT_TypeDef',
    DNT_Field:                      'DNT_Field',
    DNT_MethodDef:                  'DNT_MethodDef',
    DNT_Param:                      'DNT_Param',
    DNT_InterfaceImpl:              'DNT_InterfaceImpl',
    DNT_MemberRef:                  'DNT_MemberRef',
    DNT_Constant:                   'DNT_Constant',
    DNT_CustomAttribute:            'DNT_CustomAttribute',
    DNT_FieldMarshal:               'DNT_FieldMarshal',
    DNT_DeclSecurity:               'DNT_DeclSecurity',
    DNT_ClassLayout:                'DNT_ClassLayout',
    DNT_FieldLayout:                'DNT_FieldLayout',
    DNT_StandAloneSig:              'DNT_StandAloneSig',
    DNT_EventMap:                   'DNT_EventMap',
    DNT_Event:                      'DNT_Event',
    DNT_PropertyMap:                'DNT_PropertyMap',
    DNT_Property:                   'DNT_Property',
    DNT_MethodSemantics:            'DNT_MethodSemantics',
    DNT_MethodImpl:                 'DNT_MethodImpl',
    DNT_ModuleRef:                  'DNT_ModuleRef',
    DNT_TypeSpec:                   'DNT_TypeSpec',
    DNT_ImplMap:                    'DNT_ImplMap',
    DNT_FieldRVA:                   'DNT_FieldRVA',
    DNT_Assembly:                   'DNT_Assembly',
    DNT_AssemblyProcessor:          'DNT_AssemblyProcessor',
    DNT_AssemblyOS:                 'DNT_AssemblyOS',
    DNT_AssemblyRef:                'DNT_AssemblyRef',
    DNT_AssemblyRefProcessor:       'DNT_AssemblyRefProcessor',
    DNT_AssemblyRefOS:              'DNT_AssemblyRefOS',
    DNT_File:                       'DNT_File',
    DNT_ExportedType:               'DNT_ExportedType',
    DNT_ManifestResource:           'DNT_ManifestResource',
    DNT_NestedClass:                'DNT_NestedClass',
    DNT_GenericParam:               'DNT_GenericParam',
    DNT_MethodSpec:                 'DNT_MethodSpec',
    DNT_GenericParamConstraint:     'DNT_GenericParamConstraint',
}


class DNetDirectory(VStruct):
    def __init__(self):
        super(DNetDirectory, self).__init__()
        self.cb = vp.v_uint32()
        self.nMajor = vp.v_uint16()
        self.nMinor = vp.v_uint16()
        self.nMetaDataRVA = vp.v_uint32()
        self.nMetaDataSize = vp.v_uint32()


class DNetMetaDataHeader(VStruct):
    def __init__(self):
        super(DNetMetaDataHeader, self).__init__()
        self.Signature = vp.v_uint32()
        self.nMajor = vp.v_uint16()
        self.nMinor = vp.v_uint16()
        self.reserved = vp.v_uint32()
        self.nVersionLength = vp.v_uint32()

    def vsParse(self, bytez, offset, fast=True):
        super(DNetMetaDataHeader, self).vsParse(bytez, offset, fast)
        here = 0x10 + offset
        version_end_offset = here + self.nVersionLength
        sVersion = bytez[here:version_end_offset]
        self.sVersion = vp.v_str(len(sVersion))
        self.sVersion = sVersion

        sFlags = bytez[version_end_offset:version_end_offset + 2]
        self.nFlags = vp.v_uint16(struct.unpack("<H", sFlags)[0])
        sNumberOfStreams = bytez[version_end_offset + 2:version_end_offset + 4]
        self.nNumberOfSteams = vp.v_uint16(
            struct.unpack("<H", sNumberOfStreams)[0])


class DNetStreamInfo(VStruct):
    def __init__(self):
        super(DNetStreamInfo, self).__init__()
        self.nOffset = vp.v_uint32()
        self.nSize   = vp.v_uint32()

    def vsParse(self, bytez, offset, fast=True):
        super(DNetStreamInfo, self).vsParse(bytez, offset, fast)
        here = offset + len(self)
        _s = []
        offset = here
        while bytez[offset] != '\x00':
            _s.append(bytez[offset])
            offset += 1
        _slen = len(_s)
        nblocks = (_slen // DWORD_SIZE) + 1
        slen = nblocks * DWORD_SIZE
        self.sName = vp.v_str(slen)
        sName = bytez[here:here + slen]
        self.sName = sName


class DNetTablesHeader(VStruct):
    def __init__(self):
        super(DNetTablesHeader, self).__init__()
        self.nReserve = vp.v_uint32()
        self.nUnknown = vp.v_uint32()
        self.nMaskValidLow = vp.v_uint32()
        self.nMaskValidHigh = vp.v_uint32()
        self.nMaskSortedLow = vp.v_uint32()
        self.nMaskSortedHigh = vp.v_uint32()

    def vsParse(self, *args, **kwargs):
        super(DNetTablesHeader, self).vsParse(*args, **kwargs)
        self.nMaskValid = (self.nMaskValidHigh << 32) + self.nMaskValidLow
        self.nMaskSorted = (self.nMaskSortedHigh << 32) + self.nMaskSortedLow


class DNetTableRow_Module(VStruct):
    def __init__(self):
        super(DNetTableRow_Module, self).__init__()
        self.Generation = vp.v_uint16()
        self.Name = vp.v_uint16()
        self.Mvid = vp.v_uint16()
        self.EncId = vp.v_uint16()
        self.EncBaseId = vp.v_uint16()


class DNetTableRow_TypeRef(VStruct):
    def __init__(self):
        super(DNetTableRow_TypeRef, self).__init__()
        self.ResolutionScope = vp.v_uint16()
        self.Name = vp.v_uint16()
        self.Namespace = vp.v_uint16()


class DNetTableRow_TypeDef(VStruct):
    def __init__(self):
        super(DNetTableRow_TypeDef, self).__init__()
        self.Flags = vp.v_uint32()
        self.Name = vp.v_uint16()
        self.Namspace = vp.v_uint16()
        self.Extends = vp.v_uint16()
        self.FieldList = vp.v_uint16()
        self.MethodList = vp.v_uint16()


class DNetTableRow_Field(VStruct):
    def __init__(self):
        super(DNetTableRow_Field, self).__init__()
        self.Flags = vp.v_uint16()
        self.Name = vp.v_uint16()
        self.Signature = vp.v_uint16()


class DNetTableRow_MethodDef(VStruct):
    def __init__(self):
        super(DNetTableRow_MethodDef, self).__init__()
        self.RVA = vp.v_uint32()
        self.ImplFlags = vp.v_uint16()
        self.Flags = vp.v_uint16()
        self.Name = vp.v_uint16()
        self.Signature = vp.v_uint16()
        self.ParamList = vp.v_uint16()

    def vsParse(self, bytez, offset, fast=True):
        super(DNetTableRow_MethodDef, self).vsParse(bytez, offset, fast)
        self.nOffset = offset
        self.nToken = 0


def GetMaskNumberByBits(nBits):
    if nBits < 0:
        return None
    return 1 << nBits


def MIDToToken(nMid):
    return 0x6000000 + nMid


def TokenToMid(nToken):
    return nToken & 0xFFFFFF


class PyDNet(object):
    def __init__(self, filename, debug=False):
        self.filename = filename
        self.pe = pefile.PE(self.filename)
        with open(self.filename, 'rb') as _ifile:
            self.filedata = [ord(_) for _ in _ifile.read()]
        self.filesize = len(self.filedata)
        # ---------------------------------------------------------------------
        self.Methods = None
        self.DNetDirectory = None
        self.nDNetDirectoryOffset = None
        # ---------------------------------------------------------------------
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.debug("Initialized!")

    def Parse(self):
        '''
        Parse the file specified the filename when __init__() is called.
        '''
        with open(self.filename, 'rb') as _ifile:
            pedata = _ifile.read()
        de = self._GetDNetEntry()
        if de is None:
            raise RuntimeError(".NET directory not found")

        nDirectoryBaseOffset = de.VirtualAddress
        self.nDNetDirectoryOffset = self.FileOffsetFromRVA(de.VirtualAddress)
        self.logger.debug(
            ".NET directory file offset: %s",
            hex(self.nDNetDirectoryOffset))

        self.DNetDirectory = DNetDirectory()
        self.DNetDirectory.vsParse(pedata, offset=self.nDNetDirectoryOffset)
        self.logger.debug(
            ".NET directory info: cb: 0x%s, rva: 0x%s",
            hex(self.DNetDirectory.cb), hex(self.DNetDirectory.nMetaDataRVA))

        self.nDNetMetaDataHeaderOffset = self.FileOffsetFromRVA(
            self.DNetDirectory.nMetaDataRVA)
        self.DNetMetaDataHeader = DNetMetaDataHeader()
        self.DNetMetaDataHeader.vsParse(
            pedata, offset=self.nDNetMetaDataHeaderOffset)
        self.logger.debug(
            ".NET metadata signature: 0x%s, version: %s",
            self.DNetMetaDataHeader.Signature,
            self.DNetMetaDataHeader.sVersion)

        self.nStreamsOffset = self.nDNetMetaDataHeaderOffset + len(self.DNetMetaDataHeader)
        self.StreamMain = None
        nStreamInfoOffset = self.nStreamsOffset
        for i in range(self.DNetMetaDataHeader.nNumberOfSteams):
            dnsi = DNetStreamInfo()
            dnsi.vsParse(pedata, nStreamInfoOffset)
            self.logger.debug(
                ".NET stream: %s, offset: %s, size: %s",
                dnsi.sName, hex(dnsi.nOffset), hex(dnsi.nSize))

            if self.StreamMain is None:
                self.StreamMain = dnsi
            nStreamInfoOffset += len(dnsi)

        nTargetStreamOffset = nStreamInfoOffset
        thdr = DNetTablesHeader()
        thdr.vsParse(pedata, nTargetStreamOffset)
        self.logger.debug(
            ".NET main stream header: %s at %s",
            hex(thdr.nMaskValid), hex(nTargetStreamOffset))

        nStartOfNumberOfRows = nTargetStreamOffset + len(thdr)
        rc = self._LoadTablesInfo(
            pedata, nStartOfNumberOfRows, thdr.nMaskValid)
        return rc

    def Close(self):
        '''
        Close the PE file handle to free up the file for edit/delete
        '''
        self.pe.close()

    def GetSectionByRVA(self, rva):
        '''
        Given an RVA, find the section that such RVA belongs to

        @return section on success, None if not found.
        '''
        for section in self.pe.sections:
            sstart = section.VirtualAddress
            send = sstart + section.Misc_VirtualSize
            if sstart <= rva and rva <= send:
                return section
        return None

    def GetSectionOffsetFromRVA(self, rva):
        section = self.GetSectionByRVA(rva)
        if section is None:
            return None
        return rva - section.VirtualAddress

    def FileOffsetFromRVA(self, rva):
        section = self.GetSectionByRVA(rva)
        if section is None:
            return None
        offset = self.GetSectionOffsetFromRVA(rva)
        return section.PointerToRawData + offset

    def MIDToToken(self, nMid):
        return MIDToToken(nMid)

    def TokenToMID(self, nToken):
        return TokenToMID(nToken)

    def ReadDWORD(self, offset):
        _s = [chr(_) for _ in self.ReadBytes(offset, 4)]
        return struct.unpack("<I", ''.join(_s))[0]

    def ReadBytes(self, offset, size):
        if offset < 0 or offset + size > self.filesize:
            return None
        _bytez = self.filedata[offset:offset + size]
        return _bytez

    def SetByte(self, offset, bytez):
        if offset < 0 or offset + len(bytez) > self.filedata:
            return False
        for i in range(len(bytez)):
            self.filedata[offset + i] = bytez[i]
        return True

    # -------------------------------------------------------------------------
    def _GetDNetEntry(self):
        for _de in self.pe.OPTIONAL_HEADER.DATA_DIRECTORY:
            if _de.name == 'IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR':
                de = _de
                break
        return de

    def _LoadTablesInfo(self, data, nStartOfNumberOfRows, nMask):
        '''
        Load .NET tables content. This function does minimum amount of work,
        only to get to the MethodDef table and parse out the methods info.
        '''
        nNumberOfRows = 0
        self.Tables = list()

        # First, check all known TokenType against the valid mask from
        # .NET metadata header to determine how many tables are available
        for i in range(len(DNT_Types)):
            nTokenType = DNT_Types[i]
            nMaskNumber = GetMaskNumberByBits(nTokenType)
            bExist = (nMaskNumber & nMask) != 0
            if bExist:
                tbl = {
                    'nTokenType': nTokenType,
                    'name': DNT_Names.get(nTokenType)
                }
                self.Tables.append(tbl)

        # Read the number of rows for each table. The number of entries is
        # determine by the ValidMask field of the .NET metadata header
        for i in range(len(self.Tables)):
            v = self.Tables[i]
            o = nStartOfNumberOfRows + i * DWORD_SIZE
            nRows = self.ReadDWORD(o)
            self.Tables[i].update({
                'nRows': nRows, 'nIndex': i
            })

        nStartOfTablesData = nStartOfNumberOfRows + DWORD_SIZE * (len(self.Tables))
        self.logger.debug("Start of tables data: %s", hex(nStartOfTablesData))
        nCurrentOffset = 0

        # For each table, parse the table content, but only to advance the file
        # offset. The only table we really care about is the MethodDef table
        for i in range(len(self.Tables)):
            tbl = self.Tables[i]
            rows = list()
            self.logger.debug(
                "Table %s strats at %s",
                tbl.get('name'), hex(nStartOfTablesData + nCurrentOffset))
            for j in range(1, tbl.get('nRows') + 1):
                # NOTE: Row index starts at 1
                nTokenType = tbl.get('nTokenType')
                if nTokenType == DNT_Module:
                    ctor = DNetTableRow_Module
                elif nTokenType == DNT_TypeRef:
                    ctor = DNetTableRow_TypeRef
                elif nTokenType == DNT_TypeDef:
                    ctor = DNetTableRow_TypeDef
                elif nTokenType == DNT_Field:
                    ctor = DNetTableRow_Field
                elif nTokenType == DNT_MethodDef:
                    ctor = DNetTableRow_MethodDef
                else:
                    # ignore the other tables after MethodDef
                    continue
                row = ctor()
                row.vsParse(data, nStartOfTablesData + nCurrentOffset)
                if nTokenType == DNT_MethodDef:
                    # Save the token and the MID for convenience
                    row.nToken = MIDToToken(j)
                    row.nMID = j
                self.logger.debug("Adding a %s row", tbl.get('name'))
                nCurrentOffset += len(row)
                rows.append(row)
            tbl.update({'rows': rows})

        # The Tables variable goes out of scope here. So, we are saving
        # the methods for use later.
        for i in range(len(self.Tables)):
            if self.Tables[i].get('nTokenType') == DNT_MethodDef:
                self.Methods = self.Tables[i].get('rows')
                return True

        return False
