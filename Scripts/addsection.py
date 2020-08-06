'''
This is a utility to add a section to a PE file. Given a binary file on disk,
this utility will performs the following:
- Check if the PE header has enough room for an additional section header
- If not:
  - Grow the header by OPTIONAL_HEADER.FileAlignment bytes
  - Fix the PointerToRawData of all other sections
  - Fix the RVA of all the data directory entries
- Append the binary file to the end of the file, padding to match alignment
- Fill out the section header data

This file can be run via command line, or imported as a module.
'''

from __future__ import print_function
import argparse
import pefile
import struct
import os


SECTION_HEADER_SIZE             =   0x28
SECTION_HEADER_START            =   0x178

IMAGE_SCN_CNT_CODE              =   0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA  =   0x00000040
IMAGE_SCN_MEM_READ              =   0x40000000
IMAGE_SCN_MEM_EXECUTE           =   0x20000000

TMP_FILENAME                   =   'tmp.bin'


def AlignUp(num, align):
    if num % align == 0:
        return num
    return ((num / align) + 1) * align


def PadBytes(bytez, align):
    blen = len(bytez)
    nsize = AlignUp(blen, align)
    pad = [0x00 for _ in range(nsize - blen)]
    padded = bytez + pad
    return padded


def PadString(s, align):
    bytez = [ord(_) for _ in s]
    padded = PadBytes(bytez, align)
    return ''.join([chr(_) for _ in padded])


def GrowHeader(ofile, nfile):
    '''
    Grow the header. Number of bytes to grow is determined by the
    OPTIONAL_HEADER.FileAlignment field.

    The original file is unchanged. A new file is created.
    '''
    pe = pefile.PE(ofile)
    nSize = pe.OPTIONAL_HEADER.FileAlignment
    with open(ofile, 'rb') as ifile:
        with open(nfile, 'wb') as ofile:
            ofile.write(ifile.read(pe.OPTIONAL_HEADER.SizeOfHeaders))
            ofile.write("\x00" * nSize)
            ofile.write(ifile.read())

    pe = pefile.PE(nfile)
    pe.OPTIONAL_HEADER.SizeOfHeaders += nSize
    for section in pe.sections:
        nNewRawData = section.PointerToRawData + nSize
        section.PointerToRawData = nNewRawData
    for dd in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
        if dd.VirtualAddress > 0:
            offset = dd.get_field_absolute_offset('VirtualAddress')
            nNewSize = dd.VirtualAddress + nSize
            pe.set_bytes_at_offset(offset, struct.pack("<I", nNewSize))
    pe.write(nfile)
    return True


def HasEnoughHeaderSpace(filename):
    '''
    Determine if current PE header has enough room for a new section header
    '''
    pe = pefile.PE(filename)
    size_of_section_headers = SECTION_HEADER_SIZE * len(pe.sections)
    total_header_size = SECTION_HEADER_START + size_of_section_headers
    available_bytes = pe.OPTIONAL_HEADER.SizeOfHeaders - total_header_size
    return available_bytes >= SECTION_HEADER_SIZE


def AddSection(ifilename, ofilename, sname, sfilename, tfilename=TMP_FILENAME):
    '''
    Add a section to a PE file.
    The original file is not modifiled. A new file is created.

    Arguments:
        ifilename   :   input filename
        ofilename   :   output filename
        sname       :   section name, at most 8 bytes long
        sfilename   :   binary file that contains section data
        tfilename   :   temp filename, in case we need to grow the header
    '''
    use_tmp_file = False
    if not HasEnoughHeaderSpace(ifilename):
        GrowHeader(ifilename, tfilename)
        use_tmp_file = True
        pefilename = tfilename
    else:
        pefilename = ifilename
    sec = Section(pefilename, sfilename)
    sec.SetSectionName(sname)
    sec.WriteNewFile(ofilename)
    sec.pe.close()
    if use_tmp_file:
        os.remove(tfilename)
    return sec.header.VirtualAddress, sec.header.PointerToRawData


class SectionHeader(object):
    def __init__(self):
        self.Name = [0, 0, 0, 0, 0, 0, 0, 0]
        self.VirtualSize = 0
        self.VirtualAddress = 0
        self.PointerToRawData = 0
        self.SizeOfRawData = 0
        self.PointerToRelocations = 0
        self.PointerToLineNumbers = 0
        self.NumberOfRelocations = 0
        self.NumberOfLineNumbers = 0
        self.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_INITIALIZED_DATA


class Section(object):
    def __init__(self, filename, datafilename):
        self.filename = filename
        self.datafilename = datafilename
        self.header = SectionHeader()
        self.pedata = [ord(_) for _ in open(filename, 'rb').read()]
        self.pe = pefile.PE(filename)

        self.data = open(datafilename, 'rb').read()

        self.data_offset = 0
        self.header_offset = 0
        self.Attach()


    def __str__(self):
        info = [
            (hex(self.header_offset + 0x00),    hex(0x00),  'Name',                 ''.join([chr(_) for _ in self.header.Name])),
            (hex(self.header_offset + 0x08),    hex(0x08),  'Misc_VirtualSize',     hex(self.header.VirtualSize)),
            (hex(self.header_offset + 0x0C),    hex(0x0C),  'VirtualAddress',       hex(self.header.VirtualAddress)),
            (hex(self.header_offset + 0x10),    hex(0x10),  'SizeOfRawData',        hex(self.header.SizeOfRawData)),
            (hex(self.header_offset + 0x14),    hex(0x14),  'PointerToRawData',     hex(self.header.PointerToRawData)),
            (hex(self.header_offset + 0x18),    hex(0x18),  'PointerToRelocations', hex(self.header.PointerToRelocations)),
            (hex(self.header_offset + 0x1C),    hex(0x1c),  'PointerToLineNumbers', hex(self.header.PointerToLineNumbers)),
            (hex(self.header_offset + 0x20),    hex(0x20),  'NumberOfRelocations',  hex(self.header.NumberOfRelocations)),
            (hex(self.header_offset + 0x24),    hex(0x24),  'NumberOfLineNumbers',  hex(self.header.NumberOfLineNumbers)),
            (hex(self.header_offset + 0x28),    hex(0x28),  'Characteristics',      hex(self.header.Characteristics)),

        ]
        s = '[IMAGE_SECTION_HEADER]\n'
        f = '{0:<8}{1:<6}{2:<30}{3}\n'
        for l in info:
            s += f.format(*l)
        return s

    def Attach(self):
        self._update_header_offset()
        self._update_raw_address()
        self._update_raw_size()
        self._update_virtual_address()
        self._update_virtual_size()

    def WriteNewFile(self, filename):
        header_data = ''
        header_data += ''.join([chr(_) for _ in self.header.Name])
        header_data += struct.pack("<I", self.header.VirtualSize)
        header_data += struct.pack("<I", self.header.VirtualAddress)
        header_data += struct.pack("<I", self.header.SizeOfRawData)
        header_data += struct.pack("<I", self.header.PointerToRawData)
        header_data += struct.pack("<I", self.header.PointerToRelocations)
        header_data += struct.pack("<I", self.header.PointerToLineNumbers)
        header_data += struct.pack("<H", self.header.NumberOfRelocations)
        header_data += struct.pack("<H", self.header.NumberOfLineNumbers)
        header_data += struct.pack("<I", self.header.Characteristics)

        pe = pefile.PE(self.filename)
        pe.FILE_HEADER.NumberOfSections += 1
        pe.set_bytes_at_offset(self.header_offset, header_data)
        pe.write(filename)

        section_size = AlignUp(len(self.data), pe.OPTIONAL_HEADER.FileAlignment)
        open(filename, 'ab').write(PadString(self.data, section_size))

        return True

    def SetSectionName(self, name):
        nlen = len(name)
        if nlen >= 8:
            raise RuntimeError("Section name can only be 8 bytes long")
        _padded = PadString(name, 8)
        self.header.Name = [ord(_) for _ in _padded]
        return True

    def _update_raw_address(self):
        pe = self.pe
        sec = pe.sections[-1]
        self.header.PointerToRawData = AlignUp(sec.PointerToRawData + sec.SizeOfRawData, pe.OPTIONAL_HEADER.FileAlignment)

    def _update_header_offset(self):
        pe = self.pe
        self.header_offset = SECTION_HEADER_START + (SECTION_HEADER_SIZE * len(pe.sections))

    def _update_virtual_address(self):
        pe = self.pe
        sec = pe.sections[-1]
        self.header.VirtualAddress = AlignUp(sec.VirtualAddress + sec.Misc_VirtualSize, pe.OPTIONAL_HEADER.SectionAlignment)

    def _update_virtual_size(self):
        pe = self.pe
        self.header.VirtualSize = len(self.data)

    def _update_raw_size(self):
        pe = self.pe
        self.header.SizeOfRawData = AlignUp(len(self.data), pe.OPTIONAL_HEADER.FileAlignment)


def main(argv):
    parser = argparse.ArgumentParser(
        description='Utility to add a section to a PE file',)
    parser.add_argument('-i', '--ifilename', required=True,
        dest='ifilename', help='input filename')
    parser.add_argument('-o', '--ofilename', required=True,
        dest='ofilename', help='onput filename')
    parser.add_argument('-s', '--sfilename', required=True,
        dest='sfilename', help='section data filename')
    parser.add_argument('-n', '--name', required=True,
        dest='sname', help='section name')
    parser.add_argument('-t', '--tfilename', required=False, default='',
        dest='tfilename', help='input filename')

    args = parser.parse_args(argv[1:])
    AddSection(
        ifilename=args.ifilename,
        ofilename=args.ofilename,
        sname=args.sname,
        sfilename=args.sfilename
    )


if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
