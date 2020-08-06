'''
Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
'''
import json
import argparse
import base64
import struct
import logging
import os
from addsection import AddSection
from pydnet import PyDNet


SECTION_FILENAME = 'section.bin'


def LoadMethods(jsfile):
    result = dict()
    with open(jsfile, 'rb') as _jsfile:
        js = json.loads(_jsfile.read())
    for m in js:
        result[m.get('nToken')] = m
    logging.info("Loaded %d methods from JSON file", len(js))
    return result


def WriteSectionData(js, fname):
    logging.info("Writing to section data file: %s", fname)
    nsize = 0
    with open(fname, 'wb') as ofile:
        for nToken, minfo in js.items():
            offset = ofile.tell()
            hdr = base64.b64decode(minfo.get('sHeader'))
            body = base64.b64decode(minfo.get('sBody'))
            ofile.write(hdr)
            ofile.write(body)
            minfo.update({'offset': offset})
        nsize = ofile.tell()
    logging.info("Section file size: %s (%d)", hex(nsize), nsize)
    return True


def PatchDWORD(bytez, offset, value):
    newbytes = [ord(_) for _ in struct.pack("<I", value)]
    bytez[offset + 0] = newbytes[0]
    bytez[offset + 1] = newbytes[1]
    bytez[offset + 2] = newbytes[2]
    bytez[offset + 3] = newbytes[3]


def FixMethodsInfo(filename, newmethods, section_rva):
    logging.info("Using section virtual address: %s", hex(section_rva))
    with open(filename, 'rb') as _ifile:
        bytez = [ord(_) for _ in _ifile.read()]
    pdn = PyDNet(filename, debug=False)
    pdn.Parse()
    pdn.Close()

    for md in pdn.Methods:
        new_method_info = newmethods.get(md.nToken, None)
        if new_method_info is None:
            continue
        newRVA = new_method_info.get('offset') + section_rva
        logging.debug(
            "Method %s: old RVA: %s, new RVA: %s",
            hex(md.nToken), hex(md.RVA), hex(newRVA))
        PatchDWORD(bytez, md.nOffset, newRVA)
    open(filename, 'wb').write(''.join([chr(_) for _ in bytez]))


def main(argv):
    desc = 'Utility to fix a .NET assembly after dumping MSIL at run time'
    parser = argparse.ArgumentParser(
        description=desc,)
    parser.add_argument(
        '-f', '--filename', required=True,
        dest='filename', help='target assembly')
    parser.add_argument(
        '-o', '--ofilename', required=True,
        dest='ofilename', help='output filename')
    parser.add_argument(
        '-j', '--jsonfile', required=True,
        dest='jsonfile', help='json file')
    parser.add_argument(
        '-s', '--section-filename', default=SECTION_FILENAME,
        dest='sfilename', help='temp section data file')
    parser.add_argument(
        '-v', '--verbose', default=False, action='store_true',
        dest='verbose', help='verbose')
    args = parser.parse_args(argv[1:])

    fmt = "%(name)s %(levelname)-10s %(funcName)20s : %(message)s"
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format=fmt)
    else:
        logging.basicConfig(level=logging.INFO, format=fmt)

    methods = LoadMethods(args.jsonfile)
    WriteSectionData(methods, args.sfilename)
    va, _base = AddSection(
        args.filename, args.ofilename, 'FLARE', args.sfilename)
    logging.info("New section VA: %s, file offset: %s", hex(va), hex(_base))
    logging.info("Removing temporary section file: %s", args.sfilename)
    os.remove(args.sfilename)
    FixMethodsInfo(args.ofilename, methods, va)
    print("DONE")
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
