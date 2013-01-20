#!/usr/bin/env python

import os
import pefile
import pylzma
import struct
from pprint import pprint
from functools import wraps

try:
    from collections import OrderedDict
except:
    from ordereddict import OrderedDict

import definitions


def cached_property(func, name=None):
    """
    cached_property(func, name=None) -> a descriptor
    This decorator implements an object's property which is computed
    the first time it is accessed, and which value is then stored in
    the object's __dict__ for later use. If the attribute is deleted,
    the value will be recomputed the next time it is accessed.
    Usage:
        class X(object):
            @cachedProperty
            def foo(self):
                return computation()
    """
    if name is None:
        name = func.__name__

    @wraps(func)
    def _get(self):
        try:
            value = self.__dict__[name]
        except KeyError:
            value = func(self)
            self.__dict__[name] = value
        return value

    def _del(self):
        self.__dict__.pop(name, None)

    return property(_get, None, _del)


class InnoUnpacker(object):

    def __init__(self, filename, debug=False):
        """Initialize the Inno Setup Unpacker with the executable file to unpack"""
        self.filename = filename
        self.debug = debug
        # table sizes
        self.SetupIDSize = 64
        self.CRCCompressedBlockHeaderSize = 9
        # output files
        self.setup_0_filename = 'setup-0.unpacked'

    @cached_property
    def struct_constants(self):
        """Dictionary of parsed data from matching version Struct.pas file"""
        version = self.TSetupID.split('(')[-1].split(')')[0]
        parser = definitions.parser_for_version(version)
        return dict(parser)

    @cached_property
    def TSetupLdrOffsetTable(self):
        """Table that contains the setup-0 and setup-1 compressed data offsets inside the binary"""
        # resource id magic number
        SetupLdrOffsetTableResID = 11111

        # parse executable resources to find TSetupLdrOffsetTable structure offset
        pe = pefile.PE(self.filename, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])

        rt_rcdata_type = pefile.RESOURCE_TYPE['RT_RCDATA']
        rt_rcdata_directory = [entry for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries if entry.id == rt_rcdata_type][0]
        resource = [entry for entry in rt_rcdata_directory.directory.entries if entry.id == SetupLdrOffsetTableResID][0]
        resource = resource.directory.entries[0]

        data_rva = resource.data.struct.OffsetToData
        size = resource.data.struct.Size
        TSetupLdrOffsetTableData = pe.get_memory_mapped_image()[data_rva:data_rva+size]
        pe.close()

        # extract TSetupLdrOffsetTable fields
        keys = ['ID', 'Version', 'TotalSize', 'OffsetEXE', 'UncompressedSizeEXE', 'CRCEXE', 'Offset0', 'Offset1', 'TableCRC']
        values = struct.unpack('<12s8L', TSetupLdrOffsetTableData)
        return OrderedDict(zip(keys, values))

    @cached_property
    def TSetupID(self):
        """String of the Inno Setup version used to generate the installer"""
        # read SetupHeader from setup-0.bin
        with open(self.filename) as f:
            f.seek(self.TSetupLdrOffsetTable['Offset0'])
            TSetupID = f.read(self.SetupIDSize)
        return TSetupID

    @cached_property
    def TCompressedBlockHeader(self):
        """Table that cointains the size of the compressed data"""
        # extract Compress HdrCRC + TCompressedBlockHeader
        with open(self.filename) as f:
            f.seek(self.TSetupLdrOffsetTable['Offset0'] + self.SetupIDSize)
            CRCCompressedBlockHeaderData = f.read(self.CRCCompressedBlockHeaderSize)

        keys = ['HdrCRC', 'StoredSize', 'Compressed']
        values = struct.unpack('<lL?', CRCCompressedBlockHeaderData)
        return OrderedDict(zip(keys, values))

    @cached_property
    def setup_0_extracted(self):
        """Decompress setup-0 data to disk"""
        # decompress setup-0.bin data
        DecompressBuffer = 4096
        DecompressCRCSize = 4

        f = open(self.filename, 'rb')
        f.seek(self.TSetupLdrOffsetTable['Offset0'] + self.SetupIDSize + self.CRCCompressedBlockHeaderSize)

        decompress = pylzma.decompressobj()
        with open(self.setup_0_filename, 'wb') as o:
            read_count = 0
            while read_count < self.TCompressedBlockHeader['StoredSize']:
                crc = f.read(DecompressCRCSize)
                data = f.read(DecompressBuffer)
                #assert(zlib.crc32(data) == struct.unpack('<l', crc)[0])
                o.write(decompress.decompress(data, DecompressBuffer))
                read_count += len(crc) + len(data)
            o.write(decompress.flush())

        f.close()
        return True

    @property
    def setup_0_data(self):
        """File object to the uncompressed setup-0 data"""
        if self.setup_0_extracted:
            return open(self.setup_0_filename, 'rb')

    @cached_property
    def TSetupHeader(self):
        """Table from setup-0 that packs Inno Setup installer options"""
        TSetupHeader = OrderedDict()
        LeadBytesSize = 32
        TSetupVersionDataSize = 10
        TMD5DigestSize = 16
        TSetupSaltSize = 8
        # Set size is calculated as such:
        # (Max div 8) - (Min div 8) + 1
        # Min is usually 0, and Max the number of elements
        OptionsSetSize = (len(self.struct_constants['TSetupHeaderOption']) / 8) + 1

        # read setup-0 data
        with self.setup_0_data as f:
            # read variable length strings
            keys = self.struct_constants['TSetupHeader_StringsList']
            values = self._read_strings(f, keys)
            TSetupHeader.update(zip(keys, values))

            # skip LeadBytes
            f.seek(LeadBytesSize, os.SEEK_CUR)

            # read packed integers
            keys = self.struct_constants['TSetupHeader_IntegersList']
            values = []
            for i in range(len(keys)):
                value = struct.unpack('<l', f.read(4))[0]
                values.append(value)
            TSetupHeader.update(zip(keys, values))

            # skip MinVersion, OnlyBelowVersion
            f.seek(TSetupVersionDataSize * 2, os.SEEK_CUR)
            # skip BackColor, BackColor2, WizardImageBackColor
            f.seek(4 * 3, os.SEEK_CUR)
            # skip PasswordHash, PasswordSalt
            f.seek(TMD5DigestSize + TSetupSaltSize, os.SEEK_CUR)
            # skip ExtraDiskSpaceRequired, SlicesPerDisk
            f.seek(8 + 4, os.SEEK_CUR)

            # skip sets UninstallLogMode, DirExistsWarning, PrivilegesRequired
            f.seek(3 * 1, os.SEEK_CUR)
            # skip sets ShowLanguageDialog, LanguageDetectionMethod, CompressMethod
            f.seek(3 * 1, os.SEEK_CUR)
            # skip sets ArchitecturesAllowed, ArchitecturesInstallIn64BitMode
            f.seek(2 * 1, os.SEEK_CUR)

            # skip SignedUninstallerOrigSize, SignedUninstallerHdrChecksum
            f.seek(2 * 4, os.SEEK_CUR)
            # skip Options Set
            f.seek(OptionsSetSize, os.SEEK_CUR)

            # store end of TSetupHeader location as its size and offset
            TSetupHeader['EndOffset'] = TSetupHeader['Size'] = f.tell()

        return TSetupHeader

    @cached_property
    def SetupLanguageEntries(self):
        """List of language entries"""
        SetupLanguageEntries = OrderedDict()

        with self.setup_0_data as f:
            f.seek(self.TSetupHeader['Size'])

            # read all language entries
            for i in range(self.TSetupHeader['NumLanguageEntries']):
                TSetupLanguageEntry = OrderedDict()
                TSetupLanguageEntry['Start'] = f.tell()

                # read variable length strings
                keys = self.struct_constants['TSetupLanguageEntry_StringsList']
                values = self._read_strings(f, keys)
                TSetupLanguageEntry.update(zip(keys, values))

                # skip integer values and boolean
                f.seek(6 * 4 + 1, os.SEEK_CUR)

                TSetupLanguageEntry['Size'] = f.tell() - TSetupLanguageEntry['Start']
                # store TSetupLanguageEntry indexed by language name
                SetupLanguageEntries[TSetupLanguageEntry['Name']] = TSetupLanguageEntry

            SetupLanguageEntries['EndOffset'] = f.tell()
            SetupLanguageEntries['Size'] = SetupLanguageEntries['EndOffset'] - self.TSetupHeader['Size']
        return SetupLanguageEntries

    @cached_property
    def CustomMessagesEntries(self):
        """List of custom messages"""
        CustomMessagesEntries = OrderedDict()

        with self.setup_0_data as f:
            f.seek(self.SetupLanguageEntries['EndOffset'])

            for i in range(self.TSetupHeader['NumCustomMessageEntries']):
                TSetupCustomMessageEntry = OrderedDict()
                TSetupCustomMessageEntry['Start'] = f.tell()

                keys = self.struct_constants['TSetupCustomMessageEntry_StringsList']
                values = self._read_strings(f, keys)
                TSetupCustomMessageEntry.update(zip(keys, values))

                TSetupCustomMessageEntry['LangIndex'] = struct.unpack('<l', f.read(4))[0]

                TSetupCustomMessageEntry['Size'] = f.tell() - TSetupCustomMessageEntry['Start']
                CustomMessagesEntries[TSetupCustomMessageEntry['Name']] = TSetupCustomMessageEntry

            CustomMessagesEntries['EndOffset'] = f.tell()
            CustomMessagesEntries['Size'] = CustomMessagesEntries['EndOffset'] - self.SetupLanguageEntries['EndOffset']
        return CustomMessagesEntries

    def run(self):
        print('TSetupID: %s' % self.TSetupID)
        print('TSetupLdrOffsetTable:')
        pprint(self.TSetupLdrOffsetTable.items())
        if self.debug:
            self._dump_setup_0()
        print('TCompressedBlockHeader:')
        pprint(self.TCompressedBlockHeader.items())
        print('TSetupHeader:')
        pprint(self.TSetupHeader.items())
        print('SetupLanguageEntries:')
        pprint(self.SetupLanguageEntries.items())
        print('CustomMessagesEntries:')
        pprint(self.CustomMessagesEntries.items())

    # Helper functions
    def _read_strings(self, fileobj, keys):
        """Read len(keys) number of strings from fileobj's current position"""
        f = fileobj
        values = []
        for i in range(len(keys)):
            string_length = struct.unpack('<l', f.read(4))[0]
            if self.debug and string_length > 512:
                # skip long data strings in debug mode
                value = 'BIGSTRING OFFSET:%s LENGTH:%s' % (f.tell(), string_length)
                f.seek(string_length, os.SEEK_CUR)
            else:
                value = f.read(string_length)
            values.append(value)
        return values

    # Debug functions
    def _dump_setup_0(self, output='setup-0.bin'):
        """Dump compressed setup-0 data to disk"""
        f = open(self.filename, 'rb')
        f.seek(self.TSetupLdrOffsetTable['Offset0'])
        with open(output, 'wb') as o:
            buffer_size = 1024
            data = f.read(buffer_size)
            while data:
                o.write(data)
                data = f.read(buffer_size)
        f.close()


if __name__ == '__main__':
    unpacker = InnoUnpacker('setup_tyrian_2000.exe', debug=True)
    unpacker.run()
