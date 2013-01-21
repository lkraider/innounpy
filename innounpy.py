#!/usr/bin/env python

import os
import pefile
import pylzma
import struct
from pprint import pprint
from utils import cached_property

try:
    import simplejson as json
except:
    import json
try:
    from collections import OrderedDict
except:
    from ordereddict import OrderedDict


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
        return struct_for_TSetupID(self.TSetupID)

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
        TSetupHeader = self.struct_constants['TSetupHeader']

        # size of hash digests
        hash_sizes = {
            'TMD5Digest': 16,
            'TSHA1Digest': 20,
        }
        p = TSetupHeader['fields']['PasswordHash']
        p['size'] = hash_sizes.get(p['type'])

        # read setup-0 data
        with self.setup_0_data as f:
            reading = True
            for name, field in TSetupHeader['fields'].iteritems():
                # skip LeadBytes
                if name == "LeadBytes":
                    f.seek(field['size'], os.SEEK_CUR)
                    continue
                # skip everything from MinVersion onwards
                if name == "MinVersion":
                    reading = False
                if reading:
                    field['value'] = self._read_field(f, field)
                else:
                    f.seek(field['size'], os.SEEK_CUR)
            TSetupHeader['EndOffset'] = TSetupHeader['size'] = f.tell()
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
    def _read_field(self, fileobj, field):
        if 'string' in field['type']:
            return self._read_string(fileobj, field['size'])
        if 'integer' in field['type']:
            return self._read_integer(fileobj, field['size'])

    def _read_string(self, fileobj, string_size=(4,1)):
        """
        Read string from fileobj's current position.
        `string_size` - tuple of string header size and single char size
        """
        f = fileobj
        assert(string_size[0] == 4)
        string_length = struct.unpack('<l', f.read(4))[0]
        if self.debug and string_length > 512:
            # skip long data strings in debug mode
            value = 'BIGSTRING OFFSET:%s LENGTH:%s' % (f.tell(), string_length)
            f.seek(string_length, os.SEEK_CUR)
        else:
            value = f.read(string_length)
        return value

    def _read_integer(self, fileobj, size):
        s = 'q' if size == 8 else 'l'
        return struct.unpack('<%s' % s, fileobj.read(size))[0]


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


# Helper Struct loader functions

def struct_for_TSetupID(TSetupID):
    version = TSetupID.partition('(')[-1].rpartition(')')[0].replace(') (', '')
    return struct_for_version(version)


def struct_for_version(version):
    major, minor, release = map(int, version.replace('u', '').split('.'))
    is_unicode = 'u' if version[-1] == 'u' else ''
    version = '%d%d%02d%s' % (major, minor, release, is_unicode)
    filepath = 'structs/Struct%s.json' % version
    if not os.path.isfile(filepath):
        raise IOError('File not found: %s' % filepath)
    data = json.load(open(filepath), object_pairs_hook=OrderedDict)
    return data['Struct%s' % version]


if __name__ == '__main__':
    unpacker = InnoUnpacker('setup_tyrian_2000.exe', debug=True)
    unpacker.run()
