import pefile
import pylzma
import struct
from collections import OrderedDict
from pprint import pprint

# magic numbers
SetupLdrOffsetTableResID = 11111
SetupIDSize = 64
Setup0LZMAOffset = 13

# configurable
filename = 'setup_tyrian_2000.exe'

# parse executable resources to find TSetupLdrOffsetTable offset
pe = pefile.PE(filename, fast_load=True)
pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])

rt_rcdata_index = [entry.id for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE['RT_RCDATA'])
rt_rcdata_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_rcdata_index]
resource = [entry for entry in rt_rcdata_directory.directory.entries if entry.id == SetupLdrOffsetTableResID][0]
resource = resource.directory.entries[0]

data_rva = resource.data.struct.OffsetToData
size = resource.data.struct.Size
TSetupLdrOffsetTableData = pe.get_memory_mapped_image()[data_rva:data_rva+size]
pe.close()

# extract TSetupLdrOffsetTable fields
keys = ['ID', 'Version', 'TotalSize', 'OffsetEXE', 'UncompressedSizeEXE', 'CRCEXE', 'Offset0', 'Offset1', 'TableCRC']
values = struct.unpack('<12s8L', TSetupLdrOffsetTableData)
TSetupLdrOffsetTable = OrderedDict(zip(keys, values))

print('TSetupLdrOffsetTable:')
pprint(TSetupLdrOffsetTable.items())

# read SetupHeader from setup-0.bin
f = open(filename)
f.seek(TSetupLdrOffsetTable['Offset0'])

TSetupID = f.read(SetupIDSize)
print 'TSetupID:', TSetupID

# dump setup-0.bin
f.seek(TSetupLdrOffsetTable['Offset0'] + SetupIDSize)
o = open('setup-0.bin', 'wb')
buffer_size = 1024
data = f.read(buffer_size)
while data:
    o.write(data)
    data = f.read(buffer_size)

# decompress setup-0.bin data
f.seek(TSetupLdrOffsetTable['Offset0'] + SetupIDSize + Setup0LZMAOffset)
decompress = pylzma.decompressobj()
o = open('setup-0.unpacked', 'wb')
data = f.read(1)
while data:
    o.write(decompress.decompress(data, 1))
    data = f.read(1)
o.write(decompress.flush())
