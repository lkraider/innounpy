import pefile
import struct
from collections import OrderedDict
from pprint import pprint

# magic numbers
SetupLdrOffsetTableResID = 11111

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

