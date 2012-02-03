import struct
from collections import OrderedDict


f = open('setup_tyrian_2000.exe')

f.seek(1458540) # SetupLdrOffsetTableID byte offset - need to figure out how to find it

keys = ['ID', 'Version', 'TotalSize', 'OffsetEXE', 'UncompressedSizeEXE', 'CRCEXE', 'Offset0', 'Offset1', 'TableCRC']
values = struct.unpack('<12s8L', f.read(44))
TSetupLdrOffsetTable = OrderedDict(zip(keys, values))

import pprint
pprint.pprint(TSetupLdrOffsetTable.items())