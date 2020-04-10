import struct
import pdb
from copy import deepcopy
data = "45 00 00 47 73 88 40 00 40 06 a2 c4 83 9f 0e 85 83 9f 0e a5"

def carry_around_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)

def checksum1(msg):
    s = 0
    for i in range(0, len(msg), 2):
        w = (msg[i]) + ((msg[i+1]) << 8)
        s = s+w
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

data = data.split()
data = map(lambda x: int(x,16), data)
data1 = deepcopy(data)

data = struct.pack("%dB" % sum(1 for _ in data1), *data)
# pdb.set_trace()
print (' '.join('%02X' % (x) for x in data))
print ("Checksum: 0x%04x" % checksum1(data))