import struct

size = struct.calcsize('i 4s f')
print("Size in bytes: {}".format(size))