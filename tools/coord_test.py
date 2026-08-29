import struct

# Bytes: 71 50 3B C3 DD E6 59 C2 86 2D 6D C3 DC 0A 3E 40
b = bytes.fromhex("71 50 3B C3 DD E6 59 C2 86 2D 6D C3 DC 0A 3E 40")
x, y, z, w = struct.unpack('<ffff', b)
print(f"Coordinates at +0x00 of 0x6F2C6BE0: X={x:.3f}, Y={y:.3f}, Z={z:.3f}, W={w:.3f}")

# Next bytes: FE 61 FD 35 FD 41 FD 48 EF AF F7 B0 68 C9 F9 77
# Next bytes: 00 00 00 00 00 00 00 00 BE 4F C3 47 01 00 00 01 C1 7A B0 00 00 00 00 00 00 00 00 00 00 00 00 00
