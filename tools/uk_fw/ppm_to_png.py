#!/usr/bin/env python3
"""Convert a binary PPM (P6, 8-bit RGB) to PNG using only the standard library.

Used to turn the guest-side capture (ias-shot writes P6 so no image library is
needed on either side) into a reviewable image on the host.

usage: ppm_to_png.py in.ppm out.png
"""
import struct
import sys
import zlib


def read_ppm(path):
    data = open(path, "rb").read()
    fields = []
    pos = 0
    while len(fields) < 4:
        while pos < len(data) and data[pos:pos + 1].isspace():
            pos += 1
        if data[pos:pos + 1] == b"#":
            while data[pos:pos + 1] not in (b"\n", b""):
                pos += 1
            continue
        start = pos
        while pos < len(data) and not data[pos:pos + 1].isspace():
            pos += 1
        fields.append(data[start:pos])
    if fields[0] != b"P6":
        raise ValueError("not a binary PPM (P6)")
    width, height, maxval = (int(f) for f in fields[1:])
    if maxval != 255:
        raise ValueError("only 8-bit PPM is supported")
    pixels = data[pos + 1:]
    if len(pixels) != width * height * 3:
        raise ValueError(f"pixel data is {len(pixels)} bytes, expected {width * height * 3}")
    return width, height, pixels


def write_png(path, width, height, rgb):
    stride = width * 3
    raw = bytearray()
    for y in range(height):
        raw.append(0)                                   # filter type 0 (None)
        raw += rgb[y * stride:(y + 1) * stride]

    def chunk(tag, payload):
        return (struct.pack(">I", len(payload)) + tag + payload +
                struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF))

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    with open(path, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n")
        f.write(chunk(b"IHDR", ihdr))
        f.write(chunk(b"IDAT", zlib.compress(bytes(raw), 9)))
        f.write(chunk(b"IEND", b""))


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    width, height, pixels = read_ppm(sys.argv[1])
    write_png(sys.argv[2], width, height, pixels)
    print(f"{sys.argv[2]}: {width}x{height} PNG")


if __name__ == "__main__":
    main()
