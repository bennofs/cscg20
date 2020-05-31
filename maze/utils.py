#!/usr/bin/env python3

fh = bytes.fromhex

def decode(b):
    b = fh(b)
    k = b[0]
    i = b[1]
    for idx, c in enumerate(b[2:]):
        yield c ^ k
        if k + i > 0x100:
            print(k, i, idx)
        k = k + i + ((k + i) // 0x100)
        k = k & 0xff
