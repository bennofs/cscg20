#!/usr/bin/env python3
import operator
import string
from functools import reduce

prefix = b'CSCG{'
suffix = b'}'
data = b'6W6?BHW,#BB/FK[?VN@u2e>m8'


def linear_decomp(trans, unknown):
    decomp = { cipher: [cipher] for cipher in trans }
    for u in unknown:
        decomp[u] = [u]
    todo = set(decomp.keys())
    while todo:
        x = todo.pop()
        for cipher in list(decomp):
            cipherNew = cipher ^ x
            if cipherNew not in decomp:
                todo.add(cipherNew)
                decomp[cipherNew] = decomp[cipher] + decomp[x]
    return decomp

def make_trans():
    trans = {}
    for cipher, plain in zip(data, prefix):
        trans[cipher] = plain
    for cipher, plain in zip(data[::-1], suffix[::-1]):
        trans[cipher] = plain
    return trans

def complete_trans(t, extra, decomp):
    complete = dict(t)
    complete.update(extra)
    for b, d in decomp.items():
        if b in complete:
            continue
        complete[b] = reduce(operator.xor, (complete[x] for x in d), 0)
    return complete

def detrans(t, data):
    return bytes(t[d] for d in data)

trans = make_trans()
unknown = []
while True:
    decomp = linear_decomp(trans, unknown)
    try:
        unknown += [next(x for x in data if x not in decomp)]
    except StopIteration:
        break

assert len(unknown) == 2

for k1 in range(256):
    for k2 in range(256):
        t = complete_trans(trans, {unknown[0]: k1, unknown[1]: k2}, decomp)
        x = detrans(t, data)
        if all(v in string.printable.encode() for v in x):
            print(x)
