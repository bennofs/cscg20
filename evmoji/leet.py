#!/usr/bin/env python3
import fileinput


pairs = {}
for a,b in [('i', '1'), ('a', '4'), ('o', '0'), ('e', '3'), ('s', '5'), ('b', '8'), ('g', '9')]:
    pairs[a] = b


def process(l):
    if not l:
        yield ""
        return
    if l[0] not in pairs:
        yield from ((l[0] + x) for x in process(l[1:]))
        return
    t = pairs[l[0]]
    for c in process(l[1:]):
        yield t+c
        yield l[0]+c

if __name__ == '__main__':
    for l in fileinput.input():
        l = l.strip()
        for p in process(l):
            print("n3w_ag3_v1rtu4liz4t1on_" + p)
