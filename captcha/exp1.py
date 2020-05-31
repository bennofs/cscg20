#!/usr/bin/env python3
import numpy as np
import sys
from hashlib import sha256
from imageio import imread, imwrite

def segment(i, axis=0, threshold=0):
    collapsed = i.sum(axis=axis)
    return np.diff(np.concatenate(([0], collapsed, [0])) <= threshold).nonzero()[0]


def main(inpfile):
    print(inpfile)
    i = imread(inpfile)[:,:,3]
    h, w = i.shape

    s = segment(i, threshold=500)


    out = np.repeat(np.pad(i, (h+1,w+1),constant_values=0)[:,:,np.newaxis], 3, axis=-1)
    out[:,s,0] = 255;

    for idx, (xs, xe) in enumerate(zip(s[::2], s[1::2])):
        seg = i[:,xs:xe+1]
        seglines = segment(seg, axis=1)
        if len(seglines) < 2:
            print("weird", inpfile)
            continue
        start, end = seglines[0], seglines[-1]
        out[start,xs:xe+1,1] = 255
        if end < h:
            out[end,xs:xe+1,1] = 255
        a = i[start:end,xs:xe+1]
        key = sha256(a.data.tobytes()).hexdigest()[:16]
        imwrite(f"single/{key}.png", a)

    imwrite(f"out/{inpfile}", out)


if __name__ == '__main__':
    for f in sys.argv[1:]:
        main(f)
