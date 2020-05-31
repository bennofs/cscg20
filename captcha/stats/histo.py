#!/usr/bin/env python3
import numpy as np
import sys
from imageio import imread, imwrite

def main(fname):
    img = imread(fname)
    print(img.sum())


if __name__ == '__main__':
    for i in sys.argv[1:]:
        main(i)
