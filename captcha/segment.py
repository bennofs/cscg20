#!/usr/bin/env python3
import numpy as np
from skimage import filtes, io
from matplotlib import pyplot as plt

from helpers import *

def simple_horizontal(image, threshold=500):
    """
    Computes a simple horizontal segmentation of the input captcha
    by splitting at black vertical "bars"
    """
    is_data = image.sum(axis=0) > threshold
    edges = np.diff(np.concatenate(([False], is_data))).nonzero()
    dims = image.shape

    start_edge = 0
    while start_edge < len(edges):
        if start_edge + 1 >= len(edges):
            debug("missing end edge", image)
            break


        start = edges[start_edge]
        if start
        end =
    last_end = 0
    while last_end < dims[1]:
        start = is_data[last_end:].nonzero()
        if bars[start]
    pass

if __name__ == '__main__':
    pass
