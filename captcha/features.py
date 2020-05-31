#!/usr/bin/env python3
import numpy as np
from skimage import filters, io, measure, feature

from helpers import *

def shape_context_for_point(image, loc):
    """Computes the shape context for a location (row,col) in the given image
    """
    row, col = loc

    nz_rows, nz_cols = image.nonzero()
    dist = np.log((nz_rows - row)**2 + (nz_cols - col)**2 + 1)
    angle = np.arctan2(nz_rows, nz_cols)

    # discretize
    dist = (dist * 4).astype(np.uint8)
    angle = (angle * 3).astype(np.uint8)

    out = np.zeros((angle.max() + 1, dist.max() + 1))
    for a,d in zip(angle, dist):
        out[a][d] += 1

    return out

if __name__ == '__main__':
    import sys
    import seaborn as sns
    from matplotlib import pyplot as plt
    img = io.imread(sys.argv[1])

    img = filters.sobel(img)
    out = np.repeat(img[...,np.newaxis], 3, axis=-1)
    #plt.imshow(img)
    #plt.show()
    debug("img", out)
