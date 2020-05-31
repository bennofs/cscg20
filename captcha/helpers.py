#!/usr/bin/env python3
import numpy as np
import shutil
from hashlib import sha256
from imageio import imwrite


debug_data = np.zeros((1, 500, 3), dtype=np.uint8)
def debug(msg, data, color_axis=None):
    global debug_data
    print(f"!! debug {msg}")

    if color_axis is not None:
        new_data = np.zeros(data.shape + (3,), dtype=np.uint8)
        new_data[:, :, color_axis] = data
        data = new_data

    if len(data.shape) == 2:
        data = np.repeat(data[...,np.newaxis], 3, axis=-1)

    end = debug_data.shape[0]
    pad = np.zeros((data.shape[0] + 1, debug_data.shape[1], 3), dtype=np.uint8)
    debug_data = np.concatenate((debug_data, pad), axis=0)
    debug_data[end, :, 2] = 255
    debug_data[end + 1:end + 1 + data.shape[0], 0:data.shape[1], :] = data

    imwrite(".debug.png", debug_data)
    shutil.copyfile(".debug.png", "debug.png")


def imgid(img):
    return sha256(img.data.tobytes()).hexdigest()[:16]
