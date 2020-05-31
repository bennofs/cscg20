#!/usr/bin/env python3
import numpy as np
import shutil
import sys
from imageio import imread, imwrite
import cv2


def load(fname):
    return imread(fname)[:, :, 3]


def segment(img, axis=0, max_threshold=0, min_size=5, max_size=20):
    collapsed = img.sum(axis=axis)
    mask = np.concatenate(([0], collapsed, [0])) <= 255
    seps = np.diff(mask).nonzero()[0]
    for i in range(0, len(seps), 2):
        start, end = seps[i], seps[i+1]
        if end - start > max_size:
            size = end - start
            left = start + (size * 2) // 7
            right = start + (size * 5) // 7
            sub = collapsed[left:right]
            if sub.min() < max_threshold:
                splitpoints = (sub == sub.min()).nonzero()[0]
                if len(splitpoints) != 1:
                    print("weird")
                else:
                    yield start, splitpoints[0] + left
                    yield splitpoints[0] + 1 + left, end
                    continue
            else:
                print("not below max_threshold", sub.min())

        yield seps[i], seps[i+1]

debug_data = np.zeros((1, 500, 3), dtype=np.uint8)
def debug(data, color_axis=None):
    print("debug!")
    if color_axis is not None:
        new_data = np.zeros(data.shape + (3,), dtype=np.uint8)
        new_data[:, :, color_axis] = data
        data = new_data
    global debug_data
    end = debug_data.shape[0]
    pad = np.zeros((data.shape[0] + 1, debug_data.shape[1], 3), dtype=np.uint8)
    debug_data = np.concatenate((debug_data, pad), axis=0)
    debug_data[end, :, 2] = 255
    debug_data[end + 1:end + 1 + data.shape[0], 0:data.shape[1], :] = data
    imwrite(".debug.png", debug_data)
    shutil.copyfile(".debug.png", "debug.png")


def draw_segments(img):
    extended = np.pad(img, (1, 1), constant_values=0)
    out = np.repeat(extended[:, :, np.newaxis], 3, axis=-1)

    for start, end in segment(img, max_threshold=10000):
        out[:, start, 0] = 255
        out[:, end, 1] = 255

    return out


def main(fname):
    img = load(fname)
    ridge_filter = cv2.ximgproc.RidgeDetectionFilter_create()
    img = ridge_filter.getRidgeFilteredImage(img)

    segments = segment(img, max_threshold=10000)
    debug(draw_segments(img))


if __name__ == '__main__':
    for f in sys.argv[1:]:
        main(f)
