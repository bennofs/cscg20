#!/usr/bin/env python3
import os
from imageio import imread, imwrite

import cluster
import helpers


def segment_vertical(img):
    sums = img.sum(axis=1)
    threshold = 10
    is_data = (sums >= threshold).nonzero()[0]
    if len(is_data) < 2:
        return 0, img.shape[0]
    top = is_data[0]
    bottom = is_data[-1]
    return top, bottom


def make_single_images(image):
    for startX, endX in cluster.segment(image, max_threshold=10000):
        startY, endY = segment_vertical(image[:, startX:endX])
        yield image[startY:endY, startX:endX]


correct = 0
wrong = 0
for fname in os.listdir("train"):
    text = fname[:-len(".png")]
    image = imread(f"train/{fname}")[...,3]
    singles = list(make_single_images(image))
    if len(text) == len(singles):
        for char, single in zip(text, singles):
            d = f"train_single/{char}"
            os.makedirs(d, exist_ok=True)
            imwrite(d + "/" + helpers.imgid(single) + ".png", single)
        correct = correct + 1
    else:
        imwrite(f"bad/{fname}", image)
        wrong = wrong + 1
    print(correct, wrong)
