#!/usr/bin/env python3
import requests
import base64
import os
import numpy as np
import time

from imageio import imread
from lxml import html

s = requests.Session()


def getImages(stage):
    doc = html.fromstring(s.get(f"http://hax1.allesctf.net:9200/captcha/{stage}").text)
    return [base64.b64decode(src[len("data:image/png;base64,"):]) for src in doc.xpath("//img/@src")]


def submit(stage, solutions):
    r = s.post(
        f"http://hax1.allesctf.net:9200/captcha/{stage}",
        data={str(idx): solution for idx, solution in enumerate(solutions)},
        allow_redirects=False,
    )
    r.raise_for_status()
    redirect = r.headers["Location"]
    if "fail" in redirect:
        if "=" in redirect:
            return redirect.split("=")[1]
        else:
            return None
    else:
        return int(stage) + 1


def reshape(img):
    out = np.zeros((32, 32))
    start0 = (out.shape[0] - img.shape[0]) // 2
    start1 = (out.shape[1] - img.shape[1]) // 2
    out[start0:start0+img.shape[0], start1:start1+img.shape[1]] = img
    return out


def loadClassified(d):
    out = {}
    for cls in os.listdir(d):
        for img in os.listdir(f"{d}/{cls}/"):
            out.setdefault(cls, [])
            x = imread(f"{d}/{cls}/{img}")
            i = reshape(x)
            out[cls] += [i]
    return out


def segment(img, axis=0, min_size=5, max_size=20):
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
            splitpoint = sub.argmin()

            yield start, splitpoint + left
            yield splitpoint + 1 + left, end
        else:
            yield seps[i], seps[i+1]


def segment_vertical(img):
    sums = img.sum(axis=1)
    is_data = (sums >= 10).nonzero()[0]
    if len(is_data) < 2:
        return 0, img.shape[0]
    top = is_data[0]
    bottom = is_data[-1]
    return top, bottom


def dist(a, b):
    diff = (a-b).flatten()
    return np.dot(diff,diff)


def solve_captcha(captcha, classified, preindex):
    image = imread(captcha)[...,3]
    solution = ""
    pieces = []
    for startX, endX in segment(image):
        startY, endY = segment_vertical(image[:, startX:endX])
        single = reshape(image[startY:endY, startX:endX])
        score_preindex = {}
        for cls, imgs in preindex.items():
            d = min(dist(img, single) for img in imgs)
            score_preindex[cls] = d
        bestk = list(sorted(classified.keys(), key=lambda cls: score_preindex[cls]))
        best = (None, float("inf"))
        for cls in bestk:
            d = min(dist(img, single) for img in classified[cls])
            if d < best[1]:
                best = (cls, d)
            if d == 0:
                break
        #pieces += [(single, best[1])]
        solution += best[0]
    return solution, pieces


if __name__ == '__main__':
    classified = loadClassified("train_single")
    preindex = { cls: [np.mean(np.stack(imgs), axis=0)] for cls, imgs in classified.items() }
    stage = 0
    while True:
        print("stage", stage)
        captcha = getImages(stage)
        if stage == 4:
            print("done!")
            with open("flag.png", "wb") as f:
                f.write(captcha[0])
                break
        print("solving", len(captcha))
        t = time.time()
        solutions = [solve_captcha(c, classified, preindex)[0] for c in captcha]
        e = time.time()
        print("time", e - t)
        stage = submit(stage, solutions)
        if not isinstance(stage, int):
            print("failed")
            stage = 0

# CSCG{Y0UR_B0T_S0LV3D_THE_CAPTCHA}
