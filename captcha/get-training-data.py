#!/usr/bin/env python3
from api import *

if __name__ == '__main__':
    i = 0
    while True:
        data = getImages(0)
        correct = submit(0, "watever")
        with open(f"train/{correct}.png", "wb") as f:
            f.write(data[0])
        if i % 10 == 0:
            print(i)
        i += 1
