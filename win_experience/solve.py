#!/usr/bin/env python3
from hashlib import md5

with open("words") as f:
    for w in f.read().split():
        w = w.replace(".", "")
        w = w.replace(",", "")
        for x in [w.lower(), w.title()]:
            print(x[::-1])
            print(md5(x[::-1].encode()).hexdigest().upper())
