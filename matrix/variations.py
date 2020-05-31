#!/usr/bin/env python3
import string

payload = b"6W6?BHW,#BB/FK[?VN@u2e>m8"
#           CSCG{1S_TH1S_FLAG_REAL? }
needle = b"CSCG{1S_}"
needlepay = payload[:8] + payload[-1:]

# first try: hex
def dhex(x):
    for v in x:
        print(f"{v:02x}", end=" ")
    print("")

# maybe bits?
def dbin(x):
    for v in x:
        print(f"{v:08b}", end=" ")
    print("")

# add octal and dec for fun
def doct(x):
    for v in x:
        print(f"{v:03o}", end=" ")
    print("")

def ddec(x):
    for v in x:
        print(f"{v:03}", end=" ")
    print("")


dhex(needlepay)
dhex(needle)
print("")
ddec(needlepay)
ddec(needle)
print("")
dbin(needlepay)
dbin(needle)
