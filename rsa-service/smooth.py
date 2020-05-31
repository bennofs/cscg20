#!/usr/bin/env python3
from sage.all import *
from Crypto.PublicKey import RSA

message = b"Quack! Quack!"
question_to_ask = b"Hello! Can you give me the flag, please? I would really appreciate it!"
base = int.from_bytes(message, "big")
target = int.from_bytes(question_to_ask, "big")

def topem(p, q, e, d):
    p = int(p)
    q = int(q)
    e = int(e)
    d = int(d)
    return RSA.construct((p*q, e, d)).exportKey().decode()

def random_smooth(lbound, smoothness):
    r = 2
    while r <= lbound:
        r *= random_prime(smoothness)
    return r

def construct_prime(smoothness):
    while True:
        p = random_smooth(int(sqrt(target)) + 1, smoothness) + 1
        if is_prime(p):
            return p

def solve(p1, p2):
    N = p1 * p2
    assert N > target

    G = Integers(N)
    order = (p1 - 1) * (p2 - 1)
    d = pari.znlog(G(target), G(base), factor(p1-1)*factor(p2-1))
    if not d:
        return "no dlog"
    if d % 2 == 0:
        return "not odd"

    e = pow(d, -1, (p1-1)*(p2-1))
    print(topem(p1, p2, e, d))

smoothness = 10**6
while True:
    p = construct_prime(smoothness)
    q = construct_prime(smoothness)
    err = solve(p, q)
    if not err:
        break
    print(err)
