#!/usr/bin/env python3
from sage.all import *
from itertools import chain, combinations, takewhile
from functools import reduce
import operator
import math
from Crypto.PublicKey import RSA

message = b"Quack! Quack!"
question_to_ask = b"Hello! Can you give me the flag, please? I would really appreciate it!"
base = int.from_bytes(message, "big")
target = int.from_bytes(question_to_ask, "big")


product = lambda x: reduce(operator.mul, x, 1)


def topem(p, q, e, d):
    p = int(p)
    q = int(q)
    e = int(e)
    d = int(d)
    u = pow(q, -1, p)
    data = [
        0,
        p*q,
        e,
        d,
        p,
        q,
        d % (p-1),
        d % (q-1),
        u
    ]
    binary_key = DerSequence(data).encode()
    key_type = 'RSA PRIVATE KEY'
    return PEM.encode(binary_key, key_type, None, None)

def powerset(iterable):
    "powerset([1,2,3]) --> () (1,) (2,) (3,) (1,2) (1,3) (2,3) (1,2,3)"
    s = list(iterable)
    return chain.from_iterable(combinations(s, r) for r in range(len(s)+1))

def brute(start, factorset):
    i = 0
    for f in powerset(factorset):
        i += 1
        if i % 100000 == 0:
            print(i)
        if is_prime(start * product(f) + 1):
            print("found", start, f)
            return list(f)

    print("not found")

# compute two primes p1 and p2 such that p1-1 and p2-1 are smooth numbers
ps = iter(Primes())
brute_factors = list(takewhile(lambda x: x < 1000000, ps))
factors_p1 = []
while product(factors_p1) <= target:
    factors_p1 += [next(ps)]
factors_p2 = []
while product(factors_p2) <= target:
    factors_p2 += [next(ps)]

def smooth_primes(e2, e3, lim):
    a = pow(2, e2) * pow(3, e3)
    for _ in range(e2, lim):
        a *= 2
        a2 = a
        for _ in range(e3, lim):
            a2 *= 3
            if is_prime(a + 1):
                yield a

def solve(p1, p2):
    N = p1 * p2
    assert N > target

    G = Integers(N)
    order = (p1 - 1) * (p2 - 1)
    d = pari.znlog(G(target), G(base), factor(p1-1)*factor(p2-1))
    assert d, "dlog must exist"
    assert d % 2 == 1, "d must be odd"

    e = pow(d, -1, (p1-1)*(p2-1))
    print(topem(p1, p2, e, d))

# # solve dlog (this is possible because the order of our group is smooth)
# # we need to explictly give the factorization of the group order

# # compute RSA key
