#!/usr/bin/env python3
from sage.all import *
from itertools import chain, combinations, takewhile
from functools import reduce
import operator
import math
from Crypto.PublicKey import RSA
from Crypto.Util.asn1 import DerSequence
from Crypto.IO import PEM

message = b"Quack! Quack!"
question_to_ask = b"Hello! Can you give me the flag, please? I would really appreciate it!"

gcd = math.gcd
lcm = lambda a,b: a*b / gcd(a,b)
product = lambda x: reduce(operator.mul, x, 1)

base = int.from_bytes(message, "big")
target = int.from_bytes(question_to_ask, "big")

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
    print(data)
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

# p = random_prime(int(sqrt(target)+10000), lbound=int(sqrt(target)))
p = 1033086403525638195235964915333916884809477467206304885651969970234655081694832084799
q = 1033086403525638195235964915333916884809477467206304885651969970234655081694832086197
#q += 4

e = 3
d = pow(e, -1, (p-1)*(q-1))
print(topem(p,q,e,d))
