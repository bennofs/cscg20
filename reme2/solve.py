#!/usr/bin/env python3
import base64
import sys
from Crypto.Cipher import AES
from Crypto.Protocol import KDF

cipher = open("./2nd.bin", "rb").read()

derived = KDF.PBKDF2(open("./key.bin", "rb").read(), bytes([1,2,3,4,5,6,7,8]), 48)
print(len(derived))
key = derived[:32]
iv = derived[32:48]
aes = AES.new(key, AES.MODE_CBC, iv=iv)
sys.stdout.buffer.write(aes.decrypt(cipher))

# CSCG{n0w_u_know_st4t1c_and_dynamic_dotNet_R3333}
