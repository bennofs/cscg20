#!/usr/bin/env python3
import base64
from Crypto.Cipher import AES
from Crypto.Protocol import KDF

cipher = base64.b64decode(open("./enc").read())

derived = KDF.PBKDF2(b"A_Wise_Man_Once_Told_Me_Obfuscation_Is_Useless_Anyway", b'Ivan Medvedev', 48)
print(len(derived))
key = derived[:32]
iv = derived[32:48]
aes = AES.new(key, AES.MODE_CBC, iv=iv)
print(aes.decrypt(cipher).decode("utf-16"))
