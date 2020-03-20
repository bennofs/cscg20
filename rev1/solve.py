#!/usr/bin/env python3
import socket

s = socket.socket()
s.connect(("hax1.allesctf.net", 9600))

print(s.recv(100))
s.send(b"y0u_5h3ll_p455\n")
print(s.recv(100))
print(s.recv(100))

# CSCG{ez_pz_reversing_squ33zy}
