#!/usr/bin/env python3
import angr
import socket

p = angr.Project("./rev2")
sm = p.factory.simulation_manager(p.factory.entry_state())
sm.explore(find=lambda s: b"right" in s.posix.dumps(1))

s = socket.socket()
s.connect(("hax1.allesctf.net", 9601))
print(s.recv(100))
s.send(sm.one_found.posix.dumps(0))
print(s.recv(100))
print(s.recv(100))

# CSCG{1s_th4t_wh4t_they_c4ll_on3way_transf0rmati0n?}
