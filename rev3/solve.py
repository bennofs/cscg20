#!/usr/bin/env python3
import angr
import socket

p = angr.Project("./rev3")
sm = p.factory.simulation_manager(p.factory.entry_state())
sm.explore(find=lambda s: b"right" in s.posix.dumps(1))

s = socket.socket()
s.connect(("hax1.allesctf.net", 9602))
print(s.recv(100))
s.send(sm.one_found.posix.dumps(0))
print(s.recv(100))
print(s.recv(100))

# CSCG{pass_1_g3ts_a_x0r_p4ss_2_g3ts_a_x0r_EVERYBODY_GETS_A_X0R}
