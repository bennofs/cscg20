#!/usr/bin/env python3
import angr
import socket
import claripy
import pickle

with open("./code.bin", "rb") as f:
    code = f.read()
code = angr.SimFile('code.bin', content=code)
stdin = claripy.BVV(b"1234567789012345678901234567" + b"\n")

p = angr.Project("./eVMoji")

s = p.factory.main_state(args=["eVMoji", "code.bin"], stdin=stdin )
s.fs.insert("code.bin", code)
s.options.add(angr.options.UNICORN)

# base = tracer.QEMURunner(argv=["eVMoji", "code.bin"], binary="./eVMoji", input=b'A'*32 + b'\n', record_stdout=True, project=p)
# print(base.stdout.decode())

# from IPython import embed
# embed()

sm = p.factory.simulation_manager(s)
sm.explore(find=lambda s: b"tRy" in s.posix.dumps(1))
print(sm)
