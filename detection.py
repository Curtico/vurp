from pwn import *


def scan(binary):
    e = ELF(f"./{binary}")
    p = process(f"./{binary}")
    #r = ROP(e)

    #-- overflow time --#
    p.sendline(cyclic(1000))
    p.interactive()






def detect_overflow():
    pass
#detecting overflow types soontm