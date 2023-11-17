from pwn import *
import os

def find_rip_offset(binary: str):
    p = process(binary)
    p.sendline(cyclic(1024, n=8))
    p.wait()
    core = p.corefile
    p.close()
    os.remove(core.file.name)
    return cyclic_find(core.read(core.rsp, 8), n=8)
