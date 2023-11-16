from pwn import *

context.update(
    arch="amd64",
    endian="little",
    log_level="warning",
    os="linux",
    #terminal=["tmux", "split-window", "-h", "-p 65"]
    terminal=["st"]
)

def scan(binary):
    e = ELF(f"./{binary}")
    p = process(f"./{binary}")
    #r = ROP(e)

    #-- overflow time --#
    p.sendline(cyclic(3000))
    p.wait()

    if p.poll() and p.poll() < 0:
        detect_overflow()
    p.interactive()





def detect_overflow():
    print('Overflowed')
#detecting overflow types soontm