from pwn import *

context.update(
    arch="amd64",
    endian="little",
    log_level="warning",
    os="linux",
    # terminal=["tmux", "split-window", "-h", "-p 65"]
    terminal=["st"]
)


def scan(binary):
    e = ELF(f"./{binary}")
    p = process(f"./{binary}")
    # r = ROP(e)

    # -- overflow time --#
    p.sendline(cyclic(3000))
    p.wait()

    if p.poll() and p.poll() < 0:  # maybe change to -11 in the future
        return detect_overflow(e, p)  # ret2vurp in the future
    p.interactive()


def detect_overflow(elf_proc, proc_):
    try:
        if elf_proc.sym['win']:  # ret2win check
            proc_.kill()
            return 'ret2win'
    except KeyError:
        print("win funciton not found")
        pass
    return "Overflow Not Found"

# detecting overflow types soontm
