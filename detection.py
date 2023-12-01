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
    e = ELF(f"{binary}")
    p = process(f"{binary}")
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
            print("[+] Win Found ret2win detected :)")
            proc_.kill()
            return 'ret2win'  # can change depending on how we wanna return things
    except KeyError:
        print("[!] Win function not found")
        pass

    try:
        if elf_proc.sym['system']:  # ret2win check
            print("[+] Win Found ret2system detected :)")
            proc_.kill()
            return 'ret2system'  # can change depending on how we wanna return things
    except KeyError:
        print("[!] system function not found")
        pass
    proc_.kill() # keep with final return
    return "Overflow Not Found :("  # in theory this should not happen

# detecting overflow types soontm


def find_rip_offset(binary: str):
    p = process(binary)
    p.sendline(cyclic(1024, n=8))
    p.wait()
    core = p.corefile
    p.close()
    os.remove(core.file.name)
    return cyclic_find(core.read(core.rsp, 8), n=8)
