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
        os.remove(p.corefile.file.name)
        return detect_overflow(e, p)  # ret2vurp
    return "not an overflow"


def detect_overflow(elf_proc, proc_):
    try:
        if elf_proc.sym['win']:  # win symbol check
            try:
                if next(elf_proc.search(b'Replace it with a new item >>>')):
                    print("[+] Win AND array abuse detected")
                    proc_.kill()
                    return 'arrayAbuse'
            except StopIteration:
                print('[!] Array Abuse not detected')
            print("[+] Win Found ret2win detected :)")
            proc_.kill()
            return 'ret2win or rop parameters'  # can change depending on how we wanna return things
    except KeyError:
        print("[!] Win function not found")

    try:
        if elf_proc.sym['system']:  # ret2win check
            print("[+] Win Found ret2system detected :)")
            proc_.kill()
            return 'ret2system'  # can change depending on how we wanna return things
    except KeyError:
        print("[!] system function not found")
    try:
        if elf_proc.sym['execve']:
            print('[+] Execve symbol found')
            proc_.kill()
            return 'ret2execve'
    except:
        print('[+] Execve symbol not found')
    try:
        if next(elf_proc.search(b'<<< Leak: %p\n')):
            print('[+] Leak detected ret2one')
            proc_.kill()
            return 'ret2one'
    except:
        print('[!] Ret2one not detected')

    try:
        if next(elf_proc.search(b'<<< CPUs %u .\n')):
            print('[+] ret2syscall detected')
            proc_.kill()
            return 'ret2syscall'
    except:
        print('[!] ret2syscall not found')

    proc_.kill()  # keep with final return
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
