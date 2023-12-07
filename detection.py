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
    try:
        if p.poll() and p.poll() < 0:  # maybe change to -11 in the future
            os.remove(p.corefile.file.name)
            return detect_overflow(e, p, binary)  # ret2vurp
    except:
        print('[!] Probably not an overflow')

    e = ELF(f"{binary}")
    p = process(f"{binary}")

    try:
        if detect_printf(e, p):
            return 'printf'
    except:
        print('[!] Probably not an printf')

    return "unknown"


def detect_overflow(elf_proc, proc_, binary):
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
            try:
                if next(elf_proc.search(b'/bin/sh')):
                    print('[+] bin/sh ret2system')
                    proc_.kill()
                    return 'ret2system'
            except:
                print('[!] Not a bin.sh ret2system')
            try:
                if next(elf_proc.search(b'/bin/cat flag.txt')):
                    print("[+] cat flag.txt ret2system")
                    proc_.kill()
                    return 'ret2system'
            except:
                print('[!] Not a bin/cat flag.txt ret2system')
            proc_.kill()
            return 'write gadget'  # can change depending on how we wanna return things
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

    e = ELF(f"{binary}")
    p = process(f"{binary}")
    #
    if detect_printf(e, p):
        proc_.kill()
        return 'printf'
    proc_.kill()  # keep with final return
    return "Overflow Not Found :("  # in theory this should not happen


# detecting overflow types soontm

def detect_printf(bin, proc):
    # Payload for printf searching
    pointers = b"%p" * 5  # Prints the address, or pointer of the arguement that it is given
    #print(pointers)
    proc.sendline(pointers)
    output = proc.recvuntil(b'0x', timeout=1)
    # print("This is what the payload is giving me\n:", output) - Testing
    if b'0x' in output:  # Does this need to be bytes?
        #print(output)
        proc.kill()
        return True
    else:
        proc.kill()
        return False


def find_rip_offset(binary: str):
    p = process(binary)
    p.sendline(cyclic(1024, n=8))
    p.wait()
    core = p.corefile
    p.close()
    os.remove(core.file.name)
    return cyclic_find(core.read(core.rsp, 8), n=8)
