from pwn import *
import os

context.update(
    arch="amd64",
    endian="little",
    log_level="warning",
    os="linux",
    terminal=["st"]
)

def scan(binary):
	e = ELF(f"./{binary}")
	p = process(f"./{binary}")

	return detect_printf(e, p)

def detect_printf(bin, proc):

	# Payload for printf searching
	pointers = b"%p" * 10 # Prints the address, or pointer of the arguement that it is given
	input = b'AAAAAAAA'
	payload = pointers + input

	proc.sendline(payload)
	output = proc.recvall().decode('utf-8')
	#print("This is what the payload is giving me\n:", output) - Testing

	if '0x414141' or 'nil' in output: # Does this need to be bytes?
		print ("Printf vulnerabilty found")
		return True
	else:
		return False
  
def find_rip_offset(binary: str):
    p = process(binary)
    p.sendline(cyclic(1024, n=8))
    p.wait()
    core = p.corefile
    p.close()
    os.remove(core.file.name)
    return cyclic_find(core.read(core.rsp, 8), n=8)
