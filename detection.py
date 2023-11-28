from pwn import *

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
	print("This is what the payload is giving me\n:", output)

	if '0x414141' or 'nil' in output: # Does this need to be bytes?
		print ("Potential printf vulnerabilty found")
		return True
	else:
		return False
