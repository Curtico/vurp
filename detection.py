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

	# Does this binary even have a printf function
	# Maybe i could use the binary.disas() function to search, in case the symbol table is stripped?
	# Super basic start here
	if bin.sym['printf']:
		print('potential for printf vuln')

		# Setting up payloads for various types of printf vulns, I need to research these more.
		payload_p = b"%p" * 10 # Prints the address, or pointer of the arguement that it is given
		payload_d = b"%d" * 10 # Prints the value as a decimal number, might leak data from the stack
		payload_x = b"%x" * 10 # same as payload_d, but shows as a hexadecimal number
		payload_s = b"%s" * 10 # Reads a string from the stack until it encounters a null byte. Might be used to leak something cool from the stack.
		payload_n = b"%n" * 10 # This one I don't understand well, writes the current number of characters? I think it helps in arbitrary writes?
		payload_c = b"%c" * 10 # Prints the char of the arguement, could be used to leak a single byte, or help with a single write

		proc.sendline(payload_p)
		output = proc.recvall().decode('utf-8')
		print("This is what the payload is giving me\n:", output)

		# Write some checks here to check if the output gave you something weird.

	else:
		return 'no printf functions found' # Is this even something that can happen?
