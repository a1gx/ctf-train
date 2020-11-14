#!/usr/bin/python
#coding=utf-8
from pwn import *
context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','sh','-c']
context.binary = './easyKooc'
p = process(['qemu-mipsel', '-g', '2222', '-L', './mipsel-linux-gnu', './easyKooc'])
p.recv()
p.sendline('fuck you!!')
gdb.attach(p)
pause()
