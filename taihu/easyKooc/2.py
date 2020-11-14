#!/usr/bin/python
#coding=utf-8
from pwn import *
context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','sh','-c']
context.binary = './easyKooc'
p = process('qemu-mipsel -L ./mipsel-linux-gnu ./easyKooc',shell=True)
print context.word_size
