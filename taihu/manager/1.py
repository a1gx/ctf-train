#!/usr/bin/python
#coding=utf-8
from pwn import *
context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','sh','-c']
context.binary = './pwn'
p = process('./pwn')
def mean(idx):
	p.sendlineafter('>>>',str(idx))
def add(name,num,size,info):
	mean(1)
	p.sendlineafter(':\n',name)
	p.sendlineafter(':\n',str(num))
	p.sendlineafter(':\n',str(size))
	p.sendafter(':\n',info)
def edit(num,choice,payload):
	mean(2)
	p.sendlineafter(':\n',str(num))
	p.sendlineafter('> ',str(choice))
	p.sendlineafter(':\n',payload)
def remove(idx):
	p.sendlineafter(':\n',str(idx))
def show(idx):
	p.sendlineafter(':\n',str(idx))

