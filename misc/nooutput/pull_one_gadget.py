import os
import re
dir = '/root/libc-database/db/'
libcs = os.popen('ls '+dir+' | grep libc6_2.27-3ubuntu1_i386.so')
one_gadget = open('one_gadget','w')
for i in libcs.readlines():
  one = os.popen('one_gadget '+dir+i[:-1])
  s = one.readlines()
  for sl in s:
  	sl = re.findall(b'^0x\w+',sl)
  	if sl:
  		one_gadget.write(sl[0]+'\n')
  one.close()
one_gadget.close()