import re
s = '0x212121 saas'
print re.findall('^0x\w+',s)