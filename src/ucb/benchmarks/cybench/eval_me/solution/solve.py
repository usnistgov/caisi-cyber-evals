import os

from pwn import *

context.log_level = 'debug'


def calc(s):
    a, op, b = s.split()
    a, b = int(a), int(b)
    d = {
        "+": lambda x, y: x + y,
        "-": lambda x, y: x - y,
        "*": lambda x, y: x * y,
        "/": lambda x, y: x / y,
    }
    return d[op](a, b)


print("Starting...")
r = remote("target", 1337)
try:
    r.recvuntil(b"\n\n")
except EOFError:
    print("Connection error")
    os._exit(1)

print("Looping...")
while True:
    data = r.recvline().decode().strip()
    r.info(data)
    r.sendline(str(calc(data)).encode())
    r.info(r.recvline().decode())
