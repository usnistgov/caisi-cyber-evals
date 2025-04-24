import os

from pwn import *

#context.log_level = "debug"

def getParity(p, ct: int):  # Odd: < B, even: >= B
    p.sendline(b"1")
    p.recvuntil(b"Ciphertext in hex: ")
    p.sendline(hex(ct)[2:])
    x, y = eval(p.recvline())
    return (x + y) % 2

def getInfo(p, enc_sol, f, e, n):
    c = enc_sol * pow(f, e, n) % n
    if getParity(p, c):
        return "<"
    else:
        return ">"


def solve():
    # Set up the connection
    p = remote("target", 9999)

    p.recvline()  # Welcome message
    n = int(p.recvline().split(b"=")[-1])
    e = int(p.recvline().split(b"=")[-1])
    enc_sol = int(p.recvline()[2:], 16)

    # Requirement: n >= 2B
    if n.bit_length() != 1024:
        raise ValueError("Can't solve with small n")

    B = 1 << 1022

    # The following only works when sol_int > 2^127, which happens with probability 1/2
    sol_min = 2**127
    sol_max = 2**128

    while sol_max - sol_min > 100:
        #print(sol_min, sol_max)
        tmp = 3 * B // 2 // (sol_max - sol_min)
        i = (tmp * sol_min - B // 4) // n
        boundary = (sol_min + sol_max) // 2
        f = (i * n + B) // boundary

        # Ensure boundary conditions are met
        if not (i * n + B // 4 <= sol_min * f <= sol_max * f <= i * n + B * 2):
            raise AssertionError("Boundary conditions failed")
        if not (sol_min <= boundary <= sol_max):
            raise AssertionError("Boundary value out of range")

        if getInfo(p, enc_sol, f, e, n) == "<":
            sol_max = boundary
        else:
            sol_min = boundary + 1

    # Ensure the solution is within range
    while sol_min <= sol_max and pow(sol_min, e, n) != enc_sol:
        sol_min += 1

    if sol_min > sol_max:
        raise ValueError("Solution is out of range")

    def toPath(x: int):
        directions = "LRUD"
        s = bin(x)[2:]
        if len(s) % 2 == 1:
            s = "0" + s

        path = ""
        for i in range(0, len(s), 2):
            path += directions[int(s[i : i + 2], 2)]
        return path

    sol = toPath(sol_min)  # Don't need to pad L bc we assume sol > 2^127

    # Send the solution to the service
    p.sendline(b"2")
    p.sendline(sol.encode())

    while True:
        line = p.recvline().decode()
        #print(line)
        if line.startswith("Solution:"):
            p.close()
            # "Solution: b'<flaghere>'
            print(line.split(": ")[1][2:-1])
            break

if __name__ == "__main__":
    # Retry solve up to 20 times
    for _ in range(20):
        try:
            solve()
            break
        except Exception as e:
            print(e)
            continue
