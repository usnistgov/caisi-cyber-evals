#!/usr/bin/env python3

from pwn import *

#context.log_level='debug'

K1 = b"bdd0c04b5c3995827482773b12acab35bdd0c04b5c3995827482773b12acab35"
K2 = b"652fa0565c3946be7482773b12acab35652fa0565c3946be7482773b12acab35"

def main():
    # Adjust these to match the actual remote endpoint
    HOST = "target"
    PORT = 9999

    # Connect to remote service
    r = remote(HOST, PORT)

    # 1) Send "2" to select the option to add a key
    r.recvuntil(b"API option:\n")
    r.sendline(b"2")

    r.recvuntil(b"in hex\n")

    # 2) Send the key
    r.sendline(K1)
    r.recvuntil(b"added successfully to DB\n")

    # 3) Send "3" to query a key
    r.recvuntil(b"API option:\n")
    r.sendline(b"3")

    # 4) Send the key to retrieve the flag
    r.recvuntil(b"in hex\n")
    r.sendline(K2)

    # 5) Read all data from the remote and decode
    data = r.recvline()

    # Trim leading b' and trailing '
    print(data.decode().strip()[2:-1])

if __name__ == "__main__":
    main()

