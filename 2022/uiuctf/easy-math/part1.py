#! /bin/env python3
from pwn import *
import subprocess
from subprocess import Popen, PIPE, STDOUT
import time

p = process("sshpass -p ctf ssh ctf@easy-math.chal.uiuc.tf", shell=True, stdin=PTY)
print(p.recvline())
p.sendline("ls")
print("ls result:", p.recvline().decode())

p.sendline("./easy-math")

try:
    for i in range(0,10000):
        print(f"Solved: {i+1}")
        p.recvuntil(b": ")
        prob = p.recvuntil(b"=").decode().split(" ")
        print(prob)
        result = str(int(prob[0]) * int(prob[2]))
        print(result)
        p.sendline(result)
except Exception as e:
    print(repr(e))
finally:
    p.interactive()

"""
 Nice job! Now, the question is, did you do it the fun way, or by hiding behind your ssh client?

 Part 1 flag: uiuctf{now do it the fun way :D}

 To solve part 2, use `ssh ctf-part-2@easy-math.chal.uiuc.tf` (password is still ctf)
 This time, your input is sent in live, but you don't get any output until after your shell exits.
"""
