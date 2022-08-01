#! /bin/env python3
from pwn import *
import subprocess
from subprocess import Popen, PIPE, STDOUT
import time

p = process("sshpass -p ctf ssh ctf-part-2@easy-math.chal.uiuc.tf", shell=True, stdin=PTY)
#p = process("sshpass -p 6d49a6fb ssh ctf-part-3@easy-math.chal.uiuc.tf", shell=True, stdin=PTY)

time.sleep(2)
p.sendline(b"""exec python3 -c \"import os
from subprocess import Popen, PIPE
from time import sleep
os.mkfifo(\\"/tmp/fifo\\")
fd = os.open(\\"/tmp/fifo\\", os.O_RDWR)
r, w = os.pipe()
os.dup2(fd,0)
p = Popen(\\"/home/ctf/easy-math\\", stdout=w)
def recvuntil(fd, data):
    global p
    interm = b\\"\\"
    while True:
        b = os.read(fd, 1)
        interm += (b)
        if data in interm:
            break
    return interm
try:
    for i in range(0,10000):
        print(f\\"Solved: {i+1}\\")
        print(recvuntil(r, b\\": \\"))
        prob = recvuntil(r, b\\"=\\").decode().split(\\" \\")
        print(prob)
        result = str(int(prob[0]) * int(prob[2]))
        print(result)
        os.write(fd, result.encode() + b\\"\\n\\")
except Exception as e:
    print(repr(e))

print(recvuntil(r, b\\"}\\"))\"
""")
p.interactive()

