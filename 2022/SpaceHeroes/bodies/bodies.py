from pwn import *
import time

context.encoding = 'latin-1'
context.log_level = 'debug'

stats_dict = {"qr": "QR= ", "rms": "RMS= ", "angmon": "ANGMOM= ", "epoch": "EPOCH= ", "l": "L= "}

p = remote("0.cloud.chals.io", 24054)

nasa = process(["telnet", "horizons.jpl.nasa.gov", "6775"])
for i in range(5):
	p.recvuntil("Enter the <")
	stat = p.recvuntil(">")[:-1].decode()
	stat = stats_dict[stat]
	print(stat)
	
	p.recvuntil("for ")
	body = p.recvuntil(" ")[:-1].decode()
	print(body)

	nasa.recvuntil("Horizons>")
	nasa.sendline(f"Name= {body}") 
	nasa.recvuntil("? ] :")
	nasa.sendline()

	nasa.recvuntil(stat)
	val = nasa.recvuntil(" ").replace(b'\r', b'').replace(b'\n', b'')
	print(val)
	
	p.sendline(val)
	p.recvuntil("Correct")
	nasa.sendline()
	time.sleep(1)
nasa.kill()
print(p.recvall())
