from pwn import *
import os

# level data is stored in the text segment, dump it
p = process("objcopy -O binary --only-section=.data game game.data", shell=True)
p.wait()

fd = os.open("./game.data", os.O_RDONLY)

# get past some junk at the start of the section
os.read(fd, 20)

while True:
    # levels are 100 characters long, print out with newlines for readability
    data = os.read(fd, 100)
    print(data + b"\n")
    if len(data) == 0:
        break

# clean up
os.close(fd)