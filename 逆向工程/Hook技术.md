<!-- TOC -->

- [1. Hook分类](#1-hook分类)
    - [1.1. 按照挂钩对象分类](#11-按照挂钩对象分类)
    - [1.2. 按照挂钩数量分类](#12-按照挂钩数量分类)
- [2. Ring3层Hook](#2-ring3层hook)
    - [2.1. 系统消息Hook](#21-系统消息hook)
    - [2.2. lpk Hook](#22-lpk-hook)
    - [2.3. Inline Hook（API Hook）](#23-inline-hookapi-hook)
        - [2.3.1. 步骤](#231-步骤)
        - [2.3.2. 多线程环境](#232-多线程环境)
        - [2.3.3. 其它事项](#233-其它事项)
    - [2.4. IAT Hook](#24-iat-hook)
    - [2.5. EAT Hook](#25-eat-hook)
    - [2.6. SEH Hook](#26-seh-hook)
    - [2.7. VEH Hook](#27-veh-hook)
    - [2.8. VirtualFunctionHook](#28-virtualfunctionhook)
    - [2.9. 实现全局Hook](#29-实现全局hook)
- [3. Ring0层Hook](#3-ring0层hook)
    - [3.1. IRP Hook](#31-irp-hook)
    - [3.2. MSR Hook](#32-msr-hook)
    - [3.3. SSDT Hook](#33-ssdt-hook)
        - [3.3.1. 步骤](#331-步骤)
    - [3.4. 优缺点](#34-优缺点)
    - [3.5. Object Hook](#35-object-hook)
    - [3.6. 修改页属性为可写的两种方法](#36-修改页属性为可写的两种方法)
        - [3.6.1. 通过页表基址修改页属性](#361-通过页表基址修改页属性)
        - [3.6.2. 修改CR0寄存器关闭页保护](#362-修改cr0寄存器关闭页保护)
- [4. Hook检测](#4-hook检测)
- [5. Hook注意事项](#5-hook注意事项)
    - [5.1. Hook库](#51-hook库)
    - [5.2. _declspec(naked)](#52-_declspecnaked)

<!-- /TOC -->
# 1. Hook分类
## 1.1. 按照挂钩对象分类
* 本地钩子：挂钩本进程。
* 远程钩子：挂钩其他进程。
    * 上层钩子：钩子位于对方进程。
    * 底层钩子：钩子位于安装钩子的进程，涉及到跨进程通信。
## 1.2. 按照挂钩数量分类
* 只挂钩一个进程
* 挂钩多个进程
* 挂钩全部进程（对于新创建的进程也要进行挂钩）
# 2. Ring3层Hook
## 2.1. 系统消息Hook
通过微软官方提供的API进行消息Hook，进行系统消息Hook时，可以通过向目标进程发送消息的方法来强制目标进程触发挂钩
* SetWindowsHookEx
* UnhookWindowsHookEx
* CallNextHookEx
## 2.2. lpk Hook
利用Windows提供的未公开函数InitializeLpkHooks可以HOOK位于Windows中lpk.dll（用于支持多语言包功能）的4个函数LpkTabbedTextOut，LpkPSMTextOut，LpkDrawTextEx，LpkEditControl。
```vb
Private Sub Form_Load() 
    DLLhwnd = LoadLibrary("lpk.dll") '加载 DLL 
    DLLFunDre = GetProcAddress(DLLhwnd, "LpkDrawTextEx") '获取回调函数地址

    LpkHooksInfo.lpHookProc_LpkTabbedTextOut = 0 
    LpkHooksInfo.lpHookProc_LpkPSMTextOut = 0 
    LpkHooksInfo.lpHookProc_LpkDrawTextEx = GetLocalProcAdress(AddressOf HookProc1) '设置要 HOOK 的 LPK 函数
    LpkHooksInfo.lpHookProc_LpkEditControl = 0 
    InitializeLpkHooks LpkHooksInfo 
End Sub 
Private Sub Form_Unload(Cancel As Integer) 
    LpkHooksInfo.lpHookProc_LpkTabbedTextOut = 0 
    LpkHooksInfo.lpHookProc_LpkPSMTextOut = 0 
    LpkHooksInfo.lpHookProc_LpkDrawTextEx = DLLFunDre 
    LpkHooksInfo.lpHookProc_LpkEditControl = 0 
    InitializeLpkHooks LpkHooksInfo 
    FreeLibrary DLLhwnd 
End Sub 
```
然后新建一个模块，在模块中加入以下代码
```vb
Public Declare Function LoadLibrary Lib "kernel32" Alias "LoadLibraryA" (ByVal lpLibFileName As String) As Long 
Public Declare Function GetProcAddress Lib "kernel32" (ByVal hModule As Long, ByVal lpProcName As String) As Long 
Public Declare Function FreeLibrary Lib "kernel32" (ByVal hLibModule As Long) As Long
Public Declare Sub InitializeLpkHooks Lib "user32" (lpProcType As Any) 

Type LpkHooksSetting 
    lpHookProc_LpkTabbedTextOut As Long 
    lpHookProc_LpkPSMTextOut As Long 
    lpHookProc_LpkDrawTextEx As Long 
    lpHookProc_LpkEditControl As Long 
End Type 

Public DLLhwnd As Long, DLLFunDre As Long 
Public LpkHooksInfo As LpkHooksSetting 

Public Function GetLocalProcAdress(ByVal lpProc As Long) As Long 
    GetLocalProcAdress = lpProc 
End Function 

Function HookProc1(ByVal a1 As Long, ByVal a2 As Long, ByVal a3 As Long, ByVal a4 As Long, ByVal a5 As Long, ByVal a6 As Long, ByVal a7 As Long, ByVal a8 As Long, ByVal a9 As Long, ByVal a10 As Long) As Long 
    HookProc1 = 0 
End Function 
```
运行发现窗体中标题栏和按钮上的文字都没有了，因为函数LpkDrawTextEx已经被替换成函数HookProc1了。函数LpkDrawTextEx有10个参数，其中几个是字符串指针，可以用来截获窗体要显示的文字，然后改成另一种语言的文字。
## 2.3. Inline Hook（API Hook）
Inline Hook也可用于零环
### 2.3.1. 步骤
* 选择Hook点
    * 避开全局变量以防重定向问题
    * 根据业务来决定Hook位置，过滤参数 OR 修改返回结果
    * JMP、CALL指令：Code = 跳转地址 - 补丁地址 - 5，至少需要五个字节
* 修改页面属性为可写
* 保存现场以备脱钩
* 改写代码，重定向到Hook业务代码
    * Hook业务代码要保存寄存器环境，退出前恢复环境
    * Hook业务代码最后需要执行JMP、CALL指令被覆盖的代码，然后跳转回原代码（或者选择脱钩、调用、再挂钩）
### 2.3.2. 多线程环境
在多线程的情况下，频繁进行挂钩与脱钩操作可能会出现异常导致崩溃，解决方法如下（参见MHook库）
* 使用原子操作：InterlockedExchange64
* 先上信号量或者互斥锁
* 先挂起其它线程并保证线程的IP指针不位于替换区域
* 七字节Hook：一般来说，库函数第一行指令为`mov edi,edi`，且上方会存在五字节的空白字段，这七个字节微软设计用于热补丁。可以将第一行指令修改为跳转到五字节，五字节修改为跳转到我们的Hook函数
### 2.3.3. 其它事项
* 对于不同的CPU，替换的汇编代码有所区别
* 多核情况下的挂钩安全
* 绕过Inline Hook检测
## 2.4. IAT Hook
替换导入表中的函数地址来获取控制权。
## 2.5. EAT Hook
替换导出表中的函数地址来获取控制权。
## 2.6. SEH Hook
安装一个顶层SEH函数，并在函数开头插入触发异常代码，以此获取控制权。
## 2.7. VEH Hook
插入一个优先VEH函数，并在函数开头插入触发异常代码，以此获取控制权。
## 2.8. VirtualFunctionHook
替换C++虚函数表中的函数指针来获取控制权。
## 2.9. 实现全局Hook
挂钩NtResumeThread函数，对于所有新创建的进程都进行挂钩操作。但是NtResumeThread并不是创建进程才调用，所以需要先枚举系统进程一次，将系统进程中NtResumeThread都挂钩上，这样，之后每次触发钩子时先判断NtResumeThread是否已经被挂钩，如果没有则是创建新进程的调用。
# 3. Ring0层Hook
## 3.1. IRP Hook

## 3.2. MSR Hook
也称为SYSENTER-HOOK或者KiFastCallEntry-Hook，它通过修改SYSENTER_EIP_MSR寄存器，使其指向我们自己的函数，那么我们就可以在自己的的函数中对所有来自3环的函数调用进行第一手过滤。
## 3.3. SSDT Hook
编写驱动加载至内核空间，将驱动中的我们自己的函数地址替换到SSDT中，应用层调用API后，最后会拐到我们自己的函数中，达到Hook的目的。
### 3.3.1. 步骤
* 找到系统服务表中的函数地址表：定义一下系统服务表的结构体，然后通过extern关键词导入内核文件导出的KeServiceDescriptorTable变量，即可获取系统服务表中的函数地址表（KeServiceDescriptorTableShadow未导出，需要用一些非公开的方法来定位此地址，通常都是采用硬性编码的，没有系统适应性）
* 通过全局变量保存原来的系统服务表中的函数地址，用于日后脱钩
* 编写准备用于替换的函数：参数需要保持一致，在替换函数中，需要完成本来函数的功能（将原函数地址转换为带参数的函数指针类型并根据参数调用）
* 修改页属性为可写并修改系统服务表中的函数地址为替换函数的地址
* 驱动卸载前脱钩（可选）
## 3.4. 优缺点
* 优点
    * 简单
    * 稳定
* 缺点
    * 容易被检测到，被绕过
    * 只能HOOK存在于SSDT中的函数
    * 在64位的系统下基本无法工作，除非你能跨过微软的安全防护，目前还没有人破解WIN8.1
## 3.5. Object Hook

## 3.6. 修改页属性为可写的两种方法
### 3.6.1. 通过页表基址修改页属性
```c
if(RCR4 & 0x00000020)
{
    //说明是2-9-9-12分页
    KdPrint(("2-9-9-12分页 %p\n", RCR4));
    KdPrint(("PTE1 %p\n", *(DWORD*)(0xC0000000 + ((HookFunAddr >> 9) & 0x007FFFF8))));
    *(DWORD64*)(0xC0000000 + ((HookFunAddr >> 9) & 0x007FFFF8)) |= 0x02;
    KdPrint(("PTE1 %p\n", *(DWORD*)(OxC0000000 + ((HookFunAddr >> 9) & 0X007FFFF8))));
}
else
{
    //说明是10-10-12分页
    KdPrint(("10-10-12分页"));
    KdPrint(("PTE1 %p\n", *(DWORD*)(OxC0000000 + ((HookFunAddr >> 10) & 0x003FFFFC))));
    *(DWORD*)(OxC0000000 + ((HookFunAddr >>10 ) & 0x003FFFFC)) |= 0x02;
    KdPrint(("PTE2 %p\n", *(DWORD*)(OxC0000000 + ((HookFunAddr >> 10) & 0x003FFFFC))));
}
```
### 3.6.2. 修改CR0寄存器关闭页保护
该方法比较简单，但是在多核环境中存在隐患，如果在HOOK的过程中发生CPU核心切换，会导致CR0切换。
```c
VOID PageProtectOn()
{
    _asm{
        mov eax,cr0
        or eax,10000h
        mov cr0,eax
        sti
    }
}
VOID PageProtectOff()
{
    _asm{
        cli
        mov eax,cr0
        and eax,not 10000h
        mov cr0,eax
    }
}
```
# 4. Hook检测
* HOOK修改的是内存中的数据，本地文件却没有修改。可以将本地文件加载到内存中，然后进行对比。
* 对内存模块进行CRC校验。
* 设置回调函数，检测某个IAT或者函数的前几个指令是否被修改。
* 对VirtualProtect函数和WriteProcess函数进行HOOK，检测修改内容的合法性。
* 利用PsSetCreateProcessNotifyRoutineEx注册回调函数，监控进程创建，对比特定的进程，如果创建，设置创建标志为假，创建失败。
* 利用PsSetCreateThreadNotifyRoutine注册回调函数，监控线程创建，通过进程路径.找到对应进程名.判断是否符合，如果是的话.找到回调函数地址( pWin32Address = (UCHAR**)((UCHAR)Thread + 0x410);)并改为C3。
* 利用PsSetLoadImageNotifyRoutine拦截模块，首先需要获取模块基地址(让其载入)，PE寻找基地址，解析到OEP，修改oep为ret即可。
# 5. Hook注意事项
## 5.1. Hook库
* EasyHook，支持Ring0（不够稳定）和Ring3，该库对多线程未进行处理
* Mhook，只支持Ring3
## 5.2. _declspec(naked)
就是告诉编译器，在编译的时候，不要优化代码，不要添加额外代码来控制堆栈平衡，一切代码都需要自己来写，防止破坏被Hook函数的堆栈或者导致堆栈不平衡。
```c
#define NAKED __declspec(naked)
void NAKED code(void)
{
    __asm{
        ret
    }
}
```
