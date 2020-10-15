<!-- TOC -->

- [1. DOS头](#1-dos头)
- [2. PE头](#2-pe头)
    - [2.1. IMAGE_FILE_HEADER](#21-image_file_header)
        - [2.1.1. Machine](#211-machine)
        - [2.1.2. Characteristics](#212-characteristics)
    - [2.2. IMAGE_OPTIONAL_HEADER32](#22-image_optional_header32)
    - [2.3. Subsystem](#23-subsystem)
    - [2.4. IMAGE_DATA_DIRECTORY](#24-image_data_directory)
- [3. 节表](#3-节表)
    - [3.1. 结构体](#31-结构体)
    - [3.2. 节属性](#32-节属性)
- [4. 导入表](#4-导入表)
    - [4.1. IMAGE_THUNK_DATA](#41-image_thunk_data)
        - [4.1.1. _IMAGE_IMPORT_BY_NAME](#411-_image_import_by_name)
- [5. 导出表](#5-导出表)
- [6. 重定位表](#6-重定位表)
- [7. 资源](#7-资源)

<!-- /TOC -->
# 1. DOS头
```
IMAGE_DOS_HEADER STRUCT 
  +00h WORD e_magic      // Magic DOS signature MZ(4Dh 5Ah)   DOS可执行文件标记，恒定为4D 5A（MZ），IMAGE_DOS_SIGNATURE
  +02h WORD e_cblp       // Bytes on last page of file  
  +04h WORD e_cp         // Pages in file
  +06h WORD e_crlc       // Relocations
  +08h WORD e_cparhdr    // Size of header in paragraphs
  +0ah WORD e_minalloc   // Minimun extra paragraphs needs
  +0ch WORD e_maxalloc   // Maximun extra paragraphs needs
  +0eh WORD e_ss         // intial(relative)SS value   DOS代码的初始化堆栈SS 
  +10h WORD e_sp         // intial SP value   DOS代码的初始化堆栈指针SP 
  +12h WORD e_csum       // Checksum 
  +14h WORD e_ip         // intial IP value   DOS代码的初始化指令入口[指针IP] 
  +16h WORD e_cs         // intial(relative)CS value   DOS代码的初始堆栈入口 CS
  +18h WORD e_lfarlc     // File Address of relocation table 
  +1ah WORD e_ovno       // Overlay number
  +1ch WORD e_res[4]     // Reserved words 
  +24h WORD e_oemid      // OEM identifier(for e_oeminfo) 
  +26h WORD e_oeminfo    // OEM information;e_oemid specific  
  +29h WORD e_res2[10]   // Reserved words 
  +3ch LONG e_lfanew     // Offset to start of PE header   指向PE文件头 
IMAGE_DOS_HEADER ENDS
```
# 2. PE头
```
IMAGE_NT_HEADERS STRUCT 
  +00h DWORD Signature                            // PE文件标识，恒定为50 45 00 00（PE）
  +04h IMAGE_FILE_HEADER FileHeader               // 标准PE头
  +18h IMAGE_OPTIONAL_HEADER32 OptionalHeader     // 拓展PE头
IMAGE_NT_HEADERS ENDS
```
## 2.1. IMAGE_FILE_HEADER
```
IMAGE_FILE_HEADER STRUCT
  +04h WORD  Machine;               // 运行平台
  +06h WORD  NumberOfSections;      // 文件的区块数目，区块表紧跟在IMAGE_NT_HEADERS后边
  +08h DWORD TimeDateStamp;         // 文件创建日期和时间，采用1970/01/01以来的格林威治时间（GMT）计算的秒数
  +0Ch DWORD PointerToSymbolTable;  // COFF符号表（用于调试）的文件偏移位置，现在基本没用了
  +10h DWORD NumberOfSymbols;       // COFF符号表中的符号数目，COFF符号是一个大小固定的结构，如果想找到COFF 符号表的结束位置，则需要这个变量
  +14h WORD  SizeOfOptionalHeader;  // IMAGE_OPTIONAL_HEADER32结构大小，对于32位PE文件，这个值通常是00E0h；对于64位PE32+文件，这个值是00F0h
  +16h WORD  Characteristics;       // 文件属性
IMAGE_FILE_HEADER ENDS
```
### 2.1.1. Machine
```
0x0000                            // 任意平台
0x014C IMAGE_FILE_MACHINE_I386    // x86
0x0200 IMAGE_FILE_MACHINE_IA64    // Intel Itanium
0x8664 IMAGE_FILE_MACHINE_AMD64   // x64
```
更多定义参见Windows.inc文件。
### 2.1.2. Characteristics
与运算获取。
```
0x0001 IMAGE_FILE_RELOCS_STRIPPED     // 禁止重定位，必须从指定基地址加载，若地址被占用，则报错
0x0002 IMAGE_FILE_EXECUTABLE_IMAGE    // 文件可执行
0x0004 IMAGE_FILE_LINE_NUMS_STRIPPED  // 不存在行信息
0x0008 IMAGE_FILE_LOCAL_SYMS_STRIPPED // 不存在符号信息
0x0010 IMAGE_FILE_AGGRESIVE_WS_TRIM   // 调整工作集
0x0020 IMAGE_FILE_LARGE_ADDRESS_AWARE // 应用程序可以处理大于2GB的地址
0x0080 IMAGE_FILE_BYTES_REVERSED_LO   // 小尾方式
0x0100 IMAGE_FILE_32BIT_MACHINE       // 只在32位平台运行
0x0200 IMAGE_FILE_DEBUG_STRIPPED      // 不包含调试信息
0x0400 IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP // 不能从可移动盘运行
0x0800 IMAGE_FILE_NET_RUN_FROM_SWAP       // 不能从网络运行
0x1000 IMAGE_FILE_SYSTEM                  // 系统文件
0x2000 IMAGE_FILE_DLL                 // DLL文件
0x4000 IMAGE_FILE_UP_SYSTEM_ONLY      // 不能在多处理器计算机上运行
0x8000 IMAGE_FILE_BYTES_REVERSED_HI   // 大尾方式
```
## 2.2. IMAGE_OPTIONAL_HEADER32
以下偏移以IMAGE_NT_HEADERS为基准。
```
IMAGE_OPTIONAL_HEADER32 STRUCT
  +18h WORD   Magic;                  // 标志字, ROM 映像（0107h）,PE32（010Bh），PE32+（020Bh）
  +1Ah BYTE   MajorLinkerVersion;     // 链接程序的主版本号
  +1Bh BYTE   MinorLinkerVersion;     // 链接程序的次版本号
  +1Ch DWORD SizeOfCode;              // 所有含代码的节的总大小 文件对齐后大小 编译器填写 无用
  +20h DWORD SizeOfInitializedData;   // 所有含已初始化数据的节的总大小 文件对齐后大小 编译器填写 无用
  +24h DWORD SizeOfUninitializedData; // 所有含未初始化数据的节的大小 文件对齐后大小 编译器填写 无用
  +28h DWORD AddressOfEntryPoint;     // 程序执行入口RVA
  +2Ch DWORD BaseOfCode;              // 代码的区块的起始RVA 编译器填写 无用
  +30h DWORD BaseOfData;              // 数据的区块的起始RVA 编译器填写 无用
  +34h DWORD ImageBase;               // 程序的首选装载地址
  +38h DWORD SectionAlignment;        // 内存中的区块的对齐大小
  +3Ch DWORD FileAlignment;           // 文件中的区块的对齐大小
  +40h WORD  MajorOperatingSystemVersion;  // 要求操作系统最低版本号的主版本号
  +42h WORD  MinorOperatingSystemVersion;  // 要求操作系统最低版本号的副版本号
  +44h WORD  MajorImageVersion;       // 可运行于操作系统的主版本号
  +46h WORD  MinorImageVersion;       // 可运行于操作系统的次版本号
  +48h WORD  MajorSubsystemVersion;   // 要求最低子系统版本的主版本号
  +4Ah WORD  MinorSubsystemVersion;   // 要求最低子系统版本的次版本号
  +4Ch DWORD Win32VersionValue;       // 一般为0
  +50h DWORD SizeOfImage;             // 映像装入内存后的总尺寸，可以比实际值大，必须内存对齐
  +54h DWORD SizeOfHeaders;           // 所有头 + 区块表的尺寸大小，必须文件对齐
  +58h DWORD CheckSum;                // 映像的校检和
  +5Ch WORD  Subsystem;               // 可执行文件期望的子系统，驱动（1），图形界面（2），控制台、DLL（3）
  +5Eh WORD  DllCharacteristics;      // DllMain()函数何时被调用，默认为 0
  +60h DWORD SizeOfStackReserve;      // 初始化时的栈大小
  +64h DWORD SizeOfStackCommit;       // 初始化时实际提交的栈大小
  +68h DWORD SizeOfHeapReserve;       // 初始化时保留的堆大小
  +6Ch DWORD SizeOfHeapCommit;        // 初始化时实际提交的堆大小
  +70h DWORD LoaderFlags;             // 与调试有关，默认为0
  +74h DWORD NumberOfRvaAndSizes;     // 下边数据目录的项数，这个字段自Windows NT 发布以来一直是16
  +78h IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];  // 数据目录表，指向多种不同用途的数据块
IMAGE_OPTIONAL_HEADER32 ENDS
```
## 2.3. Subsystem
```
0x0 IMAGE_SUBSYSTEM_UNKNOWN         // 未知的子系统
0x1 IMAGE_SUBSYSTEM_NATIVE          // 不需要子系统（如驱动程序）
0x2 IMAGE_SUBSYSTEM_WINDOWS_GUI     // Windows图形界面
0x3 IMAGE_SUBSYSTEM_WINDOWS_CUI     // Windows控制台界面
0x5 IMAGE_SUBSYSTEM_OS2_CUI         // OS2控制台界面
0x7 IMAGE_SUBSYSTEM_POSIX_CUI       // POSIX控制台界面
0x8 IMAGE_SUBSYSTEM_NATIVE_WINDOWS  // 不需要子系统
0x9 IMAGE_SUBSYSTEM_WINDOWS_CE_GUI  // Windows CE图形界面
```
## 2.4. IMAGE_DATA_DIRECTORY
每个项的结构如下
```
IMAGE_DATA_DIRECTORY STRUCT
  +0x0 DWORD VirtualAddress      // 数据的起始RVA
  +0x4 DWORD isize               // 数据块的长度
IMAGE_DATA_DIRECTORY END
```
所有项目如下，以下偏移以IMAGE_NT_HEADERS为基准。
```
  0x78 DWORD EXPORT          // 导出表
  0x7C DWORD
  0x80 DWORD IMPORT          // 导出表
  0x84 DWORD
  0x88 DWORD RESOURCE        // 资源
  0x8C DWORD
  0x90 DWORD EXCEPTION       // 异常
  0x94 DWORD
  0x98 DWORD SECURITY        // 安全
  0x9C DWORD
  0xA0 DWORD BASERELOC       // 重定位
  0xA4 DWORD
  0xA8 DWORD DEBUG           // 调试
  0xAC DWORD
  0xB0 DWORD COPYRIGHT       // 描述字串
  0xB4 DWORD
  0xB8 DWORD GLOBALPTR       // RVA to be used as Global Pointer (IA-64 only)
  0xBC DWORD
  0xC0 DWORD TLS             // TLS
  0xC4 DWORD
  0xC8 DWORD LOAD_CONFIG     // 载入配置
  0xCC DWORD
  0xD0 DWORD BOUND_IMPORT    // 绑定导入表
  0xD4 DWORD
  0xD8 DWORD IAT             // 导入地址表
  0xDC DWORD
  0xE0 DWORD DELAY_IMPORT    // 延迟载入描述
  0xE4 DWORD
  0xE8 DWORD COM_DESCRIPTOR  // COM信息
  0xEC DWORD
  0xF0 DWORD Reserved        // 保留
  0xF4 DWORD
```
# 3. 节表
## 3.1. 结构体
节表位于IMAGE_NT_HEADERS之后。由一系列的IMAGE_SECTION_HEADER结构排列而成，每个结构用来描述一个节，结构的排列顺序和它们描述的节在文件中的排列顺序是一致的。全部有效结构的最后以一个空的IMAGE_SECTION_HEADER结构作为结束。
```
typedef struct _IMAGE_SECTION_HEADER {
    +0x0    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME]; // 节名称，前边带有“$” 的相同名字的区块在载入时候将会按照“$” 后边的字符的字母顺序进行合并
    +0x8    union {
                DWORD   PhysicalAddress; 
                DWORD   VirtualSize;        // 在内存中实际占用的大小，当前节数据内存中文件对齐前的真实尺寸
            } Misc;
    +0xC    DWORD   VirtualAddress;         // 在内存中的偏移地址，该偏移地址加上imagebase就是当前节数据在内存中的真正地址
    +0x10   DWORD   SizeOfRawData;          // 当前节数据在文件中对齐后的大小
    +0x14   DWORD   PointerToRawData;       // 当前节数据在文件中的偏移地址
    +0x18   DWORD   PointerToRelocations;   // 调试相关
    +0x1C   DWORD   PointerToLinenumbers;   // 调试相关
    +0x20   WORD    NumberOfRelocations;    // 调试相关
    +0x22   WORD    NumberOfLinenumbers;    // 调试相关
    +0x24   DWORD   Characteristics;        // 文件属性，比如该节数据属性是否为可执行属性，都在这里面
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```
## 3.2. 节属性
```
0x00000020 IMAGE_SCN_CNT_CODE               // Section contains code.(包含可执行代码)
0x00000040 IMAGE_SCN_CNT_INITIALIZED_DATA   // Section contains initialized data(该块包含已初始化的数据)
0x00000080 IMAGE_SCN_CNT_UNINITIALIZED_DATA // Section contains uninitialized data(该块包含未初始化的数据)
0x00000200 IMAGE_SCN_LNK_INFO               // Section contains comments or some other type of information
0x00000800 IMAGE_SCN_LNK_REMOVE             // Section contents will not become part of image
0x00001000 IMAGE_SCN_LNK_COMDAT             // Section contents comdat
0x00004000 IMAGE_SCN_NO_DEFER_SPEC_EXC      // Reset speculative exceptions handling bits in the TLB entries for this section
0x00008000 IMAGE_SCN_GPREL                  // Section content can be accessed relative to GP
0x00500000 IMAGE_SCN_ALIGN_16BYTES          // Default alignment if no others are specified
0x01000000 IMAGE_SCN_LNK_NRELOC_OVFL        // Section contains extended relocations
0x02000000 IMAGE_SCN_MEM_DISCARDABLE        // Section can be discarded
0x04000000 IMAGE_SCN_MEM_NOT_CACHED         // Section is not cachable
0x08000000 IMAGE_SCN_MEM_NOT_PAGED          // Section is not pageable
0x10000000 IMAGE_SCN_MEM_SHARED             // Section is shareable(该块为共享块)
0x20000000 IMAGE_SCN_MEM_EXECUTE            // Section is executable.(该块可执行)
0x40000000 IMAGE_SCN_MEM_READ               // Section is readable(该块可读)
0x80000000 IMAGE_SCN_MEM_WRITE              // Section is writeable(该块可写)
```
# 4. 导入表
导入表以IMAGE_IMPORT_DESCRIPTOR的数组开始，每个被PE文件链接进来的DLL文件都分别对应一个项，最后以一个全0的IID作为结束标志。
```
struct _IMAGE_IMPORT_DESCRIPTOR {
    +0x00 union {
              DWORD   Characteristics;
              DWORD   OriginalFirstThunk;   // INT即导入名称表的RVA（IMAGE_THUNK_DATA数组）
          } DUMMYUNIONNAME;
    +0x04 DWORD   TimeDateStamp;            // 时间戳，一般为空
    +0x08 DWORD   ForwarderChain;           // 一般情况下忽略，老版功能遗留
    +0x0C DWORD   Name;                     // 导入模块名的RVA
    +0x10 DWORD   FirstThunk;               // IAT即导入地址表的RVA（IMAGE_THUNK_DATA数组）
} IMAGE_IMPORT_DESCRIPTOR;
```
## 4.1. IMAGE_THUNK_DATA
```
struct _IMAGE_THUNK_DATA{
  +0x0 union {
        DWORD ForwarderString     // 只有当IMAGE_IMPORT_DESCRIPTOR中的ForwarderChain有值时，它才有效
        DWORD Function            // 函数的实际内存地址，只有在载入内存中时才有效
        DWORD Ordinal             // 最高位为1时，表示函数以序号方式输入，这时候低31位被看作一个函数序号
        DWORD AddressOfData       // 最高位为0时，表示函数以字符串类型的函数名方式输入，该值是一个RVA，指向一个IMAGE_IMPORT_BY_NAME结构
     }u1;
}IMAGE_THUNK_DATA32;
```
### 4.1.1. _IMAGE_IMPORT_BY_NAME
```
struct _IMAGE_IMPORT_BY_NAME {
  +0x0 WORD    Hint;                 // 指出函数在所在的dll的输出表中的序号
  +0x2 BYTE    Name[1];              // 指出要输入的函数的函数名
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
```
# 5. 导出表
```
IMAGE_EXPORT_DIRECTORY STRUCT
{
  +00h DWORD Characteristics        // 未使用，总是定义为0
  +04h DWORD TimeDateStamp          // 文件生成时间
  +08h WORD MajorVersion            // 未使用，总是定义为0
  +0Ah WORD MinorVersion            // 未使用，总是定义为0
  +0Ch DWORD Name                   // 模块的真实名称，编译时写入
  +10h DWORD Base                   // 基数，加上序数就是函数地址数组的索引值
  +14h DWORD NumberOfFunctions      // 导出函数的总数
  +18h DWORD NumberOfNames          // 以名称方式导出的函数的总数，该字段的值只会小于或者等于NumberOfFunctions
  +1Ch DWORD AddressOfFunctions     // 指向输出函数地址的RVA数组
  +20h DWORD AddressOfNames         // 指向输出函数名字的RVA数组
  +24h DWORD AddressOfNameOrdinals  // 指向输出函数序号的RVA数组
};IMAGE_EXPORT_DIRECTORY ENDS
```
# 6. 重定位表
```
IMAGE_BASE_RELOCATION STRUC
{
  +00h DWORD VirtualAddress   // 重定位数据开始的RVA 地址
  +04h DWORD SizeOfBlock      // 重定位块得长度，标识重定向字段个数
  +08h WORD TypeOffset        // 指向数组，每项大小为16位，高4位代表重定位类型，低12位是重定位地址，它与VirtualAddress相加即是指向PE映像中需要修改的那个代码的地址
};
IMAGE_BASE_RELOCATION ENDS
```
TypeOffset高位字节的代码定义：
```
  0x0 IMAGE_REL_BASED_ABSOLUTE   // 使块按照32位对齐，位置为0
  0x1 IMAGE_REL_BASED_HIGH       // 高16位必须应用于偏移量所指高字16位
  0x2 IMAGE_REL_BASED_LOW        // 低16位必须应用于偏移量所指低字16位
  0x3 IMAGE_REL_BASED_HIGHLOW    // 全部32位应用于所有32位
  0x4 IMAGE_REL_BASED_HIGHADJ    // 需要32位，高16位为偏移量，低16位为下一个偏移量数组元素，组合为一个带符号数，加上32位的一个数，然后加上8000，把高16位保存在偏移量的16位域内
  0x5 IMAGE_REL_BASED_MIPS_JMPADDR // Unknown
  0x6 IMAGE_REL_BASED_SECTION      // Unknown
  0x7 IMAGE_REL_BASED_REL32        // Unknown
```
# 7. 资源
PE文件中的资源是按照资源类型 -> 资源ID -> 资源代码页的3层树型目录结构来组织资源的。每一层都是以IMAGE_RESOURCE_DIRECTORY结构为头部，后面跟着一个IMAGE_RESOURCE_DIRECTORY_ENTRY结构数组。其中IMAGE_RESOURCE_DIRECTORY负责指出后面数组中的成员个数，IMAGE_RESOURCE_DIRECTORY_ENTRY数组成员分别指向下一层目录结构。
```
IMAGE_RESOURCE_DIRECTORY STRUCT    // 其中结构体中的成员指出的RVA偏移量都是对于此结构体的地址作为基地址
{
  +00h DWORD Characteristics       // 理论上为资源的属性，不过事实上总是0
  +04h DWORD TimeDateStamp         // 资源的产生时刻
  +08h WORD MajorVersion           // 理论上为资源的版本，不过事实上总是0
  +0Ah WORD MinorVersion
  +0Ch WORD NumberOfNamedEntries   // 以名称（字符串）命名的入口数量
  +0Eh WORD NumberOfIdEntries      // 以ID（整型数字）命名的入口数量
};IMAGE_RESOURCE_DIRECTORY ENDS

IMAGE_RESOURCE_DIRECTORY_ENTRY STRUCT  // 该结构的偏移以节点头为基准
{
  +10h DWORD Name           // 第一层目录时，代表资源类型
                            // 第二层目录时，代表资源名称；最高位为0时，低位为ID值；最高位为1时，低位为字符串（IMAGE_RESOURCE_DIR_STRING_U）
                            // 第三层目录时，代表资源语言类型
  +14h DWORD OffsetToData   // 第一、二层目录时，代表下层数据偏移地址；第三层目录时，代表资源数据地址（IMAGE_RESOURCE_DATA_ENTRY）
};IMAGE_RESOURCE_DIRECTORY_ENTRY ENDS

typedef struct _IMAGE_RESOURCE_DATA_ENTRY {
  +0x0 DWORD   OffsetToData          // 资源数据的RVA
  +0x4 DWORD   Size                  // 资源数据的长度
  +0x8 DWORD   CodePage              // 代码页, 一般为0
  +0xC DWORD   Reserved              // 保留字段
} IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

IMAGE_RESOURCE_DIR_STRING_U STRUCT
{
  +00h DWORD Length        // 字符串的长度
  +04h DWORD NameString    // UNICODE字符串，由于字符串是不定长的。由Length指定长度
};IMAGE_RESOURCE_DIR_STRING_U ENDS
```
以下为资源类型：
```
0x1  光标
0x2  位图
0x3  图标
0x4  菜单
0x5  对话框
0x6  字符串
0x7  字体目录
0x8  字体
0x9  加速键
0xA  未格式化资源
0xB  消息表
0xC  光标组
0xD  未知类型
0xE  图标组
0xF  未知类型
0x10 版本信息
```
