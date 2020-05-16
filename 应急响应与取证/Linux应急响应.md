<!-- TOC -->

- [1. 查看进程](#1-查看进程)
- [2. 定位网络通信的进程](#2-定位网络通信的进程)
- [3. 查看历史命令](#3-查看历史命令)
- [4. 清除进程](#4-清除进程)
- [5. 删除病毒文件](#5-删除病毒文件)
- [6. 检查启动项](#6-检查启动项)
- [7. 检查驱动](#7-检查驱动)

<!-- /TOC -->
# 1. 查看进程
* top
* ps -aux
# 2. 定位网络通信的进程
`while true; do netstat -antp | grep [ip]; done`，如果对象是域名的话，可以先修改`/etc/hosts`文件，修改域名指向
# 3. 查看历史命令
* history
# 4. 清除进程
* ps -elf | grep [pid] kill -9 [pid]
# 5. 删除病毒文件
* ls -al /proc/[pid]/exe rm -f [exe_path]
# 6. 检查启动项
* 查看定时任务：crontab -l
* 查看ana定时任务：cat/etc/anacrontab
* 查看所有服务：service --status-all
* 检查最近天内修改的文件：find /usr/bin/ /usr/sbin/ /bin/ /usr/local/bin/ -type f -mtime +7 | xargs ls -la
* 检查是否存在病毒守护进程：lsof -p [pid]
* 检查是否存在病毒守护进程：strace -tt-T -etrace=all-p$pid
# 7. 检查驱动
* 枚举/扫描系统驱动：lsmod
* wget ftp://ftp.pangeia.com.br/pub/seg/pac/chkrootkit.tar.gztar zxvf chkrootkit.tar.gzcd chkrootkit-0.52make sense./chkrootkit
* rkhunter
    * Wgethttps://nchc.dl.sourceforge.net/project/rkhunter/rkhunter/1.4.4/rkhunter-1.4.4.tar.gz
    * tar -zxvf rkhunter-1.4.4.tar.gz
    * cd rkhunter-1.4.4
    * ./installer.sh --install
    * rkhunter -c