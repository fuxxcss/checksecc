# checksecc
* [Why checksecc ?](#why)
* [Introduction](#introduction)
* [How to Install ?](#install)
* [How to Use ?](#check-one-elf-file)
      * [Check File](#check-one-elf-file)
      * [Check Kernel](#check-the-kernel)
      * [Check Process](#check-one-process)
* [Version](#version-information)
* [ToDo]()
## why
checksec.sh is a linux specified gadget,because it used Shell and readelf. If you need to check something in other place, maybe you need checksecc.
## introduction
The checksecc is a c rewrite of checksec and has some highlights. It retains all the core functionality of checksec,you can operate on it just like the original.we removed some uncommon features and added some useful features.
``` shell
> checkc --help or just checkc
Usage: checkc [--format={cli,csv,xml,json}] [OPTION]

      Options:
      ## Checksecc Options
      --file={file}
      --dir={directory}
      --listfile={file list separated by *}
      --proc-all
      --proc-id={process ID}
      --kernel[=kconfig]
      --remote={ip:port}
      --remote-rev={port}
      --version
      --help

     ## Modifiers
      --format={cli,csv,xml,json}have a try
      --extended

For more information, see:
https://github.com/fuxxcss/checksecc

```
## install 
install checksecc by source:
``` shell
cd srcs
make && make install
```
if you need to update , make clean first
``` shell
make clean
```
## check one elf file
For example , we compile one file with gcc features.
``` shell
> gcc -z now -fstack-protector-all test.c -o test
```
And then use checkc to check this file.
``` shell
> checkc --file=./test
File                        ./test
RELRO                       Full RELRO
STACK CANARY                Canary found
NX                          NX enabled
PIE                         PIE enabled
RPATH                       NO RPATH
RUNPATH                     NO RUNPATH
Stripped                    Not Stripped
```
For example , we compile one file with clang features.
``` shell
> clang -fsanitize=address test.c -o test
```
And then use checkc to check this file with extended features.
``` shell
> checkc --file=./test --extended
File                        ./test
RELRO                       Partial RELRO
STACK CANARY                No Canary found
NX                          NX enabled
PIE                         PIE enabled
RPATH                       NO RPATH
RUNPATH                     NO RUNPATH
Stripped                    Not Stripped
Sanitized asan              Yes
Sanitized tsan              NO
Sanitized msan              NO
Sanitized lsan              Yes
Sanitized ubsan             Yes
Sanitized dfsan             NO
Sanitized safestack         NO
Sanitized cet-ibt           NO
Sanitized cet-shadow-stack  NO
Fortified                   FORTIFY SOURCE support available (/lib/x86_64-linux-gnu/libc.so.6) : Yes
Fortified                   Binary compiled with FORTIFY SOURCE support (./test) : Yes
Fortified                   __sprintf_chk Fortified
Fortified                   __longjmp_chk Fortified
Fortified                   __fprintf_chk Fortified
Fortified                   __vsprintf_chk Fortified
Fortified                   __snprintf_chk Fortified
Fortified                   __vsnprintf_chk Fortified
```
## check file list
We need delim * to check file list
``` shell
> checkc --listfile=test*test1*
File                        test
RELRO                       Full RELRO
STACK CANARY                No Canary found
NX                          NX enabled
PIE                         PIE enabled
RPATH                       NO RPATH
RUNPATH                     NO RUNPATH
Stripped                    Not Stripped

File                        test1
RELRO                       Partial RELRO
STACK CANARY                No Canary found
NX                          NX enabled
PIE                         PIE enabled
RPATH                       NO RPATH
RUNPATH                     NO RUNPATH
Stripped                    Stripped
```
## check the kernel
For example , we check Linux debian 5.10.0-20-amd64.
``` shell
> checkc --kernel
Kconfig                     /boot/config-5.10.0-20-amd64
User ASLR                   LEVEL 2
Kernel ASLR                 Enabled
Kernel NX                   Enabled
Kernel Stack Canary         Strong
Kernel Stack Poison         Disabled
Slab Freelist Hardened      Enabled
Slab Freelist Random        Enabled
SMAP                        Enabled
PTI                         Enabled
```
## check one process
we focus on selinux and seccomp.
``` shell
> ps -aux | grep 1592
root        1592  0.0  0.1 320324  8788 ?        Ssl  13:43   0:00 /usr/libexec/upowerd
> checkc --proc-id=1592
PID                         1592
Selinux                     No Selinux
SECCOMP                     Seccomp-bpf
File                        /usr/libexec/upowerd
RELRO                       Full RELRO
STACK CANARY                Canary found
NX                          NX enabled
PIE                         PIE enabled
RPATH                       NO RPATH
RUNPATH                     NO RUNPATH
Stripped                    Stripped
```
## version information
``` shell
> checkc --version
checksecc v0.1,fuxxcss
https://github.com/fuxxcss/checksecc

```
## ToDo
``` shell
other install ways
pe check
windows check
fix some error: /lib64 、 DSO has no entrypoint
```



