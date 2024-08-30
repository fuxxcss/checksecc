#include<fcntl.h>
#include<unistd.h>
#include<string.h>
#include"functions.h"
#include"types.h"

//user space ASLR
char *chk_kernel_aslr(){
    //read /proc/sys/kernel/randomize_va_space
    int fd;
    fd=open("/proc/sys/kernel/randomize_va_space","r");
    if(fd < 0) CHK_ERROR4("Access randomize_va_space failed");
    unsigned int aslr;
    if(read(fd,&aslr,8) < 0) CHK_ERROR4("Read randomize_va_space failed");
    if(aslr == 0) return "\033[31mASLR LEVEL 0\033[m";
    else if(aslr ==1) return "\033[33mASLR LEVEL 1\033[m";
    else if(aslr ==2) return "\033[32mASLR LEVEL 2\033[m";
    else CHK_ERROR4("Unknown ASLR LEVEL");
    close(fd);
}

//kernel space ASLR
char *chk_kernel_kaslr();

//cpu nx support
char *chk_kernel_nx(){
    //read /proc/cpuinfo
    int fd;
    fd=open("/proc/cpuinfo","r");
    if(fd < 0) CHK_ERROR4("Access cpuinfo failed");
    char cpuinfo[512];
    if(read(fd,cpuinfo,512) < 0) CHK_ERROR4("Read cpuinfo failed");
    if(strstr(cpuinfo," nx ")) return "CPU NX\033[31m Yes \033[m";
    else return "CPU NX\033[32m NO \033[m";
    close(fd);
}
