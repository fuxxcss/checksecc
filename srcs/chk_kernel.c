#include<fcntl.h>
#include<unistd.h>
#include<string.h>
#include<sys/utsname.h>
#include<zlib.h>
#include"functions.h"
#include"types.h"
#include"loader.h"

/*
 *  linux on x86
 */

// chk_elf_pie can use this return 0 1 2 3 .
unsigned int chk_user_aslr_flag(){
    //read /proc/sys/kernel/randomize_va_space
    int fd;
    fd=open("/proc/sys/kernel/randomize_va_space","r");
    if(fd < 0) CHK_ERROR4("open randomize_va_space failed");
    unsigned int aslr;
    if(read(fd,&aslr,8) < 0) CHK_ERROR4("read randomize_va_space failed");
    close(fd);
    // because CHK_ERROR4 return 0
    return ++aslr;
}

//user space ASLR
char *chk_user_aslr(char *){
    // return ++aslr
    unsigned int aslr=chk_user_aslr_flag();
    if(aslr == 0) return NULL;
    else if(aslr ==1) return "\033[31mASLR LEVEL 0\033[m";
    else if(aslr ==2) return "\033[33mASLR LEVEL 1\033[m";
    else if(aslr ==3) return "\033[32mASLR LEVEL 2\033[m";
    else CHK_ERROR4("Unknown ASLR LEVEL");
}

//kernel space ASLR
char *chk_kernel_aslr(char *info){
    if(strstr(info,"CONFIG_RANDOMIZE_BASE=y")) return "\033[32mEnabled\033[m";
    else return "\033[33mDisabled\033[m";
}

//cpu nx support
bool chk_cpu_nx(){
    //read /proc/cpuinfo
    FILE *fp;
    fp=fopen("/proc/cpuinfo","r");
    if(fp == NULL) CHK_ERROR3("open cpuinfo failed");
    // size = 0 
    unsigned int size=FILE_SIZE(fp);
    printf("%d\n",size);
    // need to add '\0'
    char *cpuinfo=MALLOC(size+1,char);
    if(fread(cpuinfo,sizeof(char),size,fp) < 0) CHK_ERROR3("read cpuinfo failed");
    cpuinfo[size]='\0';
    CHK_PRINT1(cpuinfo);
    close(fp);
    char *str=strstr(cpuinfo," nx ");
    free(cpuinfo);
    if(str) return true;
    else return false;
}

/*
 * kernel space nx 
 * code is not writable, data is not executable, and read-only data is neither writable nor executable.
 */
char *chk_kernel_nx(char *info){
    if(chk_cpu_nx()){
        if(strstr(info,"CONFIG_STRICT_KERNEL_RWX=y")) return "\033[32mEnabled\033[m";
        else return "\033[33mDisabled\033[m";
    }
    else return "CPU not support nx";
}

//kernel stack canary
char *chk_kernel_stack_canary(char *info){
    if(strstr(info,"CONFIG_STACKPROTECTOR=y")){
        if(strstr(info,"CONFIG_STACKPROTECTOR_STRONG=y")) return "\033[32mStrong\033[m";
        else return "\033[32mEnabled\033[m";
    }
    else return "\033[33mDisabled\033[m";
}

//poison kernel stack before returning from syscalls
char *chk_kernel_stack_poison(char *info){
    if(strstr(info,"CONFIG_GCC_PLUGIN_STACKLEAK=y")) return "\033[32mEnabled\033[m";
    else return "\033[33mDisabled\033[m";
}

//slab freelist hardened
char *chk_kernel_slab_freelist_hardened(char *info){
    if(strstr(info,"CONFIG_SLAB_FREELIST_HARDENED=y")) return "\033[32mEnabled\033[m";
    else return "\033[33mDisabled\033[m";
}

//slab freelist random
char *chk_kernel_slab_freelist_random(char *info){
    if(strstr(info,"CONFIG_SLAB_FREELIST_RANDOM=y")) return "\033[32mEnabled\033[m";
    else return "\033[33mDisabled\033[m";
}

// Supervisor Mode Access Protection x86
char *chk_kernel_smap(char *info){
    if(strstr(info,"CONFIG_X86_SMAP=y")) return "\033[32mEnabled\033[m";
    else return "\033[33mDisabled\033[m";
}

// PAGE TABLE ISOLATION
char *chk_kernel_pti(char *info){
    if(strstr(info,"CONFIG_PAGE_TABLE_ISOLATION=y")) return "\033[32mEnabled\033[m";
    else return "\033[33mDisabled\033[m";
}

//kernel config
char *chk_kernel_config(char *option){
    char *kernelinfo=NULL;
    FILE *fp;
    if(option == NULL) {
        // set CONFIG_IKCONFIG
        gzFile gzfp;
        gzfp=gzdopen("/proc/config.gz","rb");
        if(gzfp != NULL) {
            unsigned int size=gzFILE_SIZE(gzfp);
            kernelinfo=MALLOC(size,char);
            size_t result=gzread(gzfp,kernelinfo,size);
            gzclose(gzfp);
            if(result < 0){
                free(kernelinfo);
                CHK_PRINT1("read /proc/config.gz failed");
            }
            else goto kernelinfo_ok;
        }
        // uname -r
        struct utsname uts;
        if(uname(&uts) < 0) CHK_ERROR4("uname -r failed");
        char *release=uts.release;
        char *config;
        // /boot/config-${release}
        config=str_append("/boot/config-",release);
        fp=fopen(config,"r");
        if(fp) {
            unsigned int size=FILE_SIZE(fp);
            kernelinfo=MALLOC(size,char);
            size_t result=fread(kernelinfo,sizeof(char),size,fp);
            fclose(fp);
            if(result < 0){
                free(kernelinfo);
                CHK_PRINT1("read /boot/config-${release} failed");
            }
            else goto kernelinfo_ok;
        }
        // /usr/src/linux-headers-${release}
        char *lh_release=str_append("/usr/src/linux-headers-",release);
        config=str_append(lh_release,"/.config");
        fp=fopen(config,"r");
        if(fp) {
            unsigned int size=FILE_SIZE(fp);
            kernelinfo=MALLOC(size,char);
            size_t result=fread(kernelinfo,sizeof(char),size,fp);
            if(result < 0){
                free(kernelinfo);
                CHK_PRINT1("read /usr/src/linux-headers-${release}/.config failed");
            }
            else goto kernelinfo_ok;
        }
        // all failed
        CHK_ERROR4("cannot find kernel config");
    }
    else {
        fp=fopen(option,"r");
        if(fp == NULL) CHK_ERROR4("open kconfig failed");
        unsigned int size=FILE_SIZE(fp);
        kernelinfo=MALLOC(size,char);
        size_t result=fread(kernelinfo,sizeof(char),size,fp);
        fclose(fp);
        if(result < 0){
            free(kernelinfo);
            CHK_ERROR4("read kconfig failed");   
        }
    }
    // kernelinfo is ready
    kernelinfo_ok:
    return kernelinfo;
}

// https://www.kernel.org/doc/html/latest/security/self-protection.html
// https://www.kernelconfig.io/*
void chk_kernel(char *kernelinfo,char *option){
    if(kernelinfo == NULL)
        kernelinfo=chk_kernel_config(option);
    // chk kernel feature
    char *(*chk_kernel_func[CHK_KERN_NUM])(char *)={
        chk_user_aslr,
        chk_kernel_aslr,
        chk_kernel_nx,
        chk_kernel_stack_canary,
        chk_kernel_stack_poison,
        chk_kernel_slab_freelist_hardened,
        chk_kernel_slab_freelist_random,
        chk_kernel_smap,
        chk_kernel_pti
    };
    char *chk_kernel_array[CHK_KERN_NUM]={
        "User ASLR",
        "Kernel ASLR",
        "Kernel NX",
        "Kernel Stack Canary",
        "Kernel Stack Poison",
        "Slab Freelist Hardened",
        "Slab Freelist Random",
        "SMAP",
        "PTI"
    };
    if(kernelinfo != NULL){
        /*  current   */
        chk_info *kernel_info=MALLOC(1,chk_info);
        /*  head    */
        chk_info *head=kernel_info;
        for(int num=0;num < CHK_KERN_NUM;num++){
            chk_info *new=MALLOC(1,chk_info);
            new->chk_type=chk_kernel_array[num];
            char *result=chk_kernel_func[num](kernelinfo);
            /*  null handler   */
            if(!result) new->chk_result="NULL";
            else new->chk_result=result;
            kernel_info->chk_next=new;
            kernel_info=new;
        }
        /*  tail    */
        kernel_info->chk_next=NULL;
        /*  format output   */
        format_output(head);
        /*  free kernelinfo */
        free(kernelinfo);
    }
    else CHK_ERROR1("Check Kernel failed");
}