#include<fcntl.h>
#include<unistd.h>
#include<string.h>
#include<dirent.h>
#include"functions.h"
#include"types.h"
#include"loader.h"

// TODO multi-thread check procs

// check for Seccomp mode
char *chk_linux_proc_seccomp(char *path){
    char *status=str_append(path,"/status");
    int fd;
    fd=open(status,"r");
    if(fd < 0) CHK_ERROR4("open /proc/pid/status failed");
    char seccomp[512];
    if(read(fd,seccomp,512) < 0) CHK_ERROR4("read /proc/pid/status failed");
    char *location=strstr(seccomp,"Seccomp:");
    if(location == NULL) CHK_ERROR4("Seccomp flag not found");
    // Seccomp:	x , flag=x
    unsigned int offset=10;
    char flag=*(location+offset);
    if(flag == '0') return "\033[31mNo Seccomp\033[m";
    else if(flag == '1') return "\033[32mSeccomp strict\033[m";
    else if(flag =='2') return "\033[32mSeccomp-bpf\033[m";
    else CHK_ERROR4("Unknown Seccomp LEVEL");
    close(fd);
}

// only linux now
void chk_linux_proc(char *path,char *pid,char *exe){
    // chk aslr and cpu nx first
    char *aslr=chk_kernel_aslr();
    if(aslr == NULL) CHK_ERROR2(exe,"Check ASLR failed");
    CHK_PRINT("PIE depends on ASLR: ",aslr);
    char *nx=chk_kernel_nx();
    if(nx == NULL) CHK_ERROR2(exe,"Check CPU NX failed");
    CHK_PRINT("NX depends on CPU NX flag: ",nx);
    // chk_info
    chk_info *head;
    // chk this exe file
    head=chk_file_one_elf(exe,cfo_file);
    // chk proc feature
    char *(*chk_proc_func[CHK_PROC_NUM])(char *)={
        chk_linux_proc_seccomp,
    };
    char *chk_proc_array[CHK_PROC_NUM]={
        "SECCOMP",
    };
    for(int num=0;num < CHK_PROC_NUM;num++){
        chk_info *new=MALLOC(1,chk_info);
        new->chk_type=chk_proc_array[num];
        char *result=chk_proc_func[num](path);
        /*  null handler   */
        if(!result) new->chk_result="NULL";
        else new->chk_result=result;
        // head insert
        new->chk_next=head->chk_next;
        head->chk_next=new;
    }
    // head insert pid
    chk_info *new=MALLOC(1,chk_info);
    new->chk_type="PID";
    new->chk_result=pid;
    new->chk_next=head->chk_next;
    head->chk_next=new;
    //format output
    format_output(head);
}

void chk_proc(char *option,chk_proc_option cpo){
    switch (cpo)
    {
    case cpo_id:
        char *proc=str_append("/proc/",option);
        int fd=open(proc,"r");
        if(fd < 0) CHK_ERROR2(option,"pid is not exist or not unprivileged(not root)");
        close(fd);
        char *link=str_append(proc,"/exe");
        // max len 64
        char exe[64];
        int len=readlink(link,exe,64);
        if(len < 0) CHK_ERROR2(option,"Permission denied. Requested process ID belongs to a kernel thread");
        chk_linux_proc(proc,option,exe);
        break;
    case cpo_all:
        DIR *dir;
        if((dir=opendir("/proc")) == NULL) CHK_ERROR1("/proc is not exist or not accessible");
        /*  check all procs   */
        struct dirent *file;
        while((file=readdir(dir))!=NULL){
            if(file->d_name == "." || file->d_name == "..") continue;
            if(file->d_name[0] >= '1'&& file->d_name[0] <='9')
                chk_proc(file->d_name,cpo_id);
        }
        break;
    }
}