/*  check files */

#include<stdio.h>
#include"stdlib.h"
#include<dirent.h>
#include<string.h>
#include<fcntl.h>
#include"functions.h"
#include"types.h"
#include"loader.h"

/*  elf name    */
char *chk_elf_name(Binary *elf){
    return elf->bin_name;
}

/*  check relro */
char *chk_elf_relro(Binary *elf){
    
}

/*  check stack canary  */
char *chk_elf_stack_canary(Binary *elf){
    
}

/*  check nx    */
char *chk_elf_nx(Binary *elf){
    
}

/*  check pie   */
char *chk_elf_pie(Binary *elf){
    
}

/*  check rpath */
    
char *chk_elf_rpath(Binary *elf){
    
}

/*  check runpath   */
char *chk_elf_runpath(Binary *elf){
    
}

/*  check stripped  */
char *chk_elf_stripped(Binary *elf){
    
}

/*  check selfrando */
char *chk_elf_selfrando(Binary *elf){

}

/*  check clang cfi */
char *chk_elf_clang_cfi(Binary *elf){

}

/*  check safestack */
char *chk_elf_safestack(Binary *elf){

}

/*  check sanitized */
char *chk_elf_sanitized(Binary *elf){

}

void chk_file_one_elf(Binary *elf){
    /*  We have 8 basic check functions */
    char *(*chk_basic_func[CHK_BAS_NUM])(Binary*)={
        chk_elf_name,
        chk_elf_relro,
        chk_elf_stack_canary,
        chk_elf_nx,
        chk_elf_pie,
        chk_elf_rpath,
        chk_elf_runpath,
        chk_elf_stripped,
    };
    char *chk_basic_array[CHK_BAS_NUM]={
        "FILE",
        "RELRO",
        "STACK CANARY",
        "NX",
        "PIE",
        "RPATH",
        "RUNPATH",
        "Stripped",
    };
    /*  head    */
    chk_info *elf_info=(chk_info*)malloc(sizeof(chk_info));
    chk_info *head=elf_info;
    for(int num=0;num < CHK_BAS_NUM;num++){
        chk_info *new=(chk_info*)malloc(sizeof(chk_info));
        new->chk_type=chk_basic_array[num];
        new->chk_result=chk_basic_func[num](elf);
        elf_info->chk_next=new;
        elf_info=new;
    }
    /*  todo    */
    /*  1 fortify-related check function    */
    char **fortify_array=chk_elf_fortify(elf);
    CHK_PRINT("FORTIFY",*fortify_array[0]);
    CHK_PRINT("Fortified",*fortify_array[1]);
    CHK_PRINT("Fortifiable",*fortify_array[2]);

    if(EXTENTED){
        /*  We have 4 extented check functions  */
        char *(*chk_extented_func[CHK_EXT_NUM])(Binary*)={
            chk_elf_selfrando,
            chk_elf_clang_cfi,
            chk_elf_safestack,
            chk_elf_sanitized
        };
        char *chk_extented_array[CHK_EXT_NUM]={
            "SELFRANDO",
            "Clang CFI",
            "SafeStack",
            "Sanitized"
        };
        for(int num=0;num < CHK_EXT_NUM;num++){
            chk_info *new=(chk_info*)malloc(sizeof(chk_info));
            new->chk_type=chk_basic_array[num];
            new->chk_result=chk_basic_func[num](elf);
            elf_info->chk_next=new;
            elf_info=new;
        }
    }
    /*  tail    */
    elf_info->chk_next=NULL;
    /*  output with format  */
    format_output(head);
}

void chk_file_one_pe(Binary *pe){
    return false;
}

void chk_file_one(char *fn,int fd){
    /*  fortify?    */
    if(FILE_FORTIFY) {
        chk_file_fortify(fn,fd);
        return;
    }
    /*  binary load    */
    Binary *bin=load_binary(fn,fd);
    if(bin ==NULL) return false;
    /*  elf or pe   */
    switch (bin->bin_type)
    {
    case BIN_TYPE_ELF32:
        chk_file_one_elf(bin);
        break;
    case BIN_TYPE_ELF64:
        chk_file_one_elf(bin);
        break;
    case BIN_TYPE_PE:
        chk_file_one_pe(bin);
        break;
    }
}

void chk_file_fortify(char *fn,int fd){
    Binary *bin=load_binary(fn,fd);
    if(bin->bin_type == BIN_TYPE_PE) CHK_ERROR3("PE type is unsupported.");
}

void chk_file(char *option,chk_file_option cfo){
    bool stat;
    int fd;
    switch (cfo)
    {
    case cfo_file:
        /*  open file  */
        if((fd=open(option,O_RDONLY)) < 0) CHK_ERROR2(option,"file is not exist or not readable");
        /*  check one file  */
        chk_file_one(option,fd);
        break;
    case cfo_dir:
        /*  open dir*/
        DIR *dir;
        if((dir=opendir(option)) == NULL) CHK_ERROR2(option,"directory is not exist or not accessible");
        /*  check all files   */
        struct dirent *file;
        while((file=readdir(dir))!=NULL){
            if(file->d_name == "." || file->d_name == "..") continue;
            chk_file(file->d_name,cfo_file);
        }
        break;
    case cfo_listfile:
        /*  check file list */
        char *file=strtok(option,"|");
        while(file !=NULL){
            chk_file(file,cfo_file);
            file=strtok(option,"|");
        }
        break;
    case cfo_fortify:
        /*  set fortify flag    */
        FILE_FORTIFY=true;
        chk_file(option,cfo_file);
        break;
    }
}
