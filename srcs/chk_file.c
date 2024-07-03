/*  check files */

#include<stdio.h>
#include<stdlib.h>
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
    bool relro=false;
    bool full=false;
    /*  search program header   */
    Programh *ph=elf->hd->Pxheader.ph->ph_next;
    while(ph){
        /*  segment type == GNU_RELRO*/
        if(ph->sgm_type == PH_GNU_RELRO) relro=true;
        ph=ph->ph_next;
    }
    /*  search dynamic section  */
    Section *dynamic=NULL;
    Section *sect=elf->sect->sect_next;
    while(sect){
        if(sect->sect_name == ".dynamic"){
            dynamic=sect;
            break;
        }
        sect=sect->sect_next;
    }
    if(!dynamic) CHK_ERROR4("dynamic section not found.");
    /*  search BIND_NOW falg    */
    switch (elf->bin_type){
        case BIN_TYPE_ELF32:
            uint16_t dyn32_num=dynamic->sect_size/sizeof(E32_dyn);
            for(uint16_t num=0;num < dyn32_num;num++){
                uintptr_t dyn32_addr=(uintptr_t)sect->sec_bytes+num*sizeof(E32_dyn);
                E32_dyn *dyn32=(E32_dyn*)dyn32_addr;
                /*  d_tag == DT_FLAGS   */
                if(dyn32->d_tag == DT_FLAGS)
                    /*  d_val == DT_BIND_NOW    */
                    if(dyn32->d_un.d_val == DT_BIND_NOW)
                        full=true;
            }
            break;
        case BIN_TYPE_ELF64:
            uint16_t dyn64_num=dynamic->sect_size/sizeof(E64_dyn);
            for(uint16_t num=0;num < dyn64_num;num++){
                uintptr_t dyn64_addr=(uintptr_t)sect->sec_bytes+num*sizeof(E64_dyn);
                E64_dyn *dyn64=(E64_dyn*)dyn64_addr;
                /*  d_tag == DT_FLAGS   */
                if(dyn64->d_tag == DT_FLAGS)
                    /*  d_val == DT_BIND_NOW    */
                    if(dyn64->d_un.d_val == DT_BIND_NOW)
                        full=true;
            }
    }
    if(relro){
        if(full) return "\033[32mFull RELRO\033[m";
        else return "\033[33mPartial RELRO\033[m";
    }
    else return "\033[31mNo RELRO\033[m";
}

/*  check stack canary  */
char *chk_elf_stack_canary(Binary *elf){
    bool canary=false;
    Symbol *sym=elf->sym->sym_next;
    /*  search function symbol  */
    while(sym){
        const char* name=sym->sym_name;
        if(strcmp(name,"__stack_chk_fail") == 0 || \
           strcmp(name,"__stack_chk_guard") == 0 || \
           strcmp(name,"__intel_security_cookie") == 0)
            canary=true;
        sym=sym->sym_next;
    }
    if(canary) return "\033[32mCanary found\033[m";
    else return "\033[31mNo Canary found\033[m";
}

/*  check nx    */
char *chk_elf_nx(Binary *elf){
    bool stack=false;
    bool rwe=false;
    /*  search program header   */
    Programh *gnu_stack=NULL;
    Programh *ph=elf->hd->Pxheader.ph->ph_next;
    while(ph){
        /*  segment type == GNU_STACK*/
        if(ph->sgm_type == PH_GNU_STACK){
            stack=true;
            gnu_stack=ph;
            break;
        }
        ph=ph->ph_next;
    }
    /*  segment flag == RWE*/
    if(gnu_stack && (gnu_stack->sgm_flag & PF_X & PF_W & PF_R))
        rwe=true;
    if(stack && !rwe) return "\033[32mNX enabled\033[m";
    else return "\033[31mNX disabled\033[m";
}

/*  check pie   */
char *chk_elf_pie(Binary *elf){
    uint32_t type;
    switch(elf->bin_type){
        case BIN_TYPE_ELF32:
            type=elf->hd->Fileheader.e32fh->e_type;
            break;
        case BIN_TYPE_ELF64:
            type=elf->hd->Fileheader.e64fh->e_type;
    }
    switch(type){
        case ET_EXEC:
            return "\033[31mNo PIE\033[m";
        case ET_DYN:
            goto dyn;
        case ET_REL:
            return "\033[33mREL\033[m";
        default:
            return NULL;
    }
    /*  DYN */
    dyn:
    bool debug=false;
    /*  search dynamic section  */
    Section *dynamic=NULL;
    Section *sect=elf->sect->sect_next;
    while(sect){
        if(sect->sect_name == ".dynamic"){
            dynamic=sect;
            break;
        }
        sect=sect->sect_next;
    }
    if(!dynamic) CHK_ERROR4("dynamic section not found.");
    /*  search DEBUG    */
    switch (elf->bin_type){
        case BIN_TYPE_ELF32:
            uint16_t dyn32_num=dynamic->sect_size/sizeof(E32_dyn);
            for(uint16_t num=0;num < dyn32_num;num++){
                uintptr_t dyn32_addr=(uintptr_t)sect->sec_bytes+num*sizeof(E32_dyn);
                E32_dyn *dyn32=(E32_dyn*)dyn32_addr;
                /*  d_tag == DT_DEBUG   */
                if(dyn32->d_tag == DT_DEBUG) debug=true;
            }
            break;
        case BIN_TYPE_ELF64:
            uint16_t dyn64_num=dynamic->sect_size/sizeof(E64_dyn);
            for(uint16_t num=0;num < dyn64_num;num++){
                uintptr_t dyn64_addr=(uintptr_t)sect->sec_bytes+num*sizeof(E64_dyn);
                E64_dyn *dyn64=(E64_dyn*)dyn64_addr;
                /*  d_tag == DT_DEBUG   */
                if(dyn64->d_tag == DT_DEBUG) debug=true;
            }
    }
    if(debug) return "\033[32mPIE enabled\033[m";
    else return "\033[33mDSO\033[m";
}

/*  check rpath */
char *chk_elf_rpath(Binary *elf){
    /*  search dynamic section  */
    Section *dynamic=NULL;
    Section *sect=elf->sect->sect_next;
    while(sect){
        if(sect->sect_name == ".dynamic"){
            dynamic=sect;
            break;
        }
        sect=sect->sect_next;
    }
    if(!dynamic) CHK_ERROR4("dynamic section not found.");
    bool rpath=false;
    /*  search RPATH    */
    switch (elf->bin_type){
        case BIN_TYPE_ELF32:
            uint16_t dyn32_num=dynamic->sect_size/sizeof(E32_dyn);
            for(uint16_t num=0;num < dyn32_num;num++){
                uintptr_t dyn32_addr=(uintptr_t)sect->sec_bytes+num*sizeof(E32_dyn);
                E32_dyn *dyn32=(E32_dyn*)dyn32_addr;
                /*  d_tag == DT_RPATH   */
                if(dyn32->d_tag == DT_RPATH) rpath=true;
            }
            break;
        case BIN_TYPE_ELF64:
            uint16_t dyn64_num=dynamic->sect_size/sizeof(E64_dyn);
            for(uint16_t num=0;num < dyn64_num;num++){
                uintptr_t dyn64_addr=(uintptr_t)sect->sec_bytes+num*sizeof(E64_dyn);
                E64_dyn *dyn64=(E64_dyn*)dyn64_addr;
                /*  d_tag == DT_RPATH   */
                if(dyn64->d_tag == DT_RPATH) rpath=true;
            }
    }
    if(rpath) return "\033[31mRPATH\033[m";
    else return "\033[32mNO RPATH\033[m";
}

/*  check runpath   */
char *chk_elf_runpath(Binary *elf){
    /*  search dynamic section  */
    Section *dynamic=NULL;
    Section *sect=elf->sect->sect_next;
    while(sect){
        if(sect->sect_name == ".dynamic"){
            dynamic=sect;
            break;
        }
        sect=sect->sect_next;
    }
    if(!dynamic) CHK_ERROR4("dynamic section not found.");
    bool runpath=false;
    /*  search RUNPATH    */
    switch (elf->bin_type){
        case BIN_TYPE_ELF32:
            uint16_t dyn32_num=dynamic->sect_size/sizeof(E32_dyn);
            for(uint16_t num=0;num < dyn32_num;num++){
                uintptr_t dyn32_addr=(uintptr_t)sect->sec_bytes+num*sizeof(E32_dyn);
                E32_dyn *dyn32=(E32_dyn*)dyn32_addr;
                /*  d_tag == DT_RUNPATH   */
                if(dyn32->d_tag == DT_RUNPATH) runpath=true;
            }
            break;
        case BIN_TYPE_ELF64:
            uint16_t dyn64_num=dynamic->sect_size/sizeof(E64_dyn);
            for(uint16_t num=0;num < dyn64_num;num++){
                uintptr_t dyn64_addr=(uintptr_t)sect->sec_bytes+num*sizeof(E64_dyn);
                E64_dyn *dyn64=(E64_dyn*)dyn64_addr;
                /*  d_tag == DT_RUNPATH   */
                if(dyn64->d_tag == DT_RUNPATH) runpath=true;
            }
    }
    if(runpath) return "\033[31mRUNPATH\033[m";
    else return "\033[32mNO RUNPATH\033[m";
}

/*  check stripped  */
char *chk_elf_stripped(Binary *elf){
    /*  search FUNC type    */
    bool strip=true;
    Symbol *sym=elf->sym->sym_next;
    while(sym){
        if(sym->sym_type == SYM_TYPE_FUNC){
            strip=false;
            break;
        }
        sym=sym->sym_next;
    }
    if(strip) return "\033[31mStripped\033[m";
    else return "\033[32mNot Stripped\033[m";
}

/*  check sanitized */
char **chk_elf_sanitized(Binary *elf){
    /*  
        CHK_SAN_NUM 7
        [asan, tsan, msan, lsan, 
        ubsan, dfsan, safestack]
    */
    bool san_bool[CHK_SAN_NUM]={false};
    char *san_str[CHK_SAN_NUM]={
        "__asan",
        "__tsan",
        "__msan",
        "__lsan",
        "__ubsan",
        "__dfsan",
        "__safestack"
    };
    /*  check dynsym for these strings*/
    Symbol *sym=elf->sym->sym_next;
    while(sym){
        /*  only need dynamic func*/
        if(sym->sym_type == SYM_TYPE_FUNC) continue;
        const char *name=sym->sym_name;
        /*  compare strlen(san_str[.]) bytes */
        for(int i=0;i<CHK_SAN_NUM;i++){
            if(strncpy(name,san_str[i],strlen(san_str[i])) == 0)
                san_bool[i]=true;
        }
        sym=sym->sym_next;
    }
    
    /*  CHK_CET_NUM 2   */
    bool cet_bool[CHK_CET_NUM]={false};
    char *cet_str[CHK_CET_NUM]={
        "cet-ibt",
        "cet-shadow-stack"
    };
    /*  
        check indirect branch trace 
        gcc -fcf-protection=full
        rough implementation:search endbr64, f30f1efa
    */
    Section *text;
    Section *sect=elf->sect->sect_next;
    while(sect){
        if(sect->sect_name == ".text"){
            text=sect;
            break;
        }
        sect=sect->sect_next;
    }
    if(!text) CHK_ERROR4("text section not found.");
    const uint8_t endbr64[4]={0xf3,0x0f,0x1e,0xfa};
    if(strstr(sect->sec_bytes,endbr64)) cet_bool[0]=true;
    /*  
        check shadow call stack
        now only for aarch64
    */
    bool cet_bool[1]=false;

    /*  return string array */
    static char* ret[CHK_SAN_NUM+CHK_CET_NUM+1];
    for(int i=0;i<CHK_SAN_NUM;i++){
        /*  __asan -> asan  */
        ret[i]=san_str[i]+2;
        if(san_bool[i] ==false) strcat(ret[i]," \033[32mNO\033[m\n");
        else strcat(ret[i]," \033[31mYes\033[m\n");
    }
    for(int i=CHK_SAN_NUM;i<CHK_CET_NUM+CHK_SAN_NUM;i++){
        ret[i]=cet_str[i];
        if(cet_bool[i] ==false) strcat(ret[i]," \033[32mNO\033[m\n");
        else strcat(ret[i]," \033[31mYes\033[m\n");
    }
    ret[CHK_SAN_NUM+CHK_CET_NUM]=NULL;
    return ret;
}

/*  check fortified */
char **chk_elf_fortified(Binary *elf){
    /*  check FORTIFY_SOURCE    */
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
        char *result=chk_basic_func[num](elf);
        /*  null handler   */
        if(!result) new->chk_result="NULL";
        else new->chk_result=result;
        elf_info->chk_next=new;
        elf_info=new;
    }
    if(EXTENTED){
        /*  We have 2 extented check functions  */
        char *(*chk_extented_func[CHK_EXT_NUM])(Binary*)={
            chk_elf_sanitized,
            chk_elf_fortified
        };
        char *chk_extented_array[CHK_EXT_NUM]={
            "Sanitized",
            "Fortified"
        };
        for(int num=0;num < CHK_EXT_NUM;num++){
            char **result=chk_extented_func[num](elf);
            /*  null handler   */
            while(*result){
                chk_info *new=(chk_info*)malloc(sizeof(chk_info));
                new->chk_type=chk_extented_array[num];
                new->chk_result=*result;
                elf_info->chk_next=new;
                elf_info=new;
                result++;
            }
        }
    }
    /*  tail    */
    elf_info->chk_next=NULL;
    /*  output with format  */
    format_output(head);
}

void chk_file_one_pe(Binary *pe){
    return;
}

void chk_file_one(Binary *bin){
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

void chk_file(char *option,chk_file_option cfo){
    bool stat;
    switch (cfo)
    {
    case cfo_file:
        /*  load file  */
        Binary *bin=load_binary(option);
        if(bin == NULL) return;
        /*  check one file  */
        chk_file_one(bin);
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
    }
}
