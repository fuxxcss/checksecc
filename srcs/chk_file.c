/*  check files */

#include<stdio.h>
#include<stdlib.h>
#include<dirent.h>
#include<string.h>
#include<fcntl.h>
#include"functions.h"
#include"types.h"
#include"loader.h"

/*  global flag */
extern bool EXTENTED;

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
        if(ph->sgm_type == PH_GNU_RELRO){
            relro=true;
            break;
        }
        ph=ph->ph_next;
    }
    /*  search dynamic section  */
    Section *dynamic=NULL;
    Section *sect=elf->sect->sect_next;
    while(sect){
        if(strcmp(sect->sect_name,".dynamic")==0){
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
                uintptr_t dyn32_addr=(uintptr_t)sect->sect_bytes+num*sizeof(E32_dyn);
                E32_dyn *dyn32=(E32_dyn*)dyn32_addr;
                /*  d_tag == DT_FLAGS   */
                if(dyn32->d_tag == DT_FLAGS)
                    /*  d_val == DT_BIND_NOW    */
                    if(dyn32->d_un.d_val == DF_BIND_NOW)
                        full=true;
            }
            break;
        case BIN_TYPE_ELF64:
            uint16_t dyn64_num=dynamic->sect_size/sizeof(E64_dyn);
            for(uint16_t num=0;num < dyn64_num;num++){
                uintptr_t dyn64_addr=(uintptr_t)sect->sect_bytes+num*sizeof(E64_dyn);
                E64_dyn *dyn64=(E64_dyn*)dyn64_addr;
                /*  d_tag == DT_FLAGS   */
                if(dyn64->d_tag == DT_FLAGS)
                    /*  d_val == DT_BIND_NOW    */
                    if(dyn64->d_un.d_val == DF_BIND_NOW)
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

/*  
 *  check nx    
 *  NX depends on CPU NX flag
 */
char *chk_elf_nx(Binary *elf){
    // check cpu nx first
    bool nx=chk_cpu_nx();
    if(!nx) CHK_ERROR4("CPU not support nx or Check CPU NX failed");
    bool stack=false;
    bool rwx=false;
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
    /*  segment flag == RWE */
    if(gnu_stack && (gnu_stack->sgm_flag & PF_X & PF_W & PF_R))
        rwx=true;
    if(stack && !rwx) return "\033[32mNX enabled\033[m";
    else return "\033[31mNX disabled\033[m";
}

/*
 * check pie   
 * PIE depends on ASLR
 */
char *chk_elf_pie(Binary *elf){
    // check aslr first
    unsigned int aslr=chk_user_aslr_flag();
    if(aslr == 0) CHK_ERROR4("Check ASLR failed");
    if(aslr == 48) return "\033[31mASLR LEVEL 0\033[m";
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
        if(strcmp(sect->sect_name,".dynamic")==0){
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
                uintptr_t dyn32_addr=(uintptr_t)sect->sect_bytes+num*sizeof(E32_dyn);
                E32_dyn *dyn32=(E32_dyn*)dyn32_addr;
                /*  d_tag == DT_DEBUG   */
                if(dyn32->d_tag == DT_DEBUG) debug=true;
            }
            break;
        case BIN_TYPE_ELF64:
            uint16_t dyn64_num=dynamic->sect_size/sizeof(E64_dyn);
            for(uint16_t num=0;num < dyn64_num;num++){
                uintptr_t dyn64_addr=(uintptr_t)sect->sect_bytes+num*sizeof(E64_dyn);
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
        if(strcmp(sect->sect_name,".dynamic")==0){
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
                uintptr_t dyn32_addr=(uintptr_t)sect->sect_bytes+num*sizeof(E32_dyn);
                E32_dyn *dyn32=(E32_dyn*)dyn32_addr;
                /*  d_tag == DT_RPATH   */
                if(dyn32->d_tag == DT_RPATH) rpath=true;
            }
            break;
        case BIN_TYPE_ELF64:
            uint16_t dyn64_num=dynamic->sect_size/sizeof(E64_dyn);
            for(uint16_t num=0;num < dyn64_num;num++){
                uintptr_t dyn64_addr=(uintptr_t)sect->sect_bytes+num*sizeof(E64_dyn);
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
        if(strcmp(sect->sect_name,".dynamic")==0){
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
                uintptr_t dyn32_addr=(uintptr_t)sect->sect_bytes+num*sizeof(E32_dyn);
                E32_dyn *dyn32=(E32_dyn*)dyn32_addr;
                /*  d_tag == DT_RUNPATH   */
                if(dyn32->d_tag == DT_RUNPATH) runpath=true;
            }
            break;
        case BIN_TYPE_ELF64:
            uint16_t dyn64_num=dynamic->sect_size/sizeof(E64_dyn);
            for(uint16_t num=0;num < dyn64_num;num++){
                uintptr_t dyn64_addr=(uintptr_t)sect->sect_bytes+num*sizeof(E64_dyn);
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
    if(strip) return "\033[32mStripped\033[m";
    else return "\033[31mNot Stripped\033[m";
}

/*  
    check sanitized gcc/llvm
*/
chk_info *chk_elf_sanitized(Binary *elf){
    /*  
        CHK_SAN_NUM 7
        [asan, tsan, msan, lsan, 
        ubsan, dfsan, safestack]
    */
    bool san_bool[CHK_SAN_NUM]={false};
    char *san_str[CHK_SAN_NUM]={
        "asan",
        "tsan",
        "msan",
        "lsan",
        "ubsan",
        "dfsan",
        "safestack"
    };
    /*  check dynsym for these strings*/
    Symbol *sym=elf->sym->sym_next;
    while(sym){
        /*  only need dynamic func*/
        if(sym->sym_type == SYM_TYPE_FUNC){
            sym=sym->sym_next;
            continue;
        }
        const char *name=sym->sym_name;
        /*  compare strlen(san_str[.]) bytes */
        for(int i=0;i<CHK_SAN_NUM;i++){
            char *str=str_append("__",san_str[i]);
            size_t size=strlen(str);
            if(strncmp(name,str,size) == 0){
                san_bool[i]=true;
            }
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
        if(strcmp(sect->sect_name,".text") == 0){
            text=sect;
            break;
        }
        sect=sect->sect_next;
    }
    if(!text) CHK_ERROR4("text section not found.");
    const uint8_t endbr64[5]={0xf3,0x0f,0x1e,0xfa,'\0'};
    if(strstr(sect->sect_bytes,endbr64)) cet_bool[0]=true;
    /*  
        check shadow call stack
        now only for aarch64
        so false
    */
   cet_bool[1]=false;
   /*   return chk_info */
    char *type="Sanitized ";
    chk_info *info=MALLOC(1,chk_info);
    /*  head    */
    chk_info *head=info;
    for(int i=0;i<CHK_SAN_NUM;i++){
        chk_info *new=MALLOC(1,chk_info);
        new->chk_type=str_append(type,san_str[i]);
        if(san_bool[i] ==false) new->chk_result="\033[31mNO\033[m";
        else new->chk_result="\033[32mYes\033[m";
        info->chk_next=new;
        info=new;
    }
    for(int i=0;i<CHK_CET_NUM;i++){
        chk_info *new=MALLOC(1,chk_info);
        new->chk_type=str_append(type,cet_str[i]);
        if(cet_bool[i] ==false) new->chk_result="\033[31mNO\033[m";
        else new->chk_result="\033[32mYes\033[m";
        info->chk_next=new;
        info=new;
    }
    /*  tail    */
    info->chk_next=NULL;

    return head;
}

/*  check fortified */
typedef struct hashmap{
    bool _hit;
    char *_str;
    struct hashmap *_next;
}hashmap;

void free_hashmap(hashmap *hm){
    for(int i=0;i<HASHMAP_SIZE;i++){
        hashmap *head=(hm+i)->_next;
        while(head){
            hashmap *tmp=head;
            head=head->_next;
            free(tmp);
        }
    }
    free(hm);
}

chk_info *chk_elf_fortified(Binary *elf){
    /*  check FORTIFY_SOURCE    */
    /*  search dynamic and dynstr  section*/
    Section *dynamic=NULL;
    Section *dynstr=NULL;
    Section *sect=elf->sect->sect_next;
    while(sect){
        if(strcmp(sect->sect_name,".dynamic")==0) dynamic=sect;
        if(strcmp(sect->sect_name,".dynstr")==0) dynstr=sect;
        sect=sect->sect_next;
    }
    if(!dynamic) CHK_ERROR4("dynamic section not found.");
    if(!dynstr) CHK_ERROR4("dynstr section not found.");
    /*  search DT_NEEDED on .dynstr    */
    char *libc_version=NULL;
    uint64_t offset,addr;
    char *libc_str="libc.so";
    size_t libc_str_len=strlen(libc_str);
    switch (elf->bin_type){
        case BIN_TYPE_ELF32:
            uint16_t dyn32_num=dynamic->sect_size/sizeof(E32_dyn);
            for(uint16_t num=0;num < dyn32_num;num++){
                uintptr_t dyn32_addr=(uintptr_t)dynamic->sect_bytes+num*sizeof(E32_dyn);
                E32_dyn *dyn32=(E32_dyn*)dyn32_addr;
                /*  d_tag == DT_NEEDED  */
                if(dyn32->d_tag == DT_NEEDED){
                    /*  offset = d_un.d_val  */
                    offset=dyn32->d_un.d_val;
                    /*  so addr */
                    addr=dynstr->sect_bytes+offset;
                    if(strncmp(libc_str,addr,libc_str_len)==0) libc_version=addr;
                }
            }
            break;
        case BIN_TYPE_ELF64:
            uint16_t dyn64_num=dynamic->sect_size/sizeof(E64_dyn);
            for(uint16_t num=0;num < dyn64_num;num++){
                uintptr_t dyn64_addr=(uintptr_t)dynamic->sect_bytes+num*sizeof(E64_dyn);
                E64_dyn *dyn64=(E64_dyn*)dyn64_addr;
                /*  d_tag == DT_NEEDED  */
                if(dyn64->d_tag == DT_NEEDED){
                    /*  offset = d_un.d_val  */
                    offset=dyn64->d_un.d_val;
                    /*  so addr */
                    addr=dynstr->sect_bytes+offset;
                    if(strncmp(libc_str,addr,libc_str_len)==0) libc_version=addr;
                }
            }
    }
    if(!libc_version) CHK_ERROR4("libc and libstdc++ are not used.");
    /*  load libc version, indexing by bin_arch*/
    char *arch_path[CHK_LIBC_PATH_NUM]={
        /*  ARCH_X86 = 0    */
        "/lib/i386-linux-gnu/",
        "/lib/x86_64-linux-gnu/",
        "/lib/aarch64-linux-gnu/"
    };
    char *libc_path=str_append(arch_path[elf->bin_arch],libc_version);
    /*  load libc   */
    Binary *libc=load_binary(libc_path);
    /*  keep fortify source funcs in hashmap and count it */
    hashmap *hm=MALLOC(HASHMAP_SIZE,hashmap);
    size_t fortify_count=0;
    /*  init hashmap    */
    for(int i=0;i<HASHMAP_SIZE;i++) {(hm+i)->_next=NULL;}
    Symbol *libc_sym=libc->sym->sym_next;
    while(libc_sym){
        char *suffix="_chk";
        char *libc_func_str=libc_sym->sym_name;
        if(strcmp(libc_func_str+strlen(libc_func_str)-strlen(suffix),suffix) ==0 ){
            size_t libc_func_len=strlen(libc_func_str);
            size_t map_index=(libc_func_len*libc_func_len)%HASHMAP_SIZE;
            /* head insert  */
            hashmap *new=MALLOC(1,hashmap);
            new->_hit=false;
            new->_str=libc_func_str;
            new->_next=(hm+map_index)->_next;
            (hm+map_index)->_next=new;
            fortify_count++;
        }
        libc_sym=libc_sym->sym_next;
    }
    /*  return chk_info    */
    char *type="Fortified ";
    chk_info *info=MALLOC(1,chk_info);
    /*  head    */
    chk_info *head=info;
    /*  compare elf funcs with libc funcs   */
    /*  count fortified */
    size_t fortified_count=0;
    Symbol *elf_sym=elf->sym->sym_next;
    while(elf_sym){
        char *prefix="__";
        char *elf_func_str=elf_sym->sym_name;
        size_t elf_func_len=strlen(elf_func_str);
        size_t map_index=(elf_func_len*elf_func_len)%HASHMAP_SIZE;
        /*  search in hashmap   */
        hashmap *hm_tmp=(hm+map_index)->_next;
        while(hm_tmp){
            /*  fortified  */
            if(strcmp(hm_tmp->_str,elf_func_str)==0){
                fortified_count++;
                if(!hm_tmp->_hit){
                    hm_tmp->_hit=true;
                    chk_info *new=MALLOC(1,chk_info);
                    new->chk_type=type;
                    new->chk_result=str_append(hm_tmp->_str," \033[32mFortified\033[m");
                    info->chk_next=new;
                    info=new;
                }
            }
            /*  fortifiable  
            else if(strncmp(hm_tmp->_str+strlen(prefix),elf_func_str,elf_func_len)==0){
                if(!hm_tmp->_hit){
                    hm_tmp->_hit=true;
                    chk_info *new=MALLOC(1,chk_info);
                    new->chk_type=type;;
                    new->chk_result=str_append(elf_func_str," \033[31mFortifiable\033[m");
                    info->chk_next=new;
                    info=new;
                }
            }
            */
            hm_tmp=hm_tmp->_next;
        }
        elf_sym=elf_sym->sym_next;
    }
    /*  tail    */
    info->chk_next=NULL;
    /*  free hashmap and libc   */
    free_hashmap(hm);
    free_binary(libc);
    /*  head insert */
    chk_info *insert=head;
    /*  first info : whether libc has FORTIFY SOURCE    */
    chk_info *libc_info=MALLOC(1,chk_info);
    libc_info->chk_type=type;
    char *first_info="FORTIFY SOURCE support available (";
    first_info=str_append(first_info,libc_path);
    if(fortify_count) libc_info->chk_result=str_append(first_info,") : \033[32mYes\033[m");
    else libc_info->chk_result=str_append(first_info,") : \033[31mNO\033[m");
    libc_info->chk_next=insert->chk_next;
    insert->chk_next=libc_info;
    insert=libc_info;
    /*  second info : whether target is fortified   */
    chk_info *target_info=MALLOC(1,chk_info);
    target_info->chk_type=type;
    char *second_info="Binary compiled with FORTIFY SOURCE support (";
    second_info=str_append(second_info,elf->bin_name);
    if(fortified_count) target_info->chk_result=str_append(second_info,") : \033[32mYes\033[m");
    else target_info->chk_result=str_append(second_info,") : \033[31mNO\033[m");
    target_info->chk_next=insert->chk_next;
    insert->chk_next=target_info;

    return head;
}

chk_info *chk_file_one_elf(Binary *elf){
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
        "File",
        "RELRO",
        "STACK CANARY",
        "NX",
        "PIE",
        "RPATH",
        "RUNPATH",
        "Stripped",
    };
    /*  current   */
    chk_info *elf_info=MALLOC(1,chk_info);\
    /*  head    */
    chk_info *head=elf_info;
    for(int num=0;num < CHK_BAS_NUM;num++){
        chk_info *new=MALLOC(1,chk_info);
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
        chk_info *(*chk_extented_func[CHK_EXT_NUM])(Binary*)={
            chk_elf_sanitized,
            chk_elf_fortified
        };
        for(int num=0;num < CHK_EXT_NUM;num++){
            chk_info *result=chk_extented_func[num](elf);
            chk_info *tmp=result;
            elf_info->chk_next=result->chk_next;
            /*  find the tail   */
            while(result->chk_next) result=result->chk_next;
            elf_info=result;
            /*  free fortify/sanitize's head */
            free(tmp);
        }
    }
    /*  tail    */
    elf_info->chk_next=NULL;
    /*  chk_info head   */
    return head;
}

void chk_file_one_pe(Binary *pe){
    return;
}

chk_info *chk_file_one(Binary *bin){
    /*  elf or pe   */
    switch (bin->bin_type)
    {
    case BIN_TYPE_ELF32:
        return chk_file_one_elf(bin);
    case BIN_TYPE_ELF64:
        return chk_file_one_elf(bin);
    case BIN_TYPE_PE:
        chk_file_one_pe(bin);
        return NULL;
    }
}

void chk_file(char *option,chk_file_option cfo){
    bool stat;
    switch (cfo)
    {
    case cfo_file:
        /*  load file  */
        Binary *bin=load_binary(option);
        if(bin == NULL) CHK_ERROR1("load file failed");
        /*  check one file  */
        chk_info *head;
        head=chk_file_one(bin);
        /*  output with format  */
        format_output(head);
        /*  free load   */
        free_binary(bin);
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
        char *token="*";
        char *path=strtok(option,token);
        while(path !=NULL){
            chk_file(path,cfo_file);
            CHK_PRINT3();
            path=strtok(NULL,token);
        }
        break;
    }
}