#include<stdlib.h>
#include<stdio.h>
#include<unistd.h>
#include<string.h>
#include<sys/mman.h>
#include<sys/stat.h>
#include"loader.h"

static void load_elf_symbol_funcs(Binary *bin,uintptr_t sym_addr,uint64_t upper,uint64_t str_addr,sym_type type){
    switch (bin->bin_type)
    {
    case BIN_TYPE_ELF32:
        for(uint64_t sym_num=0;sym_num < upper;sym_num+=sizeof(E32_sym)){
            E32_sym *sym_st=(E32_sym*)(sym_addr+sym_num);
            Symbol *new;
            if(sym_st->st_info & STT_FUNC)
                new=(Symbol *)malloc(sizeof(Symbol));
            else continue;
            new->sym_type=type;
            /*  name from strtab or dynstr  */
            uint64_t offset=sym_st->st_name;
            new->sym_name=(char *)str_addr+offset;
            new->sym_addr=sym_st->st_value;
            new->sym_next=bin->sym->sym_next;
            bin->sym->sym_next=new;
            }
        break;
    case BIN_TYPE_ELF64:
        for(uint64_t sym_num=0;sym_num < upper;sym_num+=sizeof(E64_sym)){
            E64_sym *sym_st=(E64_sym*)(sym_addr+sym_num);
            Symbol *new;
            if(sym_st->st_info & STT_FUNC)
                new=(Symbol *)malloc(sizeof(Symbol));
            else continue;
            new->sym_type=type;
            /*  name from strtab or dynstr  */
            uint64_t offset=sym_st->st_name;
            new->sym_name=(char *)str_addr+offset;
            new->sym_addr=sym_st->st_value;
            new->sym_next=bin->sym->sym_next;
            bin->sym->sym_next=new;
            }
        break;
    }
}

static void load_elf_symbols(Binary *bin){
    /*  load function symbols   */
    Section *sect=bin->sect;
    sect=sect->sect_next;
    /*  symtab,dynsym,strtab,dynstr and their size*/
    uintptr_t sym_addr[4]={0};
    uint64_t size[4]={0};
    while(sect){
        const char *name=sect->sect_name;
        if(strcmp(name,".symtab") == 0) {
            sym_addr[0]=(uintptr_t)sect->sec_bytes;
            size[0]=sect->sect_size;
        }
        else if(strcmp(name,".dynsym") == 0) {
            sym_addr[1]=(uintptr_t)sect->sec_bytes;
            size[1]=sect->sect_size;
        }
        else if(strcmp(name,".strtab") == 0) {
            sym_addr[2]=(uintptr_t)sect->sec_bytes;
            size[2]=sect->sect_size;
        }
        else if(strcmp(name,".dynstr") == 0) {
            sym_addr[3]=(uintptr_t)sect->sec_bytes;
            size[3]=sect->sect_size;
        }
        sect=sect->sect_next;
    }
    /*  head insert */
     /*  head    */
    Symbol *sym=(Symbol *)malloc(sizeof(Symbol));
    bin->sym=sym;
    /*  tail    */
    sym->sym_next=NULL;
    /*  symtab  */
    if(sym_addr[0] == 0) LDR_ERROR1(bin->bin_name,"no symtab.");
    else load_elf_symbol_funcs(bin,sym_addr[0],size[0],sym_addr[2],SYM_TYPE_FUNC);
    /*  dynsym  */
    if(sym_addr[1] == 0) LDR_ERROR1(bin->bin_name,"no dynsym.");
    else load_elf_symbol_funcs(bin,sym_addr[1],size[1],sym_addr[3],SYM_TYPE_DYN_FUNC); 
}

static uintptr_t load_elf_section_shstrtab(Binary *bin,void *mem,uint64_t *sh_info){
    char *name=".shstrtab";
    uint64_t size,flags;
    /*  section contents addr and section vma*/
    uintptr_t sc_addr,vma;
    Section *shstrtab=(Section *)malloc(sizeof(Section));
    /*  section header (.shstrtab) addr  */
    uintptr_t sh_addr=(uintptr_t)mem+sh_info[0]+sh_info[2]*sh_info[3];
    switch (bin->bin_type)
    {
    case BIN_TYPE_ELF32:
        E32_sh *sh32=(E32_sh*)sh_addr;
        size=sh32->sh_size;
        vma=sh32->sh_addr;
        sc_addr=sh32->sh_offset+(uintptr_t)mem;
        flags=sh32->sh_flags;
        break;
    case BIN_TYPE_ELF64:
        E64_sh *sh64=(E64_sh*)sh_addr;
        size=sh64->sh_size;
        vma=sh64->sh_addr;
        sc_addr=sh64->sh_offset+(uintptr_t)mem;
        flags=sh64->sh_flags;
        break;
    }
    shstrtab->sect_name=name;
    shstrtab->sect_size=size;
    shstrtab->sect_vma=vma;
    shstrtab->sect_type=SECT_TYPE_DATA;
    /*  load section contents   */
    uint8_t *bytes=(uint8_t *)malloc(size);
    shstrtab->sec_bytes=bytes;
    for(uint64_t offset=0;offset < size;offset++)
        bytes[offset]=*(uint8_t*)(sc_addr+offset);
    bin->sect->sect_next=shstrtab;
    return sc_addr;
}

static void load_elf_sections(Binary *bin,void *mem,uint64_t *sh_info){
    char *name;
    uint64_t size,flags;
    /*  section contents addr and section vma*/
    uintptr_t sc_addr,vma;
    Section *sect=(Section *)malloc(sizeof(Section));
    /*  tail insert */
    /*  head    */
    bin->sect=sect;
    /*  we need .shstrtab first */
    uintptr_t shstrtab_addr=load_elf_section_shstrtab(bin,mem,sh_info);
    sect=sect->sect_next;
    for(int sh_num=0;sh_num < sh_info[1];sh_num++){
        /*  we had .shstrtab    */
        if(sh_num == sh_info[3]) continue;
        Section *new=(Section *)malloc(sizeof(Section));
        /*  section header addr*/
        uint64_t sh_addr=(uint64_t)mem+sh_info[0]+sh_num*sh_info[2];
        /*  section name string table addr*/
        uintptr_t sn_addr;
        switch (bin->bin_type)
        {
        case BIN_TYPE_ELF32:
            E32_sh *sh32=(E32_sh*)sh_addr;
            sn_addr=shstrtab_addr+sh32->sh_name;
            name=(char *)sn_addr;
            size=sh32->sh_size;
            vma=sh32->sh_addr;
            sc_addr=sh32->sh_offset+(uintptr_t)mem;
            flags=sh32->sh_flags;
            break;
        case BIN_TYPE_ELF64:
            E64_sh *sh64=(E64_sh*)sh_addr;
            sn_addr=shstrtab_addr+sh64->sh_name;
            name=(char *)sn_addr;
            size=sh64->sh_size;
            vma=sh64->sh_addr;
            sc_addr=sh64->sh_offset+(uintptr_t)mem;
            flags=sh64->sh_flags;
            break;
        }
        new->sect_name=name;
        new->sect_size=size;
        new->sect_vma=vma;
        if(flags & SHF_EXECINSTR)
            new->sect_type=SECT_TYPE_CODE;
        else
            new->sect_type=SECT_TYPE_DATA;
        /*  load section contents   */
        uint8_t *bytes=(uint8_t *)malloc(size);
        new->sec_bytes=bytes;
        for(uint64_t offset=0;offset < size;offset++)
            bytes[offset]=*(uint8_t*)(sc_addr+offset);
        sect->sect_next=new;
        sect=new;
    }
    /*  tail    */
    sect->sect_next=NULL;
}

static void load_elf(Binary *bin,void *mem){
    /*  load sections   */
    /*  uint64_t [shtb_addr,sh_num,sh_size,shstr_offset] */
    uint64_t sh_info[4];
    switch (bin->bin_type)
    {
    case BIN_TYPE_ELF32:
        E32_fh *elf32_fh=(E32_fh*)mem;
        /*  section header table*/
        sh_info[0]=elf32_fh->e_shoff;
        sh_info[1]=elf32_fh->e_shnum;
        sh_info[2]=elf32_fh->e_shentsize;
        sh_info[3]=elf32_fh->e_shstrndx;
        break;
    case BIN_TYPE_ELF64:
        E64_fh *elf64_fh=(E64_fh*)mem;
        /*  section header table*/
        sh_info[0]=elf64_fh->e_shoff;
        sh_info[1]=elf64_fh->e_shnum;
        sh_info[2]=elf64_fh->e_shentsize;
        sh_info[3]=elf64_fh->e_shstrndx;
        break;
    }
    load_elf_sections(bin,mem,sh_info);
    if(bin->sect->sect_next == NULL) return;
    /*  load symbols    */
    load_elf_symbols(bin);
}

static void load_info_arch(Binary *bin,uint64_t machine){
    if(bin->bin_type == BIN_TYPE_PE)
        switch(machine)
        {
        case IMAGE_FILE_MACHINE_I386:
            bin->bin_arch=ARCH_X86;
            break;
        case IMAGE_FILE_MACHINE_AMD64:
            bin->bin_arch=ARCH_X64;
            break;
        default:
            bin->bin_arch=ARCH_UNKNOWN;
        }
    else if(bin->bin_type == BIN_TYPE_ELF32 || bin->bin_type == BIN_TYPE_ELF64)
        switch(machine)
        {
        case EM_386:
            bin->bin_arch=ARCH_X86;
            break;
        case EM_X86_64:
            bin->bin_arch=ARCH_X64;
            break;
        default:
            bin->bin_arch=ARCH_UNKNOWN;
        }
}

static void load_info(Binary *bin,void *mem){
    /*  explicit type conversion */
    uint16_t *mz=(uint16_t*)mem;
    uint32_t *elf=(uint32_t*)mem;
    /*  elf class uint8  */
    uintptr_t elfclass_addr=(uintptr_t)mem+sizeof(uint32_t);
    uint8_t *elfclass=(uint8_t*)elfclass_addr;
    if(*mz == MZ_MAGIC){
        bin->bin_type=BIN_TYPE_PE;
        MZ_fh *mz_fh=(MZ_fh*)mem;
        /*  pe file header addr   */
        uintptr_t pe_fh_addr=(uintptr_t)mem+mz_fh->peaddr;
        PE_fh *pe_fh=(PE_fh*)pe_fh_addr;
        load_info_arch(bin,pe_fh->machine);
        if(pe_fh->opt_hdr_size > 0){
            /*  pe entry addr */
            uintptr_t pe_entry_addr=pe_fh_addr+sizeof(PE_fh)+PE_ENTRY_OFFSET;
            uint32_t *pe_entry=(uint32_t*)pe_entry_addr;
            bin->entry=*pe_entry;
        }
        else bin->entry=0;
    }
    else if(*elf == ELF_MAGIC && *elfclass == E32_flag){
        bin->bin_type=BIN_TYPE_ELF32;
        E32_fh *elf_fh=(E32_fh*)mem;
        load_info_arch(bin,elf_fh->e_machine);
        bin->entry=elf_fh->e_entry;
    }
    else if(*elf == ELF_MAGIC && *elfclass == E64_flag){
        bin->bin_type=BIN_TYPE_ELF64;
        E64_fh *elf_fh=(E64_fh*)mem;
        load_info_arch(bin,elf_fh->e_machine);
        bin->entry=elf_fh->e_entry;
    }
    else bin->bin_type=BIN_TYPE_UNKNOWN;
}

Binary *load_binary(char *fn,int fd){
    /*  file init */
    struct stat file_stat;
    void *file_mem;
    int file_size;
    char *file_name;
    fstat(fd,&file_stat);
    file_size=file_stat.st_size;
    file_name=fn;
    file_mem=mmap(NULL,file_size,PROT_READ | PROT_WRITE,MAP_PRIVATE,fd,0);
    if(file_mem == MAP_FAILED) LDR_ERROR2(fn,"mmap failed.");
    /*  Binary init */
    Binary *bin=(Binary *)malloc(sizeof(Binary));
    bin->bin_size=file_size;
    bin->bin_name=file_name;
    load_info(bin,file_mem);
    if(bin->bin_type < 0) LDR_ERROR2(fn,"unsupported binary type.");
    if(bin->bin_arch < 0) LDR_ERROR2(fn,"unsupported architecture.");
    if(bin->entry ==0 ) LDR_ERROR1(fn,"cannot find entry point.");
    switch (bin->bin_type)
    {
    case BIN_TYPE_ELF32:
        load_elf(bin,file_mem);
        break;
    case BIN_TYPE_ELF64:
        load_elf(bin,file_mem);
        break;
    case BIN_TYPE_PE:
        LDR_ERROR2(fn,"unsupported pe analysis now!");
        break;
    }
    if(bin->sect->sect_next == NULL) LDR_ERROR2(fn,"load sections failed.");
    if(bin->sym->sym_next == NULL) LDR_ERROR2(fn,"load symbols failed.");
    return bin;
}

void show_symbols(Binary *bin){
    printf("scanning symbols\n...\n");
    Symbol *sym=bin->sym;
    sym=sym->sym_next;
    while(sym){
        printf("%-28s 0x%016jx %s\n",sym->sym_name,sym->sym_addr,(sym->sym_type==SYM_TYPE_FUNC)? "FUNC":"DYN_FUNC");
        sym=sym->sym_next;
    }
    printf("\n");
}

void show_sections(Binary *bin){
    printf("scanning sections\n...\n");
    Section *sect=bin->sect;
    sect=sect->sect_next;
    while(sect){
        printf("0x%016jx %-8ju %s %s\n",sect->sect_vma,sect->sect_size,sect->sect_name,(sect->sect_type==SECT_TYPE_CODE)?"CODE":"DATA");
        sect=sect->sect_next;
    }
    printf("\n");
}