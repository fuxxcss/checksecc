#ifndef _loader_h_
#define _loader_h_

#include<stdio.h>
#include<stdint.h>
#include<elf.h>
#include"pe.h"

/*  expection handle    */
#define LDR_ERROR1(info1,info2) \
    printf("LDR ERROR:%s %s\n",info1,info2) \

#define LDR_ERROR2(info1,info2) {\
    printf("LDR ERROR:%s %s\n",info1,info2); \
    return NULL;\
}

/*  elf format  */
#define ELF_MAGIC 0x464c457f
#define E32_flag 1
#define E64_flag 2
typedef Elf32_Ehdr E32_fh;
typedef Elf64_Ehdr E64_fh;
typedef Elf32_Shdr E32_sh;
typedef Elf64_Shdr E64_sh;
typedef Elf32_Sym E32_sym;
typedef Elf64_Sym E64_sym;
typedef Elf32_Phdr E32_ph;
typedef Elf64_Phdr E64_ph;
typedef Elf32_Dyn E32_dyn;
typedef Elf64_Dyn E64_dyn;


/*  pe format   */
#define MZ_MAGIC 0x5a4d
#define PE_ENTRY_OFFSET sizeof(uint32_t) <<2
typedef struct mz_hdr MZ_fh;
typedef struct pe_hdr PE_fh;

/*  enum type   */
typedef enum {
    BIN_TYPE_UNKNOWN=-1,
    BIN_TYPE_ELF32,
    BIN_TYPE_ELF64,
    BIN_TYPE_PE
}bin_type;

typedef enum {
    ARCH_UNKNOWN=-1,
    ARCH_X86,
    ARCH_X64
}bin_arch;

typedef enum {
    SYM_TYPE_FUNC,
    SYM_TYPE_DYN_FUNC,
}sym_type;

typedef enum {
    SECT_TYPE_CODE=0,
    SECT_TYPE_DATA,
}sect_type;

typedef enum{
    PH_DYNAMIC,
    PH_GNU_RELRO,
    PH_GNU_STACK,
    PH_LOAD,
    PH_INTERP,
    PH_UNKNOWN
}ph_type;

/*  struct Symbol: Section: Binary  */
typedef struct Symbol{
    sym_type sym_type;
    /*  function name or string content */
    const char *sym_name;
    uint64_t sym_addr;
    /*  link    */
    struct Symbol *sym_next;
}Symbol;

typedef struct Section{
    sect_type sect_type;
    const char* sect_name;
    uintptr_t sect_vma;
    uint64_t sect_size;
    /*  contents    */
    uint8_t *sec_bytes;
    /*  link    */
    struct Section *sect_next;
}Section;

typedef struct Programh{
    /*  segments type   */
    ph_type sgm_type;
    /*  segments vma    */
    uintptr_t sgm_vma;
    /*  segment flag    */
    uint64_t sgm_flag;
    /*  link    */
    struct Programh *ph_next;
}Programh;

typedef struct Header{
    /*  file header */
    union{
        E32_fh *e32fh;
        E64_fh *e64fh;
        MZ_fh *mzfh;
    }Fileheader;
    /*  program header/pecoff header  */
    union{
        Programh *ph;
        PE_fh *peh;
    }Pxheader;

}Header;

typedef struct Binary{
   /* file format */
    bin_type bin_type;
    /*   arch  */
    bin_arch bin_arch;
    /*   binary name */
    const char *bin_name;
    /*   binary size */
    uint64_t bin_size;
    /*   entry point */
    uint64_t entry;
    /*  binary symbols  */
    Symbol *sym;
    /*  binary sections */
    Section *sect;
    /*  binary headers */
    Header *hd;
}Binary;

/*  load binary */
Binary *load_binary(char *fn);

/*  load symbols, sections  */
static void load_symbols(Binary *bin,void *mem);
static void load_info(Binary *bin,void *mem);
static void load_sections(Binary *bin,void *mem,uint64_t *sh_info);
static void load_programhs(Binary *bin,void *mem);
static void load_programhs(Binary *bin,void *mem);

/*  show all info   */
void show_symbols(Binary *bin);
void show_sections(Binary *bin);

#endif