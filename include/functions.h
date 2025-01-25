#ifndef _FUNC_H_
#define _FUNC_H_
#include<capstone/capstone.h>
#include"types.h"
#include"loader.h"

/*  expection handle    */
#define CHK_ERROR1(info) {\
    if(DEBUG)\
    printf("CHK ERROR:%s\n",info); \
    return;\
}

#define CHK_ERROR2(info1,info2) {\
    if(DEBUG)\
    printf("CHK ERROR:%s, %s\n",info1,info2); \
    return;\
}

#define CHK_ERROR3(info) {\
    if(DEBUG)\
    printf("CHK ERROR:%s\n",info); \
    return false;\
}

#define CHK_ERROR4(info) {\
    if(DEBUG)\
    printf("CHK ERROR:%s\n",info); \
    return NULL;\
}

#define CHK_PRINT1(info) printf("%s\n",info); 

#define CHK_PRINT2(info1,info2) printf("%s %s\n",info1,info2); 

#define CHK_PRINT3() printf("\n");


/*  get file size,return unsigned int   */
#define FILE_SIZE(fp) ({\
    fseek(fp,0,SEEK_END);\
    unsigned int size=ftell(fp);\
    fseek(fp,0,SEEK_SET);\
    size;\
})

#define gzFILE_SIZE(gzfp) ({\
    gzseek(gzfp,0,SEEK_END);\
    unsigned int size=gztell(gzfp);\
    gzseek(gzfp,0,SEEK_SET);\
    size;\
})

/*  loader func */
Binary *load_binary(char *fn);

size_t dis_asm(Binary *bin,csh *handle,cs_insn **insn);

void free_binary(Binary *bin);

void free_str();

/*  check files func    */
void chk_file(char *option,chk_file_option cfo);

chk_info *chk_file_one_elf(Binary *elf);

/*  check process func  */
void chk_proc(char *option,chk_proc_option cpo);

/*  check kernel func   */
void chk_kernel(char *kernelinfo,char *option); 

/*  set output format   */
output set_format(char *option);

/*  format output   */
void format_output(chk_info *info);

/*  str append  */
char *str_append(char *des,char *src);

#endif