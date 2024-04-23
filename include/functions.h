#ifndef _FUNC_H_
#define _FUNC_H_
#include "types.h"

/*  expection handle    */
#define CHK_ERROR1(info) {\
    printf("CHK ERROR:%s\n",info); \
};

#define CHK_ERROR2(info1,info2) {\
    printf("CHK ERROR:%s, %s\n",info1,info2); \
};

#define CHK_ERROR3(info) {\
    printf("CHK ERROR:%s\n",info); \
    return false;\
};

/*  check files func    */
void chk_file(char *option,chk_file_option cfo);

/*  check process func  */
void chk_proc(char *option,chk_proc_option cpo);

/*  check kernel func   */
void chk_kernel(char *option); //optional option

/*  set output format   */
output set_format(char *option);

/*  format output   */
void format_output(chk_info *info);


#endif