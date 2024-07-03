#ifndef _TYPES_H_
#define _TYPES_H_

/*  global flag   */
bool DEBUG;
bool VERBOSE;
bool EXTENTED;
output OUTPUT;

/*  macro constant  */
#define CHK_BAS_NUM 8
#define CHK_EXT_NUM 2
#define CHK_SAN_NUM 7
#define CHK_CET_NUM 2

/*  c bool enum */
typedef enum{
    false=0,
    true
}bool;

/*  cfo enum    */
typedef enum {
    cfo_file,
    cfo_dir,
    cfo_listfile,
}chk_file_option;

/*  cpo enum    */
typedef enum {
    cpo_name,
    cpo_all,
    cpo_id,
}chk_proc_option;

/*  output format enum  */
typedef enum{
    cli,
    csv,
    xml,
    json
}output;

/*  check function enum */
typedef enum{
    CHK_UNKNOWN,
    CHK_FILE,
    CHK_PROC,
    CHK_KERNEL
}chk_func;

/*  chk information struct  */
typedef struct chk_info{
    char *chk_type;
    char *chk_result;
    struct chk_info *chk_next;
}chk_info;


#endif