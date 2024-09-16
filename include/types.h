#ifndef _TYPES_H_
#define _TYPES_H_

/*  macro constant  */

/*  basic check functions   */
#define CHK_BAS_NUM 8
/*  extented check functions    */
#define CHK_EXT_NUM 2
/*  sanitized num   */
#define CHK_SAN_NUM 7
/*  ibt and shadow-stack    */
#define CHK_CET_NUM 2
/*  proc check functions    */
#define CHK_PROC_NUM 2
/*  kernel check functions    */
#define CHK_KERN_NUM 9
/*  libc path ,up to bin_arch  */
#define CHK_LIBC_PATH_NUM 3
/*  hashmap size    */
#define HASHMAP_SIZE (2 << 6)
/*  max buffer size */
#define MAXBUF 4096

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
    cpo_all,
    cpo_id,
}chk_proc_option;

/*  cro enum    */
typedef enum{
    cro_open,
    cro_reverse,
}chk_remote_option;

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
    CHK_KERNEL,
    CHK_REMOTE,
}chk_func;

/*  chk information struct  */
typedef struct chk_info{
    char *chk_type;
    char *chk_result;
    struct chk_info *chk_next;
}chk_info;

/*  str struct  */
typedef struct strlink{
    char *_str;
    struct strlink *_next;
}strlink;

#endif