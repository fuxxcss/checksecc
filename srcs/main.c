#include<stdio.h>
#include<stdlib.h>
#include<getopt.h>
#include<stdint.h>
#include"functions.h"
#include"types.h"

/*  usage   */
static void help(){
    printf("Usage: checkc [--format={cli,csv,xml,json}] [OPTION]\n\n\
      Options:\n\
      ## Checksec Options\n\
      --file={file}\n\
      --dir={directory}\n\
      --listfile={file list separated by |}\n\
      --proc={process name}\n\
      --proc-all\n\
      --proc-libs={process ID}\n\
      --kernel[=kconfig]\n\
      --version\n\
      --help\n\n\
     ## Modifiers\n\
      --debug\n\
      --verbose\n\
      --format={cli,csv,xml,json}\n\
      --output={cli,csv,xml,json}\n\
      --extended\n\n\
For more information, see:\n\
https://github.com/fuxxcss/checksecc\n\n");
    exit(0);
}

/*  version info    */
static void version(){
    printf("checksecc v0.1,fuxxcss\n\
https://github.com/fuxxcss/checksecc\n\n");
    exit(0);
}

/*  long options args   */
static struct option long_options[]={
    {"file",required_argument,NULL,'0'},
    {"dir",required_argument,NULL,'1'},
    {"listfile",required_argument,NULL,'2'},
    {"proc",required_argument,NULL,'3'},
    {"proc-all",no_argument,NULL,'4'},
    {"proc-libs",required_argument,NULL,'5'},
    {"kernel",optional_argument,NULL,'6'},
    {"version",no_argument,NULL,'v'},
    {"help",no_argument,NULL,'h'},
    {"debug",no_argument,NULL,'d'},
    {"verbose",no_argument,NULL,'r'},
    {"format",required_argument,NULL,'f'},
    {"output",required_argument,NULL,'f'},
    {"extended",no_argument,NULL,'e'}
};

/*  check function  type*/
static chk_func func=CHK_UNKNOWN;
static char *arg;
static uint8_t chk_mode;

/*  parse args  */
static void parse_args(int *pargc,char ***pargv){
    if(*pargc <2) help();
    /*  option args */
    char *optstring="vh";
    int opt;
    int index=0;
    /*  match option, long option   */
    while((opt=getopt_long(*pargc,*pargv,optstring,long_options,&index))!=-1){
        switch (opt)
        {
        case 'v':
            version();
            break;
        case 'h':
            help();
            break;
        case '0':
            func=CHK_FILE;
            arg=optarg;
            chk_mode=cfo_file;
            break;
        case '1':
            func=CHK_FILE;
            arg=optarg;
            chk_mode=cfo_dir;
            break;
        case '2':
            func=CHK_FILE;
            arg=optarg;
            chk_mode=cfo_listfile;
            break;
        case '3':
            func=CHK_PROC;
            arg=optarg;
            chk_mode=cpo_name;
            break;
        case '4':
            func=CHK_PROC;
            arg=optarg;
            chk_mode=cpo_all;
            break;
        case '5':
            func=CHK_PROC;
            arg=optarg;
            chk_mode=cpo_id;
            break;
        case '6':
            func=CHK_KERNEL;
            arg=optarg;
            break;
        case 'd':
            DEBUG=true;
            break;
        case 'r':
            VERBOSE=true;
            break;
        case 'f':
            OUTPUT=set_format(optarg);
        case 'e':
            EXTENTED=true;
            break;
        case '?':
            printf("\033[31mError:Unknown option %s.\033[m\n\n",&optopt);
            break;
        }
    }
}

/*  main func   */
int main(int argc,char **argv){
    parse_args(&argc,&argv);
    switch (func)
    {
    case CHK_FILE:
        chk_file(arg,chk_mode);
        break;
    case CHK_PROC:
        chk_proc(arg,chk_mode);
        break;
    case CHK_KERNEL:
        chk_kernel(arg);
        break;
    case CHK_UNKNOWN:
        printf("\033[31mError:Unknown check function.\033[m\n\n");
        break;
    }
}