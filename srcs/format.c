#include<string.h>
#include<stdio.h>
#include<stdbool.h>
#include"functions.h"
#include"types.h"
#include"loader.h"

/*  global flag   */
bool EXTENTED;
bool DEBUG;
output OUTPUT;

/*  global str link */
strlink sl;

output set_format(char *option){
    if(strcmp(option,"cli") ==0) return cli;
    if(strcmp(option,"csv") ==0) return csv;
    if(strcmp(option,"xml") ==0) return xml;
    if(strcmp(option,"json") ==0) return json;
    return cli;
}

static void cli_output(chk_info *info){
    info=info->chk_next;
    while(info){
        printf("%-28s%s\n",info->chk_type,info->chk_result);
        info=info->chk_next;
    }
}

static void csv_output(chk_info *info){
    info=info->chk_next;
    size_t len = strlen(info->chk_result);
    printf("%.*s",len-3,info->chk_result+5);
    info=info->chk_next;
    while(info){
        size_t len = strlen(info->chk_result);
        // len of '\033[m' = 3
        // len of '\033[31m' = 5
        printf(",%.*s",len-3,info->chk_result+5);
        info=info->chk_next;
    }
    printf("\n");
}

static void xml_output(chk_info *info){
    info=info->chk_next;
    printf("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    printf("<");
    while(info){
        size_t len = strlen(info->chk_result);
        printf("%s=\"%.*s\" ",info->chk_type,len-3,info->chk_result+5);
        info=info->chk_next;
    }
    printf("/>\n");
}

static void json_output(chk_info *info){
    info=info->chk_next;
    size_t len = strlen(info->chk_result);
    printf("{\"%.*s\":{",len-3,info->chk_result+5);
    info=info->chk_next;
    len = strlen(info->chk_result);
    printf("\"%s\":\"%.*s\"",info->chk_type,len-3,info->chk_result+5);
    info=info->chk_next;
    while(info){
        len = strlen(info->chk_result);
        printf(",\"%s\":\"%.*s\"",info->chk_type,len-3,info->chk_result+5);
        info=info->chk_next;
    }
    printf("}}\n");
}

void free_chk_info(chk_info *info){
    chk_info *head=info;
    info=info->chk_next;
    while(info){
        chk_info *tmp=info;
        info=info->chk_next;
        free(tmp);
    }
    free(head);
}

void format_output(chk_info *info){
    switch (OUTPUT)
    {
    case cli:
        cli_output(info);
        break;
    case csv:
        csv_output(info);
        break;
    case xml:
        xml_output(info);
        break;
    case json:
        json_output(info);
        break;
    }
    free_chk_info(info);
}

/*  append string [des src]*/
char *str_append(char *des,char *src){
    if(des == NULL || src == NULL) return NULL;
    size_t des_size=0;
    for(;des[des_size] != '\0';des_size++);
    size_t src_size=0;
    for(;src[src_size] != '\0';src_size++);
    size_t append_size=des_size+src_size;
    /*  plus one for '\0'  */
    char *append=MALLOC(append_size+1,char);
    for(size_t i=0;i<des_size;i++) append[i]=des[i];
    for(size_t i=0;i<src_size;i++) append[i+des_size]=src[i];
    append[append_size]='\0';
    /*  head insert */
    strlink *new=MALLOC(1,strlink);
    new->_str=append;
    new->_next=sl._next;
    sl._next=new;

    return append;
}

/*  free string by strlink  */
void free_str(){
    strlink *next=sl._next;
    while(next){
        strlink *tmp=next;
        next=next->_next;
        free(tmp->_str);
        free(tmp);
    }
}