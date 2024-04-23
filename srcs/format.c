/*  utils.c covers
    set_format
    format_output
    */
#include<string.h>
#include<stdio.h>
#include"functions.h"
#include"types.h"

output set_format(char *option){
    if(strcmp(option,"cli") ==0) return cli;
    if(strcmp(option,"csv") ==0) return csv;
    if(strcmp(option,"xml") ==0) return xml;
    if(strcmp(option,"json") ==0) return json;
    return cli;
}

static void cli_output(chk_info *info){
    /*  todo: draw color    */
    info=info->chk_next;
    while(info){
        printf("%-28s%s\n",info->chk_type,info->chk_result);
        info=info->chk_next;
    }
}

static void csv_output(chk_info *info){
    info=info->chk_next;
    printf("%s",info->chk_result);
    info=info->chk_next;
    while(info){
        printf(",%s",info->chk_result);
        info=info->chk_next;
    }
    printf("\n");
}

static void xml_output(chk_info *info){
    info=info->chk_next;
    printf("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    printf("<");
    while(info){
        printf("%s=\"%s\" ",info->chk_type,info->chk_result);
        info=info->chk_next;
    }
    printf("/>\n");
}

static void json_output(chk_info *info){
    info=info->chk_next;
    printf("{\"%s\":{",info->chk_result);
    info=info->chk_next;
    printf("\"%s\":\"%s\"",info->chk_type,info->chk_result);
    info=info->chk_next;
    while(info){
        printf(",\"%s\":\"%s\"");
        info=info->chk_next;
    }
    printf("}}\n");
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
}