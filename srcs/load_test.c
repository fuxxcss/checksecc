#include "loader.h"
#include "loader.c"
#include<stdio.h>
#include<fcntl.h>

int main(){
    int fd=open("/root/test",O_RDONLY);
    Binary *bin=load_binary("/root/test",fd);
    if(bin){
    show_sections(bin);
    show_symbols(bin);
    }
}