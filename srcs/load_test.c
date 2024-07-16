#include "loader.h"
#include "loader.c"
#include<stdio.h>
#include<fcntl.h>

int main(){
    Binary *bin=load_binary("/lib/x86_64-linux-gnu/libc.so.6");
    if(bin){
    show_sections(bin);
    show_symbols(bin);
    }
}