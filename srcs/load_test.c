#include "loader.h"
#include "loader.c"
#include<stdio.h>
#include<fcntl.h>

int main(){
    Binary *bin=load_binary("/root/test");
    if(bin){
    if(bin->sect)
    show_sections(bin);
    show_symbols(bin);
    }
}