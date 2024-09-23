#include<string.h>
#include<sys/socket.h> 
#include<netinet/in.h>
#include<openssl/ssl.h> 
#include"functions.h"
#include"types.h"
#include"loader.h"

/*  check overflow  */
bool str_check(char *str,unsigned int len){
    unsigned int i=0;
    for(;str[i] != '\0';i++);
    if(i >= len-1) return false;
    return true;
}

/*  SSL Content Text    */
SSL_CTX *ssl_init(){
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    SSL_CTX * ctx;
    ctx = SSL_CTX_new(SSLv23_client_method());
    return ctx;
}

void ssl_finish(SSL *ssl,SSL_CTX *ctx){
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
}

/*  SSL connect */
SSL *ssl_connect(SSL_CTX *ctx,struct sockaddr_in *dest,char *ip,char *port){
    int sockfd;
    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        return NULL;
    }
    dest->sin_family = AF_INET;
    dest->sin_port = htons(atoi(port));
    if(inet_aton(ip,(struct in_addr *)dest->sin_addr.s_addr) == 0){
        return NULL;
    }
    if (connect(sockfd,(struct sockaddr *)dest, sizeof(dest)) != 0){
        return NULL;
    }
    SSL *ssl;
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) == -1){
        return NULL;
    }
    return ssl;
}

/*  SSL bind    */
SSL *ssl_bind(SSL_CTX *ctx,struct sockaddr_in *my,char *port){
    int sockfd,new_fd;
    struct sockaddr_in their;
    socklen_t len;
    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        return NULL;
    }
    my->sin_family = PF_INET;
    my->sin_port = htons(atoi(port));
    my->sin_addr.s_addr = INADDR_ANY;
    if(bind(sockfd, (struct sockaddr *)my,sizeof(struct sockaddr)) == -1){
        return NULL;
    }
    if((new_fd = accept(sockfd, (struct sockaddr *)&their, &len)) == -1){
        return NULL;
    }
    SSL *ssl;
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, new_fd);
    if (SSL_accept(ssl) == -1){
        close(new_fd);
        return NULL;
    }
    return ssl;
}

/*  send shell commands */
bool ssl_send(SSL *ssl,char *buf){
    unsigned int len=SSL_write(ssl, buf, strlen(buf));
    if (len <= 0) return false;
    else CHK_PRINT2("Send Commands",buf);
    return true;
}

/*  receive outputs */
bool ssl_receive(SSL *ssl,char *buf,unsigned int num){
    unsigned int len=SSL_read(ssl,buf,num);
    if(len <= 0) return false;
    return true;
}

/*  check remote kernel */
void chk_remote_kernel(SSL *ssl){
    // req
    char req[5]={'K','E','R','N','\0'};
    if(!ssl_send(ssl,req)) CHK_ERROR1("send req failed");
    // ack
    char ack[4];
    if(!ssl_receive(ssl,ack,4) && strcmp(ack,"ACK") != 0) CHK_ERROR1("ack failed");
    // 4 bytes size
    unsigned int size=0;
    if(!ssl_receive(ssl,&size,4)) CHK_ERROR1("receive config size failed");
    // kernel info
    char *kernelinfo=MALLOC(size,char);
    if(!ssl_receive(ssl,kernelinfo,size)) CHK_ERROR1("receive config failed");
    /*  check kernel    */
    chk_kernel(kernelinfo,NULL);
}

/*  check remote procs  */
void chk_remote_proc(SSL *ssl){
    // req
    char req[5]={'P','R','O','C','\0'};
    if(!ssl_send(ssl,req)) CHK_ERROR1("send req failed");
    // ack
    char ack[4];
    if(!ssl_receive(ssl,ack,4) && strcmp(ack,"ACK") != 0) CHK_ERROR1("ack failed");
    // 4 bytes proc num
    unsigned int pn=0;
    if(!ssl_receive(ssl,&pn,4)) CHK_ERROR1("receive proc num failed");
    for(unsigned int i=0;i < pn;i++){
        // 4 bytes size
        unsigned int file_size=0;
        if(!ssl_receive(ssl,&file_size,4)) CHK_ERROR1("receive file size failed");
        // 4 bytes pid
        unsigned int pid=0;
        if(!ssl_receive(ssl,&pid,4)) CHK_ERROR1("receive pid failed");
        // 64 bytes name
        char file_name[64];
        if(!ssl_receive(ssl,&file_name,64)) CHK_ERROR1("receive exe name failed");
        // receive file
        char *file_mem=MALLOC(file_size,char);
        if(!ssl_receive(ssl,file_mem,file_size)) CHK_ERROR1("receive exe failed");
        /*  Binary init , edit from loader.c    */
        Binary *bin=MALLOC(1,Binary);
        bin->mem=file_mem;
        bin->bin_size=file_size;
        bin->bin_name=file_name;
        load_info(bin);
        if(bin->bin_type < 0) LDR_ERROR3(file_name,"unsupported binary type.");
        if(bin->bin_arch < 0) LDR_ERROR3(file_name,"unsupported architecture.");
        if(bin->entry ==0 ) LDR_ERROR1(file_name,"cannot find entry point.");
        bin->sect=NULL;
        bin->sym=NULL;
        load_elf(bin);
        if(bin->sect->sect_next == NULL) LDR_ERROR3(file_name,"load sections failed.");
        if(bin->sym->sym_next == NULL) LDR_ERROR3(file_name,"load symbols failed.");
        if(bin->hd == NULL) LDR_ERROR3(file_name,"load headers failed.");
        /*  check file  */
        chk_info *head;
        head=chk_file_one_elf(bin);
        // head insert pid
        chk_info *new=MALLOC(1,chk_info);
        new->chk_type="PID";
        new->chk_result=pid;
        new->chk_next=head->chk_next;
        head->chk_next=new;
        //format output
        format_output(head);
        // free load
        free_binary(bin);
    }
}

/*  check remote procs and kernel   */
void chk_remote(char *option,chk_remote_option cro){
    /* ip 255.255.255.255   */
    char ip[16];
    /*  port 0~65535    */
    char port[6];
    /*  ssl init    */
    SSL_CTX *ctx=ssl_init();
    if (ctx == NULL){
        ERR_print_errors_fp(stdout);
        return;
    }
    struct sockaddr_in *in=MALLOC(1,struct sockaddr_in);
    /*  common ssl  */
    SSL *ssl;
    switch(cro)
    {
    case cro_open:
    /*  
     *              ssl connect 
     *  remote.port <---------- local
     */
        sscanf(option,"%s:%s",ip,port);
        if(!str_check(ip,16) || !str_check(port,6)) 
            CHK_ERROR1("incorrect ip:port");
        ssl=ssl_connect(ctx,in,ip,port);
        break;
    case cro_reverse:
    /*  
     *         ssl connect 
     *  remote ----------> local.port
     */
        if(!str_check(option,6))
            CHK_ERROR1("incorrect port");
        ssl=ssl_bind(ctx,in,option);
        break;
    }
    
    ssl_finish(ssl,ctx);
}