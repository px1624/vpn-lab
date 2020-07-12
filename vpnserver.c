#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <openssl/opensslv.h>
#include <shadow.h>
#include <crypt.h>

#define PORT_NUMBER 55555
#define BUFF_SIZE 2000
#define MAX_CLIENT 10

#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }

typedef struct ip_fd{
    pid_t pid;
    struct in_addr ip;
    struct in_addr intf_addr;
    int fd_read;
    int fd_write;
} IP_FD;

IP_FD *pairs[MAX_CLIENT] = {0};

struct timeval TIMEOUT = {
    .tv_sec = 0,
    .tv_usec = 100
};
struct sockaddr_in peerAddr;

int createTunDevice() {
   int tunfd;
   struct ifreq ifr;
   memset(&ifr, 0, sizeof(ifr));

   ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  

   tunfd = open("/dev/net/tun", O_RDWR);
   ioctl(tunfd, TUNSETIFF, &ifr);       

   return tunfd;
}

int initTCPServer() {
    int sockfd;
    struct sockaddr_in server;
    char buff[100];

    sockfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHK_ERR(sockfd, "socket");
    memset(&server, '\0', sizeof(server));
    server.sin_family = AF_INET;                 
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(PORT_NUMBER);        

    int err = bind(sockfd, (struct sockaddr*) &server, sizeof(server)); 

    CHK_ERR(err, "bind");
    err = listen(sockfd, 5);
    CHK_ERR(err, "listen");
    printf("Listening on port %d...\n", PORT_NUMBER);
    return sockfd;
}

struct in_addr get_intf_addr(int newfd){
    struct sockaddr_in sa;
    char buff[BUFF_SIZE];
    int len;
    len = read(newfd, buff, BUFF_SIZE);
    inet_pton(AF_INET, buff, &(sa.sin_addr));
    return sa.sin_addr;
}

int comp_addr(struct in_addr *addr1, struct in_addr *addr2){
    char *a = malloc(20);
    char *b = malloc(20);
    bzero(a, 20); bzero(b, 20);
    char *tmp = inet_ntoa(*addr1);
    a = strcpy(a, tmp);
    tmp = inet_ntoa(*addr2);
    b = strcpy(b, tmp);
    int result = strcmp(a, b);
    free(a); free(b);
    return result;
}

void tun_to_child(int tunfd){
    int i;
    int  len;
    char buff[BUFF_SIZE];
    struct in_addr addr;

    bzero(buff, BUFF_SIZE);
    len = read(tunfd, buff, BUFF_SIZE);
    addr.s_addr = *((uint32_t *)(buff + 16));
    for(i = 0; i < MAX_CLIENT; i++){
        if(pairs[i] != NULL && comp_addr(&addr, &(pairs[i]->intf_addr)) == 0){
            printf("Got a packet from TUN: %s, sending it to child\n", inet_ntoa(pairs[i]->ip));
            write(pairs[i]->fd_write, buff, len);
            break;
        }
    }
}

void child_to_tun(int tunfd, int child_fd){
    int i;
    int  len;
    char buff[BUFF_SIZE];

    bzero(buff, BUFF_SIZE);
    len = read(child_fd, buff, BUFF_SIZE);
    write(tunfd, buff, len);
}

void tunSelected(int tunfd, SSL *ssl){
    int  len;
    char buff[BUFF_SIZE];
    int err;

    bzero(buff, BUFF_SIZE);
    len = read(tunfd, buff, BUFF_SIZE);
    err = SSL_write(ssl, buff, len);
    if(SSL_get_error(ssl, err) == SSL_ERROR_ZERO_RETURN){
        perror("SSL_write");
        close(tunfd);
        SSL_shutdown(ssl);  SSL_free(ssl);
        exit(1);
    }
}

void sslSelected (int tunfd, SSL *ssl){
    int  len;
    char buff[BUFF_SIZE];
    int err;
    bzero(buff, BUFF_SIZE);
    len = SSL_read(ssl, buff, BUFF_SIZE);
    if(len <= 0){
        perror("SSL_read");
        close(tunfd);
        SSL_shutdown(ssl);  SSL_free(ssl);
        exit(1);
    }
    printf("Got a packet from the tunnel\n");
    write(tunfd, buff, len);
}

// Return 1 if login succeeded, 0 if failed
int login(SSL *ssl){
    char buff[42];
    char *username;
    char *password;
    char *epasswd;
    struct spwd *pw;

    bzero(buff, 42);
    SSL_read(ssl, buff, 42);
    username = strtok(buff, " ");
    password = strtok(NULL, " ");
    printf("Username: %s\nPassword: %s\n", username, password);
    pw = getspnam(username);
    if(pw == NULL){
        return 0;
    }
    printf("sp_namp: %s\nsp_pwdp: %s\n", pw->sp_namp, pw->sp_pwdp);
    epasswd = crypt(password, pw->sp_pwdp);
    if(strcmp(epasswd, pw->sp_pwdp)){
        return 0;
    }
    return 1;
}
int main (int argc, char * argv[]) {

    int tunfd, listen_fd;
    SSL_METHOD *meth;
    SSL_CTX* ctx;
    SSL *ssl;
    int err;
    char buf[1024];
    char *server_cert;
    char *server_key;

    if(argc < 3){
        printf("Please provide server certificate and key file\n");
        exit(1);
    } else {
        server_cert = argv[1];
        server_key = argv[2];
    }
    printf("Using openssl version: %s\n", OPENSSL_VERSION_TEXT);

    // Step 0: OpenSSL library initialization 
    // This step is no longer needed as of version 1.1.0.
    printf("Initializing openSSL Library...\n");
    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();
    // Step 1: SSL context initialization
    printf("Initializing SSL context...\n");
    meth = (SSL_METHOD *)TLSv1_2_method();
    ctx = SSL_CTX_new(meth);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    // Step 2: Set up the server certificate and private key
    printf("Set server certificate...\n");
    SSL_CTX_use_certificate_file(ctx, server_cert, SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, server_key, SSL_FILETYPE_PEM);
    
    ssl = SSL_new (ctx);

    printf("Creating TUN interface...\n");
    tunfd  = createTunDevice();
    printf("Initializing TCP connection...\n");
    listen_fd = initTCPServer();

    // non-blocking listen fd
    int flags = fcntl(listen_fd, F_GETFL, 0);
    flags |= O_NONBLOCK;
    fcntl(listen_fd, F_SETFL, flags);

    while(1){
        int pipe_rd[2];
        int pipe_wt[2];

        int peerAddrLen = sizeof(struct sockaddr_in);
        int newfd = accept(listen_fd, (struct sockaddr *) &peerAddr, &peerAddrLen);
        if(newfd < 0){
            int i;
            fd_set rdSet;
            FD_ZERO(&rdSet);
            FD_SET(tunfd, &rdSet);
            for(i = 0; i < MAX_CLIENT; i++){
                if(pairs[i] != NULL){
                    if(waitpid(pairs[i]->pid, NULL, WNOHANG) == pairs[i]->pid){
                        printf("Child process %d exited. Resources freed.\n", pairs[i]->pid);
                        close(pairs[i]->fd_read);
                        close(pairs[i]->fd_write);
                        free(pairs[i]);
                        pairs[i] = NULL;
                    } else {
                        FD_SET(pairs[i]->fd_read, &rdSet);
                    }
                }
            }
            if(select(FD_SETSIZE, &rdSet, NULL, NULL, &TIMEOUT) > 0){
                if(FD_ISSET(tunfd,  &rdSet)) tun_to_child(tunfd);
                for(i = 0; i < MAX_CLIENT; i++){
                    if((pairs[i] != NULL) && FD_ISSET(pairs[i]->fd_read,  &rdSet)){
                        child_to_tun(tunfd, pairs[i]->fd_read);
                    }
                }
            }

            continue;
        }
        struct in_addr tmp;
        tmp = get_intf_addr(newfd);

        printf("Accept a connection from ip: %s\n", inet_ntoa(peerAddr.sin_addr));
        pipe(pipe_rd);
        pipe(pipe_wt);
        pid_t pid = fork();
        if(pid == 0){ // Child process
            close(tunfd);
            close(pipe_rd[0]);
            close(pipe_wt[1]);
            SSL_set_fd (ssl, newfd);
            err = SSL_accept (ssl);
            CHK_SSL(err);
            printf ("SSL connection established!\n");
            if(login(ssl) == 0){
                printf("Client authentication failed!\n");
                close(listen_fd);
                close(newfd);
                SSL_shutdown(ssl); SSL_free(ssl);
                exit(1);
            }
            printf("Client authentication succeeded!\n");
            // Enter the main loop
            while (1) {
                fd_set readFDSet;

                FD_ZERO(&readFDSet);
                FD_SET(pipe_wt[0], &readFDSet);
                FD_SET(newfd, &readFDSet);
                select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

                if(FD_ISSET(pipe_wt[0],  &readFDSet)) tunSelected(pipe_wt[0], ssl);
                if(FD_ISSET(newfd,  &readFDSet)) sslSelected(pipe_rd[1], ssl);
            }
        } else if(pid > 0){ // Parent process
            close(newfd);
            close(pipe_rd[1]);
            close(pipe_wt[0]);
            int i;
            IP_FD *pair = malloc(sizeof(IP_FD));
            pair->ip = peerAddr.sin_addr;
            pair->fd_write = pipe_wt[1];
            pair->fd_read = pipe_rd[0];
            pair->pid = pid;
            pair->intf_addr = tmp;
            for(i = 0; i < MAX_CLIENT; i++){
                if(pairs[i] == NULL){
                    pairs[i] = pair;
                    break;
                }
            }
        } else {
            close(newfd);
            close(pipe_rd[0]);
            close(pipe_rd[1]);
            close(pipe_wt[0]);
            close(pipe_wt[1]);
            printf("Failed to create a process!\n");
        }
        
    }
}
 
