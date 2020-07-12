#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CA_DIR "ca_client" 

#define BUFF_SIZE 2000
struct sockaddr_in peerAddr;

int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    char  buf[300];

    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
    printf("subject= %s\n", buf);

    if (preverify_ok == 1) {
        printf("Verification passed.\n");
        return 1;
    } else {
        int err = X509_STORE_CTX_get_error(x509_ctx);
        printf("Verification failed: %s.\n",
                        X509_verify_cert_error_string(err));
        return 0;
    }
}

int createTunDevice() {
    int tunfd;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  

    tunfd = open("/dev/net/tun", O_RDWR);
    ioctl(tunfd, TUNSETIFF, &ifr);       

    return tunfd;
}

SSL* setupTLSClient(const char* hostname)
{
    // Step 0: OpenSSL library initialization 
    // This step is no longer needed as of version 1.1.0.
    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();

    SSL_METHOD *meth;
    SSL_CTX* ctx;
    SSL* ssl;

    meth = (SSL_METHOD *)TLSv1_2_method();
    ctx = SSL_CTX_new(meth);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
    if(SSL_CTX_load_verify_locations(ctx,NULL, CA_DIR) < 1){
        printf("Error setting the verify locations. \n");
        exit(0);
    }
    ssl = SSL_new (ctx);
    X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl); 
    X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);

    return ssl;
}

void send_intf_addr(int sockfd){
    char intf_addr[20];
    bzero(intf_addr, 20);
    printf("Tun0 interface address: ");
    scanf("%s", intf_addr);
    write(sockfd, intf_addr, strlen(intf_addr) + 1);
}

int connectToTCPServer(char *hostname, int port){
    int sockfd;
    char *hello="Hello";

    // Get the IP address from hostname
    struct hostent* hp = gethostbyname(hostname);
    
    // Create a TCP socket
    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    //Fill in the destination information (IP, port #, and family)
    memset(&peerAddr, '\0', sizeof(peerAddr));
    memcpy(&(peerAddr.sin_addr.s_addr), hp->h_addr, hp->h_length);
    peerAddr.sin_family = AF_INET;
    peerAddr.sin_port = htons(port);

    // connect to the destination
    if(connect(sockfd, (struct sockaddr *) &peerAddr, sizeof(peerAddr)) == 0){
        printf("TCP connection established!\n");
    } else {
        printf("TCP connection failed to establish!\n");
    }

    send_intf_addr(sockfd);
    return sockfd;
}


void tunSelected(int tunfd, SSL *ssl){
    int  len;
    char buff[BUFF_SIZE];
    int err;

    printf("Got a packet from TUN\n");
    bzero(buff, BUFF_SIZE);
    len = read(tunfd, buff, BUFF_SIZE);
    SSL_write(ssl, buff, len);
}

void sslSelected (int tunfd, SSL *ssl){
    int  len;
    char buff[BUFF_SIZE];
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

// Get user credential and send to server for verification
void send_cred(SSL *ssl){
    char username[21];
    char *password;
    char *msg = malloc(42);
    
    bzero(username, 21);
    bzero(msg, 42);
    printf("Username: ");
    scanf("%s", username);
    password = getpass("Password: ");
    msg = strcat(msg, username);
    msg = strcat(msg, " ");
    msg = strcat(msg, password);
    printf("\nUsername entered: %s\nPassword entered: %s\n", username, password);
    SSL_write(ssl, msg, strlen(msg) + 1);
    free(msg);
}

int main (int argc, char * argv[]) {
    int tunfd, sockfd;
    char *hostname;
    int port;

    if (argc < 2){
        printf("Please provide server name and port!\n");
        exit(1);
    } else {
        hostname = argv[1];
        port = atoi(argv[2]);
    }

    /*----------------TLS initialization ----------------*/
    SSL *ssl   = setupTLSClient(hostname);

    /*----------------Create a TCP connection ---------------*/
    sockfd = connectToTCPServer(hostname, port);

    /*----------------TLS handshake ---------------------*/
    SSL_set_fd(ssl, sockfd);
    int err = SSL_connect(ssl); CHK_SSL(err);
    printf("SSL connection is successful\n");
    printf ("SSL connection using %s\n", SSL_get_cipher(ssl));
    tunfd  = createTunDevice();

    send_cred(ssl);
    // Enter the main loop
    while (1) {
        fd_set readFDSet;

        FD_ZERO(&readFDSet);
        FD_SET(tunfd, &readFDSet);
        FD_SET(sockfd, &readFDSet);
        select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

        if (FD_ISSET(tunfd,  &readFDSet)) tunSelected(tunfd, ssl);
        if (FD_ISSET(sockfd,  &readFDSet)) sslSelected(tunfd, ssl);
    }
}

