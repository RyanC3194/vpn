/**************************************************************************
 * simpletun.c                                                            *
 *                                                                        *
 * A simplistic, simple-minded, naive tunnelling program using tun/tap    *
 * interfaces and TCP. Handles (badly) IPv4 for tun, ARP and IPv4 for     *
 * tap. DO NOT USE THIS PROGRAM FOR SERIOUS PURPOSES.                     *
 *                                                                        *
 * You have been warned.                                                  *
 *                                                                        *
 * (C) 2009 Davide Brini.                                                 *
 *                                                                        *
 * DISCLAIMER AND WARNING: this is all work in progress. The code is      *
 * ugly, the algorithms are naive, error checking and input validation    *
 * are very basic, and of course there can be bugs. If that's not enough, *
 * the program has not been thoroughly tested, so it might even fail at   *
 * the few simple things it should be supposed to do right.               *
 * Needless to say, I take no responsibility whatsoever for what the      *
 * program might do. The program has been written mostly for learning     *
 * purposes, and can be used in the hope that is useful, but everything   *
 * is to be taken "as is" and without any kind of warranty, implicit or   *
 * explicit. See the file LICENSE for further details.                    *
 *************************************************************************/ 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000   
#define CLIENT 0
#define SERVER 1
#define PORT 55555

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

// Since we are using the same key for aes-256 and hmac-sha256, and key length for aes-256 is 32 bytes, so the key length for hmac-sha256 is also 32 bytes
# define KEY_LENGTH 32
// the length of the hash from HMAC-sha256 is 32 bytes
# define HASH_LENGTH 32
# define IV_LENGTH 16


// temp key
# define KEY "11111111111111111111111111111111"
# define IV "1111111111111111"

int debug;
char *progname;

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            needs to reserve enough space in *dev.                      *
 **************************************************************************/
int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;

  if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n){
  
  int nread;

  if((nread=read(fd, buf, n))<0){
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n){
  
  int nwrite;

  if((nwrite=write(fd, buf, n))<0){
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}


/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts those into "buf".    *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n) {

  int nread, left = n;

  while(left > 0) {
    if ((nread = cread(fd, buf, left))==0){
      return 0 ;      
    }else {
      left -= nread;
      buf += nread;
    }
  }
  return n;  
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *msg, ...){
  
  va_list argp;
  
  if(debug){
        va_start(argp, msg);
        vfprintf(stderr, msg, argp);
        va_end(argp);
  }
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...) {

  va_list argp;
  
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}



//=============Encryptions================//

// error handling
void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

/**************************************************************************
 * hmac_sha256: compute the keyed hash value of a data                    *
 * return HMAC_SHA256(key, data)                                          *
 * @param key the key used in hmac_sha256                                 *
 * @param data the data that will be hashed                               *
 * @param data_length the length of the data to hash                      *
 * @param result a buffer big enough to hold the result of the hash       *
 * @return pointer to the result of the hash (same as result param)       *
 **************************************************************************/
unsigned char *hmac_sha256(const char *key, const unsigned char *data, int data_length, unsigned char *result) {
    int result_len;
    return HMAC(EVP_sha256(), key, KEY_LENGTH, data, data_length, result, &result_len);
}


/*****************************************************************************************
 * encrypt: Encrypt data using AES-256 in CBC mode                                       *
 * Reference: https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption *                                                                             *
 * @param key key for AES-256                                                            *
 * @param iv the iv for AES-256 CBC mode                                                 *
 * @param plaintext the data that will be encrypted                                      *
 * @param plaintext_len the length of the data to be encrypted                           *
 * @param ciphertext a buffer big enough to hold the result of the encryption            *
 * @return the size of ciphertext in bytes                                               *
 *****************************************************************************************/
int encrypt(unsigned char *key, unsigned char *iv, unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

/*****************************************************************************************
 * decrypt: Decrypt data using AES-256 in CBC mode                                       *
 * Reference: https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption *                                                                             *
 * @param key key for AES-256                                                            *
 * @param iv the iv for AES-256 CBC mode                                                 *
 * @param ciphertext the data that will be decrypted                                     *
 * @param ciphertext_len the length of the data to be decrypted                          *
 * @param plaintext a buffer big enough to hold the result of the decryption             * 
 * @return the size of plaintext in bytes                                                *
 *****************************************************************************************/
int decrypt(unsigned char *key, unsigned char *iv, unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

/*****************************************************************************************
 * verify_hash: verify the hash of the data is the same as the hash passed in            *     
 * @param hash: the hash value to be compared                                            *
 * @param key key for HMAC-SHA256                                                        *
 * @param plaintext the data that will be hashed                                         *
 * @param plaintext_len the length of the data to be hashed                              *
 * @return 0 if hash from param == hash(key, data)                                       *
 *****************************************************************************************/
int verify_hash(const char * key,  unsigned char * hash, const char * plaintext, int plaintext_len) {
    unsigned char new_hash[HASH_LENGTH];
    hmac_sha256(key, plaintext, plaintext_len, new_hash);
    return memcmp(new_hash, hash, 32);
}


/****************************************************************************************************
 * mac_then_encrypt: prepend the hash of the data, and the encrypt the whole thing to achieve AE    *
 * @param key key for AES-256 and HMAC-SHA256                                                       *
 * @param iv the iv for AES-256 CBC mode                                                            *
 * @param plaintext the data that will be encrypted                                                 *
 * @param plaintext_len the length of the data to be encrypted                                      *
 * @param ciphertext a buffer big enough to hold the result of the encryption                       * 
 * @return the size of ciphertext in bytes                                                          *
 ****************************************************************************************************/
int mac_then_encrypt(unsigned char * key, unsigned char *iv, unsigned char * plaintext, int plaintext_len, unsigned char *ciphertext) {
    // first hash it
    unsigned char hash[HASH_LENGTH + plaintext_len + 32];
    hmac_sha256(key, plaintext, plaintext_len, hash);

    // concat the hash and the plain text
    memcpy(&hash[32], plaintext, plaintext_len);
    // encrypt the entire thing (hash | plain text)
    return encrypt(key, iv, hash, KEY_LENGTH + plaintext_len, ciphertext);
}

/*****************************************************************************************************
 * decrypt_verify: inverse of mac_then_encrypt, but if the hash and the data doesnt match, return -1 *
 * @param key key for AES-256 and HMAC-SHA256                                                        *
 * @param iv the iv for AES-256 CBC mode                                                             *
 * @param ciphertext the data that will be decrypted                                                 *
 * @param ciphertext_len the length of the data to be decrypted                                      *
 * @param plaintext a buffer big enough to hold the result of the decryption                         * 
 * @return -1 if the hash and data doesnt match                                                     *
 *         the size of ciphertext in bytes otherwise                                                 *
 *****************************************************************************************************/
int decrypt_verify(unsigned char * key, unsigned char *iv, unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext) {
    int plaintext_len = decrypt(key, iv, ciphertext, ciphertext_len, plaintext);

    
    // the first 32 bytes of the plaintext is the hash value, and the rest is the data
    if (verify_hash(key, plaintext, &plaintext[HASH_LENGTH], plaintext_len - HASH_LENGTH) != 0) {
        plaintext[0] = '\0';
        return -1;
    }

    // we dont need the hash part, so shift the array to the left
    int i;
    for (i = 0; i < plaintext_len - KEY_LENGTH; i++) {
        plaintext[i] = plaintext[i + KEY_LENGTH];
    }

    return plaintext_len - HASH_LENGTH;
}

void handle_client(SSL *ssl) {
    char buffer[1024];
    int bytes_received;

    // Read from client
    bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        printf("Received from client: %s\n", buffer);

        // Echo back to the client
        SSL_write(ssl, buffer, bytes_received);
    } else {
        ERR_print_errors_fp(stderr);
    }
}

int getKeyFromSSL(int port) {
  SSL_CTX *ctx;
  SSL_library_init();
  ctx = SSL_CTX_new(SSLv23_server_method());
  SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM);
  SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM);

  int server_socket, client_socket;
  struct sockaddr_in server_addr, client_addr;
  socklen_t client_addr_len = sizeof(client_addr);

  // Create socket
  if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
      perror("Error creating socket");
      exit(EXIT_FAILURE);
  }

  // Initialize server address
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  server_addr.sin_port = htons(port);

  // Bind socket to server address
  if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
      perror("Error binding socket");
      close(server_socket);
      exit(EXIT_FAILURE);
  }

  // Listen for incoming connections
  if (listen(server_socket, 5) == -1) {
      perror("Error listening for connections");
      close(server_socket);
      exit(EXIT_FAILURE);
  }

  printf("Server listening on port %d...\n", port);

  while (1) {
    // Accept connection
    if ((client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len)) == -1) {
        perror("Error accepting connection");
        return;
    }

    printf("SSL Connection accepted from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

    // Create SSL structure
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_socket);

    // Perform SSL handshake
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        close(client_socket);
        SSL_free(ssl);
        return;
    }

    // Handle client communication
    handle_client(ssl);
    printf("Done\n");
    // Clean up
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_socket);
  }
  

  // Clean up SSL context
  SSL_CTX_free(ctx);
}

void handle_server(SSL *ssl) {
    char buffer[1024];
    int bytes_received;

    // Send data to the server
    const char *data_to_send = "Hello, server!";
    SSL_write(ssl, data_to_send, strlen(data_to_send));

    // Receive data from the server
    bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        printf("Received from server: %s\n", buffer);
    } else {
        ERR_print_errors_fp(stderr);
    }
}

int sendKeyBySSL(char * address, int port) {
    SSL_CTX *ctx;
    SSL_library_init();
    ctx = SSL_CTX_new(SSLv23_client_method());
    SSL_CTX_use_certificate_file(ctx, "client.crt", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "client.key", SSL_FILETYPE_PEM);

    int client_socket;
    struct sockaddr_in server_addr;

    // Create socket
    if ((client_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    // Initialize server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(address);
    server_addr.sin_port = htons(port);

    // Connect to the server
    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Error connecting to server");
        close(client_socket);
        exit(EXIT_FAILURE);
    }

    printf("Connected to server %s:%d\n", address, port);

    // Create SSL structure
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_socket);

    // Perform SSL handshake
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        close(client_socket);
        SSL_free(ssl);
        exit(EXIT_FAILURE);
    }

    // Handle server communication
    handle_server(ssl);

    // Clean up
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_socket);

    // Clean up SSL context
    SSL_CTX_free(ctx);

    return 0;
}


/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
  fprintf(stderr, "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
  fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}

int main(int argc, char *argv[]) {
  int tap_fd, option;
  int flags = IFF_TUN;
  char if_name[IFNAMSIZ] = "";
  int header_len = IP_HDR_LEN;
  int maxfd;
  uint16_t nread, nwrite, plength;
  //  uint16_t total_len, ethertype;
  char buffer[BUFSIZE];
  char new_buffer[BUFSIZE];
  struct sockaddr_in local, remote;
  char remote_ip[16] = "";
  unsigned short int port = PORT;
  int sock_fd, net_fd, optval = 1;
  socklen_t remotelen;
  int cliserv = -1;    /* must be specified on cmd line */
  unsigned long int tap2net = 0, net2tap = 0;
  socklen_t len;
  len = sizeof(remote); 
  unsigned char key[KEY_LENGTH];
  unsigned char iv[IV_LENGTH];

  progname = argv[0];
  
  /* Check command line options */
  while((option = getopt(argc, argv, "i:sc:p:uahd")) > 0){
    switch(option) {
      case 'd':
        debug = 1;
        break;
      case 'h':
        usage();
        break;
      case 'i':
        strncpy(if_name,optarg,IFNAMSIZ-1);
        break;
      case 's':
        cliserv = SERVER;
        break;
      case 'c':
        cliserv = CLIENT;
        strncpy(remote_ip,optarg,15);
        break;
      case 'p':
        port = atoi(optarg);
        break;
      case 'u':
        flags = IFF_TUN;
        break;
      case 'a':
        flags = IFF_TAP;
        header_len = ETH_HDR_LEN;
        break;
      default:
        my_err("Unknown option %c\n", option);
        usage();
    }
  }

  argv += optind;
  argc -= optind;

  if(argc > 0){
    my_err("Too many options!\n");
    usage();
  }

  if(*if_name == '\0'){
    my_err("Must specify interface name!\n");
    usage();
  }else if(cliserv < 0){
    my_err("Must specify client or server mode!\n");
    usage();
  }else if((cliserv == CLIENT)&&(*remote_ip == '\0')){
    my_err("Must specify server address!\n");
    usage();
  }

  /* initialize tun/tap interface */
  if ( (tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) {
    my_err("Error connecting to tun/tap interface %s!\n", if_name);
    exit(1);
  }

  do_debug("Successfully connected to interface %s\n", if_name);

  


  // Use UDP
  if ( (sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket()");
    exit(1);  
  }


  if(cliserv==CLIENT){
    /* Client, try to connect to server */

    sendKeyBySSL(remote_ip, port);

  
    /* assign the destination address */
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = inet_addr(remote_ip);
    remote.sin_port = htons(port);

    int n;
    socklen_t len;

    sendto(sock_fd, "hello", 5, 
        MSG_CONFIRM, (const struct sockaddr *) &remote,  
            sizeof(remote)); 

    
  } else {
    /* Server, wait for connections */
    pid_t p = fork();
    if (p < 0) {
      perror("fork failed");
      exit(1);
    }

    if (p == 0) {
      // child that listen to ssl connection
      getKeyFromSSL(port);
      printf("??????\n");
    }

    
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(port);

    if (bind(sock_fd, (struct sockaddr*) &local, sizeof(local)) < 0){
      perror("bind()");
      exit(1);
    }
    printf("SERVER: Listening on port %d\n", port);

    memset(&remote, 0, sizeof(remote));

    // wait for a connection to know the remote address
    int n;  
    n = recvfrom(sock_fd, (char *)buffer, BUFSIZE - 1,  
                MSG_WAITALL, ( struct sockaddr *) &remote, 
                &len); 
    buffer[n] = '\0';
  }
  net_fd = sock_fd;
  printf("Remote: %s\n", inet_ntoa(remote.sin_addr));

  /* use select() to handle two descriptors at once */
  maxfd = (tap_fd > net_fd)?tap_fd:net_fd;

  while(1) {
    int ret;
    fd_set rd_set;

    FD_ZERO(&rd_set);
    FD_SET(tap_fd, &rd_set); FD_SET(net_fd, &rd_set);

    ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

    if (ret < 0 && errno == EINTR){
      continue;
    }

    if (ret < 0) {
      perror("select()");
      exit(1);
    }

    if(FD_ISSET(tap_fd, &rd_set)){
      /* data from tun/tap: just read it and write it to the network */
      
      nread = cread(tap_fd, buffer, BUFSIZE);


      tap2net++;
      //do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);
      printf("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);


      /* write length + packet */
      //int new_length = encrypt(KEY, IV,  buffer, nread, new_buffer);
      int new_length = mac_then_encrypt(KEY, IV,  buffer, nread, new_buffer);




      plength = htons(new_length);

      //nwrite = sendto(net_fd, (char *)&plength, sizeof(plength), MSG_CONFIRM, (const struct sockaddr *) &remote, sizeof(remote)); 

      nwrite = sendto(net_fd, new_buffer, new_length, MSG_CONFIRM, (const struct sockaddr *) &remote, sizeof(remote)); 
      // nwrite = send_encrypted(net_fd, buffer, nread, remote);
      
      //do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);
      printf("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);
    }

    if(FD_ISSET(net_fd, &rd_set)){
      /* data from the network: read it, and write it to the tun/tap interface. 
       * We need to read the length first, and then the packet */

      /* Read length */
      
      //nread = read_n(net_fd, (char *)&plength, sizeof(plength));
      // TODO
      //nread = recvfrom(sock_fd, (char *)&plength, sizeof(plength), MSG_WAITALL, ( struct sockaddr *) &remote, &len); 
      //if(nread == 0) {
        /* ctrl-c at the other end */
      //  break;
      //}


      net2tap++;

      /* read packet */
      //nread = read_n(net_fd, buffer, ntohs(plength));
      nread = recvfrom(sock_fd, buffer, BUFSIZE, MSG_WAITALL, ( struct sockaddr *) &remote, &len); //TODO

      
      //nread = recv_decrypt(sock_fd, buffer, ntohs(plength), remote);

      //do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);
      printf("NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);


      // decrypt the message
      int new_length = decrypt_verify(KEY, IV, buffer, nread, new_buffer);

      if (new_length == -1) {
        printf("Received a malformed message.");
        continue;
      }

      /* now buffer[] contains a full packet or frame, write it into the tun/tap interface */ 
      nwrite = cwrite(tap_fd, new_buffer, new_length);
      printf("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
    }
  }


  return(0);
}