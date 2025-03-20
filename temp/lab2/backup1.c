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

#include <arpa/inet.h> 
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/ip.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

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
# define BLOCK_SIZE 16
# define true 1
# define false 0


// control message type
# define MSGTYPE_UPDATE_KEY "update_key"
# define MSGTYPE_UPDATE_IV "update_iv"
# define MSGTYPE_TERMINATE_TUNNEL "terminate_tunnel"
# define MSGTYPE_INITIALIZE_TUNNEL "initialize_tunnel"
# define MSGTYPE_REQUEST_ADDR "addr_please"

// global variables
int debug;
char *progname;


// data of a single vpn client
struct RemoteData {
  char key[KEY_LENGTH]; // the key for encryption/decryption/hash
  char iv[IV_LENGTH];  // iv for encryption/decryption
  char vpnAddress[INET_ADDRSTRLEN];
  struct sockaddr_in addr;
  int counter_send;
  int counter_receive;
  struct RemoteData * next;
  struct RemoteData * prev;
  pthread_mutex_t mutex;
};

// structure to send arguments to the thread function
struct ThreadData {
  char * address;
  int serverPort;
  unsigned char * key;
  int clientPort;
};

struct RemoteData *g_remote_data;
char g_selfVPNAddr[INET_ADDRSTRLEN];
char g_tunName[BUFSIZE];



int get_tun_ip() {
    if (g_selfVPNAddr[0] != '\0') {
      return 0;
    } 
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Error opening socket");
        exit(EXIT_FAILURE);
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, g_tunName, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        //perror("Error getting IP address");
        close(sockfd);
        return -1;
    }

    close(sockfd);

    struct sockaddr_in *ip_address = (struct sockaddr_in *)&ifr.ifr_addr;
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_address->sin_addr), g_selfVPNAddr, INET_ADDRSTRLEN);

    printf("IP address assigned to %s: %s\n", g_tunName, g_selfVPNAddr);
    return 1;
}


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



struct RemoteData * getRemoteDataFromVPNAddr(char * vpnAddr) {
  struct RemoteData *current = g_remote_data;
  while (current != NULL) {

    if (strncmp(vpnAddr, current->vpnAddress, INET_ADDRSTRLEN) == 0) {
      return current;
    }
    current = current->next;
  }
  do_debug("Failed to find a remote with address: %s\n", vpnAddr);
  return NULL;
}



//=============Encryptions================//

// error handling
void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
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
unsigned char *hmac_sha256(const void *key, const unsigned char *data, int data_length, unsigned char *result) {
    unsigned int result_len;
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
 *         return -1 on fail                                                             *
 *****************************************************************************************/
int decrypt(unsigned char *key, unsigned char *iv, unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())){
        handleErrors();
        return -1;
    }

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        handleErrors();
        return -1;
    }

    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        handleErrors();
        return -1;
    }
    plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        handleErrors();
        return -1;
    }
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
int verify_hash(const void * key,  unsigned char * hash, const unsigned char * plaintext, int plaintext_len) {
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
    // buffer = addr | counter | plaintext
    unsigned char buffer[INET_ADDRSTRLEN + 4 + plaintext_len];
    memcpy(buffer, g_selfVPNAddr, INET_ADDRSTRLEN);


    // get destination ip from the payload
    struct iphdr *ip_header = (struct iphdr *)plaintext;
    char dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->daddr), dest_ip, INET_ADDRSTRLEN);
    printf("Destination IP: %s\n", dest_ip);
    struct RemoteData * remote = getRemoteDataFromVPNAddr(dest_ip);
    if (remote == NULL) {
      do_debug("Cant find Remote\n");
      return -2;
    }

    * (buffer + INET_ADDRSTRLEN) = remote->counter_send;
    memcpy(buffer + INET_ADDRSTRLEN + 4, plaintext, plaintext_len);
    remote->counter_send++;

    unsigned char hash[HASH_LENGTH + plaintext_len + 32];

    // hash(addr | counter | plaintext)
    hmac_sha256((const void *) key, buffer, INET_ADDRSTRLEN + 4 + plaintext_len, hash);

    // concat the hash and the plain text
    // hash is now: hash | counter | plain text
    memcpy(&hash[HASH_LENGTH], buffer + INET_ADDRSTRLEN, plaintext_len + 4);

    // cipher = encrypt(hash | plain text)
    unsigned char cipher[BUFSIZE];
    // get cipher and size
    int cipher_size = encrypt(key, iv, hash, HASH_LENGTH + plaintext_len + 4, cipher);

    // set ciphertext to: addr | cipher
    memcpy(ciphertext, g_selfVPNAddr, INET_ADDRSTRLEN);
    memcpy(ciphertext + INET_ADDRSTRLEN, cipher, cipher_size);

    // encrypt the entire thing   addr | encrypt(hash | counter | plain text)
    // addr | encrypt(hash(addr | counter | plaintext) | counter | plain text)


    return cipher_size + INET_ADDRSTRLEN;
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
    //do_debug("decrypt_verity key: \n");
    //BIO_dump_fp(stdout, (const char *)key, KEY_LENGTH);
    //do_debug("iv key: \n");
    //BIO_dump_fp(stdout, (const char *)iv, IV_LENGTH);
    // if the received is not in correct block size, its not a valid message


    //ciphertext =  addr | encrypt(hash | counter | plain text)
    char remoteAddr[INET_ADDRSTRLEN];
    memcpy(remoteAddr, ciphertext, INET_ADDRSTRLEN);

    printf("remoteAddr: %s\n", remoteAddr);


    ciphertext = ciphertext + INET_ADDRSTRLEN;
    ciphertext_len -= INET_ADDRSTRLEN;

    if (ciphertext_len % BLOCK_SIZE != 0) {
      return -1;
    }

    // hash | counter | plain text
    unsigned char decrypted[BUFSIZE];
    int decryptedLength = decrypt(key, iv, ciphertext, ciphertext_len, decrypted);

    // hash = hash(addr | counter | plaintext)
    unsigned char unhash[BUFSIZE];
    memcpy(unhash, remoteAddr, INET_ADDRSTRLEN);
    memcpy(unhash + INET_ADDRSTRLEN, decrypted + HASH_LENGTH, decryptedLength - HASH_LENGTH);

    
    // the first 32 bytes of the plaintext is the hash value, and the rest is the data
    
    if (verify_hash((const void *) key, decrypted, unhash, decryptedLength - HASH_LENGTH + INET_ADDRSTRLEN) != 0) {
        plaintext[0] = '\0';
        return -1;
    }
    


    struct RemoteData * remote = getRemoteDataFromVPNAddr(remoteAddr);
    if (remote == NULL) {
      do_debug("Cant find Remote\n");
      return -2;
    }



    int * intlocation = (int*)(&decrypted[HASH_LENGTH]);
    printf("int received: %d\n", *intlocation);
    if (*intlocation != g_remote_data->counter_receive) {
      return -1;
    }
    g_remote_data->counter_receive++;

    memcpy(plaintext, decrypted + HASH_LENGTH + 4, decryptedLength - HASH_LENGTH - 4);

    return decryptedLength - HASH_LENGTH - 4;
}

//============= SSL control channel functions ================//
/*
  The server and the client will send control information through the ssl secured channel
  The server will keep listening for connections
  The client will connect to the server when attempting to send a control message
  A single connection can have one or more messages
  Each message has the following format: <message type> <message content> 
  There are two message types: MSGTYPE_UPDATE_KEY, MSGTYPE_UPDATE_IV, MSGTYPE_TERMINATE_TUNNEL
  MSGTYPE_UPDATE_KEY: 1 message content: new session key. Update the key
  MSGTYPE_UPDATE_IV: 1 message content: new iv. Update IV
  MSGTYPE_INITIALIZE_TUNNE: message content is: <port>
  MSGTYPE_TERMINATE_TUNNEL: message content is omitted. Release the resource for this client
*/


// read key from ssl connection
int readKey(SSL * ssl) {
  unsigned char buffer[BUFSIZE];
  int bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
  if (bytes_received != KEY_LENGTH){
    do_debug("Invalid key length");
    return -1;
  }
  buffer[bytes_received] = '\0';
  pthread_mutex_lock(&g_remote_data->mutex);
  memcpy(g_remote_data->key, buffer, KEY_LENGTH);
  pthread_mutex_unlock(&g_remote_data->mutex);
  return 0;
}

int readIV(SSL * ssl) {
  unsigned char buffer[BUFSIZE];
  int bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
  if (bytes_received != IV_LENGTH){
    do_debug("Invalid key length");
    return -1;
  }
  buffer[bytes_received] = '\0';
  pthread_mutex_lock(&g_remote_data->mutex);
  memcpy(g_remote_data->iv, buffer, IV_LENGTH);
  pthread_mutex_unlock(&g_remote_data->mutex);
  return 0;
}

int serverInitializeTunnel(SSL *ssl) {
  char buffer[BUFSIZE];
  int bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
  if (bytes_received < 0){
    do_debug("SSL_read");
    return -1;
  }
  printf("port: %s\n", buffer);

  int client_socket = SSL_get_fd(ssl);

  // Obtain client address information
  struct sockaddr_in client_addr;
  socklen_t addr_len = sizeof(client_addr);

  if (getpeername(client_socket, (struct sockaddr*)&client_addr, &addr_len) == 0) {
      char client_ip[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);

      int client_port = ntohs(client_addr.sin_port);

      printf("Client IP: %s\n", client_ip);
      printf("Client Port: %d\n", client_port);

      pthread_mutex_lock(&g_remote_data->mutex);

      memset(&g_remote_data->addr, 0, sizeof(g_remote_data->addr));
      g_remote_data->addr.sin_family = AF_INET;
      g_remote_data->addr.sin_addr.s_addr = inet_addr("192.168.15.5");
      g_remote_data->addr.sin_port = htons(atoi(buffer));

      g_remote_data->counter_send = 0;
      g_remote_data->counter_receive = 0;

    
      pthread_mutex_unlock(&g_remote_data->mutex);


  } else {
      perror("getpeername");
      // Handle error
  }

  bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
  if (bytes_received < 0){
    do_debug("SSL_read");
    return -1;
  }
  buffer[bytes_received] = '\0';
  printf("READ: %s\n", buffer);
  // remote vpn addres
  strncpy(g_remote_data->vpnAddress, buffer, INET_ADDRSTRLEN);

  // send backs server's vpn address
  SSL_write(ssl, g_selfVPNAddr, strlen(g_selfVPNAddr));


  return 1;
}

int serverSendAddr(SSL * ssl) {
  // block until it gets its address in tun
  while (get_tun_ip() == -1) {
    sleep(0.1); // dont go too crazy
    continue;
  } 
  SSL_write(ssl, g_selfVPNAddr, strlen(g_selfVPNAddr));
}
/*****************************************************************************************************
 * handle_client: parse the date sent from the client                                                *
 * @param ssl SSL connection that can be used for SSL_read                                           *
 * @return 0 on success, -1 on fail                                                                  *
 *****************************************************************************************************/
int handle_client(SSL *ssl) {
    unsigned char buffer[BUFSIZE];
    int bytes_received;

    // Read from client
    while (1) {
      // the first message is the message type
      bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
      // 
      if (bytes_received > 0) {
          buffer[bytes_received] = '\0';
          do_debug("SSL Received from client: %s\n", buffer);
          if (strncmp(buffer,MSGTYPE_UPDATE_KEY, BUFSIZE) == 0) {
            readKey(ssl);
          }
          else if (strncmp(buffer,MSGTYPE_UPDATE_IV, BUFSIZE) == 0) {
            readIV(ssl);
          }
          else if (strncmp(buffer,MSGTYPE_TERMINATE_TUNNEL, BUFSIZE) == 0) {
            do_debug("terminate_tunnel iv\n");
            //TODO
          }
          else if (strncmp(buffer,MSGTYPE_INITIALIZE_TUNNEL, BUFSIZE) == 0) {
            serverInitializeTunnel(ssl);
            do_debug("initialize tunnel\n");
          }
          else if (strncmp(buffer, MSGTYPE_REQUEST_ADDR, BUFSIZE) == 0) {
              serverSendAddr(ssl);
          }
          else {
            printf("Invalid control message\n");
          }

      } else {
          ERR_print_errors_fp(stderr);
          return -1;
      }
    }
}


/*
*/
void * serverSSL(void * threadData) {
  struct ThreadData *data = (struct ThreadData *)threadData;
  int port = data->serverPort;
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

  do_debug("SSL Server listening on port %d...\n", port);

  while (1) {
    // Accept connection
    if ((client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len)) == -1) {
        perror("Error accepting connection");
        return;
    }

    do_debug("SSL Connection accepted from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

    // Create SSL structure
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_socket);

    // Perform SSL handshake
    if (SSL_accept(ssl) <= 0) {
        do_debug("SSL handshake failed\n");
        ERR_print_errors_fp(stderr);
        close(client_socket);
        SSL_free(ssl);
        return;
    }
    do_debug("SSL handshake worked\n");


    // Handle client communication
    handle_client(ssl);
    do_debug("SSL Done\n");
    // Clean up
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_socket);
  }
  

  // Clean up SSL context
  SSL_CTX_free(ctx);
}

/*****************************************************************************************************
 * updateAndSendKey: send the key to the server, also update its global variable g_remote_data->key               *
 * @param ssl SSL connection that can be used for SSL_read                                           *
 * @param key The new session key that will be used to encrypt/decrypt all future traffic until a    *
 *            session key is estabalished                                                            *
 * @return 0 on success, -1 on fail                                                                  *
 *****************************************************************************************************/
int updateAndSendKey(SSL *ssl, unsigned char * key) {
    // send message type
    SSL_write(ssl, MSGTYPE_UPDATE_KEY, strlen(MSGTYPE_UPDATE_KEY));

    // send the random key over
    SSL_write(ssl, key, KEY_LENGTH);

    // update key
    pthread_mutex_lock(&g_remote_data->mutex);
    memcpy(g_remote_data->key, key, KEY_LENGTH);
    pthread_mutex_unlock(&g_remote_data->mutex);
    return 0;
}

/*****************************************************************************************************
 * updateAndSendRandomKey: generate a new random session key and update itself and the server        *
 * @param ssl SSL connection that can be used for SSL_read                                           *
 * @return 0 on success, -1 on fail                                                                  *
 *****************************************************************************************************/
int updateAndSendRandomKey(SSL *ssl) {
  unsigned char key[KEY_LENGTH];
  // generate new random key
  RAND_bytes(key, KEY_LENGTH);
  // update and send the new key
  updateAndSendKey(ssl, key);
  return 0;
}

/*****************************************************************************************************
 * updateAndSendIV: send the IV to the server, also update its global variable g_remote_data->iv                  *
 * @param ssl SSL connection that can be used for SSL_read                                           *
 * @param iv The new session iv that will be used to encrypt/decrypt all future traffic until a      *
 *           session iv is estabalished                                                              *
 *           Size must equal to IV_LENGTH                                                            *
 * @return 0 on success, -1 on fail                                                                  *
 *****************************************************************************************************/
int updateAndSendIV(SSL *ssl, unsigned char * iv) {
    // send message type
    SSL_write(ssl, MSGTYPE_UPDATE_IV, strlen(MSGTYPE_UPDATE_IV));

    // send the random key over
    SSL_write(ssl, iv, IV_LENGTH);

    // update key
    pthread_mutex_lock(&g_remote_data->mutex);
    memcpy(g_remote_data->iv, iv, IV_LENGTH);
    pthread_mutex_unlock(&g_remote_data->mutex);
    return 0;
}

/*****************************************************************************************************
 * updateAndSendRandomIV: generate a new random session IV and update itself and the server          *
 * @param ssl SSL connection that can be used for SSL_read                                           *
 * @return 0 on success, -1 on fail                                                                  *
 *****************************************************************************************************/
int updateAndSendRandomIV(SSL *ssl) {
  unsigned char iv[IV_LENGTH];
  // generate new random key
  RAND_bytes(iv, IV_LENGTH);
  // update and send the new key
  updateAndSendIV(ssl, iv);
  return 0;
}


// tell the server to allocate resource for a new vpn tunnel
int clientInitializeTunnel(SSL * ssl, int clientPort) {
  SSL_write(ssl, MSGTYPE_INITIALIZE_TUNNEL, strlen(MSGTYPE_INITIALIZE_TUNNEL));
  char buffer[INET_ADDRSTRLEN];
  sprintf(buffer, "%d", clientPort);
  SSL_write(ssl, buffer, strlen(buffer));

  SSL_write(ssl, g_selfVPNAddr, strlen(g_selfVPNAddr));
  return 0;
}


int requestServerVPNAddress(SSL *ssl) {
  SSL_write(ssl, MSGTYPE_REQUEST_ADDR, strlen(MSGTYPE_REQUEST_ADDR));
  char buffer[INET_ADDRSTRLEN];
  int bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
  if (bytes_received < 0){
    do_debug("SSL_read");
    return -1;
  }
  buffer[bytes_received] = '\0';
  printf("READ: %s\n", buffer);
  // remote vpn addres
  strncpy(g_remote_data->vpnAddress, buffer, INET_ADDRSTRLEN); 
  return 1;
}

void handle_server(SSL *ssl, int clientPort) {
  // block until it gets its address in tun
  while (get_tun_ip() == -1) {
    sleep(0.1); // dont go too crazy
    continue;
  } 
  clientInitializeTunnel(ssl, clientPort);
  requestServerVPNAddress(ssl);
    while (1) {
      updateAndSendRandomKey(ssl);
      updateAndSendRandomIV(ssl);
      sleep(10);
    }
}

// if key is null, generate a random key
// keylength has to be KEY_LENGTH
void * clientSSL(void * threadData) {
    struct ThreadData *data = (struct ThreadData *)threadData;
    char * address = data->address;
    int port = data->serverPort;
    unsigned char * key = data->key;
    int clientPort = data->clientPort;
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

    do_debug("Connected to server %s:%d\n", address, port);

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
    handle_server(ssl, clientPort);

    // Clean up
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_socket);

    // Clean up SSL context
    SSL_CTX_free(ctx);

    return 0;
}

void tunnel(int tap_fd, int net_fd) {
  struct sockaddr_in remote;
  unsigned long int tap2net = 0, net2tap = 0;
  char buffer[BUFSIZE];
  char new_buffer[BUFSIZE];
  int maxfd;
  int nread;
  int nwrite;
  int len;
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

      do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);

      struct iphdr *ip_header = (struct iphdr *)buffer;
      // Extract destination IP address
      char dest_ip[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &(ip_header->daddr), dest_ip, INET_ADDRSTRLEN);
      printf("Destination IP: %s\n", dest_ip);


      /* write encrypted packet */
      pthread_mutex_lock(&g_remote_data->mutex);
      int new_length = mac_then_encrypt(g_remote_data->key, g_remote_data->iv,  buffer, nread, new_buffer);


      //nwrite = sendto(net_fd, new_buffer, new_length, MSG_CONFIRM, (const struct sockaddr *) &remote, sizeof(remote)); 
      nwrite = sendto(net_fd, new_buffer, new_length, MSG_CONFIRM, (const struct sockaddr *) &g_remote_data->addr, sizeof(remote)); 
      pthread_mutex_unlock(&g_remote_data->mutex);
      
      do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);
    }

    if(FD_ISSET(net_fd, &rd_set)){
      /* data from the network: read it, and write it to the tun/tap interface. */
      net2tap++;

      /* read packet */
      pthread_mutex_lock(&g_remote_data->mutex);

      nread = recvfrom(net_fd, buffer, BUFSIZE, MSG_WAITALL, ( struct sockaddr *) &remote, &len); //TODO      
      do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);

      // decrypt the message
      int new_length = decrypt_verify(g_remote_data->key, g_remote_data->iv, buffer, nread, new_buffer);

      pthread_mutex_unlock(&g_remote_data->mutex);

      if (new_length == -1) {
        do_debug("Received a malformed message.");
        continue;
      }

      /* now buffer[] contains a full packet or frame, write it into the tun/tap interface */ 
      nwrite = cwrite(tap_fd, new_buffer, new_length);
      do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
    }
  }
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
  //int header_len = IP_HDR_LEN;
  //  uint16_t total_len, ethertype;
  char buffer[BUFSIZE];
  struct sockaddr_in local;
  char remote_ip[16] = "";
  unsigned short int port = PORT;
  int sock_fd, net_fd = 1;
  int cliserv = -1;    /* must be specified on cmd line */

  progname = argv[0];
  g_selfVPNAddr[0] = '\0';
  
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
        //header_len = ETH_HDR_LEN;
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
  

  strncpy(g_tunName, if_name, BUFSIZE);

 

  
  // Use UDP
  if ( (sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket()");
    exit(1);  
  }


  g_remote_data = malloc(sizeof(struct RemoteData));
  
  if(cliserv==CLIENT){
    /* Client, try to connect to server */
    
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = 0;

    if (bind(sock_fd, (struct sockaddr*) &local, sizeof(local)) < 0){
      perror("bind()");
      exit(1);
    }

    // Get the local port
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    if (getsockname(sock_fd, (struct sockaddr*)&client_addr, &addr_len) == -1) {
        perror("Error getting local address");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }


    /* assign the destination address */
    pthread_mutex_lock(&g_remote_data->mutex);

    memset(&g_remote_data->addr, 0, sizeof(g_remote_data->addr));
    g_remote_data->addr.sin_family = AF_INET;
    g_remote_data->addr.sin_addr.s_addr = inet_addr(remote_ip);
    g_remote_data->addr.sin_port = htons(port);
    g_remote_data->counter_send = 0;
    g_remote_data->counter_receive = 0;
   
    pthread_mutex_unlock(&g_remote_data->mutex);

    // send the key and iv over
    pthread_t thread;
    int rc;
    struct ThreadData threadData;
    threadData.address = remote_ip;
    threadData.serverPort = port;
    threadData.clientPort = ntohs(client_addr.sin_port);
    threadData.key=NULL;
    rc = pthread_create(&thread, NULL, clientSSL, (void *) &threadData);

    if (rc) {
        printf("Error creating thread; return code from pthread_create() is %d\n", rc);
        exit(EXIT_FAILURE);
    }

  } else {
    /* Server, wait for connections */ 
    
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(port);

    if (bind(sock_fd, (struct sockaddr*) &local, sizeof(local)) < 0){
      perror("bind()");
      exit(1);
    }


    pthread_t thread;
    int rc;
    struct ThreadData threadData;
    threadData.serverPort = port;
    rc = pthread_create(&thread, NULL, serverSSL, (void *) &threadData);

    if (rc) {
        printf("Error creating thread; return code from pthread_create() is %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("SERVER: Listening on port %d\n", port);

  }
  net_fd = sock_fd;

  tunnel(tap_fd, net_fd);
  return(0);
}


