#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER_ADDRESS "127.0.0.1"
#define SERVER_PORT 43535
#define BUFFER_SIZE 1024

void handle_server(SSL *ssl) {
    char buffer[BUFFER_SIZE];
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

int main() {
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
    server_addr.sin_addr.s_addr = inet_addr(SERVER_ADDRESS);
    server_addr.sin_port = htons(SERVER_PORT);

    // Connect to the server
    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Error connecting to server");
        close(client_socket);
        exit(EXIT_FAILURE);
    }

    printf("Connected to server %s:%d\n", SERVER_ADDRESS, SERVER_PORT);

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
