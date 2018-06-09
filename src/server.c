/******************************************************************************
* server.c                                                                    *
*                                                                             *
* Description: This file contains the C source code for a http server.        *
*                                                                             *
* Author: HingOn Miu <hmiu@andrew.cmu.edu>                                    *
*                                                                             *
*******************************************************************************/

#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <syslog.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_PORT 65535
#define LINE_SIZE 128
/* 8192 bytes is the assumed maximum request header size */
#define BUF_SIZE 2048
/* length of the struct Buffer pointer array, a.k.a. max num of client socket *
 *  connected at the same time.                                               */
#define BUF_ARRAY_LEN 1024
/* assume the largest num of bytes sent by client is 9999 (max 4 digit) */
#define NUM_OF_BYTES_DIGIT 4
/* the highest-numbered file descriptor */
int nfds = 0;
/* global file pointer for log file uri */
char* log_uri = NULL;
/* global file pointer for lock file uri */
char* lock_uri = NULL;
/* global file pointer for www folder uri, should be "./static_site" */
char* www_folder = NULL;
/* global file pointer for cgi path uri, should be "./cgi/wsgi_wrapper.py" */
char* cgi_path = NULL;
/* global file pointer for key file uri */
char* key_uri = NULL;
/* global file pointer for certificate file uri */
char* cert_uri = NULL;
/* global pointer for storing http port number */
int http_port = 0;
/* global pointer for storing https port number */
int https_port = 0;

/**
 * @brief Buffer is for storing the message sent from client.
 *
 * Some important variables are: client_close records whether this
 * client has closed connection, total_len is the total length of the message,
 * read_len is the length have received so far, written_len is the length
 * have written back so far, buf is the actual char type buffer to store
 * data.
 *
 */
typedef struct {
    int SSL; /* record whether this client is SSL connected */
    SSL* ssl_client; /* for reading and writing back to SSL client */
    int client_close; /* record whether this client has closed connection */
    int total_len; /* total length of the message */
    int read_len; /* length have received so far */
    int written_len; /* length have written back so far */
    int body_total_len; /* total length of request entity body */
    int body_read_len; /* read length of request entity body from client */
    int body_written_len; /* written length of message body to script */
    char* bodybuf; /* buffer of request entity body */
    char* readbuf;  /* buffer of request headers */
    int response_len; /* total length of response */
    char* writebuf; /* buffer of response */
    int header_len; /* length of the first request header */
    char* client_ip; /* client's ip address */
    int cgi_writes_back; /* store the fd for script to write back */
    int cgi_reads_data; /* store the fd for script to read data */
} Buffer;

/**
 * <Writes server running status messages to log file>
 *
 * @param message The message to be written to log file.
 */
void update_log(char* message) {
    FILE* log_file = fopen(log_uri, "ab+");
    if(log_file == NULL) {
        fprintf(stdout, "Log file cannot be located.\n");
        exit(-1);
    }

    fprintf(log_file, "%s", message);
    fclose(log_file);
}

/**
 * <Closes socket and checks for error>
 *
 * @param sock It is the socket to be closed.
 *
 * @return Returns 1 if there is an error closing sock, or 0 if no error.
 */
int close_socket(int sock) {
    if (close(sock)) {
        char log_str[256] = {0};
        sprintf(log_str, "Close: Failed closing socket.\n");
        update_log(log_str);
        return 1;
    }

    return 0;
}

/**
 * <Creates a socket for server and checks for error>
 *
 * @return Returns the newly created socket for server, and if there is an
 *         error creating server socket, the program exits.
 */
int create_socket() {
    int server_sock;
    /* PF_INET for Internet Namespace and SOCK_STREAM for reliable
       transmission of bytes */
    if ((server_sock = socket(PF_INET, SOCK_STREAM, 0)) == -1)
    {
        char log_str[256] = {0};
        if (errno == EPROTONOSUPPORT) {
            sprintf(log_str,
                    "Create: The protocol or style is not supported.\n");
        }
        if (errno == EMFILE || errno == ENFILE) {
            sprintf(log_str, "Create: Too many file descriptors open.\n");
        }
        if (errno == EACCES) {
            sprintf(log_str, "Create: No privilege to create a socket.\n");
        }
        if (errno == ENOBUFS) {
            sprintf(log_str, "Create: Run out of internal buffer space.\n");
        }

        update_log(log_str);
        exit(-1);
        return EXIT_FAILURE;
    }

    return server_sock;
}

/**
 * <Binds a socket for server and checks for error>
 *
 * @param server_sock It is the server socket.
 * @param addr It is the address for server socket.
 *
 * @return Returns 0 if binded successfully, and if there is an
 *         error binding server socket, the program exits.
 */
int bind_socket(int server_sock, struct sockaddr_in addr) {
    if (bind(server_sock, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
        char log_str[256] = {0};

        if (errno == EBADF) {
            sprintf(log_str, "Bind: Invalid file descriptor.\n");
        }
        if (errno == ENOTSOCK) {
            sprintf(log_str, "Bind: Socket is not a socket.\n");
        }
        if (errno == EADDRNOTAVAIL) {
            sprintf(log_str, "Bind: Specified address is not available.\n");
        }
        if (errno == EADDRINUSE) {
            sprintf(log_str, "Bind: Specified address in use.\n");
        }
        if (errno == EINVAL) {
            sprintf(log_str, "Bind: Socket already has an address.\n");
        }
        if (errno == EACCES) {
            sprintf(log_str, "Bind: No privilege to access the address.\n");
        }

        update_log(log_str);
        close_socket(server_sock);
        exit(-1);
        return EXIT_FAILURE;
    }
    return 0;
}

/**
 * <Prepares the server socket to listen for connection and checks for error>
 *
 * @param server_sock It is the server socket.
 * @param queue_length It is the queue length for incoming connections.
 *
 * @return Returns 0 if successful, and if there is an
 *         error, the program exits.
 */
int socket_listen(int server_sock, unsigned int queue_length) {
    if (listen(server_sock, queue_length) == -1) {
        char log_str[256] = {0};

        if (errno == EBADF) {
            sprintf(log_str, "Listen: Invalid file descriptor.\n");
        }
        if (errno == ENOTSOCK) {
            sprintf(log_str, "Listen: Socket is not a socket.\n");
        }
        if (errno == EOPNOTSUPP) {
            sprintf(log_str,
                "Listen: Socket does not support this operation.\n");
        }

        update_log(log_str);
        close_socket(server_sock);
        exit(-1);
        return EXIT_FAILURE;
    }
    return 0;
}

/**
 * <Allows multiple clients to connect to server and checks for error>
 *
 * <socket_select makes the socket file descriptor in read_fd_set and
 *  write_fd_set be able to read and write in non-blocking mode so that
 *  multiple clients can be connected to server.>
 *
 * @param fds It limits the number of fds to be checked by select().
 * @param read_fd_set_p It is the pointer to read_fd_set.
 * @param write_fd_set_p It is the pointer to write_fd_set.
 *
 * @return Returns number of active connections if successful, and if
 *         there is an error, the program exits.
 */
int socket_select(int fds, fd_set* read_fd_set_p, fd_set* write_fd_set_p) {
    int active_fds =
        select(fds, read_fd_set_p, write_fd_set_p, NULL, NULL);
    if(active_fds == -1) {
        char log_str[256] = {0};

        if (errno == EBADF) {
            sprintf(log_str, "Select: Invalid file descriptor in sets.\n");
        }
        if (errno == EINTR) {
            sprintf(log_str, "Select: Interrupted by signal.\n");
        }
        if (errno == EINVAL) {
            sprintf(log_str, "Select: Invalid timeout argument.\n");
        }

        update_log(log_str);
        exit(-1);
        return EXIT_FAILURE;
    }

    return active_fds;
}

/**
 * <Accepts connection to server and checks for error>
 *
 * <socket_accept let server_sock accept new connection and create new_socket
 *  for client socket connection, so that server_sock always stays open for
 *  new connections.>
 *
 * @param server_sock It is the server socket.
 *
 * @return Returns the new client socket if successful, and if
 *         there is an error, the program exits.
 */
int socket_accept(int server_sock, char* ip_address) {
    socklen_t cli_size;
    struct sockaddr_in cli_addr;
    cli_size = sizeof(cli_addr);
    int new_socket = accept(server_sock, (struct sockaddr *) &cli_addr,
                            &cli_size);

    /* EWOULDBLOCK means socket has nonblocking mode set */
    if (new_socket == -1 && errno != EWOULDBLOCK) {
        char log_str[256] = {0};

        if (errno == EBADF) {
            sprintf(log_str, "Accept: Invalid file descriptor.\n");
        }
        if (errno == ENOTSOCK) {
            sprintf(log_str, "Accept: Socket is not a socket.\n");
        }
        if (errno == EOPNOTSUPP) {
            sprintf(log_str,
                "Accept: Socket does not support this operation.\n");
        }

        update_log(log_str);
        close(server_sock);
        exit(-1);
        return EXIT_FAILURE;
    }

    /* stores the IP address of the client */
    inet_ntop(AF_INET, &(cli_addr.sin_addr), ip_address, LINE_SIZE);

    return new_socket;
}

/**
 * <Receives message from client and checks for error>
 *
 * @param client_sock It is the client socket.
 * @param buf_array It is the pointer to the buffer pointer array.
 *
 * @return Returns 1 if read client socket succesfully, and if
 *         there is an error, closes the client socket.
 */
int socket_read(int client_sock, Buffer** buf_array) {
    Buffer* b_p = buf_array[client_sock];
    if (b_p == NULL) {
        return 0;
    }
    /* the planned length prepare to read */
    int ideal_read_len;
    /* len is the actual length read */
    int len;

    /* write to the normal read buffer for new requests */
    if ((b_p->body_total_len) == 0) {
        ideal_read_len = BUF_SIZE - (b_p->read_len);
        len = recv(client_sock,(b_p->readbuf) + (b_p->read_len), ideal_read_len, 0);
        if (len > 0) {
            /* increment the length actually read */
            b_p->read_len += len;
        }
    }
    /* POST request's body, write into the message body buffer */
    else {
        ideal_read_len = (b_p->body_total_len) - (b_p->body_read_len);
        len = recv(client_sock,(b_p->bodybuf) + (b_p->body_read_len), ideal_read_len, 0);
        if (len > 0) {
            /* increment the length actually read */
            b_p->body_read_len += len;
        }
    }

    /* len == 0 when client side closes connection, len == -1 when client
       socket read error, and in both cases, client socket should be closed */
    if (len == 0 || len == -1) {
        char log_str[256] = {0};

        if (errno == EBADF) {
            sprintf(log_str,
            "Recv: Invalid fd. Client socket closed, server running...\n");
        }
        if (errno == ENOTSOCK) {
            sprintf(log_str,
            "Recv: Not a socket. Client socket closed, server running...\n");
        }
        if (errno == EINTR) {
            sprintf(log_str,
            "Recv: Stop by signal. Client socket closed, server running...\n");

        }
        if (errno == ENOTCONN) {
            sprintf(log_str,
            "Recv: Never connected. Client socket closed, server running...\n");
        }

        update_log(log_str);
        close(client_sock);
        buf_array[client_sock] = NULL;
        return EXIT_FAILURE;
    }

    return 1;
}

/**
 * <Receives message from SSL client and checks for error>
 *
 * @param client_sock It is the SSL client socket.
 * @param buf_array It is the pointer to the buffer pointer array.
 *
 * @return Returns 1 if read SSL client socket succesfully, and if
 *         there is an error, closes the SSL client socket.
 */
int SSL_socket_read(int client_sock, Buffer** buf_array) {
    Buffer* b_p = buf_array[client_sock];
    if (b_p == NULL) {
        return 0;
    }
    /* the planned length prepare to read */
    int ideal_read_len;
    /* len is the actual length read */
    int len;

    /* write to the normal read buffer for new requests */
    if ((b_p->body_total_len) == 0) {
        ideal_read_len = BUF_SIZE - (b_p->read_len);
        len = SSL_read(b_p->ssl_client, (b_p->readbuf) + (b_p->read_len),
                       ideal_read_len);
        if (len > 0) {
            /* increment the length actually read */
            b_p->read_len += len;
        }
    }
    /* POST request's body, write into the message body buffer */
    else {
        ideal_read_len = (b_p->body_total_len) - (b_p->body_read_len);
        len = SSL_read(b_p->ssl_client, (b_p->bodybuf) + (b_p->body_read_len),
                       ideal_read_len);
        if (len > 0) {
            /* increment the length actually read */
            b_p->body_read_len += len;
        }
    }

    if (len <= 0) {
        int ret = 0;
        int error = SSL_get_error(b_p->ssl_client, ret);
        char log_str[256] = {0};

        if (error == SSL_ERROR_NONE) {
            sprintf(log_str,
                    "SSL Read: The TLS/SSL I/O operation completed.\n");
        }
        if (error == SSL_ERROR_ZERO_RETURN) {
            sprintf(log_str,
                    "SSL Read: The TLS/SSL connection has been closed.\n");
        }
        if (error == SSL_ERROR_WANT_READ) {
            sprintf(log_str,
                    "SSL Read: Should be called again later.\n");
        }
        if (error == SSL_ERROR_WANT_WRITE) {
            sprintf(log_str,
                    "SSL Read: Should be called again later.\n");
        }
        if (error == SSL_ERROR_SYSCALL) {
            sprintf(log_str,
                    "SSL Read: Some I/O error occurred.\n");
        }
        if (error == SSL_ERROR_SSL) {
            sprintf(log_str,
                    "SSL Read: A failure in the SSL library occurred.\n");
        }
        update_log(log_str);

        /* close the client socket connection */
        //SSL_shutdown(b_p->ssl_client);
        //SSL_free(b_p->ssl_client);
        close(client_sock);
        buf_array[client_sock] = NULL;
        return EXIT_FAILURE;
    }

    return 1;
}

/**
 * <Writes message to client and checks for error>
 *
 * @param client_sock It is the client socket.
 * @param buf_array It is the pointer to the buffer pointer array.
 *
 * @return Returns 1 if write client socket successfully, and if
 *         there is an error, closes the client socket.
 */
int socket_write(int client_sock, Buffer** buf_array) {
    Buffer* b_p = buf_array[client_sock];
    if (b_p == NULL) {
        return 0;
    }
    /* the planned length prepare to write */
    int ideal_send_len = (b_p -> response_len) - (b_p -> written_len);
    /* len is the actual length write back */
    int len = send(client_sock, (b_p -> writebuf)+(b_p -> written_len),
                   ideal_send_len, 0);

    /* len == -1 when write error, client socket should be closed */
    if (len == -1) {
        char log_str[256] = {0};

        if (errno == EBADF) {
            sprintf(log_str,
            "Send: Invalid fd. Client socket closed, server running...\n");
        }
        if (errno == ENOTSOCK) {
            sprintf(log_str,
            "Send: Not a socket. Client socket closed, server running...\n");
        }
        if (errno == EINTR) {
            sprintf(log_str,
            "Send: Stop by signal. Client socket closed, server running...\n");
        }
        if (errno == ENOTCONN) {
            sprintf(log_str,
            "Send: Never connected. Client socket closed, server running...\n");
        }
        if (errno == EMSGSIZE) {
            sprintf(log_str,
            "Send: Data too large. Client socket closed, server running...\n");
        }
        if (errno == ENOBUFS) {
            sprintf(log_str,
            "Send: No more buffer. Client socket closed, server running...\n");
        }

        update_log(log_str);
        close(client_sock);
        buf_array[client_sock] = NULL;
        return EXIT_FAILURE;
    }
    /* len should never equals to 0 */
    if (len > 0) {
        /* increment the length actually write back */
        (b_p -> written_len) += len;
    }

    return 1;
}

/**
 * <Writes message to SSL client and checks for error>
 *
 * @param client_sock It is the SSL client socket.
 * @param buf_array It is the pointer to the buffer pointer array.
 *
 * @return Returns 1 if write SSL client socket successfully, and if
 *         there is an error, closes the SSL client socket.
 */
int SSL_socket_write(int client_sock, Buffer** buf_array) {
    Buffer* b_p = buf_array[client_sock];
    if (b_p == NULL) {
        return 0;
    }
    /* the planned length prepare to write */
    int ideal_send_len = (b_p -> response_len) - (b_p -> written_len);
    /* len is the actual length write back */
    int len = SSL_write(b_p->ssl_client, (b_p->writebuf)+(b_p->written_len),
                    ideal_send_len);

    if (len <= 0) {
        int ret = 0;
        int error = SSL_get_error(b_p->ssl_client, ret);
        char log_str[256] = {0};

        if (error == SSL_ERROR_NONE) {
            sprintf(log_str,
                    "SSL Write: The TLS/SSL I/O operation completed.\n");
        }
        if (error == SSL_ERROR_ZERO_RETURN) {
            sprintf(log_str,
                    "SSL Write: The TLS/SSL connection has been closed.\n");
        }
        if (error == SSL_ERROR_WANT_READ) {
            sprintf(log_str,
                    "SSL Write: Should be called again later.\n");
        }
        if (error == SSL_ERROR_WANT_WRITE) {
            sprintf(log_str,
                    "SSL Write: Should be called again later.\n");
        }
        if (error == SSL_ERROR_SYSCALL) {
            sprintf(log_str,
                    "SSL Write: Some I/O error occurred.\n");
        }
        if (error == SSL_ERROR_SSL) {
            sprintf(log_str,
                    "SSL Write: A failure in the SSL library occurred.\n");
        }
        update_log(log_str);

        /* close the client socket connection */
        //SSL_shutdown(b_p->ssl_client);
        //SSL_free(b_p->ssl_client);
        close(client_sock);
        buf_array[client_sock] = NULL;
        return EXIT_FAILURE;
    }

    if (len > 0) {
        /* increment the length actually write back */
        (b_p -> written_len) += len;
    }

    return 1;
}

/**
 * <Print instructions to use this server>
 *
 */
void usage(void) {
    printf("Usage: ./lisod [http port] [https port] [log file] [lock file]\n");
    printf("               [www fdr] [cgi fdr] [key file] [cert file]\n");
    printf("  http port   a http port number on which the server listens \n");
    printf("              for incoming connections\n");
    printf("  https port  a https port number on which the server listens \n");
    printf("              for incoming SSL connections\n");
    printf("  log file    a log file URI on which the server writes \n");
    printf("              log for connections\n");
    printf("  lock file   a lock file URI the server lock on when \n");
    printf("              becoming a daemon process\n");
    printf("  www fdr     the location of the root of the website\n\n");
    printf("  cgi path    the location of the CGI programs\n\n");
    printf("  key file    the private key file path\n\n");
    printf("  cert file   the certificate file path\n");
    exit(-1);
}

/**
 * <Returns the types the server support to respond>
 *
 * @param uri It is path of the file.
 *
 * @return Returns the type if successful, and if there is an
 *         error, return NULL.
 */
char* get_content_type(char* uri) {
    char* type = NULL;
    /* in case uri indicates the current directory */
    if (uri[0] == '.') {
        char* tmp = (char*) malloc(LINE_SIZE);
        memset(tmp, 0, LINE_SIZE);
        memcpy(tmp, uri, LINE_SIZE);
        tmp[0] = 'A';
        type = strstr(tmp, ".");
        //free(tmp);
    }
    else {
        type = strstr(uri, ".");
    }

    if (type != NULL) {
        if (strcmp(type, ".html") == 0) {
            return "Content-Type: text/html\r\n";
        }
        if (strcmp(type, ".css") == 0) {
            return "Content-Type: text/css\r\n";
        }
        if (strcmp(type, ".png") == 0) {
            return "Content-Type: image/png\r\n";
        }
        if (strcmp(type, ".jpg") == 0) {
            return "Content-Type: image/jpeg\r\n";
        }
        if (strcmp(type, ".gif") == 0) {
            return "Content-Type: image/gif\r\n";
        }
        return NULL;
    }
    return NULL;
}

/**
 * <Opens and writes to a log file of http requests and responses>
 *
 * @param host It is the hostname of client.
 * @param time It is the current time.
 * @param request_line It is the request line of client.
 * @param status_code It is the status code of response.
 * @param request_body_len It is the length of request body, if any.
 *
 */
void write_log_file(char* host, char* time, char* request_line,
                    char* status_code, char* request_body_len) {
    char* tmp = (char*) malloc(LINE_SIZE);
    memset(tmp, 0, LINE_SIZE);
    /* using the Apach common log format */
    sprintf(tmp, "%s %s \"%s\" %s %s\n",
            host, time, request_line, status_code, request_body_len);

    /* check if the uri is NULL before opening it */
    if (log_uri == NULL) {
        char log_str[256] = {0};
        sprintf(log_str, "Log file cannot be located.\n");
        update_log(log_str);
        exit(-1);
    }
    FILE* log_file = fopen(log_uri, "ab+");
    if (log_file == NULL) {
        char log_str[256] = {0};
        sprintf(log_str, "Log file cannot be located.\n");
        update_log(log_str);
        exit(-1);
    }
    int log_written = fwrite(tmp , sizeof(char), strlen(tmp), log_file);
    /* check if the number of bytes written is correct */
    if (log_written != strlen(tmp)) {
        char log_str[256] = {0};
        sprintf(log_str, "Log File write error.\n");
        update_log(log_str);
        //free(tmp);
        exit(-1);
    }
    //free(tmp);
    fclose(log_file);
}

/**
 * <Writes the responses for requests to write buffer for later sending>
 *
 * @param b_p It is the pointer to Buffer.
 * @param status_code It is the status code for response.
 * @param date It is the date for response.
 * @param server It is the server name.
 * @param last_mod It is the last modified time for file.
 * @param file_len It is the file length in response.
 * @param connection It is the connection header in response.
 * @param file_type It is the type of the file in response.
 * @param file_buf It is the buffer that contains the file.
 * @param file_size It is int size of the file.
 *
 */
void header(Buffer* b_p, int status_code, char* date, char* server,
            char* last_mod, char* file_len, char* connection, char* file_type,
            char* file_buf, int file_size) {
    /* no response body, just header */
    if (file_buf == NULL) {
        (b_p->writebuf) = (char*) malloc(BUF_SIZE);
        memset((b_p->writebuf), 0, BUF_SIZE);
    }
    else {
        (b_p->writebuf) = (char*) malloc(BUF_SIZE + file_size);
        memset((b_p->writebuf), 0, BUF_SIZE + file_size);
    }

    if (status_code == 200) {
        strcat((b_p->writebuf), "HTTP/1.1 200 OK\r\n");
    }
    else if (status_code == 400) {
        strcat((b_p->writebuf), "HTTP/1.1 400 Bad Request\r\n");
    }
    else if (status_code == 403) {
        strcat((b_p->writebuf), "HTTP/1.1 403 Forbidden\r\n");
    }
    else if (status_code == 404) {
        strcat((b_p->writebuf), "HTTP/1.1 404 Not Found\r\n");
    }
    else if (status_code == 405) {
        strcat((b_p->writebuf), "HTTP/1.1 405 Method Not Allowed\r\n");
    }
    else if (status_code == 406) {
        strcat((b_p->writebuf), "HTTP/1.1 406 Not Acceptable\r\n");
    }
    else if (status_code == 411) {
        strcat((b_p->writebuf), "HTTP/1.1 411 Length Required\r\n");
    }
    else if (status_code == 415) {
        strcat((b_p->writebuf), "HTTP/1.1 415 Unsupported Media Type\r\n");
    }
    else if (status_code == 500) {
        strcat((b_p->writebuf), "HTTP/1.1 500 Internal Server Error\r\n");
    }
    else if (status_code == 503) {
        strcat((b_p->writebuf), "HTTP/1.1 503 Service Unavailable\r\n");
    }
    else if (status_code == 505) {
        strcat((b_p->writebuf), "HTTP/1.1 505 HTTP Version Not Supported\r\n");
    }
    else {
        /* there should not be other errors */
        exit(-1);
    }

    /* check if hostname is present */
    char* host_p = strstr((b_p->readbuf), "Host: ");
    char* host = (char*) malloc(LINE_SIZE);
    memset(host, 0, LINE_SIZE);
    /* makes sure the hostname belongs to the first POST request */
    if (host_p != NULL) {
        int h;
        int len = strstr(host_p, "\r\n") - host_p - strlen("Host: ");
        for (h = 0; h < len; h++) {
            host[h] = host_p[h + strlen("Host: ")];
        }
        host[h] = '\0';
    }
    else {
        host[0] = '-';
        host[1] = '\0';
    }

    /* get current time for logging */
    char* time_p = (char*) malloc(LINE_SIZE);
    memset(time_p, 0, LINE_SIZE);
    struct tm * timeinfo;
    time_t rawtime;
    time (&rawtime);
    timeinfo = gmtime (&rawtime);
    strftime (time_p, LINE_SIZE, "[%D %T]", timeinfo);

    /* status code for logging */
    char* status_p = (char*) malloc(LINE_SIZE);
    memset(status_p, 0, LINE_SIZE);
    sprintf(status_p, "%d", status_code);

    /* request body length for logging */
    char* body_len_p = (char*) malloc(LINE_SIZE);
    memset(body_len_p, 0, LINE_SIZE);
    sprintf(body_len_p, "%d", (b_p->body_total_len));

    /* request line for logging */
    char* line_p = strstr((b_p->readbuf), "\r\n");
    char* line = (char*) malloc(LINE_SIZE);
    memset(line, 0, LINE_SIZE);
    int line_len = line_p - (b_p->readbuf);
    memcpy(line, (b_p->readbuf), line_len);
    line[line_len] = '\0';

    /* writes the log file for all response */
    write_log_file(host, time_p, line, status_p, body_len_p);

    //free(host);
    //free(time_p);
    //free(line);
    //free(status_p);
    //free(body_len_p);

    /* check if the below headers are present */
    if (date != NULL) strcat((b_p->writebuf), date);
    if (server != NULL) strcat((b_p->writebuf), server);
    if (last_mod != NULL) strcat((b_p->writebuf), last_mod);
    if (file_len != NULL) strcat((b_p->writebuf), file_len);
    if (connection != NULL) strcat((b_p->writebuf), connection);
    if (file_type != NULL) strcat((b_p->writebuf), file_type);

    /* two CRLF before the message body, if any */
    strcat((b_p->writebuf), "\r\n");
    int response_header_len = strlen((b_p->writebuf));
    (b_p->response_len) = response_header_len;

    if (file_buf != NULL) {
        memcpy((b_p->writebuf) + response_header_len, file_buf, file_size);
        (b_p->response_len) += file_size;
    }

    //free(date);
    //free(server);
    //free(last_mod);
    //free(file_len);
    //free(connection);

    if ((b_p->header_len) > 0) {
        /* re-initialize request header buffer for next request */
        memmove((b_p->readbuf), (b_p->readbuf) + (b_p->header_len),
                (b_p->read_len) - (b_p->header_len));
        (b_p->read_len) -= (b_p->header_len);
        (b_p->header_len) = 0;
    }

    /* cleanup, make ready for next request */
    /* re-initialize message body buffer for next request */
    (b_p->body_total_len) = 0;
    (b_p->body_read_len) = 0;
    if ((b_p->bodybuf) != NULL) {
        //free(b_p->bodybuf);
        (b_p->bodybuf) = NULL;
    }
    return;
}

/**
 * <Parse the request line for method, http version, and file uri>
 *
 * @param request_line It is the request line string.
 * @param b_p It is the pointer of Buffer.
 *
 * @return Returns 1 if successful, and if there is an
 *         error, returns 0.
 */
int parse_request_line(char request_line[][LINE_SIZE], Buffer* b_p) {
    char* line_endp = strstr((b_p->readbuf), "\r\n");

    int line_len = line_endp - (b_p->readbuf);
    int i = 0, j = 0, k = 0;
    char temp;
    for (i = 0; i < line_len; i++) {
        temp = (b_p->readbuf)[i];
        if (temp == ' ') {
            request_line[j][k] = '\0';
            j++;
            k = 0;
        }
        else {
            request_line[j][k] = temp;
            k++;
        }
    }
    request_line[j][k] = '\0';

    /* there must be two space characters */
    if (j != 2) {
        return 0;
    }

    return 1;
}

/**
 * <Append a string to the string array>
 *
 * @param args It is the string array pointer.
 * @param name It is the string name of the field.
 * @param elem It is the string element of the field.
 */
void append_arg(char* args[], char* name, char* elem) {
    /* no need to include it to script if it does not exist */
    if (elem == NULL || strlen(elem) == 0) {
        return;
    }

    int i = 0;
    while (args[i] != NULL && i < LINE_SIZE) {
        i++;
    }
    char* tmp = (char*) malloc(LINE_SIZE + strlen(elem));
    memset(tmp, 0, LINE_SIZE + strlen(elem));
    if (name != NULL) {
        strcat(tmp, name);
    }
    strcat(tmp, elem);
    args[i] = tmp;
    args[i+1] = NULL;
    return;
}

/**
 * <Get the environmental variable for the executing the script from
 *  the http header>
 *
 * @param buffer It is the read buffer point.
 * @param header_field It is string name of the header field.
 * @param header_end It is the pointer to the end of header.
 * @param envp It is the string array of environmental variables.
 * @param env_field It is the string name of the environmental variable.
 */
void get_env_from_header(char* buffer, char* header_field, char* header_end,
                         char* envp[], char* env_field) {
    char* header_field_p = strstr(buffer, header_field);
    /* makes sure the header belongs to the first request */
    if (header_field_p != NULL && header_field_p < header_end) {
        int h;
        int len = strstr(header_field_p, "\r\n") - header_field_p
                    - strlen(header_field);
        char* env = (char*) malloc(len + 1);
        memset(env, 0, len + 1);
        for (h = 0; h < len; h++) {
            env[h] = header_field_p[h + strlen(header_field)];
        }
        env[h] = '\0';

        /* prepare the environmental variable for executing cgi */
        append_arg(envp, env_field, env);
    }
    return;
}

/**
 * <Turns a 2-digit hexidecimal int to decimal int>
 *
 * @param hex It is the hex number.
 *
 * @return Returns the dec number.
 */
int hex_to_dec(int hex) {
    int digit_0 = hex%10;
    int digit_1 = (hex - digit_0)/10;
    return digit_1 * 16 + digit_0;
}

/**
 * <Gets the arguments for executing the script from the uri>
 *
 * @param uri It is the uri path from http request.
 * @param argv It is the string array for script arguments.
 */
void get_args_from_uri(char* uri, char* argv[]) {
    /* get the arguments from "?" */
    char* question_mark = strstr(uri, "?");
    if (question_mark != NULL) {
        int len = strlen(question_mark);
        char* tmp = (char*) malloc(LINE_SIZE);
        memset(tmp, 0, LINE_SIZE);
        int i, j = 0;
        for (i = 1; i < len; i++) {
            char character = question_mark[i];
            /* "%" means there is a ascii coded in hex, needs to translate */
            /* it back into charater for the argument. eg. "%20" -> " " */
            if (character == '%') {
                char* esc_tmp = (char*) malloc(LINE_SIZE);
                memset(esc_tmp, 0, LINE_SIZE);
                esc_tmp[0] = question_mark[i+1];
                esc_tmp[1] = question_mark[i+2];
                esc_tmp[2] = '\0';
                char* hex_tmp = (char*) malloc(LINE_SIZE);
                memset(hex_tmp, 0, LINE_SIZE);
                sprintf(hex_tmp , "%c", hex_to_dec(atoi(esc_tmp)));
                tmp[j] = hex_tmp[0];
                //free(hex_tmp);
                //free(esc_tmp);
                j++;
                i += 2;
            }
            /* "+" is the delimiter, a new argument after it */
            else if (character == '+') {
                tmp[j] = '\0';
                append_arg(argv, NULL, tmp);
                tmp = (char*) malloc(LINE_SIZE);
                memset(tmp, 0, LINE_SIZE);
                j = 0;
            }
            else {
                tmp[j] = character;
                j++;
            }
        }
        tmp[j] = '\0';
        append_arg(argv, NULL, tmp);
    }
    return;
}

/**
 * <Gets script name from the script path>
 *
 * @return Returns the script name.
 */
char* get_cgi_name() {
    int len = strlen(cgi_path);
    int i;
    char* tmp = (char*) malloc(LINE_SIZE);
    memset(tmp, 0, LINE_SIZE);
    for (i = len-1; i >= 0; i--) {
        /* eg. "./cgi/arg1/agr2/wsgi_wrapper.py" -> "wsgi_wrapper.py"*/
        if (cgi_path[i] == '/') {
            int j, k = 0;
            for (j = i+1; j < len; j++) {
                tmp[k] = cgi_path[j];
                k++;
            }
            tmp[k] = '\0';
            return tmp;
        }
    }
    return tmp;
}

/**
 * <Process what is read from client so far, and write response if nessesory>
 *
 * @param client_sock It is the fd of client.
 * @param buf_array It is the pointer of array of Buffer.
 *
 * @return Returns 1 if successful, and if there is an
 *         error, returns 0.
 */
int process_request(int client_sock, Buffer** buf_array) {
    Buffer* b_p = buf_array[client_sock];
    /* check if a Buffer is properly allocated for client connection */
    if (b_p == NULL) {
        return 0;
    }

    if ((b_p->header_len) > 0) {
        /* re-initialize request header buffer for next request */
        memmove((b_p->readbuf), (b_p->readbuf) + (b_p->header_len),
                (b_p->read_len) - (b_p->header_len));
        (b_p->read_len) -= (b_p->header_len);
        (b_p->header_len) = 0;
    }

    /* initialize variable to buffers */
    char request_line[3][LINE_SIZE];
    int method = 0;
    int cgi = 0;
    char* argv[LINE_SIZE];
    argv[0] = get_cgi_name();
    argv[1] = NULL;
    char* envp[LINE_SIZE];
    envp[0] = NULL;
    int content_len_exist = 0;
    char* last_mod = NULL;
    char* file_len = NULL;
    char* file_type = NULL;
    char* file_buf = NULL;
    char* date = NULL;
    char* connection = NULL;
    char* server = NULL;
    char* uri = NULL;
    char* content_len = NULL;
    char* tmp = NULL;
    char* date_tmp = NULL;
    struct stat* fileStat = NULL;

    char* CRLF_p = strstr((b_p->readbuf), "\r\n");
    /* In the interest of robustness, servers SHOULD ignore any empty */
    /* line(s) received where a Request-Line is expected, so erase the */
    /* CRLF before the request header */
    while ((b_p->readbuf) == CRLF_p && (b_p->read_len) >= 2) {
        memmove((b_p->readbuf), (b_p->readbuf) + 2, (b_p->read_len) - 2);
        CRLF_p = strstr((b_p->readbuf), "\r\n");
        (b_p->read_len) -= 2;
    }

    /* the message is full of "\r\n", ignore them, receive more bytes */
    if ((b_p->read_len) < 2) {
        return 0;
    }

    /* if the code gets here, its valid to assume that the first 2 bytes in */
    /* readbuf is not "\r\n" */

    /* check if request header is proper */
    char* request_header_endp = strstr((b_p->readbuf), "\r\n\r\n");
    if (request_header_endp == NULL) {
        /* the received request header is invalid when its larger than 8192 */
        if ((b_p->read_len) == BUF_SIZE) {
            header(b_p, 406, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0);
            return 0;
        }
        /* the request header hasnt been fully received yet, wait till next */
        /* recv call and check again. */
        return 1;
    }
    /* Request-Line *((general-header|request-header|entity-header)CRLF)CRLF */
    int header_len = (request_header_endp - (b_p->readbuf)) + 4;
    /* stores the length of the request header */
    (b_p->header_len) = header_len;

    /* check if message body is present */
    char* content_len_p = strstr((b_p->readbuf), "Content-Length: ");
    content_len = (char*) malloc(LINE_SIZE);
    memset(content_len, 0, LINE_SIZE);
    /* makes sure the content length header belongs to the first POST request */
    if (content_len_p != NULL && content_len_p < request_header_endp) {
        content_len_exist = 1;
        /* if message body's present, check if the complete body is received */
        if ((b_p->body_total_len) == 0) {
            int h;
            int len = strstr(content_len_p, "\r\n") - content_len_p
                        - strlen("Content-Length: ");
            for (h = 0; h < len; h++) {
                content_len[h] = content_len_p[h + strlen("Content-Length: ")];
            }
            content_len[h] = '\0';

            /* prepare the environmental variable for executing cgi */
            append_arg(envp, "CONTENT_LENGTH=", content_len);

            int content_len_tmp = atoi(content_len);

            //free(content_len);

            /* it does make sense if given content length is 0 or negative */
            if (content_len_tmp <= 0) {
                header(b_p, 400, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0);
                return 0;
            }

            /* stores the total length of request body */
            (b_p->body_total_len) = content_len_tmp;

            /* initialize a variable size buffer for message body, */
            /* move previously received body data to body buffer */
            tmp = (char*) malloc((b_p->body_total_len) + LINE_SIZE);
            memset(tmp, 0, (b_p->body_total_len) + LINE_SIZE);
            int move_len = (b_p->read_len) - header_len;
            /* avoid put the next request header into body buffer too */
            if (move_len > (b_p->body_total_len)) {
                move_len = (b_p->body_total_len);
            }
            /* move the body from read buffer to body buffer */
            memcpy(tmp, request_header_endp + 4, move_len);
            (b_p->bodybuf) = tmp;
            (b_p->body_read_len) = move_len;
            (b_p->read_len) -= move_len;
        }
    }

    /* finally one complete GET or HEAD request header, or POST request */
    /* header and body are received */
    if ((content_len_exist == 0) ||
        ((content_len_exist == 1) &&
        ((b_p->body_read_len) == (b_p->body_total_len)))) {

        /* parse the request line */
        if (parse_request_line(request_line, b_p) == 1) {
            if(strcmp(request_line[0], "GET") == 0) {
                method = 1;
            }
            else if(strcmp(request_line[0], "HEAD") == 0) {
                method = 2;
            }
            else if(strcmp(request_line[0], "POST") == 0) {
                method = 3;
            }
            else {
                /* server does not support other request method options */
                header(b_p, 405, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0);
                return 0;
            }

            append_arg(envp, "REQUEST_METHOD=", request_line[0]);

            if (method == 1 && content_len_exist != 0) {
                /* GET method does not have message body */
                header(b_p, 411, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0);
                return 0;
            }
            if (method == 2 && content_len_exist != 0) {
                /* HEAD method does not have message body */
                header(b_p, 411, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0);
                return 0;
            }
            if (method == 3 && content_len_exist != 1) {
                /* POST method needs to have message body */
                header(b_p, 411, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0);
                return 0;
            }

            /* server only supports http 1.1 requests */
            if(strcmp(request_line[2], "HTTP/1.1") != 0) {
                header(b_p, 505, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0);
                return 0;
            }

            uri = (char*) malloc(LINE_SIZE);
            memset(uri, 0, LINE_SIZE);
            int uri_len = strlen(request_line[1]);
            /* check if uri given is not proper */
            if(uri_len == 0 || request_line[1][0] != '/') {
                header(b_p, 404, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0);
                return 0;
            }
            /* if no uri is given, use the default index.html */
            if (strcmp(request_line[1], "/") == 0) {
                /* www_folder could be . or /tmp/www */
                strcat(uri, www_folder);
                strcat(uri, "/index.html");
            }
            /* this is a cgi request */
            else if (strncmp(request_line[1], "/cgi/", strlen("/cgi/")) == 0) {
                cgi = 1;
                /* prepare the environmental variable for executing cgi */
                append_arg(envp, "GATEWAY_INTERFACE=", "CGI/1.1");
                append_arg(envp, "SERVER_PROTOCOL=", "HTTP/1.1");
                append_arg(envp, "SERVER_SOFTWARE=", "Liso/1.0");
                char* int_tmp = (char*) malloc(LINE_SIZE);
                memset(int_tmp, 0, LINE_SIZE);
                if (b_p->SSL == 0) {
                    sprintf(int_tmp, "%d", http_port);
                    append_arg(envp, "SERVER_PORT=", int_tmp);
                }
                else {
                    sprintf(int_tmp, "%d", https_port);
                    append_arg(envp, "SERVER_PORT=", int_tmp);
                }
                char* cgi_tmp = (char*) malloc(LINE_SIZE);
                memset(cgi_tmp, 0, LINE_SIZE);
                strcat(cgi_tmp, "/cgi/");
                strcat(cgi_tmp, get_cgi_name());
                append_arg(envp, "SCRIPT_NAME=", "/cgi");
                char* path_info = (char*) malloc(LINE_SIZE);
                memset(path_info, 0, LINE_SIZE);
                char* cgi_request_uri = (char*) malloc(LINE_SIZE);
                memset(cgi_request_uri, 0, LINE_SIZE);
                char* query_string = (char*) malloc(LINE_SIZE);
                memset(query_string, 0, LINE_SIZE);
                int i = 0, j = 0, k = 0, p = 0;
                int question_mark = 0;
                int len = strlen(request_line[1]);
                for (i = 0; i < len; i++) {
                    char character = request_line[1][i];
                    if (question_mark == 1) {
                        query_string[p] = character;
                        p++;
                    }
                    if (character == '?') {
                        question_mark = 1;
                    }
                    if (i >= strlen("/cgi") && question_mark == 0) {
                        path_info[j] = character;
                        j++;
                    }
                    if (question_mark == 0) {
                        cgi_request_uri[k] = character;
                        k++;
                    }
                }
                path_info[j] = '\0';
                cgi_request_uri[k] = '\0';
                query_string[p] = '\0';
                append_arg(envp, "PATH_INFO=", path_info);
                append_arg(envp, "REQUEST_URI=", cgi_request_uri);
                append_arg(envp, "QUERY_STRING=", query_string);
                append_arg(envp, "REMOTE_ADDR=", b_p->client_ip);
                /* inform the script that it is a SSL connection */
                if ((b_p->SSL) == 1) {
                    append_arg(envp, "HTTPS=", "1");
                }
                get_env_from_header((b_p->readbuf), "Content-Type: ",
                            request_header_endp, envp, "CONTENT_TYPE=");
                get_env_from_header((b_p->readbuf), "Accept: ",
                            request_header_endp, envp, "HTTP_ACCEPT=");
                get_env_from_header((b_p->readbuf), "Referer: ",
                            request_header_endp, envp, "HTTP_REFERER=");
                get_env_from_header((b_p->readbuf), "Accept-Encoding: ",
                            request_header_endp, envp, "HTTP_ACCEPT_ENCODING=");
                get_env_from_header((b_p->readbuf), "Accept-Language: ",
                            request_header_endp, envp, "HTTP_ACCEPT_LANGUAGE=");
                get_env_from_header((b_p->readbuf), "Accept-Charset: ",
                            request_header_endp, envp, "HTTP_ACCEPT_CHARSET=");
                get_env_from_header((b_p->readbuf), "Host: ",
                            request_header_endp, envp, "HTTP_HOST=");
                get_env_from_header((b_p->readbuf), "Cookie: ",
                            request_header_endp, envp, "HTTP_COOKIE=");
                get_env_from_header((b_p->readbuf), "User-Agent: ",
                            request_header_endp, envp, "HTTP_USER_AGENT=");
                get_env_from_header((b_p->readbuf), "Connection: ",
                            request_header_endp, envp, "HTTP_CONNECTION=");

                /* prepare the arguments for executing cgi */
                get_args_from_uri(request_line[1], argv);
            }
            /* file uri is given */
            else {
                /* www_folder could be . or /tmp/www */
                strcat(uri, www_folder);
                strcat(uri, request_line[1]);
            }

            /* get the Connection header for response */
            connection = (char*) malloc(LINE_SIZE);
            memset(connection, 0, LINE_SIZE);
            strcat(connection, "Connection: ");
            char* connection_p = strstr((b_p->readbuf), "Connection: ");
            /* makes sure the connection header belongs to the first request */
            if (connection_p != NULL && connection_p < request_header_endp) {
                char* conn_token_p;
                conn_token_p = strstr((b_p->readbuf), "keep-alive");
                if (conn_token_p != NULL &&
                    conn_token_p < request_header_endp) {
                    strcat(connection, "keep-alive\r\n");
                }
                conn_token_p = strstr((b_p->readbuf), "persist");
                if (conn_token_p != NULL &&
                    conn_token_p < request_header_endp) {
                    strcat(connection, "persist\r\n");
                }
                conn_token_p = strstr((b_p->readbuf), "close");
                if (conn_token_p != NULL &&
                    conn_token_p < request_header_endp) {
                    strcat(connection, "close\r\n");
                    (b_p->client_close) = 1;
                }
            }
            else {
                /* assume the client wants to stay connected in default */
                strcat(connection, "keep-alive\r\n");
            }

            /* prepare to connect to the script and pass along the */
            /* arguments and environmental variables got from the http */
            /* request. */
            if (cgi == 1) {
                /* piping*/
                int to_pipe[2];
                int from_pipe[2];
                if (pipe(to_pipe) || pipe(from_pipe)) {
                    header(b_p,500, NULL, NULL, NULL, NULL, NULL, NULL, NULL,0);
                    char log_str[256] = {0};
                    sprintf(log_str,
                            "Piping failed for socket %d.\n", client_sock);
                    update_log(log_str);
                    return EXIT_FAILURE;
                }
                /* server reads script's output by from_read */
                (b_p->cgi_writes_back) = from_pipe[0];
                /* updates nfds */
                if ((b_p->cgi_writes_back) > nfds) {
                    nfds = (b_p->cgi_writes_back);
                }
                /* server writes data to script by to_write */
                (b_p->cgi_reads_data) = to_pipe[1];
                /* updates nfds */
                if ((b_p->cgi_reads_data) > nfds) {
                    nfds = (b_p->cgi_reads_data);
                }

                pid_t pid;
                pid = fork();
                /* the child process handles calling the script */
                if (pid == 0) {
                    dup2(to_pipe[0], fileno(stdin));
                    dup2(from_pipe[1], fileno(stdout));
                    execve(cgi_path, argv, envp);
                    return 1;
                }
                /* the parent process returns, and continues the select loop */
                else if (pid > 0) {
                    return 1;
                }
                /* forking failure */
                else {
                    header(b_p,500, NULL, NULL, NULL, NULL, NULL, NULL, NULL,0);
                    char log_str[256] = {0};
                    sprintf(log_str,
                            "Forking failed for socket %d.\n", client_sock);
                    return EXIT_FAILURE;
                }
            }

            /******* below processes the response for non-cgi requests *******/
            fileStat = (struct stat*) malloc(sizeof(struct stat));
            memset(fileStat, 0, sizeof(struct stat));
            if(stat(uri, fileStat) < 0) {
                /* given uri is not valid */
                header(b_p, 404, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0);
                return 0;
            }

            /* get the Date header for response */
            time_t rawtime;
            struct tm * timeinfo;
            time (&rawtime);
            timeinfo = gmtime (&rawtime);
            date_tmp = (char*) malloc(LINE_SIZE);
            memset(date_tmp, 0, LINE_SIZE);
            strftime (date_tmp, LINE_SIZE, "%a, %e %h %Y %T GMT\r\n", timeinfo);
            date = (char*) malloc(LINE_SIZE);
            memset(date, 0, LINE_SIZE);
            strcat(date, "Date: ");
            strcat(date, date_tmp);

            /* get the Server header for response */
            server = (char*) malloc(LINE_SIZE);
            memset(server, 0, LINE_SIZE);
            strcat(server, "Server: Liso/1.0\r\n");

            /********** non-cgi response processing section *******************/
            /* simply respond 200 OK for POST request */
            if (method == 3) {
                header(b_p, 200, date, server, last_mod, file_len,
                       connection, file_type, file_buf, 0);
                return 1;
            }
            else {
                /* get the last modified header for response */
                last_mod = (char*) malloc(LINE_SIZE);
                memset(last_mod, 0, LINE_SIZE);
                strftime (last_mod, LINE_SIZE,
                          "Last-Modified: %a, %e %h %Y %T GMT\r\n",
                          gmtime (&(fileStat->st_mtime)));

                /* get the content length header for response */
                file_len = (char*) malloc(LINE_SIZE);
                memset(file_len, 0, LINE_SIZE);
                sprintf(file_len,
                        "Content-Length: %d\r\n", (int)(fileStat->st_size));

                /* get the content type header for response */
                file_type = get_content_type(uri);
                if (file_type == NULL) {
                    /* unsupported type */
                    header(b_p, 404, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0);
                    return 0;
                }

                /* only respond with body if it is GET request */
                if (method == 1) {
                    /* get the message body for response */
                    file_buf = (char*) malloc(fileStat->st_size + 1);
                    memset(file_buf, 0, fileStat->st_size + 1);
                    FILE* file = fopen(uri, "r");
                    if (file != NULL) {
                        size_t read_file_size =
                            fread(file_buf, 1, fileStat->st_size, file);
                        if (read_file_size != fileStat->st_size) {
                            header(b_p, 415, NULL, NULL, NULL,
                                   NULL, NULL, NULL, NULL, 0);
                            return 0;
                        }
                        else {
                            file_buf[read_file_size + 1] = '\0';
                        }
                    }
                }

                header(b_p, 200, date, server, last_mod, file_len,
                       connection, file_type, file_buf, (int)(fileStat->st_size));
                return 1;
            }
        }
        /* request line format inproper */
        header(b_p, 403, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0);
        return 0;
    }

    return 1;
}

/**
 * <Get the corresponding client socket for from_read pipe>
 *
 * @param fd It is the fd of from_read pipe.
 * @param buf_array It is the pointer of array of Buffer.
 *
 * @return Returns client socket if found matching client socket,
 *         else, returns 0.
 */
int cgi_writes_sock(int fd, Buffer** buf_array) {
    int j;
    for (j = 0; j <= nfds; j++) {
        Buffer* b_p = buf_array[j];
        if (b_p != NULL) {
            if ((b_p->cgi_writes_back) != 0 && fd == (b_p->cgi_writes_back)) {
                return j;
            }
        }
    }
    return 0;
}

/**
 * <Get the corresponding client socket for to_write pipe>
 *
 * @param fd It is the fd of to_write pipe.
 * @param buf_array It is the pointer of array of Buffer.
 *
 * @return Returns client socket if found matching client socket,
 *         else, returns 0.
 */
int cgi_reads_sock(int fd, Buffer** buf_array) {
    int j;
    for (j = 0; j <= nfds; j++) {
        Buffer* b_p = buf_array[j];
        if (b_p != NULL) {
            if ((b_p->cgi_reads_data) != 0 && fd == (b_p->cgi_reads_data)) {
                return j;
            }
        }
    }
    return 0;
}

/**
 * <Starts running the server>
 *
 * @return Returns EXIT_SUCCESS if successful, and if
 *         there is an error, the program exits.
 */
int lisod_start() {
    /* initialize variables */
    int server_sock;
    struct sockaddr_in addr;
    fd_set read_fd_set, write_fd_set;
    int active_fds;
    SSL_CTX* ssl_context;
    int ssl_server_sock;
    struct sockaddr_in ssl_addr;

    /* initialize OpenSSL library */
    SSL_load_error_strings();
    SSL_library_init();

    /* TLSv1 SSL_METHOD structure for a dedicated server */
    if ((ssl_context = SSL_CTX_new(TLSv1_server_method())) == NULL) {
        char log_str[256] = {0};
        sprintf(log_str, "Error creating SSL context.\n");
        update_log(log_str);
        return EXIT_FAILURE;
    }

    /* SSL register private key */
    if (SSL_CTX_use_PrivateKey_file(ssl_context, key_uri,
                                    SSL_FILETYPE_PEM) == 0) {
        SSL_CTX_free(ssl_context);
        char log_str[256] = {0};
        sprintf(log_str, "Error associating private key.\n");
        update_log(log_str);
        return EXIT_FAILURE;
    }

    /* SSL register certificate */
    if (SSL_CTX_use_certificate_file(ssl_context, cert_uri,
                                     SSL_FILETYPE_PEM) == 0) {
        SSL_CTX_free(ssl_context);
        char log_str[256] = {0};
        sprintf(log_str, "Error associating certificate.\n");
        update_log(log_str);
        return EXIT_FAILURE;
    }

    /* initialize the Buffer pointer array */
    Buffer* buf_array[BUF_ARRAY_LEN];
    int h;
    for (h = 0; h <= BUF_ARRAY_LEN; h++) {
        buf_array[h] = NULL;
    }

    char log_tmp[256] = {0};
    sprintf(log_tmp, "$---- Server Ready to Run ----$\n");
    update_log(log_tmp);
    /* create a http socket for server, should always stay open */
    server_sock = create_socket();

    addr.sin_family = AF_INET;
    addr.sin_port = htons(http_port);
    addr.sin_addr.s_addr = INADDR_ANY;

    /* create a https socket for server, should always stay open */
    ssl_server_sock = create_socket();

    ssl_addr.sin_family = AF_INET;
    ssl_addr.sin_port = htons(https_port);
    ssl_addr.sin_addr.s_addr = INADDR_ANY;

    /* server bind sockets to ports */
    bind_socket(server_sock, addr);
    bind_socket(ssl_server_sock, ssl_addr);

    /* servers sockets start listening */
    socket_listen(server_sock, 5);
    socket_listen(ssl_server_sock, 5);

    nfds = ssl_server_sock;
    active_fds = ssl_server_sock;

    /* finally, loop waiting for input and then write it back */
    while (1) {
        /* initialize the file descriptor sets for select() */
        FD_ZERO (&read_fd_set);
        FD_ZERO (&write_fd_set);
        /* add both server sockets to fd sets */
        FD_SET (server_sock, &read_fd_set);
        FD_SET (ssl_server_sock, &read_fd_set);

        /* add socket with available buffers to read_fd_set and write_fd_set */
        int g;
        for (g = 0; g <= nfds; g++) {
            Buffer* b_p = buf_array[g];
            if (b_p != NULL) {
                /* client socket stays open */
                /* available space in the read buffer for a given socket */
                if ((b_p->read_len) < BUF_SIZE) {
                    FD_SET(g, &read_fd_set);
                }
                /* something left in the write buffer for a given socket */
                if ((b_p->written_len) < (b_p->response_len)) {
                    FD_SET(g, &write_fd_set);
                }
                /* pipe for script to write back */
                if ((b_p->cgi_writes_back) != 0) {
                    FD_SET((b_p->cgi_writes_back), &read_fd_set);
                }
                /* pipe for server to send script message body */
                if ((b_p->cgi_reads_data) != 0 && (b_p->bodybuf) != NULL) {
                    FD_SET((b_p->cgi_reads_data), &write_fd_set);
                }
            }
        }

        /* waiting for input connections to read and write */
        active_fds = socket_select(nfds + 1, &read_fd_set, &write_fd_set);

        if (active_fds < 0) {
            char log_str[256] = {0};
            sprintf(log_str, "Server socket select error.\n");
            update_log(log_str);
            exit(-1);
        }

        /* check each connection if any is ready */
        int i;
        for (i = 0; i <= nfds; i++) {
            /* check if sockets are ready to be read */
            if (FD_ISSET(i, &read_fd_set)) {
                /* cgi script wants to write back data */
                int cgi_sock = 0;
                if ((cgi_sock = cgi_writes_sock(i, buf_array))) {
                    Buffer* b_p = buf_array[cgi_sock];
                    if ((b_p->writebuf) == NULL) {
                        char* tmp = (char*) malloc(BUF_SIZE);
                        memset(tmp, 0, BUF_SIZE);
                        (b_p->writebuf) = tmp;
                    }
                    int ideal_read_len = BUF_SIZE - (b_p->response_len);
                    int len = read(i, (b_p->writebuf) + (b_p->response_len),
                                   (size_t)ideal_read_len);
                    /* the script has no more to send */
                    if (len == 0){
                        /* if data is all written back to client */
                        close(b_p->cgi_writes_back);
                        (b_p->cgi_writes_back) = 0;
                    }
                    /* reading failure */
                    else if (len < 0) {
                        close(b_p->cgi_writes_back);
                        (b_p->cgi_writes_back) = 0;
                        header(b_p, 500, NULL, NULL, NULL, NULL,
                               NULL, NULL, NULL, 0);
                        char log_str[256] = {0};
                        sprintf(log_str,
                            "Read from pipe failed for socket %d.\n", cgi_sock);
                        update_log(log_str);
                        return EXIT_FAILURE;
                    }
                    /* reading was successful, */
                    else {
                        (b_p->response_len) += len;
                    }
                }
                /* if the http server socket is ready, it should accept a new
                   connection from client */
                else if (i == server_sock) {
                    char* ip_address = (char*) malloc(LINE_SIZE);
                    memset(ip_address, 0, LINE_SIZE);
                    int new_socket = socket_accept(server_sock, ip_address);

                    /* updates nfds */
                    if (new_socket > nfds) {
                        nfds = new_socket;
                    }
                    /* initialize a clean Buffer for new_socket */
                    buf_array[new_socket] = (Buffer*) malloc(sizeof(Buffer));
                    memset(buf_array[new_socket], 0, sizeof(Buffer));
                    (buf_array[new_socket])->client_ip = ip_address;
                    char* tmp = (char*) malloc(BUF_SIZE);
                    memset(tmp, 0, BUF_SIZE);
                    ((buf_array[new_socket])->readbuf) = tmp;
                }
                /* if the https server socket is ready, it should accept a new
                   SSL connection from client */
                else if (i == ssl_server_sock) {
                    char* ip_address = (char*) malloc(LINE_SIZE);
                    memset(ip_address, 0, LINE_SIZE);
                    int new_ssl_socket = socket_accept(ssl_server_sock,
                                                       ip_address);

                    /************ WRAP SOCKET WITH SSL ************/
                    SSL* ssl_client_context = (SSL*) malloc(sizeof(SSL));
                    if ((ssl_client_context = SSL_new(ssl_context)) == NULL) {
                        close_socket(server_sock);
                        close_socket(ssl_server_sock);
                        SSL_CTX_free(ssl_context);
                        char log_str[256] = {0};
                        sprintf(log_str,
                            "Error creating SSL context for socket %d.\n", i);
                        update_log(log_str);
                        return EXIT_FAILURE;
                    }

                    if (SSL_set_fd(ssl_client_context, new_ssl_socket) == 0) {
                        close_socket(server_sock);
                        close_socket(ssl_server_sock);
                        SSL_free(ssl_client_context);
                        SSL_CTX_free(ssl_context);
                        char log_str[256] = {0};
                        sprintf(log_str,
                            "Error creating SSL context for socket %d.\n", i);
                        update_log(log_str);
                        return EXIT_FAILURE;
                    }
                    int accept_status = SSL_accept(ssl_client_context);
                    if (accept_status <= 0) {
                        close_socket(server_sock);
                        close_socket(ssl_server_sock);
                        SSL_free(ssl_client_context);
                        SSL_CTX_free(ssl_context);
                        char log_str[256] = {0};
                        sprintf(log_str,
                            "Error accepting SSL context for socket %d.\n", i);
                        update_log(log_str);
                        return EXIT_FAILURE;
                    }
                    /************ END WRAP SOCKET WITH SSL ************/

                    /* updates nfds */
                    if (new_ssl_socket > nfds) {
                        nfds = new_ssl_socket;
                    }

                    /* initialize a clean Buffer for new_ssl_socket */
                    buf_array[new_ssl_socket] =
                        (Buffer*) malloc(sizeof(Buffer));
                    memset(buf_array[new_ssl_socket], 0, sizeof(Buffer));
                    /* indicate this is a SSL connection */
                    (buf_array[new_ssl_socket])->SSL = 1;
                    (buf_array[new_ssl_socket])->ssl_client= ssl_client_context;
                    (buf_array[new_ssl_socket])->client_ip = ip_address;
                    char* tmp = (char*) malloc(BUF_SIZE);
                    memset(tmp, 0, BUF_SIZE);
                    ((buf_array[new_ssl_socket])->readbuf) = tmp;
                }
                /* client socket is ready to be read */
                else {
                    /* check if it is a normal connection reading */
                    if ((buf_array[i])->SSL == 0) {
                        socket_read(i, buf_array);
                    }
                    /* otherwise, it must be a SSL connection reading */
                    else {
                        SSL_socket_read(i, buf_array);
                    }
                    process_request(i, buf_array);
                }
            }
            /* check if sockets are ready to be written */
            if (FD_ISSET(i, &write_fd_set)) {
                /* check if script is ready to receive the message body */
                int cgi_sock = 0;
                if ((cgi_sock = cgi_reads_sock(i, buf_array))) {
                    Buffer* b_p = buf_array[cgi_sock];
                    /* makes sure the complete message body is received */
                    /* before writing it to the script */
                    if ((b_p->body_total_len) != 0 &&
                        (b_p->body_total_len) == (b_p->body_read_len)) {
                        /* there is more left to write to script */
                        if ((b_p->body_written_len)<(b_p->body_total_len)){
                            int ideal_send_len = (b_p->body_total_len) -
                                                (b_p->body_written_len);
                            int len = write(i, (b_p->bodybuf) +
                                            (b_p->body_written_len),
                                            (size_t)ideal_send_len);
                            if (len < 0) {
                                close(b_p->cgi_reads_data);
                                (b_p->cgi_reads_data) = 0;
                                (b_p->body_total_len) = 0;
                                (b_p->body_written_len) = 0;
                                (b_p->body_read_len) = 0;
                                //free(b_p->bodybuf);
                                (b_p->bodybuf) = NULL;
                                header(b_p, 500, NULL, NULL, NULL, NULL,
                                       NULL, NULL, NULL, 0);
                                char log_str[256] = {0};
                                sprintf(log_str,
                                "Write pipe failed for sock %d.\n", cgi_sock);
                                update_log(log_str);
                                return EXIT_FAILURE;
                            }
                            if (len > 0) {
                                (b_p->body_written_len) += len;
                            }
                        }
                        /* whole body is sent, clear message body for */
                        /* next cgi POST request */
                        if ((b_p->body_written_len)==(b_p->body_total_len)){
                            close(b_p->cgi_reads_data);
                            (b_p->cgi_reads_data) = 0;
                            (b_p->body_total_len) = 0;
                            (b_p->body_written_len) = 0;
                            (b_p->body_read_len) = 0;
                            //free(b_p->bodybuf);
                            (b_p->bodybuf) = NULL;
                        }
                    }
                }
                Buffer* b_p = buf_array[i];
                if (b_p != NULL) {
                    /* make sure there is more to send before sending, when the
                       length response does not equal the length written back */
                    if ((b_p -> written_len) < (b_p->response_len)) {
                        /* check if it is a normal connection writing */
                        if (b_p->SSL == 0) {
                            socket_write(i, buf_array);
                        }
                        /* otherwise, it must be a SSL connection writing */
                        else {
                            SSL_socket_write(i, buf_array);
                        }
                    }

                    /* all data sent back, clear buffer memory for next read
                       and write from the same socket */
                    if ((b_p->response_len) != 0 &&
                        (b_p->response_len) == (b_p -> written_len)) {
                        /* if client indicate this is the last request */
                        if ((buf_array[i])->client_close == 1) {
                            buf_array[i] = NULL;
                        }
                        else {
                            (b_p->written_len) = 0;
                            (b_p->response_len) = 0;
                            (b_p->cgi_writes_back) = 0;
                            //free(b_p->writebuf);
                            (b_p->writebuf) = NULL;
                        }
                    }
                }
            }
        }
    }

    int j;
    for (j = 0; j <= nfds; j++) {
        Buffer* b_p = buf_array[j];
        if (b_p != NULL) {
            /* closes the left open sockets, including the server socket */
            close_socket(j);
        }
    }

    return EXIT_SUCCESS;
}

/***** from provided daemonize.c - begin *****/

/**
 * internal signal handler
 */
void signal_handler(int sig) {
    switch(sig) {
        case SIGHUP:
            /* rehash the server */
            break;
        case SIGTERM:
            /* finalize and shutdown the server */
            exit(EXIT_SUCCESS);
            break;
        default:
            break;
            /* unhandled signal */
    }
}

/**
 * internal function daemonizing the process
 */
int daemonize() {
    /* drop to having init() as parent */
    int i, lfp, pid = fork();
    char str[256] = {0};
    char log_str[256] = {0};
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);

    setsid();

    for (i = getdtablesize(); i>=0; i--)
        close(i);

    i = open("/dev/null", O_RDWR);
    dup(i); /* stdout */
    dup(i); /* stderr */
    umask(027);

    lfp = open(lock_uri, O_RDWR|O_CREAT, 0640);

    if (lfp < 0)
        exit(EXIT_FAILURE); /* can not open */

    if (lockf(lfp, F_TLOCK, 0) < 0)
        exit(EXIT_SUCCESS); /* can not lock */

    /* only first instance continues */
    sprintf(str, "%d\n", getpid());
    write(lfp, str, strlen(str)); /* record pid to lockfile */

    signal(SIGCHLD, SIG_IGN); /* child terminate signal */

    signal(SIGHUP, signal_handler); /* hangup signal */
    /* software termination signal from kill */
    signal(SIGTERM, signal_handler);

    sprintf(log_str,
            "Successfully daemonized lisod process, pid %d.\n", getpid());
    update_log(log_str);

    /* start running lisod server */
    lisod_start();

    return EXIT_SUCCESS;
}

/***** from provided daemonize.c - end *****/

/**
 * <Get the commandline arguments and run the server>
 *
 * @param argc It is the number of input argument.
 * @param argv It is the arguments list.
 *
 * @return Returns EXIT_SUCCESS if successful, and if
 *         there is an error, the program exits.
 */
int main(int argc, char* argv[])
{
    /* make sure the input arguments are valid */
    if (argc == 9) {
        http_port = atoi(argv[1]);
        /* port ranges from 0 to 65535 */
        if (!(http_port >= 0 && http_port <= MAX_PORT)) {
            fprintf(stdout, "Invalid http port number.\n");
            exit(-1);
        }

        https_port = atoi(argv[2]);
        /* port ranges from 0 to 65535 */
        if (!(https_port >= 0 && https_port <= MAX_PORT)) {
            fprintf(stdout, "Invalid https port number.\n");
            exit(-1);
        }

        log_uri = argv[3];
        lock_uri = argv[4];
        www_folder = argv[5];
        cgi_path = argv[6];
        key_uri = argv[7];
        cert_uri = argv[8];
    }
    else {
        usage();
    }

    /* For testing purpose daemonize() should be disabled */
    //lisod_start();
    daemonize();

    return EXIT_SUCCESS;
}
