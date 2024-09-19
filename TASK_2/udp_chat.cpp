#include <cstdlib>
#include <cstring>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/prov_ssl.h>
#include <stdio.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/rand.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER_PORT 8080


#define CA_CERT "intermediate/CAflie.pem"

#define CLIENT_CERT "alice/alice_crt.pem"
#define CLIENT_KEY "alice/alice_private_key.pem"

#define SERVER_CERT "bob/bob_crt.pem"
#define SERVER_KEY "bob/bob_private_key.pem"
struct ReceiveFuncStruct {
    int recvfrom_flag;
    char buf[1024];
};

void error(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}
// Callback function to generate cookie
static int generate_cookie_callback(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len) {
    memcpy(cookie,"pramod",6);
    *cookie_len = 6;

    return 1;
}

// Callback function to verify cookie
static int verify_cookie_callback(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len) {
    // Always accept the received cookie for simplicity
    return 1;
}

int sendMessage(int sockfd, struct sockaddr_in *dest_addr, socklen_t dest_len, const char *message) {
    int sendto_flag;

    sendto_flag = sendto(sockfd, message, strlen(message), 0, (struct sockaddr *)dest_addr, dest_len);
    if (sendto_flag < 0)
        error("sendto error");

    printf("Sent a message: %s\n", message);
    return sendto_flag;
}

ReceiveFuncStruct receiveMessage(int sockfd, struct sockaddr_in *src_addr, socklen_t *src_len) {
    ReceiveFuncStruct response;

    response.recvfrom_flag = recvfrom(sockfd, response.buf, sizeof(response.buf), 0, (struct sockaddr *)src_addr, src_len);
    if (response.recvfrom_flag < 0)
        error("recvfrom error");

    printf("Received a message: %s\n", response.buf);

    return response;
}

int sendMessageSSL(SSL *ssl, const char *message) {
    int ssl_write_flag;

    ssl_write_flag = SSL_write(ssl, message, strlen(message));
    if (ssl_write_flag <= 0)
        error("SSL_write error");

    printf("Sent a SSL message: %s\n", message);
    return ssl_write_flag;
}

ReceiveFuncStruct receiveMessageSSL(SSL *ssl) {
    ReceiveFuncStruct response;
    bzero(response.buf, sizeof(response.buf));
    response.recvfrom_flag = SSL_read(ssl, response.buf, sizeof(response.buf));
    if (response.recvfrom_flag <= 0)
    // ERR_print_errors_fp(stderr);
    // exit(0);
        error("SSL_read error");

    printf("Received a SSL message: %s\n", response.buf);

    return response;
}


void InitializeSSL()
{
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

void serverMode() {
    int server_sock, len_srv;
    struct sockaddr_in server, client;
    socklen_t len_client = sizeof(client);
	struct timeval timeout;
    // Initialize socket
    server_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_sock < 0)
        error("Opening socket");

    len_srv = sizeof(server);
    bzero(&server, len_srv);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(SERVER_PORT);

    // Bind socket
    if (bind(server_sock, (struct sockaddr *)&server, len_srv) < 0) {
        perror("Binding Error");
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    // First Handshake
    ReceiveFuncStruct resp = receiveMessage(server_sock, &client, &len_client);
    char *chat_hello_reply_ptr = strstr(resp.buf, "chat_hello");
    if (chat_hello_reply_ptr == NULL) {
        error("Error for chat_hello");
    }
    sendMessage(server_sock, &client, len_client, "chat_ok_reply");
    printf("First Handshake Done\n");

    // Second Handshake
    ReceiveFuncStruct ssl_resp = receiveMessage(server_sock, &client, &len_client);
    char *ssl_resp_ptr = strstr(ssl_resp.buf, "chat_START_SSL");
    if (ssl_resp_ptr == NULL) {
        error("Error for chat_START_SSL");
    }
    sendMessage(server_sock, &client, len_client, "chat_START_SSL_ACK");
    printf("Second Handshake Done\n");

	printf("Starting to Initialize SSL ");
    InitializeSSL();

    SSL_CTX *ctx;
    SSL *ssl;
    X509 *server_cert = NULL;
    EVP_PKEY *pkey;

    ctx = SSL_CTX_new(DTLSv1_2_server_method());
    if (!ctx) {
        error("Error Creating context");
    }

	SSL_CTX_set_security_level(ctx, 1);
	SSL_CTX_set_mode(ctx,SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_session_cache_mode(ctx,SSL_SESS_CACHE_OFF);
    SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
	SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie_callback);
    SSL_CTX_set_cookie_verify_cb(ctx, &verify_cookie_callback);

	/* Load the server certificate into the SSL_CTX structure */
	if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT, SSL_FILETYPE_PEM) <= 0) {
		error("Error Loading Server Cert");
	}

	/* Load the private-key corresponding to the server certificate */
	if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, SSL_FILETYPE_PEM) <= 0) {

		error("Error Loading Server Key");
	}

	/* Check if the server certificate and private-key matches */
	if (!SSL_CTX_check_private_key(ctx)) {
		error("Error Server key and cert do not matches");
	}
	printf("server Key and cert loaded\n");

	/* Load the RSA CA certificate into the SSL_CTX structure */
	if (!SSL_CTX_load_verify_locations(ctx, CA_CERT, NULL)) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}


    SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    timeout.tv_sec = 5;
    timeout.tv_usec = 0;



    // Create a BIO object for the socket
    BIO *bio = BIO_new_dgram(server_sock, BIO_NOCLOSE);
        /* bio = BIO_new_dgram(server_sock,BIO_NOCLOSE);   */
    BIO_ctrl(bio,BIO_CTRL_DGRAM_SET_RECV_TIMEOUT,0,&timeout);
        if(!bio){
            error("Error in creating bio");
        }

	printf("InitializeSSL Done\n");



    // Create a new SSL object for the connection
    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        close(server_sock);
        exit(EXIT_FAILURE);
    }

	SSL_set_options(ssl,SSL_OP_COOKIE_EXCHANGE);

    // Set the BIO for SSL object
    SSL_set_bio(ssl, bio, bio);



    // Listen for incoming DTLS connections
	/* int listen_res = 0; */
    if (DTLSv1_listen(ssl, (BIO_ADDR *)&server) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    printf("DTLS Listening Started\n");

    // Perform SSL handshake
    if (SSL_accept(ssl) != 1) {
        ERR_print_errors_fp(stderr);
        BIO_free(bio);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(server_sock);
        exit(EXIT_FAILURE);
    }
    printf("Server accepting ...\n");

    if(SSL_get_peer_certificate(ssl) && SSL_get_verify_result(ssl) == X509_V_OK)
        printf("Client Certificate verify Done \n");

    timeout.tv_sec = 0;
    timeout.tv_usec = 0;
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

     // Receive and Send Messages 
	char messagessl[1024];
	while (1) {
		ReceiveFuncStruct resp = receiveMessageSSL(ssl);
        // printf("server resp: %s %d",resp.buf,strcmp(resp.buf, "chat_close"));

        char *chat_close_ptr = strstr(resp.buf, "chat_close");
        if (chat_close_ptr != NULL) {
            // error("Error for chat_close");
            printf("exit called\n");
            sendMessageSSL(ssl, "chat_close");

            close(server_sock);
            exit(1);
        }
        // if(strcmp(resp.buf, "chat_close") == 0) {
        //     printf("exit called");
        //     close(server_sock);
        //     exit(EXIT_FAILURE);
        // }
	
        bzero(messagessl, sizeof(messagessl));

		/* if(strcmp(resp.buf, "exit") == 0) */
		printf("Enter the message to send: ");
		fgets(messagessl, sizeof(messagessl), stdin);
		sendMessageSSL(ssl, messagessl);
	}
}

void clientMode(char *hostname) {
    int client_sock,len_srv;
    struct sockaddr_in server;
    socklen_t len_sock_addr = sizeof(struct sockaddr_in);
	struct timeval timeout;

    // Initialize socket
    client_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (client_sock < 0)
        error("Socket error");

    // Setup server address


    len_srv = sizeof(server);
    bzero(&server, len_srv);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(SERVER_PORT);

    // server.sin_family = AF_INET;
    // struct hostent *hp = gethostbyname(hostname);
    // if (hp == 0)
    //     error("Unknown host");
    // bcopy((char *)hp->h_addr, (char *)&server.sin_addr, hp->h_length);
    // server.sin_port = htons(SERVER_PORT);

    if(connect(client_sock,(struct sockaddr*) &server,sizeof(server))){
        printf(" Error in connecting socket from client\n");
        exit(0);
    }



    // Send and receive chat_hello
    sendMessage(client_sock, &server, len_sock_addr, "chat_hello");
    ReceiveFuncStruct chat_h_res = receiveMessage(client_sock, &server, &len_sock_addr);
    char *chat_ok_reply_ptr = strstr(chat_h_res.buf, "chat_ok_reply");
    if (chat_ok_reply_ptr == NULL) {
        error("Error for chat_hello");
    }
    printf("First Handshake Done\n");

    // Second Handshake
    sendMessage(client_sock, &server, len_sock_addr, "chat_START_SSL");
    ReceiveFuncStruct start_ssl_res = receiveMessage(client_sock, &server, &len_sock_addr);
    char *start_ssl_res_ptr = strstr(start_ssl_res.buf, "chat_START_SSL_ACK");
    if (start_ssl_res_ptr == NULL) {
        error("Error for chat_START_SSL_ACK");
    }
    printf("Second Handshake Done\n");




	printf("Starting to Initialize SSL ");
	InitializeSSL();

	SSL_CTX *ctx;
	X509 *client_cert = NULL;

/* Create a SSL_CTX structure */
	ctx = SSL_CTX_new(DTLSv1_2_client_method());

	if (!ctx) {
		error("Error Creating context");
	}
	/* set to one to resolve small key error */
	SSL_CTX_set_security_level(ctx, 1);

	SSL_CTX_set_mode(ctx,SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_session_cache_mode(ctx,SSL_SESS_CACHE_OFF);
    SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);

/* Load the server certificate into the SSL_CTX structure */
	if (SSL_CTX_use_certificate_file(ctx, CLIENT_CERT, SSL_FILETYPE_PEM) <= 0) {
	/* ERR_print_errors_fp(stderr); */
	/* exit(1); */
	error("Error Loading Client Cert");
	}

	/* Load the private-key corresponding to the server certificate */
	if (SSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEY, SSL_FILETYPE_PEM) <= 0) {
		error("Error Loading Client Key");
	}

	/* Check if the server certificate and private-key matches */
	if (!SSL_CTX_check_private_key(ctx)) {
		error("Error Client key and cert do not matches");
	}
	printf("Client Key and cert loaded\n");



	/* Load the RSA CA certificate into the SSL_CTX structure */
	if (!SSL_CTX_load_verify_locations(ctx, CA_CERT, NULL)) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	/* Set flag in context to require peer (server) certificate */
	/* verification */
	/* SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL); */
	/* SSL_CTX_set_verify_depth(ctx,1); */

	printf("Client side CA loaded\n");
    const char *pfs_ciphers = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384";
    if (SSL_CTX_set_cipher_list(ctx, pfs_ciphers) != 1) {
        ERR_print_errors_fp(stderr);
        printf("Failed to set cipher suites\n");
    }

    SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

	printf("InitializeSSL Done\n");



/* ----------------------------------------------- */

/* An SSL structure is created */
   SSL *ssl = SSL_new(ctx);

    // Create a new SSL object for the connection
    // if (ssl == NULL) {
    //     ERR_print_errors_fp(stderr);
    //     SSL_CTX_free(ctx);
    //     close(client_sock);
	// 	error("client new ssl");
    //     exit(EXIT_FAILURE);
    // }


	printf("Client ssl new\n");
    // Set socket file descriptor for the SSL object
	/* Assign the socket into the SSL structure (SSL and socket without BIO) */
    /* SSL_set_fd(ssl,client_sock); */

	if (SSL_set_fd(ssl, client_sock) != 1) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        close(client_sock);
        exit(EXIT_FAILURE);
	}
	printf("Client ssl fd\n");

	/* Perform SSL Handshake on the SSL client */

	int ret_ssl_code = SSL_connect(ssl);
    if (ret_ssl_code!= 1) {
		printf("in n %d ",ret_ssl_code);
        ERR_print_errors_fp(stderr);
		/* SSL_get_error(ssl,ret_ssl_code); */
        exit(EXIT_FAILURE);
    }
	printf("Connected to ssl server\n");

	/* Receive data from the SSL server */

    if(SSL_get_peer_certificate(ssl) && SSL_get_verify_result(ssl) == X509_V_OK)
     printf("Client Certificate Verified! \n");

/* ----------------------------------------------- */

	char messagessl[1024];
	while (1) {
        bzero(messagessl, sizeof(messagessl));

		printf("Enter the message to send: ");
		fgets(messagessl, sizeof(messagessl), stdin);
		sendMessageSSL(ssl, messagessl);

		ReceiveFuncStruct resp = receiveMessageSSL(ssl);

        char *chat_close_ptr = strstr(resp.buf, "chat_close");
        if (chat_close_ptr != NULL) {
            // error("Error for chat_close");
            printf("exit called\n");
            sendMessageSSL(ssl, "chat_close");

            close(client_sock);
            exit(1);
        }
		// if(strcmp(resp.buf, "chat_close") == 0) {
        //     printf("exit called");
        //     close(client_sock);
        // }
	}
	/* char bufferssl[1024]; */
	/*     int len = SSL_read(ssl, bufferssl, sizeof(bufferssl)); */
	/*     if (len < 0) */
	/*         error("Error receiving message"); */

	/*     bufferssl[len] = '\0'; */
	/*     printf("Received SSL : %s\n", bufferssl); */



	/*     // Send and receive messages */
	/*     char message[1024]; */
	/*     while (1) { */
	/*         printf("Enter the message to send: "); */
	/*         fgets(message, sizeof(message), stdin); */
	/*         sendMessage(client_sock, &server, len_sock_addr, message); */

	/*         ReceiveFuncStruct resp = receiveMessage(client_sock, &server, &len_sock_addr); */
	/*     } */

    close(client_sock);
}

int main(int argc, char *argv[]) {

    if (argc < 2) {
        fprintf(stderr, "ERROR: no parameter provided");
        exit(EXIT_FAILURE);
    }

    if (argc == 2 && strcmp(argv[1], "-s") == 0) {
        serverMode();
    } else if (argc == 3 && strcmp(argv[1], "-c") == 0) {
        clientMode(argv[2]);
    }

    return 0;
}
