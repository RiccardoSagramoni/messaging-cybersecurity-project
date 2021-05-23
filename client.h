
#include <openssl/rand.h>
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <cstdio>
#include <iostream>
#include <limits>
#include <mutex>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <openssl/dh.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>


#define LENGTH 2048


using namespace std;

class Client {
    int sockfd = 0;
    string name;
    sockaddr_in server_addr;
    string ip = "127.0.0.1";
    const uint16_t port;

public:
    Client(const uint16_t ports);
    ~Client();
    bool configure_socket();
    bool connects();
    void exit();
    void str_overwrite_stdout();
    void* send_msg_handler(void* dummyPt);
    void* rcv_msg_handler(void* dummyPt);
    void str_trim_lf (char* arr, int length);
    sockaddr_in get_server_addr();
    int get_sock();
};

Client::Client(const uint16_t ports) : port(ports)
{
    cin >> name;
    if (name.length() > 32 || name.length() < 2) {
		printf("Name must be less than 30 and more than 2 characters.\n");
	}
}

Client::~Client()
{
}

bool Client::configure_socket() {
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        // TODO cerr 
        return false;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(ip.c_str());
    server_addr.sin_port = htons(port);

    return true;
}
bool Client::connects() {
    int ret;
    int err = connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (err == -1) {
		printf("ERROR: connect\n");
		return false;
	}
        ret = send(sockfd, &name, 32, 0);
        if (ret < 0) {
            return false;
        }
    printf("=== WELCOME TO THE CHATROOM ===\n");
    return true;
}
void Client::exit() {
    close(sockfd);
	//return EXIT_SUCCESS;
}
void Client::str_overwrite_stdout() {
    printf("%s", "> ");
    fflush(stdout);
}

void Client::str_trim_lf(char* arr, int length) {
    int i;
    for (i = 0; i < length; i++) {
        if (arr[i] == '\n') {
            arr[i] = '\0';
            break;
        }
    }
}

void *Client::send_msg_handler(void *dummyPt) {
    char message[LENGTH] = {};
    char buffer[LENGTH + 32] = {};
    while (true)
    {
        str_overwrite_stdout();
        fgets(message, LENGTH, stdin);
        str_trim_lf(message, LENGTH);
        if (strcmp(message, "exit") == 0) {
			break;
        }
        else {
            sprintf(buffer, "%s: %s\n", name, message);
            send(sockfd, buffer, strlen(buffer), 0);
        }
        bzero(message, LENGTH);
        bzero(buffer, LENGTH + 32);
    }
}

void *Client::rcv_msg_handler(void *dummyPt) {

}


int Client::get_sock() {
    return sockfd;
}
sockaddr_in Client::get_server_addr() {
    return server_addr;
}









class ClientThread {
	Client* client;
	int main_server_socket;
	sockaddr_in main_server_address;
public:
	ClientThread(Client* cli, const int socket, const sockaddr_in addr);
	void run();
    static int send_message (const int socket, void* msg, const uint32_t msg_len);
	static int receive_message (const int socket, void** msg);
    DH* get_dh2048();
    int negotiate(string username);
    EVP_PKEY* generate_key_dh();
};
ClientThread::ClientThread(Client* cli, const int socket, const sockaddr_in addr) {
    client=cli;
	main_server_socket = socket;
	main_server_address = addr;
}




DH* ClientThread::get_dh2048()
{
    static unsigned char dhp_2048[] = {
        0xBF, 0x3E, 0xD6, 0x60, 0x1C, 0x1C, 0xFE, 0x17, 0xE9, 0xEA,
        0x64, 0xBB, 0xF4, 0x50, 0x28, 0x72, 0xDA, 0xB9, 0x3C, 0xAA,
        0x6F, 0x11, 0x82, 0xA6, 0x28, 0x50, 0x9F, 0xCB, 0x3B, 0x2E,
        0x3F, 0x0C, 0xC0, 0xA1, 0xC6, 0xBF, 0x58, 0xB7, 0x07, 0x01,
        0xCB, 0x65, 0xD4, 0xD9, 0xDD, 0x7A, 0x63, 0x54, 0xBB, 0x0D,
        0xB4, 0x2F, 0x41, 0x6E, 0x56, 0xFD, 0x57, 0x54, 0xDD, 0x07,
        0xF7, 0xFB, 0x6F, 0xE9, 0x42, 0xE8, 0xD2, 0x28, 0x03, 0x9C,
        0x2E, 0x44, 0x48, 0xBA, 0x95, 0x9D, 0xC6, 0xEB, 0x5D, 0x34,
        0x6E, 0x82, 0x60, 0x5C, 0x0B, 0x12, 0xE6, 0x86, 0xBE, 0x7B,
        0x5A, 0x09, 0xAE, 0xA2, 0xEA, 0x45, 0x46, 0xBB, 0xCB, 0x14,
        0x3A, 0x9E, 0xAA, 0x15, 0xFE, 0x3C, 0x78, 0x3B, 0x07, 0xE0,
        0x80, 0xA0, 0x4D, 0x5F, 0xDE, 0xC9, 0x7D, 0xC8, 0x37, 0x56,
        0xE1, 0x51, 0x49, 0x6E, 0xB5, 0x49, 0xF5, 0xE7, 0xC4, 0xB4,
        0xB1, 0xD4, 0x77, 0x39, 0x03, 0x72, 0x75, 0x7B, 0x36, 0x2B,
        0xAF, 0xB5, 0xCA, 0x1E, 0xD6, 0xF6, 0x71, 0x0B, 0x0A, 0x12,
        0x59, 0x9B, 0x2B, 0x2F, 0x74, 0x98, 0x65, 0xC2, 0xC3, 0x8D,
        0xBF, 0x1D, 0xD0, 0x44, 0x80, 0x17, 0x9C, 0x7A, 0xDE, 0x8B,
        0x4D, 0x9D, 0x18, 0xB4, 0xE6, 0x90, 0xEB, 0x16, 0x49, 0xCD,
        0x0F, 0x77, 0x3C, 0xE6, 0x6D, 0x18, 0xF0, 0x99, 0x61, 0x34,
        0x8E, 0x06, 0xC9, 0x74, 0xF6, 0xF8, 0x5A, 0x56, 0x0B, 0x5B,
        0xBB, 0x2D, 0x04, 0xB4, 0x27, 0xD4, 0x8D, 0xF7, 0x98, 0x50,
        0x53, 0x04, 0x8B, 0xDA, 0xA1, 0xCF, 0x16, 0x7A, 0xDF, 0x46,
        0xC9, 0x62, 0xB5, 0x82, 0x56, 0xD0, 0xED, 0xF0, 0x3D, 0xBD,
        0xAB, 0xC8, 0xC6, 0x30, 0xA3, 0x28, 0x8F, 0x1C, 0x68, 0x70,
        0x1D, 0xF5, 0x40, 0xBF, 0xC3, 0x71, 0x99, 0xDE, 0x6A, 0x78,
        0xB6, 0x8B, 0x4B, 0x83, 0xD0, 0x9B
    };
    static unsigned char dhg_2048[] = {
        0x02
    };
    DH *dh = DH_new();
    BIGNUM *p, *g;

    if (dh == NULL)
        return NULL;
    p = BN_bin2bn(dhp_2048, sizeof(dhp_2048), NULL);
    g = BN_bin2bn(dhg_2048, sizeof(dhg_2048), NULL);
    if (p == NULL || g == NULL
            || !DH_set0_pqg(dh, p, NULL, g)) {
        DH_free(dh);
        BN_free(p);
        BN_free(g);
        return NULL;
    }
    return dh;
}



int ClientThread::send_message (const int socket, void* msg, const uint32_t msg_len)
{
	ssize_t ret;
	uint32_t len = htons(msg_len);	
	ret = send(socket, &len, sizeof(len), 0);
	if (ret < 0) {
		perror("Error while sending message's length");
		return -1;
	}
	ret = send(socket, msg, msg_len, 0);
	if (ret < 0) {
		perror("Error while sending message");
		return -1;
	}
}
int ClientThread::receive_message (const int socket, void** msg)
{
	ssize_t ret;
	uint32_t len;
	
	// Receive length of message
	ret = recv(socket, &len, sizeof(len), 0);
	if (ret == 0) { // Client closed the connection
		return 0;
	}	
	if (ret < 0 || ret < sizeof(len)) { // Received data too short
		perror("Message length receive_thread failed");
		return -1;
	}
	
	// Convert received length to host format
	len = ntohs(len);

	*msg = malloc(len);
	if (!(*msg)) {
		cerr << "Malloc failed (message too long?)\n";
		return -1;
	}
	
	// Receive the message
	ret = recv(socket, *msg, len, 0);
	if (ret == 0) { // Client has closed the connection
		return 0;
	}
	if (ret < 0 || ret < len) { // Received data too short
		perror("Receive per il messaggio fallito");
		
		free(*msg);
		*msg = nullptr;

		return -1;
	}

	return len;











}
void ClientThread::run()
{
	int ret;

	string username;
    negotiate(username);
	while (true) {
	}
}




int ClientThread::negotiate(string username) {
    int ret;
    EVP_PKEY* key_neg;
    //generate g^a
    EVP_PKEY* my_dh_key = generate_key_dh();
    send_message(main_server_socket, (void*) &username, username.length());
    BIO* mbio= BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(mbio, my_dh_key);
    char* pubkey_buf= NULL;
    long pubkey_size= BIO_get_mem_data(mbio, &pubkey_buf);
    send_message(main_server_socket, (void*) my_dh_key, pubkey_size);
    string message_received;
    /*while(true) {
        if (receive_message(main_server_socket, (void**) message_received)>0)
    }*/
    return ret;
}


EVP_PKEY* ClientThread::generate_key_dh()
{
	int ret;
	
	// Get DH params p and g
	EVP_PKEY* dh_params = EVP_PKEY_new();
	if (!dh_params) {
		// TODO print error?
		return nullptr;
	}
	DH* temp_dh_params = get_dh2048();
	ret  = EVP_PKEY_set1_DH(dh_params, temp_dh_params);
	free(temp_dh_params);
	if (ret != 1) {
		// TODO print error?
		return nullptr;
	}

	// Generate g**b
	EVP_PKEY_CTX* dh_gen_ctx = EVP_PKEY_CTX_new(dh_params, nullptr);
	if (!dh_gen_ctx) {
		// TODO print error?
		free(dh_params);
		return nullptr;
	}

	ret = EVP_PKEY_keygen_init(dh_gen_ctx);
	if (ret != 1) {
		// TODO print error?
		free(dh_params);
		EVP_PKEY_CTX_free(dh_gen_ctx);
		return nullptr;
	}

	EVP_PKEY* dh_key = nullptr;
	ret = EVP_PKEY_keygen(dh_gen_ctx, &dh_key);
	if (ret != 1) {
		// TODO print error?
		free(dh_params);
		EVP_PKEY_CTX_free(dh_gen_ctx);
		return nullptr;
	}

	free(dh_params);
	EVP_PKEY_CTX_free(dh_gen_ctx);
	return dh_key;
}