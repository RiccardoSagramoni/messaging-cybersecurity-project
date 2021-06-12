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
#include <list>
#include <iomanip>

#define LENGTH 2048

using namespace std;


class Client {
    int sockfd = 0;
    string name;
    string password;
    sockaddr_in server_addr;
    string ip = "127.0.0.1";
    const uint16_t port;

public:
    Client(const uint16_t _port, const string _name, const string _password);
    ~Client();
    bool configure_socket();
    bool connects();
    void exit();
    void str_overwrite_stdout();
    void str_trim_lf (char* arr, int length);
    sockaddr_in get_server_addr();
    int get_sock();

    string get_username ();
    string get_password();

    static bool does_username_exist(const string& username);
};

class ClientThread {
	Client* client;
	int server_socket;
	sockaddr_in server_address;
    unsigned char* session_key;
    size_t session_key_len;

	const string keys_folder = "keys/";
    const string filename_CA_certificate = keys_folder + "FoundationsOfCybersecurity_cert.pem";
    const string filename_crl = keys_folder + "FoundationsOfCybersecurity_crl.pem";


public:
	ClientThread(Client* cli, const int socket, const sockaddr_in addr);
	void run();
    static int send_message (const int socket, void* msg, const uint32_t msg_len);
	static long receive_message (const int socket, void** msg);
    DH* get_dh2048();
    int negotiate(const string& username);
    EVP_PKEY* generate_key_dh();
	EVP_PKEY* get_client_private_key();
    int receive_from_server_pub_key(EVP_PKEY*& peer_key);
    const EVP_CIPHER* get_authentication_encryption_cipher();
	unsigned char* sign_message(unsigned char* msg, size_t msg_len, unsigned int& signature_len);
	int send_sig(EVP_PKEY* my_dh_key,EVP_PKEY* peer_key, unsigned char* shared_key, size_t shared_key_len);
	int decrypt_and_verify_sign(unsigned char* ciphertext, size_t ciphertext_len, EVP_PKEY* my_dh_key,EVP_PKEY* peer_key, unsigned char* shared_key, size_t shared_key_len, unsigned char* iv, size_t iv_len, unsigned char* tag, EVP_PKEY* server_pubkey);
	int verify_server_signature(unsigned char* signature, size_t signature_len, unsigned char* cleartext, size_t cleartext_len, EVP_PKEY* client_pubkey);
    unsigned char* derive_session_key(EVP_PKEY* my_dh_key, EVP_PKEY* peer_key, size_t key_len);
    X509* get_CA_certificate();
    X509_CRL* get_crl();
    int build_store_certificate_and_validate_check(X509* cert, X509_CRL* crl, X509* cert_to_ver);
    void secure_free (void* addr, size_t len);
    int gcm_decrypt (unsigned char* ciphertext, int ciphertext_len,unsigned char* aad, int aad_len,unsigned char* tag,unsigned char* key,unsigned char* iv, int iv_len,unsigned char*& plaintext, size_t& plaintext_len);
    int gcm_encrypt (unsigned char* plaintext, int plaintext_len, unsigned char* aad, int aad_len, unsigned char* key, unsigned char* iv, int iv_len, unsigned char*& ciphertext, size_t& ciphertext_len,unsigned char*& tag, size_t& tag_len);
    const EVP_CIPHER* get_authenticated_encryption_cipher();
    unsigned char* generate_iv(EVP_CIPHER const* cipher, size_t& iv_len);
    int talk();
    int receive_response_command_to_server();
    void print_command();
    int send_command_to_server(unsigned char* msg, unsigned char* shared_key);
    int show(unsigned char* shared_key);
    uint8_t get_message_type(const unsigned char* msg);
    int send_plaintext (const int socket, unsigned char* msg, const size_t msg_len, unsigned char* key);
    int receive_plaintext (const int socket, unsigned char*& msg, size_t& msg_len, unsigned char* shared_key);
    int exit_by_application(unsigned char* shared_key);
    int receive_request_to_talk(unsigned char* session_key);
    int send_message_to_client(unsigned char* clients_session_key, unsigned char* server_session_key);
    int receive_message_from_client(unsigned char* clients_session_key, unsigned char* server_session_key);
    int negotiate_key_with_client (unsigned char*& clients_session_key, size_t& clients_session_key_len);
};



////////////////////////////////////////////////////////
//////                   MACROS                   //////
////////////////////////////////////////////////////////

// Type of client messages (1 byte) {
	#define		TYPE_SHOW		0x00
	#define		TYPE_TALK		0x01
	#define		TYPE_EXIT		0x02
	#define 	ACCEPT_TALK		0x03
	#define 	REFUSE_TALK		0x13
	#define 	TALKING			0x04
	#define 	END_TALK		0x05

	#define 	CLIENT_ERROR	0xFF
// }

// Type of server messages (1 byte) {
	#define		SERVER_OK				0x00
	#define		SERVER_ERR				0xFF

	#define 	SERVER_REQUEST_TO_TALK	0x01
	#define 	SERVER_END_TALK			0X02
// }

// Type of errors (1 byte) {
	#define		ERR_ALREADY_LOGGED		0x01
	#define		ERR_WRONG_TYPE			0x02

	#define 	ERR_GENERIC				0xFF
// }

#define TAG_SIZE 16