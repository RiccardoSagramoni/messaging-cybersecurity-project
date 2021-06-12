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
#include <condition_variable>

using namespace std;

class thread_bridge {
	mutex mx_new_msg;
	condition_variable cv_new_msg;
	bool is_msg_ready = false;
	unsigned char* new_msg = nullptr;
	size_t new_msg_len = 0;

	mutex mx_request_talk;
	condition_variable cv_request_talk;
	bool has_received_request_to_talk = false;

public:
	unsigned char* wait_for_new_message (size_t& msg_len);
	void insert_new_message(unsigned char* msg, size_t msg_len);
	bool check_request_talk();
	int notify_request_talk();
};

class Client {
	// Connection data {

	int server_socket = 0;
	sockaddr_in server_addr;
	const string ip = "127.0.0.1";
	const uint16_t port;

	const string client_username;
	const string client_password;

	unsigned char* session_key = nullptr;
	size_t session_key_len = 0;

	// }

	// Files {

	static const string keys_folder;
	static const string keys_extension;
	static const string filename_CA_certificate;
	static const string filename_crl;
	
	// }

	// Fundamental methods for networking {

	static int send_message (const int socket, void* msg, const uint32_t msg_len);
	static long receive_message (const int socket, void** msg);

	// }


	// Fundamental methods for cryptography {
	void secure_free (void* addr, size_t len);
	
	DH* get_dh2048();
	EVP_PKEY* generate_key_dh();
	unsigned char* generate_iv(EVP_CIPHER const* cipher, size_t& iv_len);
	unsigned char* derive_session_key(EVP_PKEY* my_dh_key, EVP_PKEY* peer_key, size_t key_len);
	
	EVP_PKEY* get_client_private_key();
	X509* get_CA_certificate();
	X509_CRL* get_crl();
	unsigned char* sign_message(unsigned char* msg, size_t msg_len, unsigned int& signature_len);
	int verify_server_signature(unsigned char* signature, size_t signature_len, unsigned char* cleartext, size_t cleartext_len, EVP_PKEY* client_pubkey);

	const EVP_CIPHER* get_authenticated_encryption_cipher();
	int gcm_decrypt (unsigned char* ciphertext, int ciphertext_len,unsigned char* aad, int aad_len,unsigned char* tag,unsigned char* key,unsigned char* iv, int iv_len, unsigned char*& plaintext, size_t& plaintext_len);
	int gcm_encrypt (unsigned char* plaintext, int plaintext_len, unsigned char* aad, int aad_len, unsigned char* key, unsigned char* iv, int iv_len, unsigned char*& ciphertext, size_t& ciphertext_len,unsigned char*& tag, size_t& tag_len);

	int send_plaintext (const int socket, unsigned char* msg, const size_t msg_len, unsigned char* key);
	int receive_plaintext (const int socket, unsigned char*& msg, size_t& msg_len, unsigned char* shared_key);

	// }


	// STS protocol (authentication and key establishment) {
	int negotiate();
	
	int receive_from_server_pub_key(EVP_PKEY*& peer_key);
	
	int send_sig(EVP_PKEY* my_dh_key,EVP_PKEY* peer_key, unsigned char* shared_key, size_t shared_key_len);
	int decrypt_and_verify_sign(unsigned char* ciphertext, size_t ciphertext_len, EVP_PKEY* my_dh_key,EVP_PKEY* peer_key, unsigned char* shared_key, size_t shared_key_len, unsigned char* iv, size_t iv_len, unsigned char* tag, EVP_PKEY* server_pubkey);
	
	int build_store_certificate_and_validate_check(X509* cert, X509_CRL* crl, X509* cert_to_ver);
	
	// }

	// User commands {
	
	int talk();
	int receive_response_command_to_server();
	void print_command_options();
	int send_command_to_server(unsigned char* msg, unsigned char* shared_key);
	int show(unsigned char* shared_key);
	uint8_t get_message_type(const unsigned char* msg);
	
	int exit_by_application(unsigned char* shared_key);
	int receive_request_to_talk(unsigned char* session_key);
	int send_message_to_client(unsigned char* clients_session_key, unsigned char* server_session_key);
	int receive_message_from_client(unsigned char* clients_session_key, unsigned char* server_session_key);
	int negotiate_key_with_client (unsigned char*& clients_session_key, size_t& clients_session_key_len);

	// }
	
	
public:
	Client(const uint16_t _port, const string _name, const string _password);
	void run();

	// Connection with the server {
	
	bool configure_socket();
	bool connect_to_server();
	void exit();

	// }

	static bool does_username_exist(const string& username);
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
