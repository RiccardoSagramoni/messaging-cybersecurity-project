#include <arpa/inet.h> // for htons, ntohs...
#include <cerrno> // for errno
#include <cstring> // for memset
#include <cstdio> // for file access and error-handling functions
#include <iostream>
#include <limits>
#include <list>
#include <mutex>
#include <netinet/in.h> // for struct sockaddr_in
#include <openssl/bio.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <shared_mutex>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h> // for close socket
#include <unordered_map>

using namespace std;

struct connection_data {
	shared_timed_mutex mutex_struct;
	
	const int socket;
	mutex mutex_socket_out;
	mutex mutex_socket_in;

	bool available = true;
	
	// TODO chiave pubblica

	connection_data(const int _socket) : socket(_socket)
	{
		
	}
};

class Server {
	static const int BACKLOG_LEN = 10;
	

	int listener_socket = -1;
	sockaddr_in server_address;

	// Hashed map which stores client's data, necessary for connection
	// Key: client's username
	// Value: data of client (socket, available state...)
	unordered_map<string, connection_data*> connected_client;
	
	// Shared mutex for accessing the hashed map
	shared_timed_mutex connected_client_mutex;
	

public:
	Server(const uint16_t port);
	~Server();

	// Functions that handle connection with clients {

	bool configure_listener_socket();
	int accept_client (sockaddr_in* client_addr);
	bool add_new_client (string username, const int socket);
	bool handle_socket_lock (const string username, const bool lock, const bool input);
	int close_client (const string username);
	
	// }
	
	// Functions that monitor current status of client connections {
	
	list<string> get_available_clients_list ();
	bool is_client_online (const string& username);

	// }
};



class ServerThread {
	const string filename_prvkey = "privkey.pem";
	const string filename_certificate = "certificate.pem";
	
	Server* server;
	
	int client_socket;
	sockaddr_in main_client_address;

	string username;

	// Base methods for networking {

	int send_message (const int socket, void* msg, const uint32_t msg_len);
	long receive_message (const int socket, void** msg);

	// }


	// Fundamental methods for cryptography {
	
	static const EVP_CIPHER* get_authenticated_encryption_cipher ();
	
	static DH* get_dh2048();
	static EVP_PKEY* generate_key_dh ();
	static unsigned char* derive_session_key (EVP_PKEY* my_dh_key, EVP_PKEY* peer_key, size_t key_len);
	
	EVP_PKEY* get_server_private_key ();
	X509* get_server_certificate ();
	static EVP_PKEY* get_client_public_key(const string& username);

	static int gcm_encrypt (unsigned char* plaintext, size_t plaintext_len,
					        unsigned char* aad, size_t aad_len, 
					        unsigned char* key,
					        unsigned char* iv, size_t iv_len, 
					        unsigned char*& ciphertext, size_t& ciphertext_len,
					        unsigned char*& tag, size_t& tag_len);
	static int gcm_decrypt (unsigned char* ciphertext, int ciphertext_len,
                            unsigned char* aad, int aad_len,
                            unsigned char* tag,
                            unsigned char* key,
                            unsigned char* iv, int iv_len,
                            unsigned char*& plaintext, size_t& plaintext_len);
	unsigned char* sign_message(unsigned char* msg, size_t msg_len, unsigned int& signature_len);

	static int verify_client_signature (unsigned char* signature, size_t signature_len, 
                                        unsigned char* cleartext, size_t cleartext_len,
                                        const string& username);
	
	static void secure_free (void* addr, size_t len);
	static unsigned char* generate_iv (EVP_CIPHER const* cipher, size_t& iv_len);
	// }


	// Management of client's request {

	//unsigned char* get_new_client_command ();
	//int execute_client_command (const unsigned char* msg);
	//int execute_show (const unsigned char*);
	//int execute_talk (const unsigned char*);
	//int execute_exit ();

	uint8_t get_request_type (const unsigned char* msg);
	bool check_username_validity(const string& username);

	// }


	// Authentication and negotiation of keys (STS protocol) {
	
	unsigned char* authenticate_and_negotiate_key (string& username, size_t& key_len);
	int STS_receive_hello_message (EVP_PKEY*& peer_key, string& username);
	int STS_send_session_key (unsigned char* shared_key, size_t shared_key_len, 
	                          EVP_PKEY* my_dh_key, EVP_PKEY* peer_key, 
							  unsigned char* iv, size_t iv_len);
	int STS_receive_response (unsigned char* shared_key, size_t shared_key_len,
	                          EVP_PKEY* my_dh_key, EVP_PKEY* peer_key, const string& username);
	
	
	// }

public:
	ServerThread(Server* _server, const int socket, const sockaddr_in addr);
	
	void run();
};



////////////////////////////////////////////////////////
//////                   MACROS                   //////
////////////////////////////////////////////////////////

// Type of client request (1 byte) {
	#define		TYPE_SHOW		0x00
	#define		TYPE_TALK		0x01
	#define		TYPE_EXIT		0x02
// }

#define TAG_SIZE 16
