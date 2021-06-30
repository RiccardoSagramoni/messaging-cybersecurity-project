#include <arpa/inet.h> // for htons, ntohs...
#include <atomic>
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
	// Socket
	const int socket;
	mutex mutex_socket_out;
	mutex mutex_socket_in;

	// Available status
	bool available = true;
	shared_timed_mutex mutex_available;

	// Variable for starting a talk
	condition_variable ready_to_talk_cv;
	mutex ready_to_talk_mutex;
	bool has_chosen_interlocutor = false;
	string interlocutor_user = "";

	// Wait for the end of talk
	condition_variable end_talk_cv;
	mutex end_talk_mutex;
	bool is_talk_ended = false;
	int talk_exit_status = 0;

	// Counter against replay attack
	mutex counter_mx;
	uint32_t server_counter = 0;
	uint32_t client_counter = 0;
	
	// Shared symmetric key
	const unsigned char* key;
	const size_t key_len;
	shared_timed_mutex mutex_key;

	connection_data(const int _socket, const unsigned char* _key, const size_t _key_len) : 
		socket(_socket), key(_key), key_len(_key_len)
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
	bool add_new_client (string username, const int socket, 
	                     const unsigned char* key, const size_t key_len);
	bool handle_socket_lock (const string& username, const bool to_lock, const uint8_t stream);
	unsigned char* get_client_shared_key (const string& username, size_t& key_len);
	int remove_client (const string& username);
	
	// }
	
	// Functions that monitor current status of client connections {
	
	list<string> get_available_clients_list ();
	int set_available_status (const string& username, const bool status);

	// }

	int prepare_for_talking (const string& username, unsigned char*& key, size_t& key_len);
	int wait_start_talk (const string& wanted_user, const string& asking_user);
	int wait_end_talk (const string& user);
	int notify_start_talk (const string& wanted_user, const string asking_user, const bool is_accepting);
	int notify_end_talk (const string& user);
	int set_talk_exit_status(const string& username, const int status);

	int check_client_counter(const string& username, const uint32_t counter);
	int get_server_counter(const string& username, uint32_t& counter);
};



class ServerThread {
	static const string filename_prvkey;
	static const string filename_certificate;
	
	Server* server;
	
	int client_socket;
	sockaddr_in main_client_address;

	string client_username;
	unsigned char* client_key = nullptr;
	size_t client_key_len = 0;

	// Fundamental methods for networking {

	static int send_message (const int socket, void* msg, const uint32_t msg_len);
	static long receive_message (const int socket, void** msg);

	// }


	// Fundamental methods for cryptography {
	
	static const EVP_CIPHER* get_authenticated_encryption_cipher ();
	
	static DH* get_dh2048();
	static EVP_PKEY* generate_key_dh ();
	static unsigned char* derive_session_key (EVP_PKEY* my_dh_key, EVP_PKEY* peer_key, size_t key_len);
	
	static EVP_PKEY* get_server_private_key ();
	static X509* get_server_certificate ();
	static EVP_PKEY* get_client_public_key(const string& username);

	static int gcm_encrypt (const unsigned char* plaintext, const int plaintext_len,
					        const unsigned char* aad, const int aad_len, 
					        const unsigned char* key,
					        const unsigned char* iv, const int iv_len, 
					        unsigned char*& ciphertext, size_t& ciphertext_len,
					        unsigned char*& tag, size_t& tag_len);
	static int gcm_decrypt (const unsigned char* ciphertext, const int ciphertext_len,
                            const unsigned char* aad, const int aad_len,
                            const unsigned char* tag,
                            const unsigned char* key,
                            const unsigned char* iv, const int iv_len,
                            unsigned char*& plaintext, size_t& plaintext_len);
	unsigned char* sign_message(const unsigned char* msg, const size_t msg_len, unsigned int& signature_len);

	static int verify_client_signature (const unsigned char* signature, const size_t signature_len, 
                                        const unsigned char* cleartext, const size_t cleartext_len,
                                        const string& username);
	
	static void secure_free (void* addr, size_t len);
	static unsigned char* generate_iv (EVP_CIPHER const* cipher, size_t& iv_len);
	// }


	// Management of client's request {

	int send_plaintext (const int socket, const unsigned char* msg, const size_t msg_len, const unsigned char* key, const string& username);
	int send_error (const int socket, const uint8_t type, const unsigned char* key, const bool own_lock, const string& username);
	int receive_plaintext (const int socket, unsigned char*& msg, size_t& msg_len, const unsigned char* key, const string& username);

	int get_new_client_command (unsigned char*& msg, size_t& msg_len);
	int execute_client_command (const unsigned char* msg, const size_t msg_len);
	int execute_show ();
	int execute_talk (const unsigned char* msg, const size_t msg_len);
	int execute_accept_talk (const unsigned char* msg, const size_t msg_len, const bool accept);
	int execute_exit ();

	uint8_t get_request_type (const unsigned char* msg);
	bool check_username_validity(const string& username);
	static int check_directory_traversal (const char* file_name);

	// }

	// Talk {

	int send_request_to_talk (const int socket, const string& from_user, const string& to_user, const unsigned char* key);
	int send_notification_for_accepted_talk_request();
	int negotiate_key_between_clients (const string& peer_username, const int peer_socket, const unsigned char* peer_key);
	int talk_between_clients (const string& peer_username, const int peer_socket, const unsigned char* peer_key);
	void talk (const string& src_username, const int src_socket, const unsigned char* src_key, const string& dest_username, const int dest_socket, const unsigned char* dest_key, atomic<int>* return_value);

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
	~ServerThread();
	
	void run();
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
