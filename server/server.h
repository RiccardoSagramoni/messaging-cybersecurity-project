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

	/**
	 * Configure the listener socket, bind server IP address
	 * and start listening for client's requests.
	 * 
	 * @return true on success
 	 * @return false on failure
	 */
	bool configure_listener_socket();

	/** 
	 * Accept client connection request from listener socker.
	 * Create a new socket for communication with the client.
	 * 
	 * @param client_addr IP address of client
	 * 
	 * @return id of new socket on success
	 * @return -1 on failure
	 */
	int accept_client (sockaddr_in* client_addr) const;

	/**
	 * Add a new client to the list of all the clients connected to the server
	 * and set its state to "available to talk".
	 * 
	 * @param username string identifier of the client
	 * @param socket socket linked to the client
	 * @return true on success
	 * @return false on failure (client already logged in)
	 */
	bool add_new_client (string username, const int socket);

	/**
	 * Exclusively lock/unlock INPUT or OUTPUT stream of the socket related to specified client
	 * 
	 * @param username string containing client's username
	 * @param lock true to lock the socket, false to unlock it
	 * @param input true to lock INPUT stream of socket, false to lock OUTPUT stream of socket
	 * 
	 * @return true on success
	 * @return false on failure
	 */
	bool handle_socket_lock (const string username, const bool lock, const bool input);

	/**
	 * // TODO
	 * 
	 * @param username 
	 * @return int 
	 */
	int close_client (const string username);

	/**
	 * Return a list of client logged to the server and available to talk
	 * 
	 * @return list of available client's usernames
	 */
	list<string> get_available_clients_list ();

	/**
	 * // TODO
	 * @return true 
	 * @return false 
	 */
	bool is_client_online (const string& username);

	/**
	 * // TODO
	 * 
	 * @return EVP_PKEY* 
	 */
	EVP_PKEY* get_privkey ();
};



class ServerThread {
	Server* server;
	
	int client_socket;
	sockaddr_in main_client_address;

	string username;

	/**
	 * // TODO
	 * 
	 * @return DH* 
	 */
	static DH* get_dh2048();

	/**
	 * Send a message though the specified socket
	 * 
	 * @param socket socket descriptor
	 * @param msg pointer to the message
	 * @param msg_len length of the message 
	 * @return 1 on success, -1 otherwise 
	 */
	int send_message (const int socket, void* msg, const uint32_t msg_len);

	/**
	 * Wait for a message, expected on the specified socket
	 * 
	 * @param socket socket descriptor
	 * @param msg the address of a pointer. 
	 * After a successful function invocation, such a pointer will point 
	 * to an allocated buffer containing the received message.
	 *            
	 * @return length of message on success, 0 if client closed the connection on the socket, 
	 * -1 if any error occurred
	 */
	long receive_message (const int socket, void** msg);

	unsigned char* get_new_client_command ();

	int execute_client_command (const unsigned char* msg);

	int execute_show (const unsigned char*);
	int execute_talk (const unsigned char*);
	int execute_exit ();

	uint8_t get_request_type (const unsigned char* msg);


	//
	bool authenticate_and_negotiate_keys (string& username);
	static EVP_PKEY* generate_key_dh ();
	static unsigned char* derive_session_key (EVP_PKEY* my_dh_key, EVP_PKEY* peer_key, size_t key_len);
	static const EVP_CIPHER* get_symmetric_cipher ();
	int receive_hello_message (EVP_PKEY*& peer_key, string& username);
	bool check_username_validity(const string& username);
	//
//
//	int receive_client_nonce(string& username, unsigned char** msg);
//
//	int encrypt_data_pubkey ();

public:
	/**
	 * Constructor
	 * 
	 * @param _server pointer to server object
	 * @param socket descriptor of the socket created for the client's connection request
	 * @param addr IP address of connected client
	 */
	ServerThread(Server* _server, const int socket, const sockaddr_in addr);
	
	/**
	 * Start the thread
	 */
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

#define		NONCE_LENGHT	256