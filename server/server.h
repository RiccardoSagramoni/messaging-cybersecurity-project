#include <arpa/inet.h> // for htons, ntohs...
#include <cerrno> // for errno
#include <cstring> // for memset
#include <cstdio> // for file access and error-handling functions
#include <iostream>
#include <limits>
#include <list>
#include <mutex>
#include <netinet/in.h> // for struct sockaddr_in
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

	unordered_map<string, connection_data*> connected_client;
	shared_timed_mutex connected_client_mutex;
	// unordered_map (utente, connection_data*); --> hash_map
	// mutex per hash map

public:
	Server(const uint16_t port);
	~Server();

	/**
	 * Configure the listener socket, bind server IP address
	 * and start listening for client's requests.
	 * 
	 * @return false in case of failure, true otherwise
	 */
	bool configure_listener_socket();

	/** 
	 * Accept client connection request from listener socker.
	 * Create a new socket for communication with the client.
	 *
	 * @param client_addr IP address of client
	 * @return new socket's id, -1 if it failed
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

	list<string> get_available_clients_list ();
};



class ServerThread {
	Server* server;
	
	int main_client_socket;
	sockaddr_in main_client_address;



	/**
	 * Send a message though the specified socket
	 * 
	 * @param socket socket descriptor
	 * @param msg pointer to the message
	 * @param msg_len length of the message 
	 * @return 1 on success, -1 otherwise 
	 */
	int send_message (const int socket, void* msg, const uint16_t msg_len);

	/**
	 * Wait for a message, expected on the specified socket
	 * 
	 * @param socket socket descriptor
	 * @param msg the address to a pointer. 
	 * After a successful function invocation, such a pointer will point 
	 * to an allocated buffer containing the received message.
	 *            
	 * @return 1 on success
	 * @return 0 if client closed the connection on the socket
	 * @return -1 if any error occurred
	 */
	int receive_message (const int socket, void** msg);

	unsigned char* get_new_client_command ();

	int execute_client_command (unsigned char* msg);

	int execute_show();
	int execute_talk();
	int execute_exit();

	uint8_t get_request_type (unsigned char* msg);

public:
	ServerThread(Server* _server, const int socket, const sockaddr_in addr);
	//--> ricevi comando, esegui
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