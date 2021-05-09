#include <arpa/inet.h> // for htons, ntohs...
#include <cerrno> // for errno
#include <cstring> // for memset
#include <cstdio> // for file access and error-handling functions
#include <iostream>
#include <limits>
#include <mutex>
#include <netinet/in.h> // for struct sockaddr_in
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h> // for close socket
#include <unordered_map>

using namespace std;

struct connection_data {
	int socket;
	mutex mutex_socket_out;
	mutex mutex_socket_in;

	bool available;
	
	// chiave pubblica
};

class Server {
	static const int BACKLOG_LEN = 10;

	int listener_socket = -1;
	sockaddr_in server_address;

	unordered_map<string, connection_data*> connected_client;
	mutex connected_client_mutex;
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
	int accept_client(sockaddr_in* client_addr) const;

	// getSocketOutput
	// releaseSocketOutput ???
};


class ServerThread {
	Server* server;

	// login
    // talk
    // show
    // logout
public:
	ServerThread(Server* serv);
	//--> ricevi comando, esegui
	void run(const int socket, const sockaddr_in addr);

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
	 * @param msg pointer to the pointer that will contain the address 
	 *            of the received message. On success, the message will 
	 *            be allocated with a malloc call.
	 * @return 1 on success, 0 if client closed the connection on the socket,
	 *        -1 if any error occurred
	 */
	int receive_message (const int socket, void** msg);
};
