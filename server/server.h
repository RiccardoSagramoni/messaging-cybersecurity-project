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
	// getSocketOutput
	// releaseSocketOutput ???

	Server(const uint16_t port);
	~Server();

	/** Configure the listener socket, bind server IP address
	 *	and start listening for client's requests.
	 *
	 *	@return false in case of failure
	 */
	bool configure_listener_socket();

	/** Accept client connection request from listener socker.
	 *	Create a new socket for communication with the client.
	 *
	 *	@param client_addr IP address of client
	 *	@return new socket's id, -1 if it failed
	 */
	int accept_client(sockaddr_in* client_addr) const;
};


class ServerThread {
	Server* server;

	// invia 	(crypto?)
	// ricevi 	(crypto?)

	// login
    // talk
    // show
    // logout
public:
	//--> ricevi comando, esegui
	void run(Server* serv, const int socket, const sockaddr_in addr);
};

