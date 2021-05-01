#include <arpa/inet.h>
#include <cerrno> // for errno
#include <climits>
#include <cstring> // for memset
#include <cstdio> // for fopen
#include <iostream>
#include <mutex>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h> // for close socket

using namespace std;

struct client_data {
	int socket;
	mutex mutex_socket_out;
	mutex mutex_socket_in;

	// chiave pubblica
};

class Server {
	static const int BACKLOG_LEN = 10;

	int listener_socket = -1;
	sockaddr_in server_address;

	// unordered_map (utente, sock); --> hash_map
	// mutex per hash map

public:
	// costruttore distruttore
	// getSocketOutput
	// releaseSocketOutput ???

	Server(const unsigned short);
	~Server();

	bool configure_listener_socket();
	int accept_client(sockaddr_in const*);
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

