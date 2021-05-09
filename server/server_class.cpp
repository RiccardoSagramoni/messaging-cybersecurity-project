#include "server.h"

Server::Server(const uint16_t port)
{
    // Configure server_address
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
	server_address.sin_port = htons(port);
	server_address.sin_addr.s_addr = INADDR_ANY;
}

Server::~Server()
{

}

/** 
 * Configure the listener socket, bind server IP address
 * and start listening for client's requests.
 * 
 * @return false in case of failure, true otherwise
 */
bool Server::configure_listener_socket ()
{
	// Check if socket has already been created
	if (listener_socket != -1) return false;

	// Create socket
	listener_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (listener_socket == -1) {
		return false;
	}

	cout << "Listener socket created\n";

	// Bind IP address to socket
	if (-1 == bind(listener_socket, (sockaddr*)&server_address, sizeof(server_address)) ) {
		return false;
	}

	cout << "Listener socket successfully binded\n";

	// Start listening to client's requests
    if (-1 == listen(listener_socket, BACKLOG_LEN) ) {
		return false;
    }

    cout << "Socket is listening\n";

	return true;
}

/** 
 * Accept client connection request from listener socker.
 * Create a new socket for communication with the client.
 * 
 * @param client_addr IP address of client
 * @return new socket's id, -1 if it failed
 */
int Server::accept_client (sockaddr_in* client_addr) const
{
    socklen_t addr_len = sizeof(client_addr);

    // It could block the thread if there are no pending requests
    return accept(listener_socket, (sockaddr*)client_addr, &addr_len);
}
