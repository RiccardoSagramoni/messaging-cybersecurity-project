#include "server.h"

Server::Server(const unsigned short port)
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

// Configure the listener_socket
// Return false in case of failure
bool Server::configure_listener_socket ()
{
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

/** Accept client connection request from listener socker.
 *	Create a new socket for communication with the client
 *	@return -1 if failed, else id of new socket
 */
int Server::accept_client (sockaddr_in const* client_addr)
{
    socklen_t addr_len = sizeof(client_addr);
    return accept(listener_socket, (sockaddr*)client_addr, &addr_len);
}




