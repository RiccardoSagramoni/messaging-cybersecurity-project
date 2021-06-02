#include "server.h"

/**
 * Launch the main function of a server thread
 * so that it can handle client's connection request
 * 
 * @param server 
 * @param socket 
 * @param addr 
 */
void new_thread (Server* server, const int socket, const sockaddr_in addr) 
{
	ServerThread st(server, socket, addr);
	st.run();
};

// Start and configure the server
// argv[1]: server port
int main (int argc, char** argv)
{
	if (argc < 2) {
		cerr << "Error: application must be launched with parameter <port>" << endl;
		exit(EXIT_FAILURE);
	}

	string port_str (argv[1]); // Get argument with port number
	unsigned long port_long = stoul(port_str); // Convert to unsigned integer

	// Check uint16_t overflow
	if (port_long > numeric_limits<uint16_t>::max()) {
		cerr << "Inserted port number too big" << endl;
		exit(EXIT_FAILURE);
	}

	// Initialize server
	Server server((uint16_t) port_long);

	// Configure socket
	if (!server.configure_listener_socket()) {
		perror("Server::configure_listener_socket() failed");
		exit(EXIT_FAILURE);
	}

	// Allocate structure for client IP address
	sockaddr_in client_addr;
	memset(&client_addr, 0, sizeof(client_addr));

	// The main thread stops waiting for a connection request from a client.
	// Then, it accepts the request and create a new thread which will handle it
	while (true) {
        int new_socket = server.accept_client(&client_addr);

        if (new_socket == -1) {
			perror("Server::accept_client failed");
			continue;
        }

        thread t(new_thread, &server, new_socket, client_addr);
		t.detach();
	}
}
