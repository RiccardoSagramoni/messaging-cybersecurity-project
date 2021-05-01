#include "server.h"

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

	// Check unsigned short overflow
	if (port_long > USHRT_MAX) {
		cerr << "Inserted port number too big" << endl;
		exit(EXIT_FAILURE);
	}

	// Initialize server
	Server server((unsigned short) port_long);

	// Configure socket
	if (!server.configure_listener_socket()) {
		perror("Server::configure_listener_socket() failed");
		exit(EXIT_FAILURE);
	}

	// Client address
	sockaddr_in client_addr;
	memset(&client_addr, 0, sizeof(client_addr));

	// Lambda expressione for starting a thread
	auto thread_main = [](Server* server, const int socket, const sockaddr_in addr) {
		ServerThread st;
		st.run(server, socket, addr);
	};

	while (true) {
        int new_socket = server.accept_client(&client_addr);

        if (new_socket == -1) {
			perror("Server::accept_client failed");
			close(new_socket);
			continue;
        }

        thread t(thread_main, &server, new_socket, client_addr);
	}
}



















