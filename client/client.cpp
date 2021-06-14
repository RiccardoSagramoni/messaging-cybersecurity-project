#include "client.h"

int main(int argc, char** argv) 
{
    if(argc != 2) {
		cerr << "Usage: " << argv[0] << " <port>\n";
		exit(EXIT_FAILURE);
	}

    string port_str (argv[1]); // Get argument with port number
	unsigned long port_long = stoul(port_str); // Convert to unsigned integer

	// Check uint16_t overflow
	if (port_long > numeric_limits<uint16_t>::max()) {
		cerr << "Inserted port number too big" << endl;
		exit(EXIT_FAILURE);
	}

    string username;
    cout << "Please enter your name: ";
    cin >> username;
    if (username.length() > 32 || username.length() < 2) {
		cerr << "Name must be less than 30 and more than 2 characters.";
	}

    if(!Client::does_username_exist(username)) {
        cerr << "Username " << username << " doesn't exist" << endl;
    }

    // Ask user the password for client's private key
    string password;
    cout << "Enter PEM password for your private key: ";
    cin >> password; // TODO check cin ?


    Client client((uint16_t)port_long, username, password);
    if (!client.configure_socket()) {
        perror("configure_listener_socket() failed");
		exit(EXIT_FAILURE);
    }
    if (!client.connect_to_server()) {
        perror("connect_to_server() failed");
		exit(EXIT_FAILURE);
    }

    cout << "=== WELCOME TO THE CHATROOM ===" << endl;

    client.exec();
}