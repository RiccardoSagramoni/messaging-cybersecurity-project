#include "client.h"
#define LENGTH 2048



void thread_main (Client* client, const int socket, const sockaddr_in addr) 
{
	ClientThread st(client, socket, addr);
	st.run();
}
void send_thread (Client* client, const int socket, const sockaddr_in addr) 
{
	ClientThread st(client, socket, addr);
    while (true) {
        // TODO st.send_message(...);
    }
	
}

void receive_thread (Client* client, const int socket, const sockaddr_in addr) 
{
	ClientThread st(client, socket, addr);
    while (true) {
       // TODO st.receive_message(...);
    }
	
}





int main(int argc, char** argv) {
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

    printf("Please enter your name: "); // TODO

    Client client((uint16_t)port_long);
    if (!client.configure_socket()) {
        perror("configure_listener_socket() failed");
		exit(EXIT_FAILURE);
    }
    if (!client.connects()) {
        perror("connect() failed");
		exit(EXIT_FAILURE);
    }

    /*thread t(send_thread, &client, client.get_sock(), client.get_server_addr());
    thread tt(receive_thread, &client, client.get_sock(), client.get_server_addr());*/
    thread t(thread_main, &client, client.get_sock(), client.get_server_addr());
    t.join(); // TODO remove
    while (true)
    {
        
    }
    //client.exit();
}