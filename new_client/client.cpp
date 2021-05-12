#include "client.h"
#define LENGTH 2048
int main(int argc, char** argv) {
    if(argc != 2){
		printf("Usage: %s <port>\n", argv[0]);
		return EXIT_FAILURE;
	}
    int port = atoi(argv[1]);
    printf("Please enter your name: ");
    Client client(port);
    if (!client.configure_socket()) {
        perror("configure_listener_socket() failed");
		exit(EXIT_FAILURE);
    }
    if (!client.connects()) {
        perror("connect() failed");
		exit(EXIT_FAILURE);
    }
    ClientThread ct;
    thread th(&ClientThread::runSend, ct, "Sample Task");
    th.join();
    //client.thrcv();
    while (true)
    {
        
    }
    //client.exit();
}