#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <cstdio>
#include <iostream>
#include <limits>
#include <mutex>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#define LENGTH 2048


using namespace std;

class Client {
    int sockfd = 0;
    string name;
    sockaddr_in server_addr;
    string ip = "127.0.0.1";
    const uint16_t port;

public:
    Client(const uint16_t ports);
    ~Client();
    bool configure_socket();
    bool connects();
    void exit();
    void str_overwrite_stdout();
    void* send_msg_handler(void* dummyPt);
    void* rcv_msg_handler(void* dummyPt);
    void str_trim_lf (char* arr, int length);
    //void thsend();
    //void thrcv();
};

Client::Client(const uint16_t ports) : port(ports)
{
    cin >> name;
    if (name.length() > 32 || name.length() < 2) {
		printf("Name must be less than 30 and more than 2 characters.\n");
	}
}

Client::~Client()
{
}

bool Client::configure_socket() {
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        // TODO cerr 
        return false;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(ip.c_str());
    server_addr.sin_port = htons(port);

    return true;
}
bool Client::connects() {
    int err = connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (err == -1) {
		printf("ERROR: connect\n");
		return false;
	}
    try
    {
        ret = send(sockfd, name, 32, 0);
        if (ret < quanti_byte) errore
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        return false;
    }
    printf("=== WELCOME TO THE CHATROOM ===\n");
    return true;
}
void Client::exit() {
    close(sockfd);
	//return EXIT_SUCCESS;
}
void Client::str_overwrite_stdout() {
    printf("%s", "> ");
    fflush(stdout);
}

void Client::str_trim_lf(char* arr, int length) {
    int i;
    for (i = 0; i < length; i++) {
        if (arr[i] == '\n') {
            arr[i] = '\0';
            break;
        }
    }
}

void *Client::send_msg_handler(void *dummyPt) {
    char message[LENGTH] = {};
    char buffer[LENGTH + 32] = {};
    while (true)
    {
        str_overwrite_stdout();
        fgets(message, LENGTH, stdin);
        str_trim_lf(message, LENGTH);
        if (strcmp(message, "exit") == 0) {
			break;
        }
        else {
            sprintf(buffer, "%s: %s\n", name, message);
            send(sockfd, buffer, strlen(buffer), 0);
        }
        bzero(message, LENGTH);
        bzero(buffer, LENGTH + 32);
    }
}

void *Client::rcv_msg_handler(void *dummyPt) {

}



/*void Client::thsend() {
    //pthread_t send_msg_thread;
    thread th1(&Client::send_msg_handler, Client, "Sample Task");
    th1.join();
    
    if(pthread_create(&send_msg_thread, NULL, send_msg_handler, NULL) != 0){
		printf("ERROR: pthread\n");
	}
}
void Client::thrcv() {
    pthread_t recv_msg_thread;
    if(pthread_create(&recv_msg_thread, NULL, rcv_msg_handler, NULL) != 0){
		printf("ERROR: pthread\n");
	}
}*/






class ClientThread{
    Client* client;
    public:
    ClientThread(Client* clients);
    ~ClientThread();
    void runSend();
    void runReceive();
};
ClientThread::ClientThread(Client* clients) {
    client=clients;
}
void ClientThread::runSend() {
    /*pthread_t send_msg_thread;
    if(pthread_create(&send_msg_thread, NULL, client::send_msg_handler, NULL) != 0){
		printf("ERROR: pthread\n");
	}*/
    client->send_msg_handler();
}
void ClientThread::runReceive() {
    /*pthread_t recv_msg_thread;
    if(pthread_create(&recv_msg_thread, NULL, client::rcv_msg_handler, NULL) != 0){
		printf("ERROR: pthread\n");
	}*/
}