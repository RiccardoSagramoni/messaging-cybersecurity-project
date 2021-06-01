#include "client.h"

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
    int ret;
    int err = connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (err == -1) {
		printf("ERROR: connect\n");
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

int Client::get_sock() {
    return sockfd;
}
sockaddr_in Client::get_server_addr() {
    return server_addr;
}