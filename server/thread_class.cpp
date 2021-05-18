#include "server.h"

ServerThread::ServerThread(Server* serv, const int socket, const sockaddr_in addr)
{
	server = serv;
	client_socket = socket;
	main_client_address = addr;
}

void ServerThread::run()
{
	int ret;

	// -) Authentication btw c/s
	ret = authenticate();
	
	
	string username; // TODO

	// -) Negotiate symmetric keys

	// -) Ready to go

	// -) Add current client to server
	server->add_new_client(username, client_socket); // TODO handle failure

	// -) Cycle
		// -) Wait for command
		// -) Execute command
	while (true) {
		unsigned char* msg = get_new_client_command();
		ret = execute_client_command(msg);
		free(msg);

		// TODO Check ret
	}
}

/**
 * Send a message though the specified socket
 * 
 * @param socket socket descriptor
 * @param msg pointer to the message
 * @param msg_len length of the message 
 * @return 1 on success, -1 otherwise 
 */
int ServerThread::send_message (const int socket, void* msg, const uint16_t msg_len)
{
	ssize_t ret;
	
	// Convert message length to network format,
	// in order to obtain architecture indipendence
	uint16_t len = htons(msg_len);	
	
	// Send message's length
	ret = send(socket, &len, sizeof(len), 0);
	if (ret < 0) {
		perror("Error while sending message's length");
		return -1;
	}
	
	// Send the message
	ret = send(socket, msg, msg_len, 0);
	if (ret < 0) {
		perror("Error while sending message");
		return -1;
	}
	
	return 1;
}

/**
 * Wait for a message, expected on the specified socket
 * 
 * @param socket socket descriptor
 * @param msg the address to a pointer. 
 * After a successful function invocation, such a pointer will point 
 * to an allocated buffer containing the received message.
 *            
 * @return length of message on success, 0 if client closed the connection on the socket, 
 * -1 if any error occurred
 */
int ServerThread::receive_message (const int socket, void** msg)
{
	ssize_t ret;
	uint16_t len;
	
	// Receive length of message
	ret = recv(socket, &len, sizeof(len), 0);
	if (ret == 0) { // Client closed the connection
		return 0;
	}	
	if (ret < 0 || ret < sizeof(len)) { // Received data too short
		perror("Message length receive failed");
		return -1;
	}
	
	// Convert received length to host format
	len = ntohs(len);

	*msg = malloc(len);
	if (!msg) {
		cerr << "Malloc failed (message too long?)\n";
		return -1;
	}
	
	// Receive the message
	ret = recv(socket, *msg, len, 0);
	if (ret == 0) { // Client has closed the connection
		return 0;
	}
	if (ret < 0 || ret < len) { // Received data too short
		perror("Receive per il messaggio fallito");
		
		free(*msg);
		*msg = nullptr;

		return -1;
	}

	return len;
}

int ServerThread::execute_client_command (const unsigned char* msg) 
{
	uint8_t request_type = get_request_type(msg);
	
	switch (request_type) {
		case TYPE_SHOW:
			execute_show(msg);
			break;
		case TYPE_TALK:
			execute_talk(msg);
			break;
		case TYPE_EXIT:
			execute_exit();
			break;
		default: // Error
			return -1;
	}

	return 1;
}

uint8_t ServerThread::get_request_type (const unsigned char* msg)
{
	return (uint8_t)msg[0];
}

int ServerThread::execute_exit()
{
	// TODO
}


int ServerThread::authenticate (string& username)
{
	int ret;

// -) Server wait for client's nonce and name
	receive_client_nonce(username, msg); //  TODO
// -) Server sends certificate and encrypted nonce
	// Encrypt nonce
	ret = encrypt_data_pubkey();
	// Prepare message

	// Send message 

	// -) Server sends server's nonce

	// -) Server waits for encrypted server nonce

	// -) Server check validity
}

int ServerThread::receive_client_nonce(string& username, unsigned char** msg)
{
	unsigned char* client_data_msg = nullptr;
	int ret = receive_message(client_socket, (void**)&client_data_msg);
	if (ret <= NONCE_LENGHT) {
		return -1; // TODO error
	}

	size_t client_data_msg_len = ret;

	// Estrai username
	size_t username_len = client_data_msg_len - NONCE_LENGHT;
	char* username_c = new char[username_len + 1];
	memcpy(username_c, client_data_msg + NONCE_LENGHT, username_len);
	username_c[username_len] = '\0';
	username.assign(username_c);
	delete[] username_c;
}

int ServerThread::encrypt_data_pubkey()
{
	// declare some useful variables:
	const EVP_CIPHER* cipher = EVP_aes_128_cbc();
	int block_size = EVP_CIPHER_block_size(cipher);

	EVP_PKEY* privkey = server->get_privkey();

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		cerr << "EVP_CIPHER_CTX_new() returned NULL\n";
		return -1; // TODO failure
	}

	int ret = EVP_SealInit(ctx, );

	EVP_PKEY_free(privkey);
	// close ctx
}