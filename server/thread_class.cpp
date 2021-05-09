#include "server.h"

ServerThread::ServerThread(Server* serv)
{
	server = serv;
}

void ServerThread::run(const int socket, const sockaddr_in addr)
{
	// TODO
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
 * @param msg pointer to the pointer that will contain the address 
 *            of the received message. On success, the message will 
 *            be allocated with a malloc call.
 * @return 1 on success, 0 if client closed the connection on the socket,
 *        -1 if any error occurred
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
