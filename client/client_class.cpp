#include "client.h"

Client::Client(const uint16_t _port, const string _username, const string _password) 
	: port(_port), client_username(_username), client_password(_password)
{

}

// Initialize static public strings
const string Client::keys_folder = "/home/par/Desktop/git_repo_cybersecurity/Cybersecurity-Project/client/keys/";
const string Client::keys_extension = "_privkey.pem";
const string Client::filename_CA_certificate = Client::keys_folder + 
											   "FoundationsOfCybersecurity_cert.pem";
const string Client::filename_crl = Client::keys_folder + "FoundationsOfCybersecurity_crl.pem";

/**
 * Create and configure a new socket
 * 
 * @return 1 on success, -1 on failure 
 */
bool Client::configure_socket() 
{
	server_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (server_socket < 0) {
		cerr << "Error: socket creation failed" << endl;
		return false;
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(ip.c_str());
	server_addr.sin_port = htons(port);

	return true;
}

bool Client::connect_to_server() 
{
	int ret = connect(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr));
	if (ret < 0) {
		cerr << "Error: connect failed" << endl;
		return false;
	}

	return true;
}

void Client::exit() 
{
	close(server_socket);
}

/**
 * Check if specified user's key is installed on this computer
 * 
 * @param username id of user 
 * @return true on success, false on failure
 */
bool Client::does_username_exist(const string& username)
{
	string filename = keys_folder + username + keys_extension;
	FILE* file = fopen(filename.c_str(), "r");
	if (!file) {
		return false;
	}
	
	fclose(file);
	return true;
}

/**
 * Generate public DH parameters for this application
 * 
 * @return DH parameters
 */
DH* Client::get_dh2048 ()
{
	static unsigned char dhp_2048[] = {
		0xD8, 0x89, 0xF9, 0xAA, 0xE2, 0xE9, 0x09, 0x58, 0xED, 0xC5,
		0xA3, 0xF4, 0xDD, 0x4A, 0x7A, 0x53, 0x56, 0xE3, 0x67, 0x05,
		0x81, 0xC2, 0x26, 0xD1, 0xE1, 0xB8, 0xA9, 0x2B, 0x15, 0x2B,
		0x1F, 0x06, 0x78, 0xFB, 0x39, 0xA9, 0xF9, 0xC1, 0xD4, 0xFF,
		0x80, 0x73, 0x11, 0xDB, 0x40, 0x1C, 0xF7, 0x5A, 0x75, 0x5B,
		0x5B, 0x41, 0x81, 0x84, 0x57, 0x34, 0xF6, 0x64, 0xEE, 0xB6,
		0xA5, 0xE4, 0x2A, 0x75, 0xFF, 0x12, 0x13, 0xC5, 0xC4, 0x86,
		0xA2, 0xDB, 0xF1, 0xAA, 0xCB, 0x79, 0x84, 0x02, 0xF1, 0x76,
		0x80, 0xF2, 0x9A, 0xC3, 0xBD, 0x8B, 0x87, 0x75, 0x99, 0x00,
		0x8D, 0x4F, 0x3E, 0x5E, 0x22, 0x74, 0xF3, 0x7A, 0xDE, 0x2D,
		0x51, 0x14, 0xD4, 0xC4, 0xC0, 0xD6, 0xAA, 0x03, 0x0C, 0x17,
		0xFB, 0x3E, 0x9B, 0xB5, 0x13, 0xD3, 0x8C, 0xD8, 0xDD, 0x74,
		0x34, 0xC7, 0x31, 0xA4, 0x7A, 0x21, 0xD0, 0x07, 0xB6, 0x77,
		0x74, 0x2E, 0xFE, 0x1B, 0xC0, 0x54, 0x81, 0xB6, 0x7B, 0x2D,
		0x39, 0x7A, 0x1C, 0x4D, 0xE3, 0x23, 0xDF, 0xDF, 0x9D, 0x6F,
		0x91, 0xFB, 0xB3, 0x0C, 0x5E, 0x87, 0x4E, 0x2D, 0x1D, 0x6B,
		0xF1, 0x97, 0x24, 0xA2, 0x58, 0xE3, 0xF4, 0x81, 0x19, 0xE0,
		0x33, 0x3B, 0x55, 0xAD, 0xA0, 0xBB, 0x44, 0x0A, 0xBF, 0x8F,
		0xAC, 0xAD, 0xAD, 0x16, 0x8C, 0x69, 0x45, 0x28, 0x81, 0x1E,
		0x9B, 0xA9, 0x0E, 0xB5, 0x02, 0x3D, 0xA1, 0xFD, 0x59, 0x6C,
		0x40, 0xDC, 0x73, 0x8A, 0xA3, 0x45, 0x76, 0x27, 0x40, 0x4F,
		0xBA, 0xEF, 0x20, 0x3A, 0x07, 0x3F, 0xDD, 0x8C, 0x69, 0x20,
		0xF6, 0xE2, 0x28, 0xE7, 0x2D, 0x31, 0xE1, 0x56, 0xB2, 0x6B,
		0x73, 0x03, 0x74, 0xBE, 0xA5, 0x3F, 0x43, 0x2E, 0xBD, 0xAB,
		0x8A, 0x40, 0xC8, 0x3B, 0xCC, 0x74, 0x98, 0x7B, 0xB0, 0xCD,
		0xED, 0xBA, 0x42, 0x29, 0x73, 0xD3
	};
	static unsigned char dhg_2048[] = {
		0x02
	};
	DH *dh = DH_new();
	BIGNUM *p, *g;

	if (dh == NULL)
		return NULL;
	p = BN_bin2bn(dhp_2048, sizeof(dhp_2048), NULL);
	g = BN_bin2bn(dhg_2048, sizeof(dhg_2048), NULL);
	if (p == NULL || g == NULL
			|| !DH_set0_pqg(dh, p, NULL, g)) {
		DH_free(dh);
		BN_free(p);
		BN_free(g);
		return NULL;
	}
	return dh;
}

/**
 * Send a message through the specified socket
 * 
 * @param socket socket descriptor
 * @param msg pointer to the message
 * @param msg_len length of the message 
 * @return 1 on success, -1 otherwise 
 */
int Client::send_message (const int socket, void* msg, const uint32_t msg_len)
{
	ssize_t ret;
	
	// Convert message length to network format,
	// in order to obtain architecture indipendence
	uint32_t len = htonl(msg_len);	
	
	// Send message's length
	ret = send(socket, &len, sizeof(len), 0);
	if (ret <= 0) {
		perror("Error while sending message's length");
		return -1;
	}
	
	// Send the message
	ret = send(socket, msg, msg_len, 0);
	if (ret <= 0) {
		perror("Error while sending message");
		return -1;
	}
	
	return 1;
}

/**
 * Wait for a message, expected on the specified socket
 * 
 * @param socket socket descriptor
 * @param msg the address of a pointer. 
 * After a successful function invocation, such a pointer will point 
 * to an allocated buffer containing the received message.
 *            
 * @return length of message on success, 0 if client closed the connection on the socket, 
 * -1 if any error occurred
 */
long Client::receive_message (const int socket, void** msg)
{
	ssize_t ret;
	uint32_t len;
	
	// Receive length of message
	ret = recv(socket, &len, sizeof(len), 0);
	if (ret == 0) { // Client closed the connection
		return 0;
	}	
	if (ret < 0 || (unsigned long)ret < sizeof(len)) { // Received data too short
		perror("Message length receive failed");
		return -1;
	}
	
	// Convert received length to host format
	len = ntohl(len);

	*msg = malloc(len);
	if (!(*msg)) {
		cerr << "Malloc failed (message too long?)\n";
		return -1;
	}
	
	// Receive the message
	ret = recv(socket, *msg, len, 0);
	if (ret == 0) { // Client has closed the connection
		return 0;
	}
	if (ret < 0 || ret < len) { // Received data too short
		perror("Receive message failed");
		
		free(*msg);
		*msg = nullptr;

		return -1;
	}

	return len;
}






void Client::exec() {
	int ret;
	thread_bridge* bridge;
	// Negotiate a symmetric key with the server
	ret = negotiate();
	if (ret < 0) {
		cerr << "Error: negotiate failed";
		return;
	}
	thread t1(&Client::receive_plaintext2, this, server_socket, bridge, session_key);
	thread t2(&Client::run, this, bridge);
	t1.join();
	t2.join();
}










/**
 * Starts client services
 */
void Client::run(thread_bridge* bridge)
{
	int ret;
	while (true) {
		print_command_options();

		//take command from user
		string command;
		cout << "Insert command: ";
		cin >> command;

		if (command == "0") {
			ret = talk();
			if (ret < 0) {
				cout<<"error talk()"<<endl;
				break;
			}
			if (ret == 0) {
				cout<<"no user with this name"<<endl;
				continue;
			}
		}
		else if (command == "1") {
			ret = show(bridge);
			if (ret < 0) {
				cout<<"error show()"<<endl;
				break;
			}
			if (ret == 0) {
				cout<<"other errors"<<endl; //TODO
				continue;
			}
		}
		else if (command == "2") {
			ret = exit_by_application();
			if (ret != 1) {
				cout<<"error exit_by_application()"<<endl;
				break;
			}
			cout<<"Bye!!"<<endl;
			secure_free(session_key,session_key_len);
			break;
		}
		else {
			break;
		}

		// check request to talk
		// if yes, stampa la richiesta a schermo
		// aspetta yes/no da utente
		// if yes, inizia protocollo
	}
}

//for send a request to talk to another client
int Client::talk () 
{
	int ret = 0;
	char* message = nullptr;
	size_t message_len = 1;
	string peer_username;
	unsigned char* plaintext = nullptr;
	size_t plaintext_len = 0;
	
	//TODO sleep thread receive request to talk

	//get user to talk
	cout << "insert username of the client:  ";
	cin >> peer_username;
	if (peer_username.empty()) {
		return -1;
	}

	//store username_lenght
	message_len += sizeof(uint32_t) + peer_username.length() + 1;
	//allocate msg
	message = (char*)malloc(message_len);
	if (!message) {
		return -1;
	}

	// craft msg
	uint8_t* type = (uint8_t*)&message[0];
	*type = TYPE_TALK;

	// insert username length
	uint32_t string_size = peer_username.length() + 1;
	string_size = htonl(string_size);
	memcpy(message + 1, &string_size, sizeof(string_size));

	// insert username
	memcpy(message + 1 + sizeof(string_size), peer_username.c_str(), peer_username.length() + 1);

	try {
		// send messsage to server
		ret = send_plaintext(server_socket, (unsigned char*)message, message_len, session_key);
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] talk: "
			<< "erro send message to server" << endl;
			throw 0;
		}

		free(message);

		// receive ok from server
		ret = receive_plaintext(server_socket, plaintext, plaintext_len, session_key);
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] talk: "
			<< "error receive response" << endl;
			throw 1;
		}
	} catch (int e) {
		if (e >= 1) {
			free(plaintext);
		}
		return -1;
	}

	// Extract message type
	uint8_t message_type = get_message_type(plaintext);
	if (message_type != SERVER_OK) {
		cerr << "[Thread " << this_thread::get_id() << "] talk: "
		<< "request to talk failed" << endl;
		return -1;
	}
	free(plaintext);

	// DIFFIE-HELLMAN PROTOCOL: exchange keys between clients
	unsigned char* clients_session_key = nullptr;
	size_t clients_session_key_lenght = 0;
	ret = negotiate_key_with_client(clients_session_key, clients_session_key_lenght);
	if (ret < 0) {
		cerr << "[Thread " << this_thread::get_id() << "] talk: "
		<< "negotiation key failed" << endl;
		return -1;
	}

	// TODO !!!!!!!!

	secure_free(clients_session_key, clients_session_key_lenght);
	return 1;
}

// DIFFIE-HELLMAN PROTOCOL: exchange keys between clients
int Client::negotiate_key_with_client (unsigned char*& clients_session_key, size_t& clients_session_key_len)
{
	int ret;
	EVP_PKEY* my_dh_key;
	BIO* mbio = nullptr;
	char* pubkey_buf = nullptr;
	uint32_t pubkey_size = 0;
	BIO* mem_bio = nullptr;
	unsigned char* key = nullptr;
	EVP_PKEY* peer_key = nullptr;
	size_t key_len = 0;

	try {
		// generate g^a
		my_dh_key = generate_key_dh();
		if (!my_dh_key) {
			cerr << "[Thread " << this_thread::get_id() << "] talk: "
			<< "error generate key" << endl;
			throw 0;
		}

		// serialize my_dh_key
		mbio = BIO_new(BIO_s_mem());
		if (!mbio) {
			cerr << "[Thread " << this_thread::get_id() << "] talk: "
			<< "error bio_new" << endl;
			throw 1;
		}

		ret = PEM_write_bio_PUBKEY(mbio, my_dh_key);
		if (ret <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] talk: "
			<< "error write bio" << endl;
			throw 2;
		}
		
		long ret_long = BIO_get_mem_data(mbio, &pubkey_buf);
		if (ret_long <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] talk: "
			<< "error get mem bio pub key" << endl;
			throw 2;
		}
		pubkey_size = (uint32_t)ret_long;

		// send g^a
		ret = send_plaintext(server_socket, (unsigned char*)pubkey_buf, pubkey_size, session_key);
		if (ret < 1) {
			cerr << "[Thread " << this_thread::get_id() << "] talk: "
			<< "error sending pub key" << endl;
			throw 3;
		}


		//receive g^b and deserialize it
		ret = receive_plaintext(server_socket, key, key_len, session_key);
		if (ret < 1) {
			cerr << "[Thread " << this_thread::get_id() << "] talk: "
			<< "error receive client key" << endl;
			throw 3;
		}
		
		mem_bio = BIO_new(BIO_s_mem());
		if (!mem_bio) {
			cerr << "[Thread " << this_thread::get_id() << "] talk: "
			<< "error bio_new" << endl;
			throw 4;
		}
		
		ret = BIO_write(mem_bio, key, key_len);
		if (ret <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] talk: "
			<< "error bio_write" << endl;
			throw 5;
		}

		peer_key = PEM_read_bio_PUBKEY(mem_bio, nullptr, nullptr, nullptr);
		if (!peer_key) {
			cerr << "[Thread " << this_thread::get_id() << "] talk: "
			<< "error pem read" << endl;
			throw 5;
		}


		//get session key for clients comunications
		clients_session_key_len = EVP_CIPHER_key_length(get_authenticated_encryption_cipher());
		clients_session_key = derive_session_key(my_dh_key, peer_key, clients_session_key_len);
		if (!clients_session_key) {
			cerr << "[Thread " << this_thread::get_id() << "] talk: "
			<< "error derive session key" << endl;
			throw 5;
		}
		

	} catch (int e) {
		if (e >= 5) {
			BIO_free(mem_bio);
		}
		if (e >= 4) {
			secure_free(key, key_len);
		}
		if (e >= 3) {
			secure_free(pubkey_buf, pubkey_size);
		}
		if (e >= 2) {
			BIO_free(mbio);
		}
		if (e >= 1) {
			EVP_PKEY_free(my_dh_key);
		}
		return -1;
	}

	BIO_free(mem_bio);
	secure_free(key, key_len);
	secure_free(pubkey_buf, pubkey_size);
	BIO_free(mbio);
	EVP_PKEY_free(my_dh_key);

	return 1;
}


//receive request to talk from another client
int Client::receive_request_to_talk(unsigned char* session_key) {
	int ret = 0;
	unsigned char* plaintext = nullptr;
	size_t plaintext_len = 0;
	string peer_username;
	uint32_t peer_username_len = 0;
	char* message = nullptr;
	size_t message_len = 1;
	unsigned char* clients_session_key = nullptr;
	size_t clients_session_key_lenght = 0;

	try {
		//receive ok by server
		ret = receive_plaintext(server_socket, plaintext, plaintext_len, session_key);
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] receive_request_to_talk: "
			<< "error receive message from server" << endl;
			throw 4;
		}
	} catch (int e) {
		if (e >= 4) {
			secure_free(plaintext, plaintext_len);
		}
		return -1;
	}
	uint8_t message_type = get_message_type(plaintext);
	if (message_type==SERVER_REQUEST_TO_TALK) {
		//TODO sleep run thread

		//check is msg is valid (is a null terminated string)
		if (plaintext[plaintext_len - 1] != '\0' || plaintext_len <= sizeof(uint32_t) + 1) {
			throw 0;
		}

		//deserialize length of username
		peer_username_len = ntohl(*(uint32_t*)(plaintext + 1));

		if (plaintext_len != sizeof(uint32_t) + 1 + peer_username_len) {
			//TODO send_error()
			throw 0;
		}

		//extract peer's username and convert it to string
		char* peer_username_c = (char*)(plaintext + 1 + sizeof(uint32_t));
		peer_username = peer_username_c;


		cout<<"you have received a request to talk from "<<peer_username<<endl;
		cout<<"press '1' if you want to accept it, '0' if you want to refuse it"<<endl;
		string buf;
		cin>>buf;
		if (buf == "1") {
			//store username_lenght
			message_len += sizeof(uint32_t) + peer_username.length() + 1;
			//allocate msg
			message = (char*)malloc(message_len);
			if (!message) {
				return -1;
			}
			//craft msg for response (accept || lenght username client sender || username client sender)
			uint8_t* type = (uint8_t*)&message[0];
			*type = ACCEPT_TALK;
			//insert username length
			uint32_t string_size = strlen(peer_username.c_str()) + 1;
			string_size = htonl(string_size);
			memcpy(message + 1, &string_size, sizeof(string_size));
			//insert username
			memcpy(message + 5, peer_username.c_str(), peer_username.length() + 1);
			if (!message) {
				return -1;
			}
			try {
				//send message to server for accepting
				int ret = send_plaintext(server_socket, (unsigned char*)message, message_len, session_key);
				if (ret <= 0) {
					cerr << "[Thread " << this_thread::get_id() << "] receive_request_to_talk: "
					<< "error send message to server for accept" << endl;
					throw 1;
				} 
			}	catch (int e) {
					if (e >= 1) {
						secure_free(plaintext, plaintext_len);
						secure_free(message, message_len);
					}
					return -1;
			}
			secure_free(message, message_len);
			secure_free(plaintext, plaintext_len);
		}
		else if (buf == "0") {
			//store username_lenght
			message_len += sizeof(uint32_t) + peer_username.length() + 1;
			//allocate msg
			message = (char*)malloc(message_len);
			if (!message) {
				return -1;
			}
			//forge message type
			uint8_t* type = (uint8_t*)&message[0];
			*type = REFUSE_TALK;
			try {
				//send message to server for refusing
				int ret = send_plaintext(server_socket, (unsigned char*)message, message_len, session_key);
				if (ret <= 0) {
					cerr << "[Thread " << this_thread::get_id() << "] receive_request_to_talk: "
					<< "error send message to server for refuse" << endl;
					throw 1;
				} 
			}	catch (int e) {
					if (e >= 1) {
						secure_free(plaintext, plaintext_len);
						secure_free(message, message_len);
					}
					return -1;
			}
			secure_free(plaintext, plaintext_len);
			secure_free(message, message_len);
			return 0;
		}
		else {
			//TODO
			return -1;
		}
	}
	else {
		//TODO send error to server
	}
	//craft and send g**b
	//generate g^b
	EVP_PKEY* my_dh_key = generate_key_dh();
	if (!my_dh_key) {
		cerr << "[Thread " << this_thread::get_id() << "] receive_request_to_talk: "
		<< "error generate key" << endl;
		return -1;
	}



	BIO* mbio = nullptr;
	char* pubkey_buf = nullptr;
	uint32_t pubkey_size = 0;
	BIO* mem_bio = nullptr;
	unsigned char* key = nullptr;
	EVP_PKEY* peer_key = nullptr;
	size_t key_len = 0;
	try {
		//serialize my_dh_key
		mbio = BIO_new(BIO_s_mem());
		if (!mbio) {
			cerr << "[Thread " << this_thread::get_id() << "] receive_request_to_talk: "
			<< "error bio_new" << endl;
			throw 1;
		}

		ret = PEM_write_bio_PUBKEY(mbio, my_dh_key);
		if (ret <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] receive_request_to_talk: "
			<< "error write bio" << endl;
			throw 1;
		}
		
		long ret_long = BIO_get_mem_data(mbio, &pubkey_buf);
		if (ret_long <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] receive_request_to_talk: "
			<< "error get mem bio pub key" << endl;
			throw 1;
		}
		pubkey_size = (uint32_t)ret_long;


		//receive g^a and deserialize it
		ret = receive_plaintext(server_socket, key, key_len, session_key);
		if (ret < 1) {
			cerr << "[Thread " << this_thread::get_id() << "] receive_request_to_talk: "
			<< "error receive client key" << endl;
			throw 2;
		}
		
		mem_bio = BIO_new(BIO_s_mem());
		if (!mem_bio) {
			cerr << "[Thread " << this_thread::get_id() << "] receive_request_to_talk: "
			<< "error bio_new" << endl;
			throw 3;
		}
		
		ret = BIO_write(mem_bio, key, key_len);
		if (ret <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] receive_request_to_talk: "
			<< "error bio_write" << endl;
			throw 3;
		}
		peer_key = PEM_read_bio_PUBKEY(mem_bio, nullptr, nullptr, nullptr);
		if (!peer_key) {
			cerr << "[Thread " << this_thread::get_id() << "] receive_request_to_talk: "
			<< "error pem read" << endl;
			throw 3;
		}


		//send g^a
		ret = send_plaintext(server_socket, (unsigned char*)pubkey_buf, pubkey_size, session_key);
		if (ret < 1) {
			cerr << "[Thread " << this_thread::get_id() << "] receive_request_to_talk: "
			<< "error sending pub key" << endl;
			throw 4;
		}

		//get session key for clients comunications
		clients_session_key_lenght = EVP_CIPHER_key_length(get_authenticated_encryption_cipher());
		clients_session_key = derive_session_key(my_dh_key, peer_key, clients_session_key_lenght);
		if (!clients_session_key) {
			cerr << "[Thread " << this_thread::get_id() << "] talk: "
			<< "error derive session key" << endl;
			throw 5;
		}



	}catch (int e) {
		if (e >= 5) {
			secure_free(clients_session_key, clients_session_key_lenght);
		}
		if (e >= 4) {
			secure_free(pubkey_buf, pubkey_size);
		}
		if (e >= 3) {
			BIO_free(mem_bio);
		}
		if (e >= 2) {
			
			secure_free(key, key_len);
		}
		if (e >= 1) {
			BIO_free(mbio);
		}
		return -1;
	}
	BIO_free(mem_bio);
	secure_free(key, key_len);
	secure_free(pubkey_buf, pubkey_size);
	BIO_free(mbio);




	secure_free(clients_session_key, clients_session_key_lenght);
	return 1;
}





int Client::send_message_to_client(unsigned char* clients_session_key, unsigned char* server_session_key) {
	string message;
	int ret;
	unsigned char* iv = nullptr;
	size_t iv_len = 0;
	unsigned char* ciphertext = nullptr;
	size_t ciphertext_len = 0;
	unsigned char* tag = nullptr;
	size_t tag_len = 0;
	size_t message_len = 0;
	char* message_to_send = nullptr;
	char* final_ciphertext = nullptr;
	size_t final_ciphertext_len = 1;
	bool control = true;
	cout<<"Start chat"<<endl;
	cout<<endl;
	while (true) {
		cin>>message;
		try {
			//generate IV
			iv = generate_iv(get_authenticated_encryption_cipher(), iv_len);
			if (!iv) {
				throw 1;
			}
			message_len = message.length() + 1;

			//allocate message
			message_to_send = (char*)malloc(message_len);
			if (!message_to_send) {
				throw 2;
			}
			memcpy(message_to_send, message.c_str(), message.length() + 1);
			//encrypt message
			ret = gcm_encrypt((unsigned char*)message_to_send, message_len, iv, iv_len, clients_session_key, iv, iv_len, ciphertext, ciphertext_len, tag, tag_len);
			if (ret < 0) {
				throw 3;
			}

			//send final packet to server
			final_ciphertext_len += ciphertext_len + iv_len + tag_len + 1;
			final_ciphertext = (char*)malloc(final_ciphertext_len);
			if (!final_ciphertext) {
				throw 4;
			}
			uint8_t* type = (uint8_t*)&final_ciphertext[0];
			*type = TALKING;
			memcpy(final_ciphertext + 1, ciphertext, ciphertext_len);
			memcpy(final_ciphertext + ciphertext_len + 1, iv, iv_len);
			memcpy(final_ciphertext + iv_len + ciphertext_len + 1, tag, tag_len + 1);

			//send it
			int ret = send_plaintext(server_socket, (unsigned char*)final_ciphertext, final_ciphertext_len, server_session_key);
			if (ret <= 0) {
					cerr << "[Thread " << this_thread::get_id() << "] send_message_to_client: "
					<< "error send message to server" << endl;
					throw 4;
			}
			cout<<"Tu:  "<<endl;
		} catch (int e) {
			if (e >= 4) {
				secure_free(final_ciphertext, final_ciphertext_len);
			}
			if (e >= 3) {
				secure_free(ciphertext, ciphertext_len);
				secure_free(tag, tag_len);
			}
			if (e >= 2) {
				secure_free(message_to_send, message_len);
			}
			if (e >= 1) {
				secure_free(iv, iv_len);
			}
			control = false;
			break;
		}
		secure_free(final_ciphertext, final_ciphertext_len);
		secure_free(message_to_send, message_len);
		secure_free(iv, iv_len);
		secure_free(ciphertext, ciphertext_len);
		secure_free(tag, tag_len);
	}
	if (!control) {
		return -1;
	}
	return 1;
}





int Client::receive_message_from_client(unsigned char* clients_session_key, unsigned char* server_session_key) 
{
	string message;
	unsigned char* plaintext_from_server = nullptr;
	size_t plaintext_from_server_len = 1;
	bool control = true;

	while(true) {
		try {
			//receive it
			int ret = receive_plaintext(server_socket, plaintext_from_server, plaintext_from_server_len, server_session_key);
			if (ret <= 0) {
					cerr << "[Thread " << this_thread::get_id() << "] receive_message_from_client: "
					<< "error receive message from server" << endl;
					throw 1;
			}
		} catch (int e) {
		
			if (e >= 1) {
				secure_free(plaintext_from_server, plaintext_from_server_len);
			}
			control = false;
			break;
		}
		uint8_t message_type = get_message_type(plaintext_from_server);
		if (message_type == SERVER_ERR) {
			return -1;
		}
		//TODO get message
		secure_free(plaintext_from_server, plaintext_from_server_len);
	}
	if (!control) {
		return -1;
	}
	return 1;
}



















//send a message type || size username || username
int Client::send_command_to_server(unsigned char* msg, unsigned char* shared_key) {
	int ret = 0;
	unsigned char* iv = nullptr;
	unsigned char* ciphertext = nullptr;
	unsigned char* tag = nullptr;
	size_t msg_len=sizeof(msg);
	size_t iv_len = 0;
	size_t tag_len = 0;
	size_t ciphertext_len = 0;
	try {
		// Generate IV
		iv = generate_iv(get_authenticated_encryption_cipher(), iv_len);
		if (!iv) {
			cerr << "[Thread " << this_thread::get_id() << "] send_command_to_server: "
			<< "generate_iv failed" << endl;
			throw 1;
		}
		// 3) Encrypt msg
		ret = gcm_encrypt(msg, msg_len, iv, iv_len, shared_key, iv, iv_len, ciphertext, ciphertext_len, tag, tag_len);
		if (ret !=1) {
			cerr << "[Thread " << this_thread::get_id() << "] send_command_to_server: "
			<< "failed to crypt" << endl;
			throw 2;
		}
		//secure_free(msg, msg_len);

		//Send messages
		//Send iv
		ret = send_message(server_socket, (void*)iv, iv_len);
		if (ret <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] send_command_to_server: "
			<< "send_message iv failed" << endl;
			throw 3;
		}
		
		//Send crypted msg
		ret = send_message(server_socket, (void*)ciphertext, ciphertext_len);
		if (ret <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] send_command_to_server: "
			<< "send_message encrypted_msg" << endl;
			throw 3;
		}

		//Send tag
		ret = send_message(server_socket, (void*)tag, tag_len);
		if (ret <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] send_command_to_server: "
			<< "send_message tag failed" << endl;
			throw 3;
		}
	} catch (int e) {
		if (e >= 2) {
			secure_free(tag, tag_len);
			secure_free(ciphertext, ciphertext_len);
		}
		if (e >= 1) {
			secure_free(iv, iv_len);
		}
		return -1;
	}
	secure_free(tag, tag_len);
	secure_free(ciphertext, ciphertext_len);
	secure_free(iv, iv_len);
	return 1;
}

/**
 * Execute the function "show" of the application, i.e. send a request 
 * to the server for the list of all the online users which are available
 * to talking.
 * 
 * @param shared_key key shared between client and server
 * 
 * @return 1 on success, -1 on failure
 */
int Client::show(thread_bridge* bridge) 
{
	unsigned char* msg_received_view = nullptr;
	size_t msg_received_view_len = 0;

	// Prepare request for show 
	char message[1] = {TYPE_SHOW};

	// Send message to server
	int ret = send_plaintext(server_socket, (unsigned char*)message, 1, session_key);
	if (ret <= 0) {
		cerr << "[Thread " << this_thread::get_id() << "] show: "
		<< "error send message to server" << endl;
		return -1;
	}
/*
	// Receive response from the server
	ret = receive_plaintext(server_socket, msg_received_view, msg_received_view_len, session_key);
	if (ret <= 0) {
		cerr << "[Thread " << this_thread::get_id() << "] show: "
		<< "error receive response" << endl;
		return -1;
	}
*/
	msg_received_view = bridge->wait_for_new_message(msg_received_view_len);
	// Check if the header the the response is correct
	uint8_t message_type = get_message_type(msg_received_view);
	if (message_type != SERVER_OK) {
		cerr << "[Thread " << this_thread::get_id() << "] show: "
		<< "wrong received message type" << endl;
		free(msg_received_view);
		return -1;
	}

	// Check if received message is a null terminated string
	if (msg_received_view[msg_received_view_len - 1] != '\0') {
		cerr << "[Thread " << this_thread::get_id() << "] show: "
		<< "wrong received message format" << endl;
		free(msg_received_view);
		return -1;
	}

	cout << endl << "ONLINE USERS:" << endl;

	// Print the username list
	size_t i = 1;
	while (i < msg_received_view_len) {
		// Extract length of username
		uint32_t username_len;
		memcpy(&username_len, msg_received_view + i, sizeof(username_len));
		username_len = ntohl(username_len);

		i += sizeof(username_len);

		cout << (char*)(msg_received_view + i) << endl;

		i += username_len;
	}

	cout << endl;

	free(msg_received_view);

	return 1;
}

int Client::exit_by_application() { // TODO here|
	size_t message_len = 1;
	//Allocate message
	char* message = (char*)malloc(message_len);
	if (!message) {
		return -1;
	}
	//forge message type
	uint8_t* type = (uint8_t*)&message[0];
	*type = TYPE_EXIT;
	try {
		//send message to server
		int ret = send_plaintext(server_socket, (unsigned char*)message, message_len, session_key);
		if (ret <= 0) {
				cerr << "[Thread " << this_thread::get_id() << "] exit_by_application: "
				<< "error send message to server" << endl;
				throw 1;
		}
		secure_free(message, message_len);
	} catch (int e) {
		if (e >= 1) {
			secure_free(message, message_len);
		}
		return -1;
	}
	return 1;
}


uint8_t Client::get_message_type(const unsigned char* msg)
{
	return (uint8_t)msg[0];
}


//negotiation of key and autentication with server
int Client::negotiate() 
{
	int ret;
	X509* cert=nullptr;
	X509* cert_CA=nullptr;
	X509_CRL* crl_CA=nullptr;
	unsigned char* ser_certificate = nullptr;
	long ser_certificate_len = 0;
	unsigned char* iv = nullptr;
	size_t iv_len = 0;
	char* username_c = nullptr;
	BIO* mbio = nullptr;
	char* pubkey_buf = nullptr;
	EVP_PKEY* public_key_from_cert = nullptr;
	unsigned char* tag = nullptr;
	EVP_PKEY* peer_key = nullptr;
	unsigned char* ciphertext = nullptr;
	size_t ciphertext_len = 0;
	EVP_PKEY* my_dh_key;

	try {
		// 1) Generate client's part of DH key, i.e. g**a
		my_dh_key = generate_key_dh();
		if (!my_dh_key) {
			cerr << "[Thread " << this_thread::get_id() << "] negotiate: "
			<< "error generate key" << endl;
			throw 0;
		}
		
		// 2) Send username to server
		// 2a) Allocate buffer for username
		username_c = (char*)malloc(client_username.length() + 1);
		if (!username_c) {
			cerr << "[Thread " << this_thread::get_id() << "] negotiate: "
			<< "error malloc username" << endl;
			throw 1;
		}
		strcpy(username_c, client_username.c_str());

		// 2b) Send to server
		ret = send_message(server_socket, (void*)username_c, client_username.length() + 1);
		if (ret < 1) {
			cerr << "[Thread " << this_thread::get_id() << "] negotiate: "
			<< "error send username" << endl;
			throw 2;
		}


		// 3) Serialize my_dh_key
		mbio = BIO_new(BIO_s_mem()); // Allocate BIO
		if (!mbio) {
			cerr << "[Thread " << this_thread::get_id() << "] negotiate: "
			<< "error bio_new" << endl;
			throw 2;
		}

		ret = PEM_write_bio_PUBKEY(mbio, my_dh_key); // Serialize key in BIO
		if (ret <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] negotiate: "
			<< "error write bio" << endl;
			throw 3;
		}
		
		long ret_long = BIO_get_mem_data(mbio, &pubkey_buf); // Extract key from BIO
		if (ret_long <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] negotiate: "
			<< "error get mem bio pub key" << endl;
			throw 3;
		}
		uint32_t pubkey_size = (uint32_t)ret_long;
		
		// 4) Send g**a
		ret = send_message(server_socket, (void*)pubkey_buf, pubkey_size);
		if (ret < 1) {
			cerr << "[Thread " << this_thread::get_id() << "] negotiate: "
			<< "error sending pub key" << endl;
			throw 3;
		}
		

		// 5) Second step of the protocol (receive public key from server)
		ret = receive_from_server_pub_key(peer_key);
		if (ret < 0) {
			cerr << "[Thread " << this_thread::get_id() << "] negotiate: "
			<< "receive_from_server_pub_key failed" << endl;
			throw 3;
		}

		//derive session key
		session_key_len = EVP_CIPHER_key_length(get_authenticated_encryption_cipher());
		session_key = derive_session_key(my_dh_key, peer_key, session_key_len);
		if (!session_key) {
			cerr << "[Thread " << this_thread::get_id() << "] negotiate: "
			<< "error derive session key" << endl;
			throw 5;
		}

		//receive iv (initialization vector)
		ret = receive_message(server_socket, (void**)&iv);
		if (ret <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] negotiate: "
			<< "error receive iv" << endl;
			throw 6;
		}

		iv_len=ret;
		//receive crypto sign
		ret = receive_message(server_socket, (void**)&ciphertext);
		if (ret <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] negotiate: "
			<< "error receive crypto sign" << endl;
			throw 7;
		}

		ciphertext_len = ret;


		//receive tag
		ret = receive_message(server_socket, (void**)&tag);
		if (ret <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] negotiate: "
			<< "error receive tag" << endl;
			throw 8;
		}

		//receive certificate of the server
		ret = receive_message(server_socket, (void**)&ser_certificate);
		if (ret <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] negotiate: "
			<< "error receive certificate" << endl;
			throw 9;
		}
		ser_certificate_len = ret;

		unsigned char* temp_ser_certificate = ser_certificate;
		cert = d2i_X509(nullptr, (const unsigned char**)&temp_ser_certificate, ser_certificate_len);
		if (!cert) {
			cerr << "[Thread " << this_thread::get_id() << "] negotiate: "
			<< "error deserialize certificate" << endl;
			throw 10;
		}

		//get certificate from file
		cert_CA = get_CA_certificate();
		if (cert_CA == NULL) {
			cerr << "[Thread " << this_thread::get_id() << "] negotiate: "
			<< "error server certificate" << endl;
			throw 11;
		}

		//get crl from file
		crl_CA = get_crl();
		if (!crl_CA) {
			cerr << "[Thread " << this_thread::get_id() << "] negotiate: "
			<< "error crl" << endl;
			throw 12;
		}

		// build store, add certificate, add crl and check validity
		ret = build_store_certificate_and_validate_check(cert_CA, crl_CA, cert);
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] negotiate: "
			<< "error build store and check validity" << endl;
			throw 13;
		}

		// Extract public key from certificate
		public_key_from_cert = X509_get_pubkey(cert);
		if (public_key_from_cert == NULL) {
			cerr << "[Thread " << this_thread::get_id() << "] negotiate: "
			<< "error exract pub key from cert" << endl;
			throw 13;
		}
		
		//decrypt and verify server signature
		ret = decrypt_and_verify_sign(ciphertext, ciphertext_len, my_dh_key, peer_key, session_key, session_key_len, iv, iv_len, tag, public_key_from_cert);
		if (ret <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] negotiate: "
			<< "error verifying server sign" << endl;
			throw 14;
		}
		//crypt sign and send it
		ret = send_sig(my_dh_key, peer_key, session_key, session_key_len);
		if (ret <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] negotiate: "
			<< "error sending sign" << endl;
			throw 14;
		}

	} catch (int e) {
		if (e >= 14) {
			EVP_PKEY_free(public_key_from_cert);
		}
		if (e >= 13) {
			X509_CRL_free(crl_CA);
		}
		if (e >= 12) {
			X509_free(cert_CA);
		}
		if (e >= 11) {
			X509_free(cert);
		}
		if (e >= 10) {
			free(ser_certificate);
		}
		if (e >= 9) {
			free(tag);
		}
		if (e >= 8) {
			free(ciphertext);
		}
		if (e >= 7) {
			free(iv);
		}
		if (e >= 6) {
			secure_free(session_key, session_key_len);
		}
		if (e >= 5) {
			EVP_PKEY_free(peer_key);
		}
		if (e >= 3) {
			BIO_free(mbio);
		}
		if (e >= 2) {
			free(username_c);
		}
		if (e >= 1) {
			EVP_PKEY_free(my_dh_key);
		}
		return -1;
	}

	EVP_PKEY_free(public_key_from_cert);
	X509_CRL_free(crl_CA);
	X509_free(cert_CA);
	X509_free(cert);
	free(ser_certificate);
	free(tag);
	free(ciphertext);
	free(iv);
	EVP_PKEY_free(peer_key);
	BIO_free(mbio);
	free(username_c);
	EVP_PKEY_free(my_dh_key);

	return 1;
}

void Client::secure_free (void* addr, size_t len) 
{
	#pragma optimize("", off);
		memset(addr, 0, len);
	#pragma optimize("", on);

	free(addr);
}


/**
 * Generate client's part of the shared private key, i.e. g**a according to DH protocol
 * 
 * @return the generated key on success, NULL otherwise
 */
EVP_PKEY* Client::generate_key_dh ()
{
	int ret;
	
	EVP_PKEY* dh_params = nullptr;
	EVP_PKEY_CTX* dh_gen_ctx = nullptr;
	EVP_PKEY* dh_key = nullptr;

	try {
		// Allocate DH params p and g
		dh_params = EVP_PKEY_new();
		if (!dh_params) {
			cerr << "Thread " << this_thread::get_id() << " failed [generate_key_dh]:\n";
			throw 0;
		}
		// Calculate DH params
		DH* temp_dh_params = get_dh2048();
		ret  = EVP_PKEY_set1_DH(dh_params, temp_dh_params);
		DH_free(temp_dh_params);
		if (ret != 1) throw 1;

		// Generate g**a
		dh_gen_ctx = EVP_PKEY_CTX_new(dh_params, nullptr);
		if (!dh_gen_ctx) throw 1;

		ret = EVP_PKEY_keygen_init(dh_gen_ctx);
		if (ret != 1) throw 2;

		ret = EVP_PKEY_keygen(dh_gen_ctx, &dh_key);
		if (ret != 1) throw 2;

	} catch (int e) {
		if (e == 2) {
			EVP_PKEY_CTX_free(dh_gen_ctx);
		}
		if (e == 1) {
			EVP_PKEY_free(dh_params);
		}

		return nullptr;
	}

	EVP_PKEY_CTX_free(dh_gen_ctx);
	return dh_key;
}




// get session key
unsigned char* Client::derive_session_key (EVP_PKEY* my_dh_key, 
												 EVP_PKEY* peer_key, 
												 size_t key_len)
{
	int ret;

	// Create a new context for deriving DH key
	EVP_PKEY_CTX* key_ctx = EVP_PKEY_CTX_new(my_dh_key, nullptr);
	if (!key_ctx) {
		cerr << "[Thread " << this_thread::get_id() << "] derive_session_key: "
		<< "error ctx" << endl;
		return nullptr;
	}

	unsigned char* secret = nullptr;
	size_t secret_len = 0;

	// Derive the shared secret between client and server
	try {
		ret = EVP_PKEY_derive_init(key_ctx);
		if (ret != 1) throw 0;

		ret = EVP_PKEY_derive_set_peer(key_ctx, peer_key);
		if (ret != 1) throw 0;
		
		ret = EVP_PKEY_derive(key_ctx, nullptr, &secret_len);
		if (ret != 1) throw 0;

		secret = (unsigned char*)malloc(secret_len);
		if (!secret) throw 1;
			
	} catch (int e) {
		if (e == 1) {
			cerr << "Thread " << this_thread::get_id() << " [derive_session_key]: allocation of shared secret failed" << endl;
		}
		else {
			cerr << "Thread " << this_thread::get_id() << " failed [derive_session_key]:\n";
			ERR_print_errors_fp(stderr);
		}

		EVP_PKEY_CTX_free(key_ctx);
		return nullptr;
	}

	ret = EVP_PKEY_derive(key_ctx, secret, &secret_len);
	EVP_PKEY_CTX_free(key_ctx);
	if (ret != 1) { 
		#pragma optimize("", off)
			memset(secret, 0, secret_len);
		#pragma optimize("", on)
		free(secret);

		return nullptr;
	}
	//
	// Hash the shared secret with SHA-256 in order to get a shared secret key
	//
	EVP_MD_CTX* md_ctx = nullptr;
	const EVP_MD* hash_type = EVP_sha256();
	unsigned char* hashed_key = nullptr;
	unsigned int hashed_key_len = 0;
	unsigned char* key = nullptr;

	try {
		// Create context for hashing
		md_ctx = EVP_MD_CTX_new();
		if (!md_ctx) throw 0;

		// Initialize context for specified hash algorithm
		ret = EVP_DigestInit(md_ctx, hash_type);
		if (ret != 1) throw 1;

		// Hash the secret
		ret = EVP_DigestUpdate(md_ctx, secret, secret_len);
		if (ret != 1) throw 1;
		
		// Generate the hashed key
		hashed_key = (unsigned char*)malloc(EVP_MD_size(hash_type));
		if (!hashed_key) throw 1;

		ret = EVP_DigestFinal(md_ctx, hashed_key, &hashed_key_len);
		if (ret != 1) throw 2; 

		// Extract first part of the hashed secret as the secret key
		key = (unsigned char*)malloc(key_len);
		if (!key) throw 2;

		// Check if required key length is a correct value
		if (key_len > hashed_key_len) throw 3;
		memcpy(key, hashed_key, key_len);

	} catch (uint8_t e) { 
		// Handle failures
		if (e >= 3) {
			free(key);
		}
		if (e >= 2) {
			#pragma optimize("", off)
				memset(hashed_key, 0, hashed_key_len);
			#pragma optimize("", on)
			free(hashed_key);
		}
		if (e >= 1) {
			EVP_MD_CTX_free(md_ctx);
		}

		#pragma optimize("", off)
			memset(secret, 0, secret_len);
		#pragma optimize("", on)
		free(secret);

		cerr << "Thread " << this_thread::get_id() << " failed [derive_session_key]:\n";
		ERR_print_errors_fp(stderr);

		return nullptr;
	}

	// Delete protected data
	#pragma optimize("", off)
		memset(secret, 0, secret_len);
		memset(hashed_key, 0, hashed_key_len);
	#pragma optimize("", on)
	free(secret);
	free(hashed_key);
	EVP_MD_CTX_free(md_ctx);

	
	return key;
}



// receive public key from server
int Client::receive_from_server_pub_key(EVP_PKEY*& peer_key) {
	int ret_int;
	long ret_long;
	char* key = nullptr;
	ret_long = receive_message(server_socket, (void**)&key);
	if (ret_long <= 0) {
		cerr << "[Thread " << this_thread::get_id() << "] receive_from_server_pub_key: "
		<< "error receive message" << endl;
		return -1;
	}
	size_t key_len = ret_long;
	BIO* mem_bio = nullptr;
	try {
		mem_bio = BIO_new(BIO_s_mem());
		if (!mem_bio) {
			cerr << "[Thread " << this_thread::get_id() << "] receive_from_server_pub_key: "
			<< "error bio_new" << endl;
			throw 0;
		}
		
		ret_int = BIO_write(mem_bio, key, key_len);
		if (ret_int <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] receive_from_server_pub_key: "
			<< "error bio_write" << endl;
			throw 1;
		}
		peer_key = PEM_read_bio_PUBKEY(mem_bio, nullptr, nullptr, nullptr);
		if (!peer_key) {
			cerr << "[Thread " << this_thread::get_id() << "] receive_from_server_pub_key: "
			<< "error pem read" << endl;
			throw 1;
		}
	} catch (int e) {
		if (e >= 1) {
			BIO_free(mem_bio);
		}
		free(key);
		return -1;
	}
	free(key);
	BIO_free(mem_bio);
	return 1;
}


// Decrypt and verify  sign
int Client::decrypt_and_verify_sign(unsigned char* ciphertext, size_t ciphertext_len,
										  EVP_PKEY* my_dh_key, EVP_PKEY* peer_key, 
										  unsigned char* shared_key, size_t shared_key_len, 
										  unsigned char* iv, size_t iv_len, unsigned char* tag,
										  EVP_PKEY* server_pubkey) 
{
	int ret;
	long ret_long;

	unsigned char* server_signature = nullptr;
	size_t server_signature_len = 0;

	BIO* mbio = nullptr;
	unsigned char* my_key_buf = nullptr;
	size_t my_key_len = 0;
	unsigned char* peer_key_buf = nullptr;
	size_t peer_key_len = 0;
	unsigned char* concat_keys = nullptr;
	size_t concat_keys_len = 0;

	try {
		// 1) Serialize server's key (g**b)
		mbio = BIO_new(BIO_s_mem());
		if (!mbio) {
			cerr << "[Thread " << this_thread::get_id() << "] decrypt_and_verify_sign: "
			<< "BIO_new failed" << endl;
			throw 1;
		}

		ret = PEM_write_bio_PUBKEY(mbio, my_dh_key);
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] decrypt_and_verify_sign: "
			<< "error BIO_write pubkey" << endl;
			throw 2;
		}

		ret_long = BIO_get_mem_data(mbio, &my_key_buf);
		if (ret_long <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] decrypt_and_verify_sign: "
			<< "error bio get meme data" << endl;
			throw 2;
		}
		my_key_len = ret_long;
		my_key_buf = (unsigned char*)malloc(my_key_len);
		if (!my_key_buf) {
			cerr << "[Thread " << this_thread::get_id() << "] decrypt_and_verify_sign: "
			<< "error malloc client key" << endl;
			throw 2;
		}
		ret = BIO_read(mbio, my_key_buf, my_key_len);
		if (ret < 1) {
			cerr << "[Thread " << this_thread::get_id() << "] decrypt_and_verify_sign: "
			<< "error bio read" << endl;
			throw 3;
		}

		// 2) Serialize peer key
		ret = PEM_write_bio_PUBKEY(mbio, peer_key);
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] decrypt_and_verify_sign: "
			<< "error serialize perr key" << endl;
			throw 3;
		}

		ret_long = BIO_get_mem_data(mbio, &peer_key_buf);
		if (ret_long <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] decrypt_and_verify_sign: "
			<< "error bio get meme data peer key" << endl;
			throw 3;
		}
		peer_key_len = ret_long;
		peer_key_buf = (unsigned char*)malloc(peer_key_len);
		if (!peer_key_buf) {
			cerr << "[Thread " << this_thread::get_id() << "] decrypt_and_verify_sign: "
			<< "error malloc peer key" << endl;
			throw 3;
		}
		ret = BIO_read(mbio, peer_key_buf, peer_key_len);
		if (ret < 1) {
			cerr << "[Thread " << this_thread::get_id() << "] decrypt_and_verify_sign: "
			<< "error bio read peer" << endl;
			throw 4;
		}

		// 3) Concat peer_key and my_key
		concat_keys_len = my_key_len + peer_key_len + 1;
		concat_keys = (unsigned char*)malloc(concat_keys_len);
		if (!concat_keys) {
			cerr << "[Thread " << this_thread::get_id() << "] decrypt_and_verify_sign: "
			<< "error concatenation of keys" << endl;
			throw 4;
		}

		memcpy(concat_keys, peer_key_buf, peer_key_len);
		memcpy(concat_keys + peer_key_len, my_key_buf, my_key_len);
		concat_keys[concat_keys_len - 1] = '\0';

		// 4) Decrypt received message with shared key
		ret = gcm_decrypt(ciphertext, ciphertext_len, iv, iv_len, tag, shared_key, iv, iv_len, server_signature, server_signature_len);
		if (ret!=1) {
			cerr << "[Thread " << this_thread::get_id() << "] decrypt_and_verify_sign: "
			<< "error decryption" << endl;
			throw 5;
		}

		// 5) Verify server sig
		ret = verify_server_signature(server_signature, server_signature_len, concat_keys, concat_keys_len, server_pubkey);
		if (ret < 0) {
			cerr << "[Thread " << this_thread::get_id() << "] decrypt_and_verify_sign: "
			<< "error verification sign" << endl;
			throw 6;
		}

	} catch (int e) {
		if (e >= 6) {
			secure_free(server_signature, server_signature_len);
		}
		if (e >= 5) {
			secure_free(concat_keys, concat_keys_len);
		}
		if (e >= 4) {
			secure_free(peer_key_buf, peer_key_len);
		}
		if (e >= 3) {
			secure_free(my_key_buf, my_key_len);
		}
		if (e >= 2) {
			BIO_free(mbio);
		}
		return -1;
	}

	secure_free(server_signature, server_signature_len);
	secure_free(concat_keys, concat_keys_len);
	secure_free(peer_key_buf, peer_key_len);
	secure_free(my_key_buf, my_key_len);
	BIO_free(mbio);

	return 1;
}




//for verify server signature
int Client::verify_server_signature (unsigned char* signature, size_t signature_len, 
										   unsigned char* cleartext, size_t cleartext_len, 
										   EVP_PKEY* server_pubkey)
{
	EVP_MD_CTX* ctx = nullptr;

	int ret;
	int return_value = -1;
	
	try {

		// 2) Verify signature
		ctx = EVP_MD_CTX_new();
		if (!ctx) {
			cerr << "[Thread " << this_thread::get_id() << "] verify_server_signature: "
			<< "EVP_MD_CTX_new returned NULL" << endl;
			throw 1;
		}

		ret = EVP_VerifyInit(ctx, EVP_sha256());
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] verify_server_signature: "
			<< "EVP_VerifyInit returned " << ret << endl;
			throw 2;
		}

		ret = EVP_VerifyUpdate(ctx, cleartext, cleartext_len);
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] verify_server_signature: "
			<< "EVP_VerifyUpdate returned " << ret << endl;
			throw 2;
		}

		ret = EVP_VerifyFinal(ctx, signature, signature_len, server_pubkey);
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] verify_server_signature: "
			<< "EVP_VerifyFinal returned " << ret << endl;
			throw 2;
		}

	} catch (int e) {
		if (e >= 2) {
			EVP_MD_CTX_free(ctx);
		}
		if (e >= 1) {
			EVP_PKEY_free(server_pubkey);
		}
		return return_value;
	}

	return 1;
}




// for encrypt and send sign
int Client::send_sig(EVP_PKEY* my_dh_key, EVP_PKEY* peer_key, unsigned char* shared_key, size_t shared_key_len) {
	int ret;
	long ret_long;

	// Declare variable for DH key serialization and encryption
	BIO* mbio = nullptr;
	char* my_key_buf = nullptr;
	uint32_t my_key_len = 0;
	char* peer_key_buf = nullptr;
	uint32_t peer_key_len = 0;
	unsigned char* encrypted_sign = nullptr;
	size_t encrypted_sign_len = 0;
	unsigned char* tag = nullptr;
	size_t tag_len = 0;
	unsigned char* iv= nullptr;
	size_t iv_len = 0;


	try {
		// 1) Prepare string < g**a, g**b > for signature
		// 1a) Serialize client's key (g**a)
		mbio = BIO_new(BIO_s_mem());
		if (!mbio) {
			cerr << "[Thread " << this_thread::get_id() << "] send_sig: "
			<< "BIO_new failed" << endl;
			throw 0;
		}

		ret = PEM_write_bio_PUBKEY(mbio, my_dh_key);
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] send_sig: "
			<< "PEM_write_bio_PUBKEY returned " << ret << endl;
			throw 1;
		}

		ret_long = BIO_get_mem_data(mbio, &my_key_buf);
		if (ret_long <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] send_sig: "
			<< "BIO_get_mem_data returned " << ret_long << endl;
			throw 1;
		}
		my_key_len = (uint32_t)ret_long;
		my_key_buf = (char*)malloc(my_key_len);
		if (!my_key_buf) {
			cerr << "[Thread " << this_thread::get_id() << "] send_sig: "
			<< "malloc buffer for server's DH key failed" << endl;
			throw 1;
		}
		ret = BIO_read(mbio, my_key_buf, my_key_len);
		if (ret < 1) {
			cerr << "[Thread " << this_thread::get_id() << "] send_sig: "
			<< "BIO_read returned " << ret << endl;
			throw 2;
		}

		// 1b) Serialize peer key (g**b)
		ret = PEM_write_bio_PUBKEY(mbio, peer_key);
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] send_sig: "
			<< "PEM_write_bio_PUBKEY returned " << ret << endl;
			throw 2;
		}

		ret_long = BIO_get_mem_data(mbio, &peer_key_buf);
		if (ret_long <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] send_sig: "
			<< "BIO_get_mem_data returned " << ret_long << endl;
			throw 2;
		}
		peer_key_len = (uint32_t)ret_long;
		peer_key_buf = (char*)malloc(peer_key_len);
		if (!peer_key_buf) {
			cerr << "[Thread " << this_thread::get_id() << "] send_sig: "
			<< "malloc buffer for client's DH key failed" << endl;
			throw 2;
		}
		ret = BIO_read(mbio, peer_key_buf, peer_key_len);
		if (ret < 1) {
			cerr << "[Thread " << this_thread::get_id() << "] send_sig: "
			<< "BIO_read returned " << ret << endl;
			throw 3;
		}

		// 1c) Concat my_key and peer_key
		size_t concat_keys_len = my_key_len + peer_key_len + 1;
		unsigned char* concat_keys = (unsigned char*)malloc(concat_keys_len);
		if (!concat_keys) {
			cerr << "[Thread " << this_thread::get_id() << "] send_sig: "
			<< "malloc concat_keys failed" << endl;
			throw 3;
		}

		memcpy(concat_keys, my_key_buf, my_key_len);
		memcpy(concat_keys + my_key_len, peer_key_buf, peer_key_len);
		concat_keys[concat_keys_len - 1] = '\0';

				
		// 2) Sign concat keys and remove them
		unsigned int signature_len = 0;
		unsigned char* signature = sign_message(concat_keys, concat_keys_len, signature_len);
		secure_free(concat_keys, concat_keys_len);

		if (!signature) {
			cerr << "[Thread " << this_thread::get_id() << "] send_sig: "
			<< "sign_message failed" << endl;
			throw 3;
		}


		// Generate IV
		iv = generate_iv(get_authenticated_encryption_cipher(), iv_len);
		if (!iv) {
			cerr << "[Thread " << this_thread::get_id() << "] send_sig: "
			<< "generate_iv failed" << endl;
			throw 3;
		}


		// 3) Encrypt signature and delete it
		ret = gcm_encrypt(signature, signature_len, iv, iv_len, shared_key, iv, iv_len, encrypted_sign, encrypted_sign_len, tag, tag_len);
		if (ret !=1) {
			cerr << "[Thread " << this_thread::get_id() << "] send_sig: "
			<< "failed to crypt" << endl;
			throw 3;
		}
		secure_free(signature, signature_len);

		if (!encrypted_sign) {
			cerr << "[Thread " << this_thread::get_id() << "] send_sig: "
			<< "encrypt_message failed" << endl;
			throw 3;
		}
	
		// 5) Send messages
		// 5a) Send iv
		ret = send_message(server_socket, (void*)iv, iv_len);
		if (ret <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] send_sig: "
			<< "send_message iv failed" << endl;
			throw 3;
		}
		
		// 5b) send crypted signature
		ret = send_message(server_socket, (void*)encrypted_sign, encrypted_sign_len);
		if (ret <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] send_sig: "
			<< "send_message encrypted_signature" << endl;
			throw 3;
		}

		// 5c) Send tag
		ret = send_message(server_socket, (void*)tag, tag_len);
		if (ret <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] send_sig: "
			<< "send_message tag failed" << endl;
			throw 3;
		}

	} catch (int e) {
		if (e >= 4) {
			secure_free(encrypted_sign, encrypted_sign_len);
		}
		if (e >= 3) {
			secure_free(peer_key_buf, peer_key_len);
		}
		if (e >= 2) {
			secure_free(my_key_buf, my_key_len);
		}
		if (e >= 1) {
			BIO_free(mbio);
		}
		return -1;
	}

	// Clean stuff
	secure_free(encrypted_sign, encrypted_sign_len);
	secure_free(peer_key_buf, peer_key_len);
	secure_free(my_key_buf, my_key_len);
	BIO_free(mbio);

	return 1;
}



// for sign message 
unsigned char* Client::sign_message(unsigned char* msg, size_t msg_len, unsigned int& signature_len)
{
	int ret;
	EVP_PKEY* prvkey = nullptr;
	EVP_MD_CTX* ctx = nullptr;
	unsigned char* signature = nullptr;
	
	try {		
		// get private key
		prvkey = get_client_private_key();
		if (!prvkey) {
			cerr << "[Thread " << this_thread::get_id() << "] sign_message: "
			<< "error getting private key" << endl;
			throw 0;
		}
		
		//new ctx
		ctx= EVP_MD_CTX_new();
		if (!ctx) {
			cerr << "[Thread " << this_thread::get_id() << "] sign_message: "
			<< "Error ctx" << endl;
			throw 1;
		}

		//initialize sign
		ret = EVP_SignInit(ctx, EVP_sha256());
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] sign_message: "
			<< "error initialize sign" << endl;
			throw 2;
		}
		
		//sign message
		ret = EVP_SignUpdate(ctx, msg, msg_len);
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] sign_message: "
			<< "error update sign" << endl;
			throw 2;
		}


		// malloc sign and get size
		signature_len = EVP_PKEY_size(prvkey);
		signature = (unsigned char*)malloc(signature_len);
		if (!signature) {
			cerr << "[Thread " << this_thread::get_id() << "] sign_message: "
			<< "error malloc sign" << endl;
			throw 2;
		}


		// finalize sign
		ret = EVP_SignFinal(ctx, signature, &signature_len, prvkey);
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] sign_message: "
			<< "error finalize sign" << endl;
			throw 3;
		}

	} catch (int e) {
		if (e >= 3) {
			free(signature);
		}
		if (e >= 2) {
			EVP_MD_CTX_free(ctx);
		}
		if (e >= 1) {
			EVP_PKEY_free(prvkey);
		}
		return nullptr;
	}
	
	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(prvkey);

	return signature;
}



//get private key
EVP_PKEY* Client::get_client_private_key ()
{
	string filename_prvkey = keys_folder + client_username + keys_extension;

	// Load my private key:
	FILE* prvkey_file = fopen(filename_prvkey.c_str(), "r");
	if (!prvkey_file) {
		cerr << "[Thread " << this_thread::get_id() << "] get_client_private_key: "
		<< "Cannot open " << filename_prvkey << endl;
		return nullptr;
	}

	EVP_PKEY* prvkey = PEM_read_PrivateKey(prvkey_file, NULL, NULL, (void*)client_password.c_str());
	fclose(prvkey_file);
	if(!prvkey) { 
		cerr << "[Thread " << this_thread::get_id() << "] get_client_private_key: "
		<< "PEM_read_PrivateKey returned NULL" << endl; 
		return nullptr;
	}

	return prvkey;
}


/**
 * Get Certificate Revocation List generated by the CA
 * 
 * @return pointer to CRL on success, NULL on failure
 */
X509_CRL* Client::get_crl() 
{
	// Open the file which contains the CRL
	FILE* file = fopen(Client::filename_crl.c_str(), "r");
	if (!file) {
		cerr << "[Thread " << this_thread::get_id() << "] get_crl: "
		<< "cannot open file " << filename_crl << endl;
		return nullptr;
	}

	// Extract the CRL
	X509_CRL* crl = PEM_read_X509_CRL(file, nullptr, nullptr, nullptr);
	fclose(file);
	if (!crl) {
		cerr << "[Thread " << this_thread::get_id() << "] get_crl: "
		<< "cannot read crle " << endl;
		return nullptr;
	}

	return crl;
}


/**
 * Get Certification Authority certificate
 * 
 * @return CA certificate on success, NULL on failure
 */
X509* Client::get_CA_certificate ()
{
	// Open file which contains CA certificate
	FILE* file = fopen(filename_CA_certificate.c_str(), "r");
	if (!file) {
		cerr << "[Thread " << this_thread::get_id() << "] get_CA_certificate: "
		<< "cannot open file " << filename_CA_certificate << endl;
		return nullptr;
	}

	// Extract the certificate
	X509* cert = PEM_read_X509(file, nullptr, nullptr, nullptr);
	fclose(file);
	if (!cert) {
		cerr << "[Thread " << this_thread::get_id() << "] get_CA_certificate: "
		<< "cannot read X509 certificate " << endl;
		return nullptr;
	}

	return cert;
}


/**
 * Build the store for verify the validity of a given certificate
 * 
 * @param CA_cert certicate of the Certification Authority
 * @param crl Certificate Revocation List
 * @param cert_to_verify certificate to be verified
 * 
 * @return 1 on success, -1 on failure 
 */
int Client::build_store_certificate_and_validate_check(X509* CA_cert, X509_CRL* crl, X509* cert_to_verify) {
	int ret = 0;
	X509_STORE* store = nullptr;
	X509_STORE_CTX* ctx = nullptr;

	try {
		// Allocate store for certificate verification
		store = X509_STORE_new();
		if (!store) {
			cerr << "[Thread " << this_thread::get_id() << "] build_store_certificate_and_validate_check: "
			<< "cannot create store " << endl;
			throw 0;
		}
		// add CA_cert to the store
		ret = X509_STORE_add_cert(store, CA_cert);
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] build_store_certificate_and_validate_check: "
			<< "cannot add certificate to store " << endl;
			throw 1;
		}
		// add crl
		ret = X509_STORE_add_crl(store, crl);
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] build_store_certificate_and_validate_check: "
			<< "cannot add crl to store " << endl;
			throw 1;
		}
		// set the flag
		ret = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] build_store_certificate_and_validate_check: "
			<< "cannot set flag " << endl;
			throw 1;
		}

		//check validity
		ctx = X509_STORE_CTX_new();
		if (!ctx) {
			cerr << "[Thread " << this_thread::get_id() << "] build_store_certificate_and_validate_check: "
			<< "cannot allocate ctx " << endl;
			throw 2;
		}
		ret = X509_STORE_CTX_init(ctx, store, cert_to_verify, NULL);
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] build_store_certificate_and_validate_check: "
			<< "Error in ctx init " << endl;
			throw 2;
		}
		ret = X509_verify_cert(ctx);
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] build_store_certificate_and_validate_check: "
			<< "Error verify cert " << endl;
			cerr << ERR_error_string(ERR_get_error(), NULL) << endl;
			throw 2;
		}

	} catch (int e) {
		if (e >= 2) {
			X509_STORE_CTX_free(ctx);;
		}
		if (e >= 1) {
			X509_STORE_free(store);
		}
		return -1;
	}
	X509_STORE_CTX_free(ctx);
	X509_STORE_free(store);
	return 1;
}


/**
 * Decrypt a message encrypted with AES128-GCM auth-encryption mode
 * 
 * @param ciphertext message to decrypt
 * @param ciphertext_len length of ciphertext
 * @param aad Additional Authenticated Data. It's the authenticated header in clear
 * @param aad_len length of AAD
 * @param tag MAC of the AAD+plaintext
 * @param key symmetric key for AES
 * @param iv initialization vector for AES
 * @param iv_len iv length
 * @param plaintext pointer to the decrypted message. The memory for the plaintext will be allocated by this function.
 * @param plaintext_len length of generated plaintext
 * 
 * @return 1 on success, -1 on failure 
 */
int Client::gcm_decrypt (unsigned char* ciphertext, int ciphertext_len,
							   unsigned char* aad, int aad_len,
							   unsigned char* tag,
							   unsigned char* key,
							   unsigned char* iv, int iv_len,
							   unsigned char*& plaintext, size_t& plaintext_len)
{
	int ret;

	EVP_CIPHER_CTX* ctx = nullptr;
	int outlen = 0;

	try {
		// Allocate plaintext
		plaintext = (unsigned char*)malloc(ciphertext_len);
		if (!plaintext) {
			cerr << "[Thread " << this_thread::get_id() << "] gcm_decrypt: "
			<< "malloc plaintext failed" << endl;
			throw 0;
		}
		
		// Create and initialise the context
		ctx = EVP_CIPHER_CTX_new();
		if (!ctx) {
			cerr << "[Thread " << this_thread::get_id() << "] gcm_decrypt: "
			<< "EVP_CIPHER_CTX_bew failed" << endl;
			throw 1;
		}

		ret = EVP_DecryptInit(ctx, get_authenticated_encryption_cipher(), key, iv);
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] gcm_decrypt: "
			<< "EVP_DecryptInit failed" << endl;
			throw 2;
		}

		// Introduce AAD data in context
		ret = EVP_DecryptUpdate(ctx, NULL, &outlen, aad, aad_len);
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] gcm_decrypt: "
			<< "EVP_DecryptUpdate AAD failed" << endl;
			throw 2;
		}

		// Provide the message to be decrypted, and obtain the plaintext output.
		ret = EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, ciphertext_len);
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] gcm_decrypt: "
			<< "EVP_DecryptUpdate plaintext failed" << endl;
			throw 2;
		}
		plaintext_len = outlen;

		// Set expected tag value
		ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag);
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] gcm_decrypt: "
			<< "EVP_CIPHER_CTX_ctrl failed" << endl;
			throw 2;			
		}

		// Finalise the decryption. A positive return value indicates success,
		// anything else is a failure (i.e. the plaintext is not trustworthy)
		ret = EVP_DecryptFinal(ctx, plaintext + outlen, &outlen);
		if (ret <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] gcm_decrypt: "
			<< "EVP_DecryptFinal returned " << ret << endl;
			throw 2;
		}
		plaintext_len += outlen;

	} catch (int e) {
		if (e >= 2) {
			EVP_CIPHER_CTX_free(ctx);
		}
		if (e >= 1) {
			free(plaintext);
		}
		return -1;
	}

	// Clean up
	EVP_CIPHER_CTX_free(ctx);
	return 1;
}

/**
 * Encrypt a message with AES128-GCM auth-encryption mode
 * 
 * @param plaintext message to encrypt
 * @param plaintext_len length of plaintext
 * @param aad Additional Authenticated Data. It's the authenticated header in clear
 * @param aad_len length of AAD
 * @param key symmetric key for AES
 * @param iv initialization vector for AES.
 * @param iv_len length of iv
 * @param ciphertext generated encrypted message. Allocated by this function
 * @param ciphertext_len length of message
 * @param tag generated MAC of AAD+plaintext. Allocated by this function.
 * 
 * @return 1 on success, -1 on failure  
 */
int Client::gcm_encrypt (unsigned char* plaintext, int plaintext_len,
							   unsigned char* aad, int aad_len, 
							   unsigned char* key,
							   unsigned char* iv, int iv_len, 
							   unsigned char*& ciphertext, size_t& ciphertext_len,
							   unsigned char*& tag, size_t& tag_len)
{
	int ret;

	EVP_CIPHER_CTX* ctx;
	
	try {
		// Allocate ciphertext
		ciphertext = (unsigned char*)malloc(plaintext_len + EVP_CIPHER_block_size(get_authenticated_encryption_cipher()));
		if (!ciphertext) {
			cerr << "[Thread " << this_thread::get_id() << "] gcm_encrypt: "
			<< "malloc ciphertext failed" << endl;
			throw 0;
		}

		// Allocate tag
		tag = (unsigned char*)malloc(TAG_SIZE);
		if (!tag) {
			cerr << "[Thread " << this_thread::get_id() << "] gcm_encrypt: "
			<< "malloc tag failed" << endl;
			throw 1;
		}
		tag_len = TAG_SIZE;

		// Create and initialize the context
		ctx = EVP_CIPHER_CTX_new();
		if (!ctx) {
			cerr << "[Thread " << this_thread::get_id() << "] gcm_encrypt: "
			<< "EVP_CIPHER_CTX_new failed" << endl;
			ERR_print_errors_fp(stderr);
			throw 3;
		}

		// Initialise the encryption operation.
		ret = EVP_EncryptInit(ctx, get_authenticated_encryption_cipher(), key, iv);
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] gcm_encrypt: "
			<< "EVP_EncryptInit returned " << ret << endl;
			ERR_print_errors_fp(stderr);
			throw 4;
		}

		int outlen;
		// Insert AAD header
		ret = EVP_EncryptUpdate(ctx, NULL, &outlen, aad, aad_len);
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] gcm_encrypt: "
			<< "EVP_EncryptUpdate AAD returned " << ret << endl;
			ERR_print_errors_fp(stderr);
			throw 4;
		}

		// Encrypt plaintext
		ret = EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, plaintext_len);
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] gcm_encrypt: "
			<< "EVP_EncryptUpdate ciphertext returned " << ret << endl;
			ERR_print_errors_fp(stderr);
			throw 4;
		}
		ciphertext_len = outlen;

		// Finalize Encryption
		ret = EVP_EncryptFinal(ctx, ciphertext + outlen, &outlen);
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] gcm_encrypt: "
			<< "EVP_EncryptFinal returned " << ret << endl;
			ERR_print_errors_fp(stderr);
			throw 4;
		}
		ciphertext_len += outlen;

		// Get the tag
		ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_SIZE, tag);
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] gcm_encrypt: "
			<< "getting the tag failed" << endl;
			ERR_print_errors_fp(stderr);
			throw 4;
		}

	} catch (int e) {
		if (e >= 4) {
			EVP_CIPHER_CTX_free(ctx);
		}
		if (e >= 2) {
			free(tag);
		}
		if (e >= 1) {
			free(ciphertext);
		}
		return -1;
	}

	// Clean up
	EVP_CIPHER_CTX_free(ctx);

	return 1;
}


const EVP_CIPHER* Client::get_authenticated_encryption_cipher ()
{
	return EVP_aes_128_gcm();
}



unsigned char* Client::generate_iv (EVP_CIPHER const* cipher, size_t& iv_len)
{
	iv_len = EVP_CIPHER_iv_length(cipher);

	// Allocate IV
	unsigned char* iv = (unsigned char*)malloc(iv_len);
	if (!iv) {
		cerr << "[Thread " << this_thread::get_id() << "] generate_iv: "
		<< "malloc iv failed" << endl;
		return nullptr;
	}
	
	int ret = RAND_bytes(iv, iv_len);
	if (ret != 1) {
		cerr << "[Thread " << this_thread::get_id() << "] generate_iv: "
		<< "RAND_bytes failed" << endl;
		ERR_print_errors_fp(stderr);
		
		free(iv);
		return nullptr;
	}

	return iv;
}





int Client::receive_response_command_to_server()
{
	return -1; // TODO
}

void Client::print_command_options() 
{
	cout<<"Select command:"<<endl;
	cout<<"0 : talk"<<endl;
	cout<<"1 : show"<<endl;
	cout<<"2 : exit"<<endl;
}





int Client::send_plaintext (const int socket, unsigned char* msg, const size_t msg_len, unsigned char* key)
{
	int ret;

	unsigned char* iv = nullptr;
	size_t iv_len = 0;
	unsigned char* ciphertext = nullptr;
	size_t ciphertext_len = 0;
	unsigned char* tag = nullptr;
	size_t tag_len = 0;

	try {
		// 1) Generate IV
		iv = generate_iv(get_authenticated_encryption_cipher(), iv_len);
		if (!iv) {
			throw 0;
		}

		// 2) Encrypt message
		ret = gcm_encrypt(msg, msg_len, iv, iv_len, key, iv, iv_len, ciphertext, ciphertext_len, tag, tag_len);
		if (ret < 0) {
			throw 1;
		}

		// 3) Send iv
		ret = send_message(socket, (void*)iv, iv_len);
		if (ret < 0) {
			throw 2;
		}

		// 4) Send message
		ret = send_message(socket, (void*)ciphertext, ciphertext_len);
		if (ret < 0) {
			throw 2;
		}

		// 5) Send tag
		ret = send_message(socket, (void*)tag, tag_len);
		if (ret < 0) {
			throw 2;
		}

	} catch (int e) {
		if (e >= 2) {
			free(ciphertext);
			free(tag);
		}
		if (e >= 1) {
			free(iv);
		}
		return -1;
	}

	free(ciphertext);
	free(tag);
	free(iv);

	return 1;
}

int Client::receive_plaintext (const int socket, unsigned char*& msg, size_t& msg_len, unsigned char* shared_key)
{
	long ret_long = -1;
	
	unsigned char* iv = nullptr;
	unsigned char* ciphertext = nullptr;
	unsigned char* tag = nullptr;

	try {
		// 1) Receive iv
		ret_long = receive_message(server_socket, (void**)&iv);
		if (ret_long <= 0) {
			throw 0;
		}
		size_t iv_len = ret_long;

		// 2) Receive ciphertext
		ret_long = receive_message(server_socket, (void**)&ciphertext);
		if (ret_long <= 0) {
			throw 1;
		}
		size_t ciphertext_len = ret_long;

		// 3) Receive tag
		ret_long = receive_message(server_socket, (void**)&tag);
		if (ret_long <= 0) {
			throw 2;
		}
		// 4) Decrypt message
		int ret = gcm_decrypt(ciphertext, ciphertext_len, iv, iv_len, tag, shared_key, iv, iv_len, msg, msg_len);
		if (ret < 0) {
			throw 3;
		}
	} catch (int e) {
		if (e >= 3) {
			free(tag);
		}
		if (e >= 2) {
			free(ciphertext);
		}
		if (e >= 1) {
			free(iv);
		}
		return (ret_long == 0) ? 0 : -1; // If ret_long is 0, then socket has been closed
	}

	free(tag);
	free(ciphertext);
	free(iv);

	return 1;
}




int Client::receive_plaintext2 (const int socket, thread_bridge* bridge, unsigned char* shared_key)
{
	long ret_long = -1;
	
	unsigned char* iv = nullptr;
	unsigned char* ciphertext = nullptr;
	unsigned char* tag = nullptr;

	try {
		// 1) Receive iv
		ret_long = receive_message(server_socket, (void**)&iv);
		if (ret_long <= 0) {
			throw 0;
		}
		size_t iv_len = ret_long;

		// 2) Receive ciphertext
		ret_long = receive_message(server_socket, (void**)&ciphertext);
		if (ret_long <= 0) {
			throw 1;
		}
		size_t ciphertext_len = ret_long;


		// 3) Receive tag
		ret_long = receive_message(server_socket, (void**)&tag);
		if (ret_long <= 0) {
			throw 2;
		}
		// 4) Decrypt message
		unsigned char* msg = nullptr;
		size_t msg_len=0;
		int ret = gcm_decrypt(ciphertext, ciphertext_len, iv, iv_len, tag, shared_key, iv, iv_len, msg, msg_len);
		if (ret < 0) {
			throw 3;
		}
		bridge->notify_new_message(msg, msg_len);
		free(msg);
	} catch (int e) {
		if (e >= 3) {
			free(tag);
		}
		if (e >= 2) {
			free(ciphertext);
		}
		if (e >= 1) {
			free(iv);
		}
		return (ret_long == 0) ? 0 : -1; // If ret_long is 0, then socket has been closed
	}
	free(tag);
	free(ciphertext);
	free(iv);

	return 1;
}