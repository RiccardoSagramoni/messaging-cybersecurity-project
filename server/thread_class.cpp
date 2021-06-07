#include "server.h"

/**
 * Constructor
 * 
 * @param _server pointer to server object
 * @param socket descriptor of the socket created for the client's connection request
 * @param addr IP address of connected client
 */
ServerThread::ServerThread(Server* serv, const int socket, const sockaddr_in addr)
{
	server = serv;
	client_socket = socket;
	main_client_address = addr;
}

/**
 * Start the thread
 */
void ServerThread::run()
{
	int ret;

	// 1) Authenticate client and negotiate session key
	cout << "START" << endl; // TODO remove

	client_key  = authenticate_and_negotiate_key(client_username, client_key_len);
	if(!client_key) {
		cerr << "[Thread " << this_thread::get_id() << "] run: "
			<< "authenticate_and_negotiate_key failed. "
			<< "Closing this thread and socket " << client_socket << endl;
		close(client_socket);
		return;
	}	
	
	cout << "STOP" << endl;	

	// 2) Add current client to server
	if (!server->add_new_client(client_username, client_socket, client_key, client_key_len)) {
		cerr << "[Thread " << this_thread::get_id() << "] run: "
		<< "client " << client_username << " already logged." << endl
		<< "Closing this thread and socket " << client_socket << endl;;
		send_error_response(client_socket, ERR_ALREADY_LOGGED, client_key);
		close(client_socket);
		return;
	}

	// -) Cycle
		// -) Wait for command
		// -) Execute command
	while (true) {
		unsigned char* msg;
		ret = get_new_client_command(msg);
		ret = execute_client_command(msg);
		free(msg);

		// TODO Check ret
	}
}

/**
 * Generate public DH parameters for this application
 * 
 * @return DH parameters
 */
DH* ServerThread::get_dh2048 ()
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
 * Get server's private key from file
 * 
 * @return server's private key
 */
EVP_PKEY* ServerThread::get_server_private_key ()
{
	// Load my private key:
	FILE* prvkey_file = fopen(filename_prvkey.c_str(), "r");
	if (!prvkey_file) {
		cerr << "[Thread " << this_thread::get_id() << "] Error: "
		<< "Cannot open " << filename_prvkey << endl;
		return nullptr;
	}

	EVP_PKEY* prvkey = PEM_read_PrivateKey(prvkey_file, NULL, NULL, NULL);
	fclose(prvkey_file);
	if(!prvkey) { 
		cerr << "[Thread " << this_thread::get_id() << "] Error: "
		<< "PEM_read_PrivateKey returned NULL" << endl; 
		return nullptr;
	}

	return prvkey;
}

X509* ServerThread::get_server_certificate ()
{
	
	FILE* file = nullptr;
	X509* cert = nullptr;

	try {
		file = fopen(filename_certificate.c_str(), "r");
		if (!file) {
			cerr << "[Thread " << this_thread::get_id() << "] get_server_certificate: "
			<< "cannot open file " << filename_certificate << endl;
			throw 0;
		}

		cert = PEM_read_X509(file, nullptr, nullptr, nullptr);
		if (!cert) {
			cerr << "[Thread " << this_thread::get_id() << "] get_server_certificate: "
			<< "cannot read X509 certificate " << endl;
			throw 1;
		}

	} catch (int e) {
		if (e >= 1) {
			fclose(file);
		}
		return nullptr;
	}

	fclose(file);
	return cert;
}

/**
 * Sign a message with server's private key
 * 
 * @param msg message to sign
 * @param msg_len length of message
 * @param signature_len return length of generated signature
 * 
 * @return generated signature of given message
 */
unsigned char* ServerThread::sign_message(unsigned char* msg, size_t msg_len, unsigned int& signature_len)
{
	int ret;
	EVP_PKEY* prvkey = nullptr;
	EVP_MD_CTX* ctx = nullptr;
	unsigned char* signature = nullptr;
	
	try {
		prvkey = get_server_private_key();
		if (!prvkey) throw 0;
		
		ctx= EVP_MD_CTX_new();
		if (!ctx) throw 1;

		ret = EVP_SignInit(ctx, EVP_sha256());
		if (ret != 1) throw 2;

		ret = EVP_SignUpdate(ctx, msg, msg_len);
		if (ret != 1) throw 2;

		signature_len = EVP_PKEY_size(prvkey);
		signature = (unsigned char*)malloc(signature_len);
		if (!signature) throw 2;

		ret = EVP_SignFinal(ctx, signature, &signature_len, prvkey);
		if (ret != 1) throw 3;

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

/**
 * Send a message through the specified socket
 * 
 * @param socket socket descriptor
 * @param msg pointer to the message
 * @param msg_len length of the message 
 * @return 1 on success, -1 otherwise 
 */
int ServerThread::send_message (const int socket, void* msg, const uint32_t msg_len)
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
long ServerThread::receive_message (const int socket, void** msg)
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

/**
 * Send an error message through the specified socket
 * 
 * @param socket socket descriptor
 * @param type type of error
 * @param key shared key between client and server
 * 
 * @return 1 on success, -1 on failure
 */
int ServerThread::send_error_response (const int socket, const uint8_t type, unsigned char* key)
{
	uint8_t msg[2] = {SERVER_ERR, type};
	
	return send_response(socket, msg, 2, key);
}

/**
 * Send a response message to the client
 * 
 * @param socket socket descriptor
 * @param msg message
 * @param msg_len message length
 * @param key shared key between client and server
 * 
 * @return 1 on success, -1 on failure
 */
int ServerThread::send_response (const int socket, unsigned char* msg, const size_t msg_len, unsigned char* key)
{
	int ret;

	unsigned char* iv = nullptr;
	size_t iv_len = 0;
	unsigned char* key = nullptr;
	size_t key_len = 0;
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
		ret = gcm_encrypt(msg, msg_len, iv, iv_len, key, iv, iv_len, ciphertext, ciphertext_len, 
		                  tag, tag_len);
		if (ret < 0) {
			throw 1;
		}

		// 3) Send iv
		ret = send_message(socket, iv, iv_len);
		if (ret < 0) {
			throw 2;
		}

		// 4) Send message
		ret = send_message(socket, ciphertext, ciphertext_len);
		if (ret < 0) {
			throw 2;
		}

		// 5) Send tag
		ret = send_message(socket, tag, tag_len);
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

/**
 * Receive a new message from the client
 * 
 * @param msg on success it will point to the received message
 * 
 * @return 1 on success, 0 if the client closes the socket, -1 if any other error occurs
 */
int ServerThread::get_new_client_command (unsigned char*& msg)
{
	long ret_long = -1;
	
	unsigned char* iv = nullptr;
	unsigned char* ciphertext = nullptr;
	unsigned char* tag = nullptr;

	size_t msg_len;

	try {
		// 1) Receive iv
		ret_long = receive_message(client_socket, (void**)&msg);
		if (ret_long <= 0) {
			throw 0;
		}
		size_t iv_len = ret_long;

		// 2) Receive ciphertext
		ret_long = receive_message(client_socket, (void**)&ciphertext);
		if (ret_long <= 0) {
			throw 1;
		}
		size_t ciphertext_len = ret_long;

		// 3) Receive tag
		ret_long = receive_message(client_socket, (void**)&tag);
		if (ret_long <= 0) {
			throw 2;
		}
		size_t tag_len = ret_long;

		// 4) Decrypt message
		int ret = gcm_decrypt(ciphertext, ciphertext_len, iv, iv_len, tag, client_key, 
		                      iv, iv_len, msg, msg_len);
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

/**
 * Parse received message from client and execute its request
 * 
 * @param msg received message
 * @return 1 on success, -1 on failure
 */
int ServerThread::execute_client_command (const unsigned char* msg) 
{
	uint8_t request_type = get_request_type(msg);
	
	switch (request_type) {
		case TYPE_SHOW:
			execute_show();
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

/**
 * Given a message, extract the type of client's message
 * 
 * @param msg received message
 * @return type of request
 */
uint8_t ServerThread::get_request_type (const unsigned char* msg)
{
	return (uint8_t)msg[0];
}


int ServerThread::execute_show ()
{
	// 1) Get list of client logged to the server
	list<string> l = server->get_available_clients_list();

	// 2) Serialize list
	// 2a) Calculate necessary space
	size_t message_len = 1;
	for (auto s : l) {
		message_len += (s.length() + 1);
	}

	// 2b) Allocate message
	char* message = (char*)malloc(message_len);
	if (!message) {
		return -1;
	}

	// 2c) Initialise message
	uint8_t* type = (uint8_t*)&message[0];
	*type = SERVER_OK;
	size_t pos = 1;

	for (auto s: l) {
		// a) Insert username length
		uint32_t string_size = s.length() + 1;
		string_size = htonl(string_size);
		memcpy(message + pos, &string_size, sizeof(string_size));
		pos += sizeof(string_size);

		// b) Insert username
		memcpy(message + pos, s.c_str(), string_size);
		pos += string_size;
	}

	// 3) Send message
	int ret = send_response(client_socket, (unsigned char*)message, message_len, client_key);
	free(message);

	if (ret < 0) {
		return -1;
	}

	return 1;
}


/**
 * Try to authenticate the client and negotiate a symmetric shared secret key,
 * using the Station-to-Station protocol (a modified version of Diffie-Hellman)
 * 
 * @param username identifier of the client
 * @param key_len reference to the variable that will contain the length of the key on success
 * 
 * @return the negotiated key on success, NULL on failure
 */
unsigned char* ServerThread::authenticate_and_negotiate_key (string& username, size_t& key_len)
{
	int ret;

	EVP_PKEY* peer_key = nullptr;
	EVP_PKEY* my_dh_key = nullptr;
	unsigned char* session_key = nullptr;
	size_t session_key_len = EVP_CIPHER_key_length(get_authenticated_encryption_cipher());
	unsigned char* iv = nullptr;

	try {
	// 1) Receive clients username and g**a
		ret = STS_receive_hello_message(peer_key, username);
		if (ret <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] authenticate_and_negotiate_key: "
			<< "STS_receive_hello_message returned " << ret << endl;
			throw 0;
		}

		// 1b) Check if username is valid
		if(!check_username_validity(username)) {
			cerr << "[Thread " << this_thread::get_id() << "] authenticate_and_negotiate_key: "
				<< " authenticate_and_negotiate_key failed: username doesn't exist" 
				<< endl;
			throw 1;
		}

	// 2) Generate random b and calculate g**b (Diffie-Helmann)
		my_dh_key = generate_key_dh();
		if (!my_dh_key) {
			cerr << "[Thread " << this_thread::get_id() << "] authenticate_and_negotiate_key: "
			<< "generate_key_dh failed" << endl;
			throw 1;
		}

	// 3) Derive shared secret k and hash it
		session_key = derive_session_key(my_dh_key, peer_key, session_key_len);
		if (!session_key) {
			cerr << "[Thread " << this_thread::get_id() << "] authenticate_and_negotiate_key: "
			<< "derive_sessione_key failed" << endl;
			throw 2;
		}

	// 4) Send g**b || encrypted_k{sign of g**b,g**a} || server's certificate
		// 4a) Allocate and initialize IV
		size_t iv_len;
		iv = generate_iv(get_authenticated_encryption_cipher(), iv_len);
		if (!iv) {
			cerr << "[Thread " << this_thread::get_id() << "] authenticate_and_negotiate_key: "
			<< "generate_iv failed" << endl;
			throw 3;
		}

		// 4b) Send message
		ret = STS_send_session_key(session_key, session_key_len, my_dh_key, peer_key, iv, iv_len);
		if (ret < 0) {
			cerr << "[Thread " << this_thread::get_id() << "] authenticate_and_negotiate_key: "
			<< "STS_send_session_key failed" << endl;
			throw 4;
		}
	// 5) Receive response message by client and check its validity
		// Message is encrypted_k{sign_by_client{g**a,g**b}}
		
		ret = STS_receive_response(session_key, session_key_len, my_dh_key, 
		                           peer_key, username);
		if (ret < 0) {
			cerr << "[Thread " << this_thread::get_id() << "] authenticate_and_negotiate_key: "
			<< "STS_receive_response failed" << endl;
			throw 4;
		}
	} catch (int e) {
		if (e >= 4) {
			free(iv);
		}
		if (e >= 3) {
			secure_free(session_key, session_key_len);
		}
		if (e >= 2) {
			EVP_PKEY_free(my_dh_key);
		}
		if (e >= 1) {
			EVP_PKEY_free(peer_key);
		}
		return nullptr;
	}

	free(iv);
	EVP_PKEY_free(my_dh_key);
	EVP_PKEY_free(peer_key);

	return session_key;
}

/**
 * Generate server's part of the shared private key, i.e. g**b according to DH protocol
 * 
 * @return the generated key on success, NULL otherwise
 */
EVP_PKEY* ServerThread::generate_key_dh ()
{
	int ret;
	
	EVP_PKEY* dh_params = nullptr;
	EVP_PKEY_CTX* dh_gen_ctx = nullptr;
	EVP_PKEY* dh_key = nullptr;

	try {
		// Allocate DH params p and g
		dh_params = EVP_PKEY_new();
		if (!dh_params) throw 0;

		// Calculate DH params
		DH* temp_dh_params = get_dh2048();
		ret  = EVP_PKEY_set1_DH(dh_params, temp_dh_params);
		DH_free(temp_dh_params);
		if (ret != 1) throw 1;

		// Generate g**b
		dh_gen_ctx = EVP_PKEY_CTX_new(dh_params, nullptr);
		if (!dh_gen_ctx) throw 1;

		ret = EVP_PKEY_keygen_init(dh_gen_ctx);
		if (ret != 1) throw 2;

		dh_key = nullptr;
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

/**
 * Derive a shared session key from server's generated key and client's received key
 * according to Diffie-Hellman key exchange method.
 * The shared secret obtained by the merge of server and client's keys is then
 * hashed with SHA-256 and the first <key_len> bytes are used as shared key
 * 
 * @param my_dh_key the key generated by the server
 * @param peer_key the key generated by the client
 * @param key_len the required length of the key
 * 
 * @return the sessione key on success, NULL otherwise
 */
unsigned char* ServerThread::derive_session_key (EVP_PKEY* my_dh_key, 
                                                 EVP_PKEY* peer_key, 
                                                 size_t key_len)
{
	int ret;

	// Create a new context for deriving DH key
	EVP_PKEY_CTX* key_ctx = EVP_PKEY_CTX_new(my_dh_key, nullptr);
	if (!key_ctx) {
		cerr << "Thread " << this_thread::get_id() << " failed [derive_session_key]:\n";
		ERR_print_errors_fp(stderr);
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
		secure_free(secret, secret_len);
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
			secure_free(hashed_key, hashed_key_len);
		}
		if (e >= 1) {
			EVP_MD_CTX_free(md_ctx);
		}

		secure_free(secret, secret_len);

		cerr << "Thread " << this_thread::get_id() << " failed [derive_session_key]:\n";
		ERR_print_errors_fp(stderr);

		return nullptr;
	}

	// Delete protected data
	secure_free(secret, secret_len);
	secure_free(hashed_key, hashed_key_len);
	EVP_MD_CTX_free(md_ctx);

	return key;
}

/**
 * Get symmetric cipher used in this application.
 * 
 * @return structure which describes chosen cipher
 */
const EVP_CIPHER* ServerThread::get_authenticated_encryption_cipher ()
{
	return EVP_aes_128_gcm();
}

/**
 * Receive the first messages sent by the client. This is the first phase of STS protocol.
 * 
 * The first messages that the client has to send are:
 *   1) His username
 *   2) The value g**a neded for the Diffie-Hellmann protocol
 * Those are sent in cleartext, since they aren't critical data and no session key is established yet.
 * 
 * @param peer_key it will contain the client's key on success
 * @param username it will contain the client's username on success
 * 
 * @return 1 on success, 0 if the client closed its socket, -1 otherwise
 */
int ServerThread::STS_receive_hello_message (EVP_PKEY*& peer_key, string& username)
{
	int ret_int;
	long ret_long;

	// Get the username
	char* username_c = nullptr;
	ret_long = receive_message(client_socket, (void**)&username_c);
	if (ret_long <= 0) {
		return -1;
	}
	username = username_c;
	free(username_c);

	// Get client's "key" g**a
	char* key = nullptr;
	ret_long = receive_message(client_socket, (void**)&key);
	if (ret_long <= 0) {
		return -1;
	}
	size_t key_len = ret_long;

	BIO* mem_bio = nullptr;
	try {
		mem_bio = BIO_new(BIO_s_mem());
		if (!mem_bio) throw 0;

		ret_int = BIO_write(mem_bio, key, key_len);
		if (ret_int <= 0) throw 1;

		peer_key = PEM_read_bio_PUBKEY(mem_bio, nullptr, nullptr, nullptr);
		if (!peer_key) throw 1;
		
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


/**
 * Receive the messages of the third step of Station-to-Station protocol, so that
 * the authentication pahse can be ended.
 * The message received is: encrypted_k{sign_by_client{g**a,g**b}}
 * 
 * @param shared_key symmetric key established between server and client
 * @param shared_key_len length of shared key
 * @param my_dh_key g**b, i.e. server's part of DH key
 * @param peer_key g**a, i.e. client's part of DH key
 * 
 * @return 1 on success, -1 on failure
 */
int ServerThread::STS_receive_response (unsigned char* shared_key, size_t shared_key_len,
                                        EVP_PKEY* my_dh_key, EVP_PKEY* peer_key,
										const string& username)
{
	int ret;
	long ret_long;

	unsigned char* iv = nullptr;
	unsigned char* ciphertext = nullptr;
	unsigned char* tag = nullptr;
	unsigned char* client_signature = nullptr;
	size_t client_signature_len = 0;

	BIO* mbio = nullptr;
	unsigned char* my_key_buf = nullptr;
	size_t my_key_len = 0;
	unsigned char* peer_key_buf = nullptr;
	size_t peer_key_len = 0;
	unsigned char* concat_keys = nullptr;
	size_t concat_keys_len = 0;

	try {
		// 1) Receive message from client
		// 1a) IV
		ret = receive_message(client_socket, (void**)&iv);
		if (ret <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] STS_receive_response: "
			<< "receive_message iv failed" << endl;
			throw 0;
		}
		size_t iv_len = ret;

		// 1b) encrypted_k{sign_by_client{g**a,g**b}}
		ret = receive_message(client_socket, (void**)&ciphertext);
		if (ret <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] STS_receive_response: "
			<< "receive_message encrypted signature failed" << endl;
			throw 1;
		}
		size_t ciphertext_len = ret;

		// 1c) tag
		ret = receive_message(client_socket, (void**)&tag);
		if (ret <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] STS_receive_response: "
			<< "receive_message tag failed" << endl;
			throw 2;
		}
		// 2) Serialize g**b (server's DH key) and g**a (client's DH key).
		// Then concatenate them.
		// 2a) Serialize server's key (g**b)
		mbio = BIO_new(BIO_s_mem());
		if (!mbio) {
			throw 3;
		}
		ret = PEM_write_bio_PUBKEY(mbio, my_dh_key);
		if (ret != 1) {
			throw 4;
		}
		ret_long = BIO_get_mem_data(mbio, &my_key_buf);
		if (ret_long <= 0) {
			throw 4;
		}
		my_key_len = ret_long;
		my_key_buf = (unsigned char*)malloc(my_key_len);
		if (!my_key_buf) {
			throw 4;
		}
		ret = BIO_read(mbio, my_key_buf, my_key_len);
		if (ret < 1) {
			throw 5;
		}
		// 2b) Serialize peer key
		ret = PEM_write_bio_PUBKEY(mbio, peer_key);
		if (ret != 1) {
			throw 5;
		}
		ret_long = BIO_get_mem_data(mbio, &peer_key_buf);
		if (ret_long <= 0) {
			throw 5;
		}
		peer_key_len = ret_long;
		peer_key_buf = (unsigned char*)malloc(peer_key_len);
		if (!peer_key_buf) {
			throw 5;
		}
		ret = BIO_read(mbio, peer_key_buf, peer_key_len);
		if (ret < 1) {
			throw 6;
		}

		// 2c) Concat peer_key and my_key
		concat_keys_len = my_key_len + peer_key_len + 1;
		concat_keys = (unsigned char*)malloc(concat_keys_len);
		if (!concat_keys) {
			throw 6;
		}

		memcpy(concat_keys, peer_key_buf, peer_key_len);
		memcpy(concat_keys + peer_key_len, my_key_buf, my_key_len);
		concat_keys[concat_keys_len - 1] = '\0';
		
		// 3) Encrypt received message with shared key
		ret = gcm_decrypt(ciphertext, ciphertext_len, iv, iv_len, tag, shared_key, 
		                  iv, iv_len, client_signature, client_signature_len);
		if (ret < 0) {
			throw 7;
		}

		// 4) Verify correctness of client's response to STS protocol
		ret = verify_client_signature(client_signature, client_signature_len, 
		                              concat_keys, concat_keys_len, username);
		if (ret < 0) {
			throw 8;
		}

	} catch (int e) {
		if (e >= 8) {
			secure_free(client_signature, client_signature_len);
		}
		if (e >= 7) {
			secure_free(concat_keys, concat_keys_len);
		}
		if (e >= 6) {
			secure_free(peer_key_buf, peer_key_len);
		}
		if (e >= 5) {
			secure_free(my_key_buf, my_key_len);
		}
		if (e >= 4) {
			BIO_free(mbio);
		}
		if (e >= 3) {
			free(tag);
		}
		if (e >= 2) {
			free(ciphertext);
		}
		if (e >= 1) {
			free(iv);
		}
		return -1;
	}

	secure_free(client_signature, client_signature_len);
	secure_free(peer_key_buf, peer_key_len);
	secure_free(my_key_buf, my_key_len);
	BIO_free(mbio);
	free(tag);
	free(ciphertext);
	free(iv);

	return 1;
}



/**
 * Check if specified username is valid, 
 * i.e. if its public key is installed on the server
 * 
 * @param username name of the user
 * @return 1 if the username is valid, 0 otherwise
 */
bool ServerThread::check_username_validity (const string& username)
{
	// Check is username exists by checking if 
	// the relative public key is installed on the server
	string file_name = "clients/" + username + ".pem";
	FILE* file = fopen(file_name.c_str(), "r");
	
	if (file) {
		// The file exists
		fclose(file);
		return true;
	}
	else {
		return false;
	}
}


/**
 * Send to the connected client the second message of the STS protcol, which is composed by:
 * 	1) The part of DH key generated by the server (g**b)
 * 	2) The signature of <g**b, g**a>, where g**a is the part of DH key generated by the client, 
 * 	   encrypted with the shared DH key
 * 	3) Server's certificate
 * The three part of this message are sent separately as three smaller messages.
 * The client is then supposed to wait for three messages in the second phase of the protocol instead of one.
 * 
 * @param shared_key the derived DH shared key between client and server
 * @param shared_key_len the length of the shared key
 * @param my_dh_key server's part of DH key (g**b)
 * @param peer_key client's part of DH key (g**b)
 * @param iv initialization vector for AES cipher (CBC mode)
 * 
 * @return 1 on success, -1 on failure
 */
int ServerThread::STS_send_session_key (unsigned char* shared_key, size_t shared_key_len, 
                                        EVP_PKEY* my_dh_key, EVP_PKEY* peer_key, 
										unsigned char* iv, size_t iv_len)
{

	int ret;
	long ret_long;

	// Declare variable for DH key serialization and encryption
	BIO* mbio = nullptr;
	char* my_key_buf = nullptr;
	uint32_t my_key_len = 0;
	char* peer_key_buf = nullptr;
	uint32_t peer_key_len = 0;
	unsigned char* tag = nullptr;
	size_t tag_len = 0;
	unsigned char* encrypted_sign = nullptr;
	size_t encrypted_sign_len = 0;

	// Declare variables for certificates
	X509* certificate = nullptr;
	unsigned char* ser_certificate = nullptr;
	long ser_certificate_len = 0;

	try {
		// 1) Serialize server's key (g**b)
		mbio = BIO_new(BIO_s_mem());
		if (!mbio) {
			cerr << "[Thread " << this_thread::get_id() << "] STS_send_session_key: "
			<< "BIO_new failed" << endl;
			throw 0;
		}

		ret = PEM_write_bio_PUBKEY(mbio, my_dh_key);
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] STS_send_session_key: "
			<< "PEM_write_bio_PUBKEY returned " << ret << endl;
			throw 1;
		}

		ret_long = BIO_get_mem_data(mbio, &my_key_buf);
		if (ret_long <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] STS_send_session_key: "
			<< "BIO_get_mem_data returned " << ret_long << endl;
			throw 1;
		}
		my_key_len = (uint32_t)ret_long;
		my_key_buf = (char*)malloc(my_key_len);
		if (!my_key_buf) {
			cerr << "[Thread " << this_thread::get_id() << "] STS_send_session_key: "
			<< "malloc buffer for server's DH key failed" << endl;
			throw 1;
		}
		ret = BIO_read(mbio, my_key_buf, my_key_len);
		if (ret < 1) {
			cerr << "[Thread " << this_thread::get_id() << "] STS_send_session_key: "
			<< "BIO_read returned " << ret << endl;
			throw 2;
		}
		

		// 2) Prepare string < g**b, g**a > for signature
		// 2a) Serialize peer key
		ret = PEM_write_bio_PUBKEY(mbio, peer_key);
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] STS_send_session_key: "
			<< "PEM_write_bio_PUBKEY returned " << ret << endl;
			throw 2;
		}

		ret_long = BIO_get_mem_data(mbio, &peer_key_buf);
		if (ret_long <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] STS_send_session_key: "
			<< "BIO_get_mem_data returned " << ret_long << endl;
			throw 2;
		}
		peer_key_len = (uint32_t)ret_long;
		peer_key_buf = (char*)malloc(peer_key_len);
		if (!my_key_buf) {
			cerr << "[Thread " << this_thread::get_id() << "] STS_send_session_key: "
			<< "malloc buffer for client's DH key failed" << endl;
			throw 2;
		}
		ret = BIO_read(mbio, peer_key_buf, peer_key_len);
		if (ret < 1) {
			cerr << "[Thread " << this_thread::get_id() << "] STS_send_session_key: "
			<< "BIO_read returned " << ret << endl;
			throw 3;
		}

		// 2b) Concat my_key and peer_key
		size_t concat_keys_len = my_key_len + peer_key_len + 1;
		unsigned char* concat_keys = (unsigned char*)malloc(concat_keys_len);
		if (!concat_keys) {
			cerr << "[Thread " << this_thread::get_id() << "] STS_send_session_key: "
			<< "malloc concat_keys failed" << endl;
			throw 3;
		}
		memcpy(concat_keys, my_key_buf, my_key_len);
		memcpy(concat_keys + my_key_len, peer_key_buf, peer_key_len);
		concat_keys[concat_keys_len - 1] = '\0';
		// 2c) Sign concat keys and remove them
		unsigned int signature_len = 0;
		unsigned char* signature = sign_message(concat_keys, concat_keys_len, signature_len);

		secure_free(concat_keys, concat_keys_len);

		if (!signature) {
			cerr << "[Thread " << this_thread::get_id() << "] STS_send_session_key: "
			<< "sign_message failed" << endl;
			throw 3;
		}
		// 3) Encrypt signature and delete it
		ret = gcm_encrypt(signature, signature_len, iv, iv_len, shared_key, iv, iv_len, 
		                  encrypted_sign, encrypted_sign_len, tag, tag_len);
		
		secure_free(signature, signature_len);

		if (ret <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] STS_send_session_key: "
			<< "encrypt_message failed" << endl;
			throw 3;
		}
		// 4) Extract and serialize certificate
		certificate = get_server_certificate();
		if (!certificate) {
			cerr << "[Thread " << this_thread::get_id() << "] STS_send_session_key: "
			<< "get_server_certificate failed" << endl;
			throw 4;
		}
		ret = i2d_X509(certificate, &ser_certificate);
		if (ret <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] STS_send_session_key: "
			<< "i2d_X509 failed" << endl;
			throw 5;
		}
		ser_certificate_len = ret;
		
		// 5) SEND MESSAGES TO CLIENT
		// 5a) g**b
		ret = send_message(client_socket, (void*)my_key_buf, my_key_len);
		if (ret <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] STS_send_session_key: "
			<< "send_message g**b failed" << endl;
			throw 6;
		}
		// 5b) iv
		ret = send_message(client_socket, (void*)iv, iv_len);
		if (ret <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] STS_send_session_key: "
			<< "send_message iv failed" << endl;
			throw 6;
		}
		// 5c) encrypted signature
		ret = send_message(client_socket, (void*)encrypted_sign, encrypted_sign_len);
		if (ret <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] STS_send_session_key: "
			<< "send_message encrypted_signature" << endl;
			throw 6;
		}
		// 5d) tag
		ret = send_message(client_socket, (void*)tag, tag_len);
		if (ret <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] STS_send_session_key: "
			<< "send_message tag failed" << endl;
			throw 6;
		}
		// 5e) server certificate
		ret = send_message(client_socket, (void*)ser_certificate, ser_certificate_len);
		if (ret <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] STS_send_session_key: "
			<< "send_message server_certificate failed" << endl;
			throw 6;
		}

		
		
		//fflush(stdout);

	} catch (int e) {
		if (e >= 6) {
			OPENSSL_free(ser_certificate);
		}
		if (e >= 5) {
			X509_free(certificate);
		}
		if (e >= 4) {
			secure_free(encrypted_sign, encrypted_sign_len);
			free(tag);
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
	OPENSSL_free(ser_certificate);
	X509_free(certificate);
	secure_free(encrypted_sign, encrypted_sign_len);
	secure_free(peer_key_buf, peer_key_len);
	secure_free(my_key_buf, my_key_len);
	BIO_free(mbio);
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
int ServerThread::gcm_encrypt (unsigned char* plaintext, int plaintext_len,
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
int ServerThread::gcm_decrypt (unsigned char* ciphertext, int ciphertext_len,
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
 * Verify if a signature made by a client is correct
 * 
 * @param signature signature too verify
 * @param signature_len length of the signature
 * @param cleartext text that is supposed to be signed
 * @param cleartext_len length of cleartext
 * @param username username of the client that signed the cleartext
 * 
 * @return 1 on success, -1 if the verification process failes, -2 if the public key of the user isn't installed on the server
 */
int ServerThread::verify_client_signature (unsigned char* signature, size_t signature_len, 
                                           unsigned char* cleartext, size_t cleartext_len,
								           const string& username)
{
	EVP_PKEY* client_pubkey = nullptr;
	EVP_MD_CTX* ctx = nullptr;

	int ret;
	int return_value = -1;
	
	try {
		// 1) Get client's public key
		client_pubkey = get_client_public_key(username);
		if (!client_pubkey) {
			cerr << "[Thread " << this_thread::get_id() << "] verify_client_signature: "
			<< "client's public key is not installed" << endl;
			return_value = -1;
			throw 0;
		}

		// 2) Verify signature
		ctx = EVP_MD_CTX_new();
		if (!ctx) {
			cerr << "[Thread " << this_thread::get_id() << "] verify_client_signature: "
			<< "EVP_MD_CTX_new returned NULL" << endl;
			throw 1;
		}

		ret = EVP_VerifyInit(ctx, EVP_sha256());
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] verify_client_signature: "
			<< "EVP_VerifyInit returned " << ret << endl;
			throw 2;
		}

		ret = EVP_VerifyUpdate(ctx, cleartext, cleartext_len);
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] verify_client_signature: "
			<< "EVP_VerifyUpdate returned " << ret << endl;
			throw 2;
		}
		ret = EVP_VerifyFinal(ctx, signature, signature_len, client_pubkey);
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] verify_client_signature: "
			<< "EVP_VerifyFinal returned " << ret << endl;
			throw 2;
		}

	} catch (int e) {
		if (e >= 2) {
			EVP_MD_CTX_free(ctx);
		}
		if (e >= 1) {
			EVP_PKEY_free(client_pubkey);
		}
		return return_value;
	}

	return 1;
}

/**
 * Free the allocated memory, without leaving any trace of its content
 * 
 * @param addr address to the allocated memory
 * @param len size of allocated memory
 */
void ServerThread::secure_free (void* addr, size_t len) 
{
	#pragma optimize("", off);
		memset(addr, 0, len);
	#pragma optimize("", on);

	free(addr);
}

/**
 * Generated initialization vector for a symmetric cipher
 * 
 * @param cipher symmetric cipher
 * 
 * @return IV on success, NULL on failure
 */
unsigned char* ServerThread::generate_iv (EVP_CIPHER const* cipher, size_t& iv_len)
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

/**
 * Get specified user's public key, which should have been installed on the server
 * 
 * @param username identifier of the user
 * @return public key of the user on success, NULL on failure
 */
EVP_PKEY* ServerThread::get_client_public_key (const string& username)
{
	// Load client's public key:
	string filename = (string)"clients/" + username + ".pem";
	FILE* pubkey_file = fopen(filename.c_str(), "r");
	if (!pubkey_file) {
		cerr << "[Thread " << this_thread::get_id() << "] get_client_public_key: "
		<< "Cannot open " << filename << endl;
		return nullptr;
	}

	EVP_PKEY* prvkey = PEM_read_PUBKEY(pubkey_file, NULL, NULL, NULL);
	fclose(pubkey_file);
	if(!prvkey) { 
		cerr << "[Thread " << this_thread::get_id() << "] get_client_public_key: "
		<< "PEM_read_PUBKEY returned NULL" << endl; 
		return nullptr;
	}

	return prvkey;
}
