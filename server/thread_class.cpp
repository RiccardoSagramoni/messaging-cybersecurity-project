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

ServerThread::~ServerThread ()
{
	if (client_key != nullptr) {
		secure_free(client_key, client_key_len);
	}
}

const string ServerThread::filename_prvkey = "privkey.pem";
const string ServerThread::filename_certificate = "certificate.pem";

/**
 * Start the thread
 */
void ServerThread::run ()
{
	int ret;

	// 1) Authenticate client and negotiate session key
	client_key  = authenticate_and_negotiate_key(client_username, client_key_len);
	if(!client_key) {
		cerr << "[Thread " << this_thread::get_id() << "] run: "
			<< "authenticate_and_negotiate_key failed. "
			<< "Closing this thread and socket " << client_socket << endl;
		
		close(client_socket);
		
		return;
	}	
	
	cout << "[Thread " << this_thread::get_id() << "]: user " << client_username << " has entered the server" << endl;	

	// 2) Add current client to server
	if (!server->add_new_client(client_username, client_socket, client_key, client_key_len)) {
		cerr << "[Thread " << this_thread::get_id() << "] run: "
		<< "client " << client_username << " already logged." << endl
		<< "Closing this thread and socket " << client_socket << endl;

		close(client_socket);

		return;
	}

	// 3) Serve the client
	try {
			
		while (true) {
			unsigned char* msg = nullptr;
			size_t msg_len;

			// 3b) Wait for command and lock socket input
			ret = get_new_client_command(msg, msg_len);
			if (ret < 0) {
				continue;
			}
			else if (ret == 0) {
				execute_exit();
				return;
			}

			// Lock socket output
			if (!server->handle_socket_lock(client_username, true, 1)) {
				return;
			}

			// 3c) Execute received command
			ret = execute_client_command(msg, msg_len);
			free(msg);
			if (ret < 0) {
				server->handle_socket_lock(client_username, false, 2);
				execute_exit();
				return;
			}
			else if (ret == 0) { // executed exit
				return;
			}

			// 3d) Unlock socket (both input and output)
			if(!server->handle_socket_lock(client_username, false, 2)) {
				return;
			}

			this_thread::yield();
		}

	} catch (...) { // Handle unpredictable failure
		server->handle_socket_lock(client_username, false, 2);
		execute_exit();
		rethrow_exception(current_exception());
	}
}

/**
 * Generate public DH parameters for this application
 * 
 * @return DH parameters on success, NULL on failure
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

/**
 * Get server's certicate from file
 * 
 * @return server's certificate on success, NULL on failure 
 */
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
 * @return generated signature of given message on success, NULL on failure
 */
unsigned char* ServerThread::sign_message(const unsigned char* msg, const size_t msg_len, unsigned int& signature_len)
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
int ServerThread::send_error (const int socket, const uint8_t type, const unsigned char* key, const bool own_lock, const string& username)
{
	uint8_t msg[2] = {SERVER_ERR, type};
	
	if (!own_lock) {
		if (!server->handle_socket_lock(client_username, true, 1)) {
			return -1;
		}
	}
	
	int ret = send_plaintext(socket, msg, 2, key, username);

	if (!own_lock) {
		if (!server->handle_socket_lock(client_username, false, 1)) {
			return -1;
		}
	}

	return ret;
}

/**
 * Send a plaintext to the client. The plaintext is encrypted and authenticated with AES-gcm.
 * This functions sends three messages through the network:
 * 1) Initialization vector
 * 2) Ciphertext
 * 3) Tag
 * 
 * @param socket socket descriptor
 * @param msg message
 * @param msg_len message length
 * @param key shared key between client and server
 * 
 * @return 1 on success, -1 on failure
 */
int ServerThread::send_plaintext (const int socket, const unsigned char* msg, const size_t msg_len, const unsigned char* key, const string& username)
{
	int ret;

	unsigned char* actual_message = nullptr;
	unsigned char* iv = nullptr;
	size_t iv_len = 0;
	unsigned char* ciphertext = nullptr;
	size_t ciphertext_len = 0;
	unsigned char* tag = nullptr;
	size_t tag_len = 0;

	try {
		uint32_t counter = 0;
		ret = server->get_server_counter(username, counter);
		if (ret != 1) {
			throw -1;
		}

		// Check integer overflow
		if (msg_len > numeric_limits<size_t>::max() - sizeof(counter)) {
			throw -1;
		}
		size_t actual_message_len = sizeof(counter) + msg_len;

		// Add counter against replay attack
		actual_message = (unsigned char*)malloc(actual_message_len);
		if (!actual_message) {
			throw -1;
		}
		counter = htonl(counter);
		memcpy(actual_message, &counter, sizeof(counter));
		memcpy(actual_message + sizeof(counter), msg, msg_len);
		
		// 1) Generate IV
		iv = generate_iv(get_authenticated_encryption_cipher(), iv_len);
		if (!iv) {
			throw 0;
		}

		// 2) Encrypt message
		ret = gcm_encrypt(actual_message, actual_message_len, iv, iv_len, key, iv, iv_len, 
		                  ciphertext, ciphertext_len, tag, tag_len);
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
		if (e >= 0) {
			free(actual_message);
		}
		return -1;
	}

	free(ciphertext);
	free(tag);
	free(iv);
	free(actual_message);

	return 1;
}

/**
 * Return the plaintext send from the client. 
 * The ciphertext is supposed to have been encrypted and authenticated with AES-gcm.
 * 
 * This functions receives three messages from the client:
 * 1) Initialization vector
 * 2) Ciphertext
 * 3) Tag
 * 
 * @param socket id of the socket
 * @param msg on success it will point to the decrypted text
 * @param msg_len on success it will contain the length of the decrypted message
 * @key symmetric shared key used for the encryption
 * 
 * @return 1 on success, 0 if client closes the socket, -1 on failure 
 */
int ServerThread::receive_plaintext (const int socket, unsigned char*& msg, size_t& msg_len, const unsigned char* key, const string& username)
{
	long ret_long = -1;
	
	unsigned char* iv = nullptr;
	unsigned char* ciphertext = nullptr;
	unsigned char* tag = nullptr;

	unsigned char* msg_with_counter;
	size_t msg_with_counter_len;

	try {
		// 1) Receive iv
		ret_long = receive_message(socket, (void**)&iv);
		if (ret_long <= 0) {
			throw 0;
		}
		size_t iv_len = ret_long;

		// 2) Receive ciphertext
		ret_long = receive_message(socket, (void**)&ciphertext);
		if (ret_long <= 0) {
			throw 1;
		}
		size_t ciphertext_len = ret_long;

		// 3) Receive tag
		ret_long = receive_message(socket, (void**)&tag);
		if (ret_long <= 0) {
			throw 2;
		}

		// 4) Decrypt message
		int ret = gcm_decrypt(ciphertext, ciphertext_len, iv, iv_len, tag, key, 
		                      iv, iv_len, msg_with_counter, msg_with_counter_len);
		if (ret < 0 || msg_with_counter_len < sizeof(uint32_t) + 1) {
			throw 3;
		}

		// 5) Check counter against replay attack
		uint32_t received_counter;
		memcpy(&received_counter, msg_with_counter, sizeof(received_counter));
		received_counter = ntohl(received_counter);

		if (server->check_client_counter(username, received_counter) != 1) {
			throw 4;
		}

		// 6) Copy type + payload to msg
		msg_len = msg_with_counter_len - sizeof(received_counter);
		msg = (unsigned char*)malloc(msg_len);
		if (!msg) {
			throw 4;
		}
		memcpy(msg, msg_with_counter + sizeof(received_counter), msg_len);

	} catch (int e) {
		if (e >= 4) {
			free(msg_with_counter);
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
		return (ret_long == 0) ? 0 : -1; // If ret_long is 0, then socket has been closed
	}

	free(msg_with_counter);
	free(tag);
	free(ciphertext);
	free(iv);

	return 1;
}

/**
 * Execute the exit command by removing all data relative to the client
 * 
 * @return 1 on success, -1 if client is not present on the server 
 */
int ServerThread::execute_exit ()
{	
	return server->remove_client(client_username);
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

	key_len = session_key_len;
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
		if (e >= 2) {
			EVP_PKEY_CTX_free(dh_gen_ctx);
		}
		if (e >= 1) {
			EVP_PKEY_free(dh_params);
		}
		return nullptr;
	}

	EVP_PKEY_CTX_free(dh_gen_ctx);
	EVP_PKEY_free(dh_params);
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

	unsigned char* iv = nullptr;
	unsigned char* ciphertext = nullptr;
	unsigned char* tag = nullptr;
	unsigned char* client_signature = nullptr;
	size_t client_signature_len = 0;

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
		// 2a) Serialize server key
		my_key_buf = (unsigned char*)serialize_evp_pkey(my_dh_key, my_key_len);
		if (!my_key_buf) {
			throw 3;
		}
		// 2b) Serialize peer key
		peer_key_buf = (unsigned char*)serialize_evp_pkey(peer_key, peer_key_len);
		if (!peer_key_buf) {
			throw 5;
		}

		// Check integer overflow
		if (peer_key_len > numeric_limits<size_t>::max() -1 ||
			my_key_len > numeric_limits<size_t>::max() - 1 - peer_key_len)
		{
			throw 6;
		}
		concat_keys_len = my_key_len + peer_key_len + 1;
		
		// 2c) Concat peer_key and my_key
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
	secure_free(concat_keys, concat_keys_len);
	secure_free(peer_key_buf, peer_key_len);
	secure_free(my_key_buf, my_key_len);
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

	// DIRECTORY TRAVERSAL: check if the generated filename 
	// could generate a directory traversal attack
	int ret = check_directory_traversal(file_name.c_str());
	if (ret != 1) {
		cerr << "[Thread " << this_thread::get_id() << "] check_username_validity: "
		<< "check_directory_traversal returned " << ret << endl;
		return false;
	}

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
 * Check if a filename is directory traversal proof
 * 
 * @param file_name name to check
 * @return 1 if the file name is correct, 0 if it's incorrect, -1 if any other error occurs 
 */
int ServerThread::check_directory_traversal (const char* file_name)
{
	char* canon_file_name = realpath(file_name, NULL);
	if (!canon_file_name) {
		cerr << "[Thread " << this_thread::get_id() << "] check_directory_traversal: "
		<< "realpath canon_file_name failed" << endl;
		return -1;
	}
	char* server_directory = realpath(".", NULL);
	if (!server_directory) {
		cerr << "[Thread " << this_thread::get_id() << "] check_directory_traversal: "
		<< "realpath server_directory failed" << endl;
		return -1;
	}

	bool ret = (strncmp(canon_file_name, server_directory, strlen(server_directory)) == 0);

	free(canon_file_name);
	free(server_directory);

	return ret ? 1 : 0;
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

	// Declare variable for DH key serialization and encryption
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
		// Prepare string < g**b, g**a > for signature
		// 1) Serialize server's key (g**b)
		size_t temp_my_key_len;
		my_key_buf = serialize_evp_pkey(my_dh_key, temp_my_key_len);
		if (!my_key_buf || temp_my_key_len > numeric_limits<uint32_t>::max()) {
			cerr << "[Thread " << this_thread::get_id() << "] STS_send_session_key: "
			<< "serialize_evp_pkey my_dh_key failed" << endl;
			throw 0;
		}
		my_key_len = temp_my_key_len;

		
		// 2) Serialize peer key
		size_t temp_peer_key_len;
		peer_key_buf = serialize_evp_pkey(peer_key, temp_peer_key_len);
		if (!my_key_buf || temp_peer_key_len > numeric_limits<uint32_t>::max()) {
			cerr << "[Thread " << this_thread::get_id() << "] STS_send_session_key: "
			<< "serialize_evp_pkey peer_key failed" << endl;
			throw 1;
		}
		peer_key_len = temp_peer_key_len;

		// Check integer overflow.
		// peer_key_len's length is fixed to 4 bytes (uint32_t), but according to 
		// C++11 standard size_t must be at least 2 bytes (usually is 4-8 bytes),
		// so we have to check if peer_key_len can "downgrade"
		if (peer_key_len > numeric_limits<size_t>::max() - 1 || 
			my_key_len > numeric_limits<size_t>::max() - 1 - (size_t)peer_key_len) 
		{
			throw 3;
		}
		size_t concat_keys_len = my_key_len + peer_key_len + 1;

		// 2b) Concat my_key and peer_key
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
			secure_free(tag, tag_len);
		}
		if (e >= 3) {
			secure_free(peer_key_buf, peer_key_len);
		}
		if (e >= 1) {
			secure_free(my_key_buf, my_key_len);
		}
		return -1;
	}

	// Clean stuff
	OPENSSL_free(ser_certificate);
	X509_free(certificate);
	secure_free(encrypted_sign, encrypted_sign_len);
	secure_free(tag, tag_len);
	secure_free(peer_key_buf, peer_key_len);
	secure_free(my_key_buf, my_key_len);

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
int ServerThread::gcm_encrypt (const unsigned char* plaintext, const int plaintext_len,
							   const unsigned char* aad, const int aad_len, 
							   const unsigned char* key,
							   const unsigned char* iv, const int iv_len, 
							   unsigned char*& ciphertext, size_t& ciphertext_len,
							   unsigned char*& tag, size_t& tag_len)
{
	int ret;

	EVP_CIPHER_CTX* ctx;
	
	try {
		// Check integer overflow for malloc size
		int block_size = EVP_CIPHER_block_size(get_authenticated_encryption_cipher());
		if (plaintext_len < 0 || block_size < 0 ||
			plaintext_len > numeric_limits<int>::max() - block_size) {
			throw 0;
		}

		// Allocate ciphertext
		ciphertext = (unsigned char*)malloc(plaintext_len + block_size);
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

		if (outlen < 0 || outlen > numeric_limits<size_t>::max()) {
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

		if (outlen < 0 || outlen > numeric_limits<size_t>::max() ||
			ciphertext_len > numeric_limits<size_t>::max() - outlen) 
		{
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
int ServerThread::gcm_decrypt (const unsigned char* ciphertext, const int ciphertext_len,
                               const unsigned char* aad, const int aad_len,
                               const unsigned char* tag,
                               const unsigned char* key,
                               const unsigned char* iv, const int iv_len,
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

		if (outlen < 0 || outlen > numeric_limits<size_t>::max()) {
			throw 2;
		}
		plaintext_len = outlen;

		// Set expected tag value
		ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void*)tag);
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

		if (outlen < 0 || outlen > numeric_limits<size_t>::max() ||
			plaintext_len > numeric_limits<size_t>::max() - outlen) {
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
int ServerThread::verify_client_signature (const unsigned char* signature, const size_t signature_len, 
                                           const unsigned char* cleartext, const size_t cleartext_len,
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
			return_value = -2;
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

	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(client_pubkey);

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

	// DIRECTORY TRAVERSAL: check if the generated filename 
	// could generate a directory traversal attack
	int ret = check_directory_traversal(filename.c_str());
	if (ret != 1) {
		cerr << "[Thread " << this_thread::get_id() << "] get_client_public_key: "
		<< "check_directory_traversal returned " << ret << endl;
		return nullptr;
	}

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

/**
 * Serialize an EVP_PKEY structure
 * 
 * @param key key to serialize
 * @param key_len on success, length of serialized key
 * 
 * @return serialized key on success, NULL on failure
 */
char* ServerThread::serialize_evp_pkey (EVP_PKEY* key, size_t& key_len)
{
	int ret;
	long ret_long;

	BIO* mbio = nullptr;
	char* key_buf = nullptr;

	try {
		// 1) Allocate BIO for serialization
		mbio = BIO_new(BIO_s_mem());
		if (!mbio) {
			cerr << "[Thread " << this_thread::get_id() << "] serialize_evp_pkey: "
			<< "BIO_new failed" << endl;
			throw 0;
		}

		// 2) Serialize key
		ret = PEM_write_bio_PUBKEY(mbio, key);
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] serialize_evp_pkey: "
			<< "PEM_write_bio_PUBKEY returned " << ret << endl;
			throw 1;
		}

		// 3) Get serialized length
		ret_long = BIO_get_mem_data(mbio, &key_buf);
		if (ret_long <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] serialize_evp_pkey: "
			<< "BIO_get_mem_data returned " << ret_long << endl;
			throw 1;
		}
		key_len = (uint32_t)ret_long;
		
		// 4) Allocate memory for serialized key
		key_buf = (char*)malloc(key_len);
		if (!key_buf) {
			cerr << "[Thread " << this_thread::get_id() << "] serialize_evp_pkey: "
			<< "malloc buffer for serialized key failed" << endl;
			throw 1;
		}

		// 5) Extract serialized key
		ret = BIO_read(mbio, key_buf, key_len);
		if (ret < 1) {
			cerr << "[Thread " << this_thread::get_id() << "] serialize_evp_pkey: "
			<< "BIO_read returned " << ret << endl;
			throw 2;
		}
	
	} catch (int e) {
		if (e >= 2) {
			secure_free(key_buf, key_len);
		}
		if (e >= 1) {
			BIO_free(mbio);
		}
		return nullptr;
	}

	BIO_free(mbio);

	return key_buf;
}



/**
 * Receive a new message from the client and lock the input stream of the socket
 * 
 * @param msg on success it will point to the received message
 * 
 * @return 1 on success, 0 if the client closes the socket, -1 if any other error occurs
 */
int ServerThread::get_new_client_command (unsigned char*& msg, size_t& msg_len)
{
	int ret = -1;
	
	try {
		// 1) Get lock for input socket
		if (!server->handle_socket_lock(client_username, true, 0)) {
			throw 0;
		}
		
		// 2) Receive message from client
		ret = receive_plaintext(client_socket, msg, msg_len, client_key, client_username);
		if (ret != 1) {
			throw 1;
		}
	
	} catch (int e) {
		if (e >= 1) {
			server->handle_socket_lock(client_username, false, 0);
		}
		return (ret == 0) ? 0 : -1; // If ret is 0, then socket has been closed
	}

	return 1;
}

/**
 * Parse received message from client and execute its request
 * 
 * @param msg received message
 * @return 1 on success, 0 if the server executed the exit, -1 on failure
 */
int ServerThread::execute_client_command (const unsigned char* msg, const size_t msg_len) 
{
	uint8_t request_type = get_request_type(msg);
	
	int ret = 0;

	if (request_type == TYPE_SHOW) {
		return execute_show();
	}
	else if (request_type == TYPE_TALK) {
		ret = execute_talk(msg, msg_len);
		return (ret < 0) ? -1 : 1;
	}
	else if (request_type == TYPE_EXIT) {
		server->handle_socket_lock(client_username, false, 2);
		ret = execute_exit();
		return (ret != 1) ? -1 : 0;
	}
	else if (request_type == ACCEPT_TALK || request_type == REFUSE_TALK) {
		ret = execute_accept_talk(msg, msg_len, (request_type == ACCEPT_TALK));
		if (ret < 0) {
			send_error(client_socket, SERVER_ERR, client_key, true, client_username);
			return -1;
		}
		return 1;
	}
	else { // Error
		send_error(client_socket, ERR_WRONG_TYPE, client_key, true, client_username);
		return -1;
	}
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

/**
 * Execute command show: send a serialized list with all the username 
 * of available (online) clients
 * 
 * @return 1 on success, -1 on failure 
 */
int ServerThread::execute_show ()
{
	// 1) Get list of client logged to the server
	list<string> l = server->get_available_clients_list();

	// 2) Serialize list
	// 2a) Calculate necessary space
	size_t message_len = 1;
	for (auto s : l) {
		// Check overflow
		if (s.length() > numeric_limits<size_t>::max() - 1 - sizeof(uint32_t) ||
			message_len > numeric_limits<size_t>::max() - 1 - sizeof(uint32_t) - s.length())
		{
			return -1;
		}

		message_len += (sizeof(uint32_t) + s.length() + 1);
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
		uint32_t string_size = s.length() + 1; // Possible Int overflows have been already checked!
		string_size = htonl(string_size);
		memcpy(message + pos, &string_size, sizeof(string_size));
		pos += sizeof(string_size);

		// b) Insert username
		memcpy(message + pos, s.c_str(), s.length() + 1);
		pos += s.length() + 1;
	}

	// 3) Send message
	int ret = send_plaintext(client_socket, (unsigned char*)message, message_len, client_key, client_username);
	free(message);
	if (ret < 0) {
		return -1;
	}

	return 1;
}

/**
 * Starts a talk between two clients. 
 * It will send an error message in case of recoverable errors
 * 
 * @param msg received message (contains the name of the second user)
 * @param msg_len message length
 * 
 * @return 1 on success, 0 if error is recoverable (e.g. wrong message format), -1 otherwise
 */
int ServerThread::execute_talk (const unsigned char* msg, const size_t msg_len)
{
	int ret;
	int return_value = 0; // 0 if error is recoverable, -1 otherwise

	string peer_username;
	unsigned char* peer_key;
	size_t peer_key_len;
	
	try {
		// 1) Check is msg is valid (is a null terminated string)
		if (msg[msg_len - 1] != '\0' || msg_len <= sizeof(uint32_t) + 1) {
			send_error(client_socket, SERVER_ERR, client_key, false, client_username);
			throw 0;
		}

		// Deserialize length of username
		uint32_t peer_username_len = ntohl(*(uint32_t*)(msg + 1));

		if (peer_username_len > numeric_limits<uint32_t>::max() - 1 - sizeof(uint32_t) ||
			msg_len != sizeof(uint32_t) + 1 + peer_username_len) 
		{
			send_error(client_socket, SERVER_ERR, client_key, false, client_username);
			throw 0;
		}

		// Extract peer's username and convert it to string
		char* peer_username_c = (char*)(msg + 1 + sizeof(uint32_t));
		peer_username = peer_username_c;
		

		// 2) Make client user unavailable
		ret = server->set_available_status(client_username, false);
		if (ret != 1) {
			return_value = -1;
			throw 0;
		}

		// 3) Prepare for talking
		ret = server->prepare_for_talking(peer_username, peer_key, peer_key_len);
		if (ret < 0) {
			if (ret == -1) {
				return_value = -1;
			}
			else {
				send_error(client_socket, SERVER_ERR, client_key, true, client_username);
			}

			throw 3;
		}
		int peer_socket = ret;

		// 4) Send request to talk
		ret = send_request_to_talk(peer_socket, client_username, peer_username, peer_key);
		if (ret < 0) {
			throw 4;
		}

		server->handle_socket_lock(peer_username, false, 1); // Unlock socket output stream

		// 5) Wait for peer answer
		ret = server->wait_start_talk(peer_username, client_username);
		if (ret < 0) {
			send_error(client_socket, SERVER_ERR, client_key, true, client_username);
			server->notify_end_talk(peer_username);
			throw 4;
		}

		// Lock peer's socket both for input and output
		if(!server->handle_socket_lock(peer_username, true, 2)) {
			send_error(client_socket, SERVER_ERR, client_key, true, client_username);
			throw 5;
		}

		// 6) Send to both clients the public key of the other client
		ret = send_public_key_for_talk(client_username, client_socket, client_key, peer_username);
		if (ret != 1) {
			return_value = -1;
			throw 7;
		}

		ret = send_public_key_for_talk(peer_username, peer_socket, peer_key, client_username);
		if (ret != 1) {
			return_value = -1;
			throw 7;
		}

		// 7) Execute DH protocol between clients
		ret = negotiate_key_between_clients(peer_username, peer_socket, peer_key);
		if (ret != 1) {
			send_error(client_socket, SERVER_ERR, client_key, true, client_username);
			throw 7;
		}

		// 8) Start talking
		ret = talk_between_clients(peer_username, peer_socket, peer_key);
		if (ret != 1) {
			return_value = -1;
			throw 7;
		}

	} catch (int e) {
		if (e >= 7) {
			server->handle_socket_lock(peer_username, false, 2);
		}
		if (e >= 5) {
			server->set_available_status(peer_username, true);
		}
		if (e >= 4) {
			secure_free(peer_key, peer_key_len);
		}
		if (e >= 1) {
			server->set_available_status(client_username, true);
		}

		return return_value;
	}
	
	server->handle_socket_lock(peer_username, false, 2);
	server->set_available_status(peer_username, true);
	secure_free(peer_key, peer_key_len);
	server->set_available_status(client_username, true);

	return 1;
}

/**
 * Send a request to talk
 * 
 * @param socket descriptor of socket related to the receiving client.
 * @param from_user username who sent the request
 * @param key symmetric key related to the receiving client
 * 
 * @return 1 on success, -1 on failure 
 */
int ServerThread::send_request_to_talk (const int socket, const string& from_user, const string& to_user, const unsigned char* key)
{
	int ret;
	
	if (from_user.length() > numeric_limits<size_t>::max() - 1 - sizeof(uint32_t) - 1) {
		cerr << "[Thread " << this_thread::get_id() << "] send_request_to_talk: "
		<<  "integer overflow" << endl;
		return -1;
	}

	// Message: SERVER_REQUEST_TO_TALK (1) | username_len (4) | username (?)
	size_t msg_len = 1 + sizeof(uint32_t) + from_user.length() + 1;
	unsigned char* msg = (unsigned char*)malloc(msg_len);
	if (!msg) {
		cerr << "[Thread " << this_thread::get_id() << "] send_request_to_talk: "
		<<  "malloc message failed" << endl;
		return -1;
	}

	msg[0] = SERVER_REQUEST_TO_TALK;
	uint32_t username_len = htonl((uint32_t)(from_user.length() + 1));
	memcpy(msg + 1, &username_len, sizeof(username_len));
	strcpy((char*)(msg + 1 + sizeof(username_len)), from_user.c_str());

	ret = send_plaintext(socket, msg, msg_len, key, to_user);
	free(msg);
	if (ret < 0) {
		cerr << "[Thread " << this_thread::get_id() << "] send_request_to_talk: "
		<< "send_plaintext failed" << endl;
		return -1;
	}

	return 1;
}

/**
 * Send to a client the public key of the other client, in order to negotiate a
 * session key client-to-client for the talk
 * 
 * @param username user who receives the message
 * @param socket socket through we send the message
 * @param key sessione key of receiving client
 * @param peer_username user who owns the public key
 * 
 * @return 1 on success, -1 on failure
 */
int ServerThread::send_public_key_for_talk (const string& username, const int socket, 
		const unsigned char* key, const string& peer_username)
{
	int ret;
	
	EVP_PKEY* peer_pubkey = nullptr;
	unsigned char* ser_peer_pubkey = nullptr;
	unsigned char* msg = nullptr;
	size_t msg_len = 0;

	try {
		// 1) Get public key of the other client
		peer_pubkey = get_client_public_key(peer_username);
		if (!peer_pubkey) {
			throw 0;
		}
		
		// 2) Serialize public key
		size_t ser_peer_pubkey_len = 0;
		ser_peer_pubkey = (unsigned char*)serialize_evp_pkey(peer_pubkey, ser_peer_pubkey_len);
		if (!ser_peer_pubkey) {
			throw 1;
		}

		// 3) Check integer overflow
		if (ser_peer_pubkey_len > numeric_limits<size_t>::max() - 1) {
			throw 2;
		}
		msg_len = 1 + ser_peer_pubkey_len;

		// 4) Prepare message
		msg = (unsigned char*)malloc(msg_len);
		if (!msg) {
			throw 2;
		}

		msg[0] = SERVER_OK;
		memcpy(msg + 1, ser_peer_pubkey, ser_peer_pubkey_len);

	} catch (int e) {
		if (e >= 2) {
			free(ser_peer_pubkey);
		}
		if (e >= 1) {
			EVP_PKEY_free(peer_pubkey);
		}
		return -1;
	}

	ret = send_plaintext(socket, msg, msg_len, key, username);

	free(msg);
	free(ser_peer_pubkey);
	EVP_PKEY_free(peer_pubkey);

	return ret;
}

/**
 * Start the negotiation protocol of the session key for a client-to-client talk
 * 
 * @param peer_socket socket of client B
 * @param peer_key key of client B
 * 
 * @return 1 on success, -1 on failure 
 */
int ServerThread::negotiate_key_between_clients (const string& peer_username, const int peer_socket, const unsigned char* peer_key)
{
	int ret;

	// 1) Receive g**a from client A (client_...)
	unsigned char* key_ga;
	size_t key_ga_len;
	ret = receive_plaintext(client_socket, key_ga, key_ga_len, client_key, client_username);
	if (ret != 1) {
		cerr << "[Thread " << this_thread::get_id() << "] negotiate_key_between_clients: "
		<< "receive_plaintext g**a from client A failed" << endl;
		return -1;
	}

	// 2) Send g**a to client B (peer_...)
	ret = send_plaintext(peer_socket, key_ga, key_ga_len, peer_key, peer_username);
	secure_free(key_ga, key_ga_len);
	if (ret != 1) {
		cerr << "[Thread " << this_thread::get_id() << "] negotiate_key_between_clients: "
		<< "send_plaintext g**a to client B failed" << endl;
		return -1;
	}

	// 3) Receive g**b + encrypted sign of <g**b, g**a> from client B
	unsigned char* key_gb;
	size_t key_gb_len;
	ret = receive_plaintext(peer_socket, key_gb, key_gb_len, peer_key, peer_username);
	if (ret != 1) {
		cerr << "[Thread " << this_thread::get_id() << "] negotiate_key_between_clients: "
		<< "receive_plaintext g**b from client B failed" << endl;
		return -1;
	}

	// 4) Send g**b + encrypted sign of <g**b, g**a> to client A
	ret = send_plaintext(client_socket, key_gb, key_gb_len, client_key, client_username);
	secure_free(key_gb, key_gb_len);
	if (ret != 1) {
		cerr << "[Thread " << this_thread::get_id() << "] negotiate_key_between_clients: "
		<< "send_plaintext g**b  + encrypted sign of <g**b, g**a> to client A failed" << endl;
		return -1;
	}

	// 5) Receive encrypted sign of <g**a, g**b> from client A
	unsigned char* final_sign;
	size_t final_sign_len;
	ret = receive_plaintext(client_socket, final_sign, final_sign_len, client_key, client_username);
	if (ret != 1) {
		cerr << "[Thread " << this_thread::get_id() << "] negotiate_key_between_clients: "
		<< "receive_plaintext encrypted sign of <g**a, g**b> from client B failed" << endl;
		return -1;
	}

	// 6) Send encrypted sign of <g**a, g**b> 
	ret = send_plaintext(peer_socket, final_sign, final_sign_len, peer_key, peer_username);
	secure_free(final_sign, final_sign_len);
	if (ret != 1) {
		cerr << "[Thread " << this_thread::get_id() << "] negotiate_key_between_clients: "
		<< "send_plaintext encrypted sign of <g**a, g**b>  from client B failed" << endl;
		return -1;
	}

	return 1;
}
/**
 * Start the talk between client A and B. 
 * Client A's data are already member variable of this thread
 * 
 * @param peer_username username of client B
 * @param peer_socket socket of client B
 * @param peer_key key of client B
 * 
 * @return 1 on success, 0 if client_socket has been closed, -1 on failure 
 */
int ServerThread::talk_between_clients (const string& peer_username, const int peer_socket, const unsigned char* peer_key)
{
	atomic<int> return_value_child(1);
	atomic<int> return_value_father(1);

	// Create new thread for communication B->A
	thread child(&ServerThread::talk, this, peer_username, peer_socket, peer_key, client_username, client_socket, client_key, &return_value_child);

	talk(client_username, client_socket, client_key, peer_username, peer_socket, peer_key, &return_value_father);

	child.join();

	// Pass the return value to the main thread of second client
	server->set_talk_exit_status(peer_username, return_value_child.load());
	server->notify_end_talk(peer_username);

	return return_value_father.load();
}

/**
 * Execute the protocol for talking between clients.
 * This function handle only one direction of the message flow.
 * 
 * @param src_socket id of the socket by which this function receives messages 
 * @param src_key key used by source client
 * @param dest_socket id of the socket by which this function sends messages
 * @param dest_key key used by destination client
 * 
 * @param return_value it will contain 1 if the talk has ended correctly, 
 * 0 if a socket has been closed, -1 if any other error occurs
 */
void ServerThread::talk (const string& src_username, const int src_socket, const unsigned char* src_key, const string& dest_username, const int dest_socket, const unsigned char* dest_key, atomic<int>* return_value)
{
	int ret;
	unsigned char* msg;
	size_t msg_len;
	
	while (true) {
		// 1) Receive from source
		ret = receive_plaintext(src_socket, msg, msg_len, src_key, src_username);
		if (ret != 1) {
			// Shutdown the faulty connection
			shutdown(src_socket, SHUT_RDWR);

			// Send closing message to dest
			unsigned char closing_msg[1]= {SERVER_END_TALK};
			send_plaintext(dest_socket, closing_msg, 1, dest_key, dest_username);

			cerr << "[Thread " << this_thread::get_id() << "] talk: "
			<< "receive_plaintext from source failed" << endl;

			return_value->store(ret);
			return;
		}

		// 3) Check type of message
		uint8_t* type_ptr = (uint8_t*)msg;
		if (*type_ptr != TALKING) {
			// Send closing message to dest
			unsigned char closing_msg[1]= {SERVER_END_TALK};
			send_plaintext(dest_socket, closing_msg, 1, dest_key, dest_username);

			if (*type_ptr == END_TALK) {
				return_value->store(1);
				cerr << "[Thread " << this_thread::get_id() << "] talk: "
				<< "closing talk (1)" << endl;
			}
			else {
				return_value->store(-1);
				cerr << "[Thread " << this_thread::get_id() << "] talk: "
				<< "received wrong message type" << endl;
			}

			free(msg);
			
			return;
		}

		*type_ptr = SERVER_OK;

		// 4) Send to destination
		ret = send_plaintext(dest_socket, msg, msg_len, dest_key, dest_username);
		free(msg);
		if (ret != 1) {
			// Shutdown the faulty connection
			shutdown(dest_socket, SHUT_RDWR);

			cerr << "[Thread " << this_thread::get_id() << "] talk: "
			<< "send plaintext to destination failed" << endl;

			return_value->store(ret);
			return;
		}
	}
}
/*
A->S1 chiudi
S1->B chiudi
S1 set closing state
B->S2 chiudi
*/

/**
 * Accept or refuse a request to talk
 * 
 * @param msg received message (contains the username of who sent the request)
 * @param msg_len message length
 * @param accept true if the request has been accepted, false otherwise
 * 
 * @return 1 on success, -1 failure 
 */
int ServerThread::execute_accept_talk (const unsigned char* msg, const size_t msg_len, const bool accept)
{
	string username = "";
	
	if (accept) {
		if (msg_len <= 1 + sizeof(uint32_t)) {
			return -1;
		}

		uint32_t len;
		memcpy(&len, msg + 1, sizeof(len));
		len = ntohl(len);

		if (len > numeric_limits<size_t>::max() ||
			(size_t)len > numeric_limits<size_t>::max() - 1 - sizeof(uint32_t) || 
			msg_len < 1 + sizeof(len) + (size_t)len) 
		{
			return -1;
		}

		username = (char*)(msg + 1 + sizeof(len));
	}

	int ret = server->notify_start_talk(client_username, username, accept);
	if (ret < 0) {
		return -1;
	}

	if (accept) {
		// Release lock so that the thread which sent the "request to talk"
		// can take control on this thread's socket
		server->handle_socket_lock(client_username, false, 2);
		ret = server->wait_end_talk(client_username);
		if (ret < 0) {
			return -1;
		}
		server->handle_socket_lock(client_username, true, 2);
	}

	return 1;
}
