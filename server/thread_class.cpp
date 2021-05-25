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
EVP_PKEY* ServerThread::get_private_key ()
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
		prvkey = get_private_key();
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
 * Start the thread
 */
void ServerThread::run()
{
	int ret;

	// -) Authentication btw c/s and negotiate session key
	string username;
	size_t key_len = 0;
	unsigned char* key = authenticate_and_negotiate_key(username, key_len);
	if(!key) {
		// TODO
		close(client_socket);
		return;
	}	

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
	if (ret < 0 || ret < sizeof(len)) { // Received data too short
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
// 1) Receive clients username and g**a
	EVP_PKEY* peer_key = nullptr;
	ret = receive_hello_message(peer_key, username);
	if (ret < 0) return nullptr;

	// Check if username is valid
	if(!check_username_validity(username)) {
		cerr << "Thread " << this_thread::get_id() 
		     << " authenticate_and_negotiate_key failed: username doesn't exist" 
		     << endl;
		return nullptr;
	}

// 2) Generate random b and calculate g**b (Diffie-Helmann)
	EVP_PKEY* my_dh_key = generate_key_dh();
	if (my_dh_key) return nullptr;

// 3) Derive shared secret k and hash it
	size_t session_key_len = EVP_CIPHER_key_length(get_symmetric_cipher());
	unsigned char* session_key = derive_session_key(my_dh_key, peer_key, session_key_len);
	if (!session_key) return nullptr;

// 4) Send g**b || encrypted_k{sign of g**b,g**a} || server's certificate
	// TODO HERE!


// 5) Recevive encrypted_k{encrypted_client{g**a,g**b}}

// 6) Check validity
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
		free(temp_dh_params);
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
			free(dh_params);
		}

		return nullptr;
	}

	free(dh_params);
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

/**
 * Get symmetric cipher used in this application.
 * 
 * @return structure which describes chosen cipher
 */
const EVP_CIPHER* ServerThread::get_symmetric_cipher ()
{
	return EVP_aes_128_cbc();
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
int ServerThread::receive_hello_message (EVP_PKEY*& peer_key, string& username)
{
	int ret_int;
	long ret_long;

	// Get the username
	char* username_c = nullptr;
	ret_long = receive_message(client_socket, (void**)&username_c);
	if (ret_long <= 0) {
		return -1;
	}
	size_t username_len = ret_long;
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
 * 
 * @return 1 on success, -1 on failure
 */
int ServerThread::send_session_key_STS (unsigned char* shared_key, size_t shared_key_len, EVP_PKEY* my_dh_key, EVP_PKEY* peer_key)
{
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

	// Declare variables for certificates
	X509* certificate = nullptr;
	unsigned char* ser_certificate = nullptr;
	size_t ser_certificate_len = 0;

	try {
		// Serialize server's key (g**b)
		mbio = BIO_new(BIO_s_mem());
		if (!mbio) {
			// TODO cerr
			throw 0;
		}

		ret = PEM_write_bio_PUBKEY(mbio, my_dh_key);
		if (ret != 1) {
			// TODO cerr
			throw 1;
		}

		ret_long = BIO_get_mem_data(mbio, &my_key_buf);
		if (ret_long <= 0) {
			throw 1;
		}

		my_key_len = (uint32_t)ret_long;


		// -) Prepare string < g**b, g**a > for signature

		// Serialize peer key
		ret = PEM_write_bio_PUBKEY(mbio, peer_key);
		if (ret != 0) {
			throw 2;
		}

		ret_long = BIO_get_mem_data(mbio, &peer_key_buf);
		if (ret_long <= 0) {
			throw 2;
		}
		peer_key_len = (uint32_t)ret_long;

		// Concat my_key and peer_key
		size_t concat_keys_len = my_key_len + peer_key_len + 1;
		unsigned char* concat_keys = (unsigned char*)malloc(concat_keys_len);
		if (!concat_keys) {
			throw 3;
		}

		memcpy(concat_keys, my_key_buf, my_key_len);
		memcpy(concat_keys + my_key_len, peer_key_buf, peer_key_len);
		concat_keys[concat_keys_len - 1] = '\0';
		
		// Sign concat keys and remove them
		unsigned int signature_len = 0;
		unsigned char* signature = sign_message(concat_keys, concat_keys_len, signature_len);

		#pragma optimize("", off)
			memset(concat_keys, 0, concat_keys_len);
		#pragma optmize("", on)
		free(concat_keys);

		if (!signature) {
			throw 3;
		}

		// Encrypt signature and delete it
		encrypted_sign = encrypt_message(signature, signature_len, shared_key, shared_key_len, encrypted_sign_len);

		free(signature);
		#pragma optimize("", off)
			memset(signature, 0, signature_len);
		#pragma optmize("", on)

		if (!encrypted_sign) {
			throw 3;
		}

		// Extract and serialize certificate
		certificate = get_server_certificate();
		if (!certificate) {
			throw 4;
		}
		ret = i2d_X509(certificate, &ser_certificate);
		if (ret <= 0) {
			throw 5;
		}
		ser_certificate_len = ret;

		// SEND MESSAGES TO CLIENT
		// 1) g**b
		ret = send_message(client_socket, (void*)my_key_buf, my_key_len);
		if (ret <= 0) {
			throw 6;
		}

		// 2) encrypted signature
		ret = send_message(client_socket, (void*)encrypted_sign, encrypted_sign_len);
		if (ret <= 0) {
			throw 6;
		}

		// 3) server certificate
		ret = send_message(client_socket, (void*)ser_certificate, ser_certificate_len);
		if (ret <= 0) {
			throw 6;
		}

	} catch (int e) {
		if (e >= 6) {
			OPENSSL_free(ser_certificate);
		}
		if (e >= 5) {
			X509_free(certificate);
		}
		if (e >= 4) {
			#pragma optimize("", off);
				memset(encrypted_sign, 0, encrypted_sign_len);
			#pragma optimize("", on);
			free(encrypted_sign);
		}
		if (e >= 3) {
			#pragma optimize("", off);
				memset(peer_key_buf, 0, peer_key_len);
			#pragma optimize("", on);
			free(peer_key_buf);
		}
		if (e >= 2) {
			#pragma optimize("", off);
				memset(my_key_buf, 0, my_key_len);
			#pragma optimize("", on);
			free(my_key_buf);
		}
		if (e >= 1) {
			BIO_free(mbio);
		}
		return -1;
	}

	// Clean stuff
	OPENSSL_free(ser_certificate);
	X509_free(certificate);
	#pragma optimize("", off);
		memset(encrypted_sign, 0, encrypted_sign_len);
	#pragma optimize("", on);
	free(encrypted_sign);
	#pragma optimize("", off);
		memset(peer_key_buf, 0, peer_key_len);
	#pragma optimize("", on);
	free(peer_key_buf);
	#pragma optimize("", off);
		memset(my_key_buf, 0, my_key_len);
	#pragma optimize("", on);
	free(my_key_buf);
	BIO_free(mbio);

	return 1;
}

/**
 * Encrypt a message with AES-128 in CBC mode, using the specified parameters
 * 
 * @param msg pointer to the message to encrypt
 * @param msg_len length of the message to encrypt
 * @param key pointer to the key
 * @param key_len length of the key
 * @param ciphertext_len the length of the final ciphertext will be returned through this reference
 * 
 * @return address to the ciphertext on success, NULL on failure
 */
unsigned char* ServerThread::encrypt_message (unsigned char* msg, size_t msg_len, 
                                              unsigned char* key, size_t key_len,
											  size_t& ciphertext_len)
{
	int ret;
	EVP_CIPHER_CTX* ctx = nullptr;
	unsigned char* ciphertext = nullptr;
	unsigned char* iv = nullptr;

	try {
		// Allocate ciphertext
		ciphertext = (unsigned char*)malloc(msg_len + EVP_CIPHER_block_size(get_symmetric_cipher()));
		if (!ciphertext) {
			cerr << "[Thread " << this_thread::get_id() << "] encrypt_message: "
			<< "malloc ciphertext failed" << endl;
			throw 0;
		}
		
		// Allocate and initialize IV
		iv = (unsigned char*)malloc(EVP_CIPHER_iv_length(get_symmetric_cipher()));
		if (!iv) {
			cerr << "[Thread " << this_thread::get_id() << "] encrypt_message: "
			<< "malloc iv failed" << endl;
			throw 1;
		}
		ret = RAND_bytes(iv, EVP_CIPHER_iv_length(get_symmetric_cipher()));
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] encrypt_message: "
			<< "RAND_bytes failed" << endl;
			throw 2;
		}

		// Allocate context for encryption
		ctx = EVP_CIPHER_CTX_new();
		if (!ctx) {
			cerr << "[Thread " << this_thread::get_id() << "] encrypt_message: "
			<< "EVP_CIPHER_CTX_new failed" << endl;
			throw 2;
		}

		// Initialize encryption context
		ret = EVP_EncryptInit(ctx, get_symmetric_cipher(), key, nullptr);
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] encrypt_message: "
			<< "EVP_EncryptIniti failed" << endl;
			throw 3;
		}

		// Encrypt message
		int outl;
		ret = EVP_EncryptUpdate(ctx, ciphertext, &outl, msg, msg_len);
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] encrypt_message: "
			<< "EVP_EncryptionUpdate failed" << endl;
			throw 3;
		}

		// Finalize encryption
		ciphertext_len = outl;
		ret = EVP_EncryptFinal(ctx, ciphertext + ciphertext_len, &outl);
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] encrypt_message: "
			<< "EVP_EncryptionUpdate failed" << endl;
			throw 3;
		}

		ciphertext_len += outl;
		
	} catch (int e) {
		if (e >= 3) {
			EVP_CIPHER_CTX_free(ctx);
		}
		if (e >= 2) {
			free(iv);
		}
		if (e >= 1) {
			free(ciphertext);
		}
		return nullptr;
	}

	EVP_CIPHER_CTX_free(ctx);
	free(iv);
	return ciphertext;
}

