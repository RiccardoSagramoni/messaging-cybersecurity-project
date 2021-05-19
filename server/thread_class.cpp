#include "server.h"

ServerThread::ServerThread(Server* serv, const int socket, const sockaddr_in addr)
{
	server = serv;
	client_socket = socket;
	main_client_address = addr;
}

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


void ServerThread::run()
{
	int ret;

	// -) Authentication btw c/s
	string username; // TODO
	ret = authenticate_and_negotiate_keys(username);	

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

/*
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

*/

int ServerThread::authenticate_and_negotiate_keys (string& username)
{
	int ret;
// 1) Receive clients username and g**a
//	username || g**a
	EVP_PKEY* peer_key; // TODO

// 2) Generate random b and calculate g**b (Diffie-Helmann)
	EVP_PKEY* my_dh_key = generate_key_dh();

// 3) Derive shared secret k and hash it
	size_t session_key_len = EVP_CIPHER_key_length(get_symmetric_cipher());
	unsigned char* session_key = derive_session_key(my_dh_key, peer_key, session_key_len);

// 4) Send g**b || encrypted_k{sign of g**b,g**a} || certificate

// 5) Recevive encrypted_k{encrypted_client{g**a,g**b}}

// 6) Check validity
}

/**
 * // TODO
 * 
 * @return EVP_PKEY* 
 */
EVP_PKEY* ServerThread::generate_key_dh ()
{
	int ret;
	
	// Get DH params p and g
	EVP_PKEY* dh_params = EVP_PKEY_new();
	if (!dh_params) {
		// TODO print error?
		return nullptr;
	}
	DH* temp_dh_params = get_dh2048();
	ret  = EVP_PKEY_set1_DH(dh_params, temp_dh_params);
	free(temp_dh_params);
	if (ret != 1) {
		// TODO print error?
		return nullptr;
	}

	// Generate g**b
	EVP_PKEY_CTX* dh_gen_ctx = EVP_PKEY_CTX_new(dh_params, nullptr);
	if (!dh_gen_ctx) {
		// TODO print error?
		free(dh_params);
		return nullptr;
	}

	ret = EVP_PKEY_keygen_init(dh_gen_ctx);
	if (ret != 1) {
		// TODO print error?
		free(dh_params);
		EVP_PKEY_CTX_free(dh_gen_ctx);
		return nullptr;
	}

	EVP_PKEY* dh_key = nullptr;
	ret = EVP_PKEY_keygen(dh_gen_ctx, &dh_key);
	if (ret != 1) {
		// TODO print error?
		free(dh_params);
		EVP_PKEY_CTX_free(dh_gen_ctx);
		return nullptr;
	}

	free(dh_params);
	EVP_PKEY_CTX_free(dh_gen_ctx);
	return dh_key;
}

/**
 * 
 * 
 * @param my_dh_key 
 * @param peer_key 
 * @param key_len 
 * @return  
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

const EVP_CIPHER* ServerThread::get_symmetric_cipher ()
{
	return EVP_aes_128_cbc();
}