#include "client.h"

ClientThread::ClientThread(Client* cli, const int socket, const sockaddr_in addr)
{
    client=cli;
	main_server_socket = socket;
	main_server_address = addr;
}

DH* ClientThread::get_dh2048 ()
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
int ClientThread::send_message (const int socket, void* msg, const uint32_t msg_len)
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

long ClientThread::receive_message (const int socket, void** msg)
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

void ClientThread::run()
{
	int ret;

	string username = client->get_username();
    negotiate(username);
	
	while (true) {

	}
}



//negotiation of key and autentication with server
int ClientThread::negotiate(const string& username) {
    int ret;
	X509* cert=nullptr;
	X509* cert_serv=nullptr;
	X509_CRL* crl_serv=nullptr;
	unsigned char* ser_certificate = nullptr;
	size_t ser_certificate_len = 0;
	unsigned char* iv = nullptr;
	size_t iv_len = 0;
    char* username_c = nullptr;
	BIO* mbio = nullptr;
	char* pubkey_buf = nullptr;
	EVP_PKEY* public_key_from_cert = nullptr;
	unsigned char* tag = nullptr;

	unsigned char* session_key = nullptr;
	size_t session_key_len = 0;
    EVP_PKEY* peer_key = nullptr;
	//sig
	unsigned char* ciphertext = nullptr;
	size_t ciphertext_len = 0;
	unsigned char* plain_sig = nullptr;
	size_t plain_sig_len_len = 0;
    //generate g^a
    EVP_PKEY* my_dh_key = generate_key_dh();
	if (!my_dh_key) {
		cerr << "[Thread " << this_thread::get_id() << "] negotiate: "
		<< "error generate key" << endl;
		return -1;
	}

	try {
		//malloc username
		username_c = (char*)malloc(username.length() + 1);
		if (!username_c) {
			cerr << "[Thread " << this_thread::get_id() << "] negotiate: "
			<< "error malloc username" << endl;
			throw 0;
		}
    	strcpy(username_c, username.c_str());
		//send username to the server
    	ret = send_message(main_server_socket, (void*) username_c, (uint32_t) strlen(username_c));
		if (ret < 1) {
			cerr << "[Thread " << this_thread::get_id() << "] negotiate: "
			<< "error send username" << endl;
			throw 1;
		}
		//serialize my_dh_key
    	mbio = BIO_new(BIO_s_mem());
    	if (!mbio) {
			cerr << "[Thread " << this_thread::get_id() << "] negotiate: "
			<< "error bio_new" << endl;
			throw 1;
		}

		ret = PEM_write_bio_PUBKEY(mbio, my_dh_key);
		if (ret <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] negotiate: "
			<< "error write bio" << endl;
			throw 2;
		}
		
		long ret_long = BIO_get_mem_data(mbio, &pubkey_buf);
		if (ret_long <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] negotiate: "
			<< "error get mem bio pub key" << endl;
			throw 2;
		}
		uint32_t pubkey_size = (uint32_t)ret_long;
		//send g^a
		ret = send_message(main_server_socket, (void*)pubkey_buf, pubkey_size);
		if (ret < 1) {
			cerr << "[Thread " << this_thread::get_id() << "] negotiate: "
			<< "error sending pub key" << endl;
			throw 2;
		}
		

		// Second step protocol (receive public key from server)
		ret = receive_from_server_pub_key(peer_key);
		if (ret < 0) throw 2;

		//derive session key
		session_key_len = EVP_CIPHER_key_length(get_symmetric_cipher());
		session_key = derive_session_key(my_dh_key, peer_key, session_key_len);
		if (!session_key) {
			cerr << "[Thread " << this_thread::get_id() << "] negotiate: "
			<< "error derive session key" << endl;
			throw 2;
		}




		//receive iv (initialization vector)
		ret = receive_message(main_server_socket, (void**)&iv);
		if (ret <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] negotiate: "
			<< "error receive iv" << endl;
			throw 5;
		}

		iv_len=ret;


		//receive crypto sign
		ret = receive_message(main_server_socket, (void**)&ciphertext);
		if (ret <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] negotiate: "
			<< "error receive crypto sign" << endl;
			throw 3;
		}

		ciphertext_len = ret;


		//receive tag
		ret = receive_message(main_server_socket, (void**)&tag);
		if (ret <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] negotiate: "
			<< "error receive tag" << endl;
			throw 4;
		}

		//receive certificate of the server
		ret = receive_message(main_server_socket, (void**)&ser_certificate);
		if (ret <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] negotiate: "
			<< "error receive certificate" << endl;
			throw 4;
		}
		ser_certificate_len = ret;
		cert = deseryalize_cert(ser_certificate, ser_certificate_len);
		if (cert == NULL) {
			cerr << "[Thread " << this_thread::get_id() << "] negotiate: "
			<< "error deserialize certificate" << endl;
			throw 4;
		}


		//get certificate from file
		cert_serv = get_server_certificate();
		if (cert_serv == NULL) {
			cerr << "[Thread " << this_thread::get_id() << "] negotiate: "
			<< "error server certificate" << endl;
			throw 4;
		}

		//get crl from file
		crl_serv = get_crl();
		if (crl_serv == NULL) {
			cerr << "[Thread " << this_thread::get_id() << "] negotiate: "
			<< "error crl" << endl;
			throw 4;
		}

		//build store, add certificate, add crl and check validity
		ret = build_store_cert_and_check(cert, crl_serv, cert_serv);
		if (ret !=1) {
			cerr << "[Thread " << this_thread::get_id() << "] negotiate: "
			<< "error build store and check validity" << endl;
			throw 4;
		}
		//extract public key from certificate
		public_key_from_cert = X509_get_pubkey(cert);
		if (public_key_from_cert == NULL) {
			cerr << "[Thread " << this_thread::get_id() << "] negotiate: "
			<< "error exract pub key from cert" << endl;
			throw 4;
		}



		
		//decrypt and verify server signature
		ret = decrypt_and_verify_sign(ciphertext, ciphertext_len, my_dh_key, public_key_from_cert, session_key, session_key_len, iv, iv_len, tag);
		if (ret <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] negotiate: "
			<< "error verifying server sign" << endl;
			throw 6;
		}

		//crypt sign and send it
		ret = send_sig(my_dh_key, peer_key, session_key, session_key_len, iv, iv_len);
		if (ret <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] negotiate: "
			<< "error sending sign" << endl;
			throw 6;
		}

	} catch (int e) {
		if (e >= 6) {
			free(iv);
		}
		if (e >= 5) {
			secure_free(ser_certificate, ser_certificate_len);
		}
		if (e >= 4) {
			secure_free(ciphertext, ciphertext_len);
		}
		if (e >= 3) {
			secure_free(session_key, session_key_len);
		}
		if (e >= 2) {
			BIO_free(mbio);
		}
		if (e >= 1) {
			free(username_c);
		}
		return -1;
	}

	free(iv);
	secure_free(ser_certificate, ser_certificate_len);
	secure_free(ciphertext, ciphertext_len);
	secure_free(session_key, session_key_len);
	BIO_free(mbio);
	free(username_c);

	return 1;
}

void ClientThread::secure_free (void* addr, size_t len) 
{
	#pragma optimize("", off);
		memset(addr, 0, len);
	#pragma optimize("", on);

	free(addr);
}


/**
 * Generate server's part of the shared private key, i.e. g**b according to DH protocol
 * 
 * @return the generated key on success, NULL otherwise
 */
EVP_PKEY* ClientThread::generate_key_dh ()
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
unsigned char* ClientThread::derive_session_key (EVP_PKEY* my_dh_key, 
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
int ClientThread::receive_from_server_pub_key(EVP_PKEY*& peer_key) {
    int ret_int;
	long ret_long;
    char* key = nullptr;
	ret_long = receive_message(main_server_socket, (void**)&key);
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

const EVP_CIPHER* ClientThread::get_symmetric_cipher ()
{
	return EVP_aes_128_cbc();
}



// decrypt and verification sign
int ClientThread::decrypt_and_verify_sign(unsigned char* ciphertext, size_t ciphertext_len, EVP_PKEY* my_dh_key,
    EVP_PKEY* peer_key, unsigned char* shared_key, size_t shared_key_len, unsigned char* iv, size_t iv_len, unsigned char* tag) {
	int ret;
	long ret_long;

	unsigned char* server_signature = nullptr;
	size_t server_signature_len = 0;

	BIO* mbio = nullptr;
	unsigned char* my_key_buf = nullptr;
	size_t my_key_len = 0;
	unsigned char* peer_key_buf = nullptr;
	size_t peer_key_len = 0;

	try {

		// 2a) Serialize server's key (g**b)
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

		// 2b) Serialize peer key
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

		// 2c) Concat peer_key and my_key
		size_t concat_keys_len = my_key_len + peer_key_len + 1;
		unsigned char* concat_keys = (unsigned char*)malloc(concat_keys_len);
		if (!concat_keys) {
			cerr << "[Thread " << this_thread::get_id() << "] decrypt_and_verify_sign: "
			<< "error concatenation of keys" << endl;
			throw 4;
		}

		memcpy(concat_keys, peer_key_buf, peer_key_len);
		memcpy(concat_keys + peer_key_len, my_key_buf, my_key_len);
		concat_keys[concat_keys_len - 1] = '\0';

		secure_free(concat_keys, concat_keys_len);

		// 3) Decrypt received message with shared key
		ret = gcm_decrypt(ciphertext, ciphertext_len, iv, iv_len, tag, shared_key, iv, iv_len, server_signature, server_signature_len);
		if (ret!=1) {
			cerr << "[Thread " << this_thread::get_id() << "] decrypt_and_verify_sign: "
			<< "error decryption" << endl;
			throw 4;
		}

		// verify server sig
		ret = verify_server_signature(server_signature, server_signature_len, concat_keys, concat_keys_len, nullptr);
		if (ret < 0) {
			cerr << "[Thread " << this_thread::get_id() << "] decrypt_and_verify_sign: "
			<< "error verification sign" << endl;
			throw 5;
		}

	} catch (int e) {
		if (e >= 5) {
			#pragma optimize("", off);
				memset(server_signature, 0, server_signature_len);
			#pragma optimize("", on);
			free(server_signature);
		}
		if (e >= 4) {
			#pragma optimize("", off);
				memset(peer_key_buf, 0, peer_key_len);
			#pragma optimize("", on);
			free(peer_key_buf);
		}
		if (e >= 3) {
			#pragma optimize("", off);
				memset(my_key_buf, 0, my_key_len);
			#pragma optimize("", on);
			free(my_key_buf);
		}
		if (e >= 2) {
			BIO_free(mbio);
		}
		if (e >= 1) {
			free(ciphertext);
		}
		return -1;
	}

	#pragma optimize("", off);
		memset(server_signature, 0, server_signature_len);
		memset(peer_key_buf, 0, peer_key_len);
		memset(my_key_buf, 0, my_key_len);
	#pragma optimize("", on);

	free(server_signature);
	free(peer_key_buf);
	free(my_key_buf);
	BIO_free(mbio);
	free(ciphertext);

	return 1;
}



//for verify server signature
int ClientThread::verify_server_signature (unsigned char* signature, size_t signature_len, 
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
int ClientThread::send_sig(EVP_PKEY* my_dh_key,EVP_PKEY* peer_key, unsigned char* shared_key, size_t shared_key_len, unsigned char* iv, size_t iv_len) {
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


	try {
		// 1) Serialize server's key (g**b)
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


		// 2) Prepare string < g**b, g**a > for signature
		// 2a) Serialize peer key
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

		// 2b) Concat my_key and peer_key
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
		
		// 2c) Sign concat keys and remove them
		unsigned int signature_len = 0;
		unsigned char* signature = sign_message(concat_keys, concat_keys_len, signature_len);

		#pragma optimize("", off)
			memset(concat_keys, 0, concat_keys_len);
		#pragma optmize("", on)
		free(concat_keys);

		if (!signature) {
			cerr << "[Thread " << this_thread::get_id() << "] send_sig: "
			<< "sign_message failed" << endl;
			throw 3;
		}

		// 3) Encrypt signature and delete it
		ret = gcm_encrypt(signature, signature_len, iv, iv_len, shared_key, iv, iv_len, encrypted_sign, encrypted_sign_len, tag, tag_len);
		if (ret !=1) {
			cerr << "[Thread " << this_thread::get_id() << "] send_sig: "
			<< "failed to crypt" << endl;
			throw 3;
		}
		#pragma optimize("", off)
			memset(signature, 0, signature_len);
		#pragma optmize("", on)
		free(signature);

		if (!encrypted_sign) {
			cerr << "[Thread " << this_thread::get_id() << "] send_sig: "
			<< "encrypt_message failed" << endl;
			throw 3;
		}
	

		// 5b) send crypted signature
		ret = send_message(main_server_socket, (void*)encrypted_sign, encrypted_sign_len);
		if (ret <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] send_sig: "
			<< "send_message encrypted_signature" << endl;
			throw 3;
		}


		// 5d) iv
		/*ret = send_message(main_server_socket, (void*)iv, EVP_CIPHER_iv_length(get_symmetric_cipher()));
		if (ret <= 0) {
			cerr << "[Thread " << this_thread::get_id() << "] STS_send_session_key: "
			<< "send_message iv failed" << endl;
			throw 6;
		}*/

	} catch (int e) {
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





// for sign message 
unsigned char* ClientThread::sign_message(unsigned char* msg, size_t msg_len, unsigned int& signature_len)
{
	int ret;
	EVP_PKEY* prvkey = nullptr;
	EVP_MD_CTX* ctx = nullptr;
	unsigned char* signature = nullptr;
	
	try {
		//get private key
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
EVP_PKEY* ClientThread::get_client_private_key ()
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






// for encrypt message (using iv)
unsigned char* ClientThread::encrypt_message (unsigned char* msg, size_t msg_len, 
                                              unsigned char* key, size_t key_len, 
                                              unsigned char* iv, size_t& ciphertext_len)
{
	int ret;
	EVP_CIPHER_CTX* ctx = nullptr;
	unsigned char* ciphertext = nullptr;

	try {
		// Allocate ciphertext
		ciphertext = (unsigned char*)malloc(msg_len + EVP_CIPHER_block_size(get_symmetric_cipher()));
		if (!ciphertext) {
			cerr << "[Thread " << this_thread::get_id() << "] encrypt_message: "
			<< "malloc ciphertext failed" << endl;
			throw 0;
		}
		
		// Allocate context for encryption
		ctx = EVP_CIPHER_CTX_new();
		if (!ctx) {
			cerr << "[Thread " << this_thread::get_id() << "] encrypt_message: "
			<< "EVP_CIPHER_CTX_new failed" << endl;
			throw 2;
		}

		// Initialize encryption context
		ret = EVP_EncryptInit(ctx, get_symmetric_cipher(), key, iv);
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] encrypt_message: "
			<< "EVP_EncryptIniti failed" << endl;
			throw 2;
		}

		// Encrypt message
		int outl;
		ret = EVP_EncryptUpdate(ctx, ciphertext, &outl, msg, msg_len);
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] encrypt_message: "
			<< "EVP_EncryptionUpdate failed" << endl;
			throw 2;
		}

		// Finalize encryption
		ciphertext_len = outl;
		ret = EVP_EncryptFinal(ctx, ciphertext + ciphertext_len, &outl);
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] encrypt_message: "
			<< "EVP_EncryptionUpdate failed" << endl;
			throw 2;
		}

		ciphertext_len += outl;
		
	} catch (int e) {
		if (e >= 2) {
			EVP_CIPHER_CTX_free(ctx);
		}
		if (e >= 1) {
			free(ciphertext);
		}
		return nullptr;
	}

	EVP_CIPHER_CTX_free(ctx);
	return ciphertext;
}



// for decrypting ciphertext (using iv)

unsigned char* ClientThread::decrypt_message (unsigned char* ciphertext, size_t ciphertext_len, unsigned char* key, size_t key_len, unsigned char* iv, size_t& plainlen) {
	unsigned char* plaintext;
	int ret;
	int outlen;
	EVP_CIPHER_CTX* ctx;
	try {
		//malloc of plaintext
		plaintext = (unsigned char*)malloc(ciphertext_len);
		if (!plaintext) {
			cerr << "[Thread " << this_thread::get_id() << "] decrypt_message: "
			<< "malloc plaintext failed" << endl;
			throw 0;
		}
		//create new ctx ciphertext
		ctx= EVP_CIPHER_CTX_new();
		if (!ctx) {
			cerr << "[Thread " << this_thread::get_id() << "] decrypt_message: "
			<< "EVP_CIPHER_CTX_new failed" << endl;
			throw 1;
		}
		// initialize decryption context
		ret = EVP_DecryptInit(ctx, get_symmetric_cipher(), key, iv);  
		if (ret!=1) {
			cerr << "[Thread " << this_thread::get_id() << "] decrypt_message: "
			<< "EVP_DecryptionUpdate failed" << endl;
			throw 2;
		}
		// start decryption
		ret = EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, ciphertext_len);
		if (ret!=1) {
			cerr << "[Thread " << this_thread::get_id() << "] decrypt_message: "
			<< "EVP_DecryptionUpdate failed" << endl;
			throw 2;
		}
		plainlen=outlen;
		// Finalize decryption
		ret = EVP_DecryptFinal(ctx, plaintext + plainlen, &outlen);
		if (ret!=1) {
			cerr << "[Thread " << this_thread::get_id() << "] decrypt_message: "
			<< "EVP_DecryptionFinal failed" << endl;
			throw 2;
		}
		plainlen+= outlen;
	} catch (int e) {
		if (e >= 2) {
			EVP_CIPHER_CTX_free(ctx);
		}
		if (e >= 1) {
			free(plaintext);
		}
		return nullptr;
	}


	EVP_CIPHER_CTX_free(ctx);

	return plaintext;
}




// for deseryalize certificate 
X509* ClientThread::deseryalize_cert(unsigned char* ser_certificate, size_t ser_certificate_len) {
	X509* cert = nullptr;
	//Deseryalize certificate
	cert = d2i_X509(NULL, (const unsigned char**)& ser_certificate, ser_certificate_len);
	if (!cert) {
		return NULL;
	}
	return cert;
}





// get crl from file 
X509_CRL* ClientThread::get_crl() {
	FILE* file = nullptr;
	X509_CRL* crl = nullptr;
// try to open the file
	try {
		file = fopen(filename_crl.c_str(), "r");
		if (!file) {
			cerr << "[Thread " << this_thread::get_id() << "] get_crl: "
			<< "cannot open file " << filename_crl << endl;
			throw 0;
		}

		crl = PEM_read_X509_CRL(file, nullptr, nullptr, nullptr);
		if (!crl) {
			cerr << "[Thread " << this_thread::get_id() << "] get_crl: "
			<< "cannot read crle " << endl;
			throw 1;
		}

	} catch (int e) {
		if (e >= 1) {
			fclose(file);
		}
		return nullptr;
	}

	fclose(file);
	return crl;
}




// for get certificate from file
X509* ClientThread::get_server_certificate ()
{
	
	FILE* file = nullptr;
	X509* cert = nullptr;
// try to open file
	try {
		file = fopen(filename_certificate.c_str(), "r");
		if (!file) {
			cerr << "[Thread " << this_thread::get_id() << "] get_server_certificate: "
			<< "cannot open file " << filename_certificate << endl;
			throw 0;
		}
// get the certificate
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






// for build the store for certificate and check validity of some certificate

int ClientThread::build_store_cert_and_check(X509* cert, X509_CRL* crl, X509* cert_to_ver) {
	int ret=0;
	X509_STORE* store = nullptr;
	X509_STORE_CTX* ctx = nullptr;
	//allocate store
	try {
		if ((store = X509_STORE_new())==NULL) {
			cerr << "[Thread " << this_thread::get_id() << "] build_store_cert_and_check: "
			<< "cannot create store " << endl;
			throw 0;
		}
		// add cert to the store
		ret = X509_STORE_add_cert(store, cert);
		if (ret<1) {
			cerr << "[Thread " << this_thread::get_id() << "] build_store_cert_and_check: "
			<< "cannot add certificate to store " << endl;
			throw 1;
		}
		// add crl
		ret = X509_STORE_add_crl(store, crl);
		if (ret<1) {
			cerr << "[Thread " << this_thread::get_id() << "] build_store_cert_and_check: "
			<< "cannot add crl to store " << endl;
			throw 1;
		}
		// set the flag
		ret = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
		if (ret<1) {
			cerr << "[Thread " << this_thread::get_id() << "] build_store_cert_and_check: "
			<< "cannot set flag " << endl;
			throw 1;
		}
		//check validity
		if ((ctx = X509_STORE_CTX_new())==NULL) {
			cerr << "[Thread " << this_thread::get_id() << "] build_store_cert_and_check: "
			<< "cannot allocate ctx " << endl;
			throw 2;
		}
		ret = X509_STORE_CTX_init(ctx, store, cert_to_ver, NULL);
		if (ret<1) {
			cerr << "[Thread " << this_thread::get_id() << "] build_store_cert_and_check: "
			<< "Error in ctx init " << endl;
			throw 2;
		}
		ret = X509_verify_cert(ctx);
		if (ret!=1) {
			cerr << "[Thread " << this_thread::get_id() << "] build_store_cert_and_check: "
			<< "Error verify cert " << endl;
			return -1;
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



int ClientThread::gcm_decrypt (unsigned char* ciphertext, int ciphertext_len,
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

		//Provide the message to be decrypted, and obtain the plaintext output.
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







int ClientThread::gcm_encrypt (unsigned char* plaintext, size_t plaintext_len,
							   unsigned char* aad, size_t aad_len, 
							   unsigned char* key,
							   unsigned char* iv, size_t iv_len, 
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
		ret = EVP_EncryptUpdate(ctx, nullptr, &outlen, aad, aad_len);
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
		tag_len = 16;
		ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag_len, tag);
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
	free(iv);
	free(tag);
	free(ciphertext);

	return 1;
}


const EVP_CIPHER* ClientThread::get_authenticated_encryption_cipher ()
{
	return EVP_aes_128_gcm();
}