#include "server.h"

Server::Server(const uint16_t port)
{
    // Configure server_address
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
	server_address.sin_port = htons(port);
	server_address.sin_addr.s_addr = INADDR_ANY;
}

Server::~Server()
{
	
}

/** 
 * Configure the listener socket, bind server IP address
 * and start listening for client's requests.
 * 
 * @return true on success
 * @return false on failure
 */
bool Server::configure_listener_socket ()
{
	// Check if socket has already been created
	if (listener_socket != -1) return false;

	// Create socket
	listener_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (listener_socket == -1) {
		return false;
	}

	cout << "Listener socket created\n";

	// Bind IP address to socket
	if (-1 == bind(listener_socket, (sockaddr*)&server_address, sizeof(server_address)) ) {
		return false;
	}

	cout << "Listener socket successfully binded\n";

	// Start listening to client's requests
    if (-1 == listen(listener_socket, BACKLOG_LEN) ) {
		return false;
    }

    cout << "Socket is listening\n";

	return true;
}

/** 
 * Accept client connection request from listener socker.
 * Create a new socket for communication with the client.
 * 
 * @param client_addr IP address of client
 * 
 * @return id of new socket on success
 * @return -1 on failure
 */
int Server::accept_client (sockaddr_in* client_addr) const
{
    socklen_t addr_len = sizeof(client_addr);

    // It could block the thread if there are no pending requests
    return accept(listener_socket, (sockaddr*)client_addr, &addr_len);
}

/**
 * Add a new client to the list of all the clients connected to the server
 * and set its state to "available to talk".
 * 
 * @param username string identifier of the client
 * @param socket socket linked to the client
 * 
 * @return true on success
 * @return false on failure (client already logged in)
 */
bool Server::add_new_client (string username, const int socket)
{
	// Acquire lock for connected_client data structure
	// (automatically unlock at the end of its scope)
	lock_guard<shared_timed_mutex> lock(connected_client_mutex);

	// Prepare data structure related to the client
	connection_data* data = new connection_data(socket);

	// Add user to the list of connected client
	auto ret = connected_client.insert({username, data});

	return ret.second;
}

/**
 * Exclusively lock/unlock INPUT or OUTPUT stream of the socket related to specified client
 * 
 * @param username string containing client's username
 * @param lock true to lock the socket, false to unlock it
 * @param input true to lock INPUT stream of socket, false to lock OUTPUT stream of socket
 * 
 * @return true on success
 * @return false on failure
 */
bool Server::handle_socket_lock (const string username, const bool lock, const bool input)
{
	// Acquire lock for reading the client data's container
	shared_lock<shared_timed_mutex> mutex_unordered_map(connected_client_mutex);
	
	connection_data* client_data;

	// Get client data associated with given username.
	// Fails if there is no associated data.
	try {
		client_data = connected_client.at(username);
	}
	catch (const out_of_range& ex) {
		return false;
	}

	// Acquire shared lock for reading client's data structure
	shared_lock<shared_timed_mutex> mutex_client_data(client_data->mutex_struct);

	// Select socket's mutex for required mode (input or output)
	mutex& socket_mutex = input ? client_data->mutex_socket_in : client_data->mutex_socket_out;
	
	// Lock or unlock selected mutex
	if (lock) {
		socket_mutex.lock();
	}
	else {
		socket_mutex.unlock();
	}
	
	return true;
}

/**
 * Return a list of client logged to the server and available to talk
 * 
 * @return list of available client's usernames
 */
list<string> Server::get_available_clients_list ()
{
	// Acquire lock for reading the client data's container
	shared_lock<shared_timed_mutex> mutex_unordered_map(connected_client_mutex);

	list<string> l;

	for (auto i : connected_client) {
		shared_lock<shared_timed_mutex> mutex_lock(i.second->mutex_struct);
		
		if (i.second->available) {
			l.push_back(i.first);
		}
	}

	return l;
}

bool Server::is_client_online (const string& username)
{
	// Acquire lock for reading the client data's container
	shared_lock<shared_timed_mutex> mutex_unordered_map(connected_client_mutex);

	return (connected_client.count(username) != 0);
}

int Server::close_client (const string username)
{
	// Acquire lock for reading the client data's container
	shared_lock<shared_timed_mutex> mutex_unordered_map(connected_client_mutex);
	
	connection_data* client_data;

	// Get client data associated with given username.
	// Fails if there is no associated data.
	try {
		client_data = connected_client.at(username);
	}
	catch (const out_of_range& ex) {
		return -1;
	}

	// Acquire exclusive lock for reading client's data structure
	lock_guard<shared_timed_mutex> mutex_client_data(client_data->mutex_struct);

	// Acquire lock without deadlock
	// TODO check comment and lock
	// ? does thread already have lock on output
	lock(client_data->mutex_socket_in, client_data->mutex_socket_out);
	lock_guard<mutex> l_socket_in(client_data->mutex_socket_in, adopt_lock);
	lock_guard<mutex> l_socket_out(client_data->mutex_socket_out, adopt_lock);

	close(client_data->socket);

	return 1;
}

/**
 * // TODO
 * 
 * @return EVP_PKEY* 
 */
EVP_PKEY* Server::get_private_key ()
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
 * // TODO
 * 
 * @param msg 
 * @param msg_len 
 * @param signature_len 
 * @return unsigned* 
 */
unsigned char* Server::sign_message(unsigned char* msg, size_t msg_len, unsigned int& signature_len)
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