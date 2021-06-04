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
 * @return true on success, false on failure
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
 * @return id of new socket on success, -1 on failure
 */
int Server::accept_client (sockaddr_in* client_addr)
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
 * @return true on success, false on failure (client already logged in)
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
 * @return true on success, false on failure
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

/**
 * Check is a specified client is currently online (logged on the server)
 * 
 * @param username identifier of client
 * @return true if the client is online, false otherwise 
 */
bool Server::is_client_online (const string& username)
{
	// Acquire lock for reading the client data's container
	shared_lock<shared_timed_mutex> mutex_unordered_map(connected_client_mutex);

	return (connected_client.count(username) != 0);
}

/**
 * Close connection with specified client
 * 
 * @param username identifier of the client
 * @return 1 on success, -1 on failure 
 */
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