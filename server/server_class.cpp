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
bool Server::add_new_client (string username, const int socket, 
                             const unsigned char* key, const size_t key_len)
{
	// Acquire lock for connected_client data structure
	// (automatically unlock at the end of its scope)
	lock_guard<shared_timed_mutex> lock(connected_client_mutex);

	// Prepare data structure related to the client
	connection_data* data = new connection_data(socket, key, key_len);

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
bool Server::handle_socket_lock (const string& username, const bool lock, const bool input)
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

	// Search for available users
	for (auto i : connected_client) {
		shared_lock<shared_timed_mutex> available_lock(i.second->mutex_available);
		
		if (i.second->available) {
			l.push_back(i.first);
		}
	}

	return l;
}

/**
 * Set availability to talk of a specified client
 * 
 * @param username id of user
 * @param status new available status
 * 
 * @return 1 on success, -1 on failure
 */
int Server::set_available_status (const string& username, const bool status)
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

	// Acquire exclusive lock for writing on data structure and set available status
	lock_guard<shared_timed_mutex> mutex_available(client_data->mutex_available);
	
	if (client_data->available == status) {
		return 0;
	}
	client_data->available = status;

	return 1;
}

/**
 * Close connection with specified client
 * 
 * @param username identifier of the client
 * @return 1 on success, -1 on failure (client is not logged online)
 */
int Server::remove_client (const string& username)
{
	// Acquire exclusive lock for writing on the client data's container
	lock_guard<shared_timed_mutex> mutex_unordered_map(connected_client_mutex);
	
	connection_data* client_data;

	// Get client data associated with given username.
	// Fails if there is no associated data.
	try {
		client_data = connected_client.at(username);
	}
	catch (const out_of_range& ex) {
		return -1;
	}

	// Bruteforce close the socket
	if (shutdown(client_data->socket, SHUT_RDWR) >= 0) {
		close(client_data->socket);
	}

	// Remove key
	#pragma optimize("", off)
		memset((void*) client_data->key, 0, client_data->key_len);
	#pragma optimize("", on)
	free((void*) client_data->key);

	// Remove client data
	connected_client.erase(username);

	return 1;
}

/**
 * Create a copy of the key shared with the chosen client
 * 
 * @param username id of client
 * @param key_len on success it will contain the length of the key
 * 
 * @return the shared key on success, NULL on failure
 */
unsigned char* Server::get_client_shared_key (const string& username, size_t& key_len)
{
	// Acquire lock for reading the client data's container
	shared_lock<shared_timed_mutex> mutex_unordered_map(connected_client_mutex);

	connection_data* client_data = nullptr;

	// Get client data associated with given username.
	// Fails if there is no associated data.
	try {
		client_data = connected_client.at(username);

	} catch (const out_of_range& ex) {
		cerr << "[Thread " << this_thread::get_id() << "] Server::get_client_shared_key: "
		<< "username " << username << " is not logged" << endl;
		return nullptr;
	}

	// Acquire shared lock for writing the key
	lock_guard<shared_timed_mutex> mutex_key(client_data->mutex_key);

	unsigned char* key = (unsigned char*)malloc(client_data->key_len);
	if (!key) {
		cerr << "[Thread " << this_thread::get_id() << "] Server::get_client_shared_key: "
		<< "malloc key failed" << endl;
		return nullptr;
	}

	memcpy(key, client_data->key, client_data->key_len);
	key_len = client_data->key_len;

	return key;
}

/**
 * Prepare the structures for starting a message conversation between two clients.
 * Check if the peer user is online and available to talk, extract his key and 
 * lock the output stream of the socket
 * 
 * @param username id of the peer user
 * @param key on success it will point to the newly-allocated key
 * @param key_len key length
 * @return 1 on success, -2 if the user isn't online, -3 if the user isn't available to talk,
 * -1 if any other error occurs
 */
int Server::prepare_for_talking (const string& username, unsigned char*& key, size_t& key_len)
{
	// Acquire lock for reading the client data's container
	shared_lock<shared_timed_mutex> mutex_unordered_map(connected_client_mutex);

	connection_data* client_data;

	// Check if client is online
	try {
		client_data = connected_client.at(username);

	} catch (const out_of_range& ex) {
		cerr << "[Thread " << this_thread::get_id() << "] Server::prepare_for_talking: "
		<< "username " << username << " is not logged" << endl;
		return -2;
	}

	// Check if the client is available to talk
	shared_lock<shared_timed_mutex> mutex_available(client_data->mutex_available);
	if (!client_data->available) {
		return -3;
	}
	mutex_available.unlock();

	// Copy shared key with client
	shared_lock<shared_timed_mutex> mutex_key(client_data->mutex_key);
	if (!client_data->key) {
		return -1;
	}
	key_len = client_data->key_len;
	key = (unsigned char*)malloc(key_len);
	if (!key) {
		return -1;
	}
	memcpy(key, client_data->key, key_len);
	mutex_key.unlock();

	client_data->mutex_socket_out.lock();

	return client_data->socket;
}

/**
 * // TODO
 * @param wanted_user 
 * @param asking_user 
 * @return 1 on success, -1 on failure 
 */
int Server::wait_start_talk (const string& wanted_user, const string& asking_user)
{
	// Acquire lock for reading the client data's container
	shared_lock<shared_timed_mutex> mutex_unordered_map(connected_client_mutex);

	connection_data* client_data;

	// Check if client is online
	try {
		client_data = connected_client.at(wanted_user);

	} catch (const out_of_range& ex) {
		cerr << "[Thread " << this_thread::get_id() << "] Server::wait_start_talk: "
		<< "username " << wanted_user << " is not logged" << endl;
		return -1;
	}

	// Check if client is already unavailable
	shared_lock<shared_timed_mutex> mutex_available(client_data->mutex_available);
	if (!client_data->available) {
		return -1;
	}
	mutex_available.unlock();

	// Wait until the "wanted" client have chosen an interlocutor
	unique_lock<mutex> talk_lock(client_data->ready_to_talk_mutex);
	while (!client_data->has_chosen_interlocutor) {
		client_data->ready_to_talk_cv.wait(talk_lock);
	}

	if (0 != asking_user.compare(client_data->interlocutor_user)) {
		return -1;
	}

	return 1;
}

/**
 * // TODO 
 * @param user 
 * @return int 
 */
int Server::wait_end_talk (const string& user)
{
	// Acquire lock for reading the client data's container
	shared_lock<shared_timed_mutex> mutex_unordered_map(connected_client_mutex);

	connection_data* client_data;

	// Check if client is online
	try {
		client_data = connected_client.at(user);

	} catch (const out_of_range& ex) {
		cerr << "[Thread " << this_thread::get_id() << "] Server::wait_end_talk: "
		<< "username " << user << " is not logged" << endl;
		return -1;
	}

	// Wait until the talk is finished
	unique_lock<mutex> end_talk_lock(client_data->end_talk_mutex);
	while (!client_data->is_talk_ended) {
		client_data->end_talk_cv.wait(end_talk_lock);
	}
	end_talk_lock.unlock();

	// Set user as available
	unique_lock<shared_timed_mutex> mutex_available(client_data->mutex_available);
	client_data->available = true;
	mutex_available.unlock();

	return 1;
}

/**
 * // TODO 
 * @param wanted_user 
 * @param asking_user 
 * @return int 
 */
int Server::notify_start_talk (const string& wanted_user, const string asking_user)
{
	// Acquire lock for reading the client data's container
	shared_lock<shared_timed_mutex> mutex_unordered_map(connected_client_mutex);

	connection_data* client_data;

	// Check if client is online
	try {
		client_data = connected_client.at(wanted_user);

	} catch (const out_of_range& ex) {
		cerr << "[Thread " << this_thread::get_id() << "] Server::wait_start_talk: "
		<< "username " << wanted_user << " is not logged" << endl;
		return -1;
	}

	// Set user as unavailable
	unique_lock<shared_timed_mutex> mutex_available(client_data->mutex_available);
	client_data->available = false;
	mutex_available.unlock();

	// Set chosen user to talk
	unique_lock<mutex> talk_lock(client_data->ready_to_talk_mutex);
	client_data->has_chosen_interlocutor = true;
	client_data->interlocutor_user = asking_user;
	client_data->ready_to_talk_cv.notify_all();
	talk_lock.unlock();

	return 1;
}

/**
 * // TODO
 * 
 * @param user 
 * @return int 
 */
int Server::notify_end_talk (const string& user)
{
	// Acquire lock for reading the client data's container
	shared_lock<shared_timed_mutex> mutex_unordered_map(connected_client_mutex);

	connection_data* client_data;

	// Check if client is online
	try {
		client_data = connected_client.at(user);

	} catch (const out_of_range& ex) {
		cerr << "[Thread " << this_thread::get_id() << "] Server::wait_end_talk: "
		<< "username " << user << " is not logged" << endl;
		return -1;
	}

	// Wake up waiting thread (main thread of socket)
	unique_lock<mutex> end_talk_lock(client_data->end_talk_mutex);
	client_data->is_talk_ended = true;
	client_data->end_talk_cv.notify_all();

	return 1;
}