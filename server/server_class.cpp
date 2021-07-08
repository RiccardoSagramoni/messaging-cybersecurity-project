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

	unsigned char* key_copy = (unsigned char*)malloc(key_len);
	if (!key_copy) {
		return false;
	}
	memcpy(key_copy, key, key_len);

	// Prepare data structure related to the client
	connection_data* data = new connection_data(socket, key_copy, key_len);

	// Add user to the list of connected client
	auto ret = connected_client.insert({username, data});

	return ret.second;
}

/**
 * Exclusively lock/unlock INPUT or OUTPUT stream of the socket related to specified client
 * 
 * @param username string containing client's username
 * @param lock true to lock the socket, false to unlock it
 * @param stream 0 to lock INPUT stream of socket, 1 to lock OUTPUT stream of socket, 2 to lock both
 * 
 * @return true on success, false on failure
 */
bool Server::handle_socket_lock (const string& username, const bool to_lock, const uint8_t stream)
{
	if (stream > 2) {
		return false;
	}
	
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

	// Lock the correct stream of the socket
	if (stream == 0) {
		if (to_lock) client_data->mutex_socket_in.lock();
		else client_data->mutex_socket_in.unlock();
	}
	else if (stream == 1) {
		if (to_lock) client_data->mutex_socket_out.lock();
		else client_data->mutex_socket_out.unlock();
	}
	else {
		if (to_lock) {
			// Avoid deadlock
			lock(client_data->mutex_socket_in, client_data->mutex_socket_out);
		}
		else {
			client_data->mutex_socket_out.unlock();
			client_data->mutex_socket_in.unlock();
		}
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
	
	// Get client data associated with given username.
	// Fails if there is no associated data.
	auto it = connected_client.find(username);
	if (it == connected_client.end()) {
		return -1;
	}
	connection_data* client_data = it->second;
	
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
	delete client_data;
	connected_client.erase(it);
	
	cout << "[Thread " << this_thread::get_id() << "]: "
	<< "user " << username << " exits" << endl;
	
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
	unique_lock<shared_timed_mutex> mutex_available(client_data->mutex_available);
	if (!client_data->available) {
		return -3;
	}
	client_data->available = false;
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
 * Block the thread and wait until the client don't answer to your talk request
 * 
 * @param wanted_user user that this thread wants to talk to
 * @param asking_user user that sent the request to talk
 * 
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


	// Wait until the "wanted" client have chosen an interlocutor
	unique_lock<mutex> talk_lock(client_data->ready_to_talk_mutex);
	while (!client_data->has_chosen_interlocutor) {
		client_data->ready_to_talk_cv.wait(talk_lock);
	}

	if (0 == asking_user.compare(client_data->interlocutor_user)) {
		// Client accepted request
		return 1;
	}

	talk_lock.unlock();

	unique_lock<shared_timed_mutex> mutex_available(client_data->mutex_available);
	client_data->available = true;

	return -1;
}

/**
 * Stop the thread and wait until the talk isn't ended.
 * Called by the thread that serves the client who received the request to talk
 * 
 * @param user name of the client that this thread serves
 * 
 * @return 1 on success, -1 on failure (user not online)
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

	return 1;
}

/**
 * Notify to the waiting threads that the client has answered to request to talk
 * 
 * @param wanted_user username of the client who received the request to talk
 * @param asking_user username of the client who sent the request to talk
 * @param is_accepting true if the client has accepted a request to talk, false otherwise
 * 
 * @return 1 on success, -1 on failure 
 */
int Server::notify_start_talk (const string& wanted_user, const string asking_user, const bool is_accepting)
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

	// Set user as unavailable if has accepted the talk request
	unique_lock<shared_timed_mutex> mutex_available(client_data->mutex_available);
	client_data->available = !is_accepting;
	mutex_available.unlock();

	// Reset end-talk flag
	unique_lock<mutex> mutex_end_talk(client_data->end_talk_mutex);
	client_data->is_talk_ended = false;
	mutex_end_talk.unlock();

	// Set chosen user to talk
	unique_lock<mutex> talk_lock(client_data->ready_to_talk_mutex);
	client_data->has_chosen_interlocutor = true;
	client_data->interlocutor_user = asking_user;
	client_data->ready_to_talk_cv.notify_all();

	return 1;
}

/**
 * Notify to the user's main server thread that the the talk has ended, so that 
 * it can restart its normal execution
 * 
 * @param user client username
 * 
 * @return 1 on success, -1 on error 
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

	// Reset ready to talk
	unique_lock<mutex> talk_lock(client_data->ready_to_talk_mutex);
	client_data->has_chosen_interlocutor = false;
	talk_lock.unlock();

	// Wake up waiting thread (main thread of socket)
	unique_lock<mutex> end_talk_lock(client_data->end_talk_mutex);
	client_data->is_talk_ended = true;
	client_data->end_talk_cv.notify_all();

	return 1;
}

/**
 * Set the exit status from a talk, so that the thread which serves the client
 * will be able to handle possible errors when it wakes up.
 * 
 * @param username name of the user
 * @param status exit status
 * 
 * @return 1 on success, -1 on failure 
 */
int Server::set_talk_exit_status(const string& username, const int status)
{
	// Acquire lock for reading the client data's container
	shared_lock<shared_timed_mutex> mutex_unordered_map(connected_client_mutex);

	connection_data* client_data;

	// Check if client is online
	try {
		client_data = connected_client.at(username);

	} catch (const out_of_range& ex) {
		cerr << "[Thread " << this_thread::get_id() << "] Server::wait_end_talk: "
		<< "user " << username << " is not logged" << endl;
		return -1;
	}

	unique_lock<mutex> m(client_data->end_talk_mutex);
	client_data->talk_exit_status = status;
	return 1;
}

/**
 * Check if counter against replay attack is valid
 * @return 1 if counter is valid, 0 if counter is not valid, -1 if username doesn't exists or counter overflows
 */
int Server::check_client_counter(const string& username, const uint32_t counter)
{
	// Acquire lock for reading the client data's container
	shared_lock<shared_timed_mutex> mutex_unordered_map(connected_client_mutex);

	connection_data* client_data;

	// Check if client is online
	try {
		client_data = connected_client.at(username);

	} catch (const out_of_range& ex) {
		cerr << "[Thread " << this_thread::get_id() << "] Server::wait_end_talk: "
		<< "user " << username << " is not logged" << endl;
		return -1;
	}

	unique_lock<mutex> lock(client_data->counter_mx);
	bool ret = (counter == client_data->client_counter);
	client_data->client_counter++;
	
	// Check overflow of counter
	if (client_data->client_counter == 0) {
		return -1;
	}

	return (ret) ? 1 : 0;
}

/**
 * Get counter against replay attack and increments it 
 * 
 * @param username id of user
 * @param counter on success it will contain the counter
 * 
 * @return 1 on success, -1 if username doesn't exists or counter overflows
 */

int Server::get_server_counter(const string& username, uint32_t& counter)
{
	// Acquire lock for reading the client data's container
	shared_lock<shared_timed_mutex> mutex_unordered_map(connected_client_mutex);

	connection_data* client_data;

	// Check if client is online
	try {
		client_data = connected_client.at(username);

	} catch (const out_of_range& ex) {
		cerr << "[Thread " << this_thread::get_id() << "] Server::wait_end_talk: "
		<< "user " << username << " is not logged" << endl;
		return -1;
	}

	unique_lock<mutex> lock(client_data->counter_mx);
	counter = client_data->server_counter;
	client_data->server_counter++;

	// Check overflow of counter
	if (client_data->server_counter == 0) {
		return -1;
	}

	return 1;
}