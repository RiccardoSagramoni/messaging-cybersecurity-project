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

DH* Server::get_dh2048(void)
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
}