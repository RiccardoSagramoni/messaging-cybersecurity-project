#include "client.h"

thread_bridge::~thread_bridge()
{
	if (new_msg) {
		free(new_msg);
		new_msg = nullptr;
	}
}

/**
 * Wait for a new message from a server
 * 
 * @param msg_len the length of the message (on success)
 * 
 * @return the received message on success, NULL on failure 
 */
unsigned char* thread_bridge::wait_for_new_message (size_t& msg_len)
{
	unique_lock<mutex> lock(mx_new_msg);
	while (!is_msg_ready) {
		cv_new_msg.wait(lock);
	}
	unsigned char* msg = new_msg;
	msg_len = new_msg_len;
	new_msg = nullptr;
	new_msg_len = 0;
	is_msg_ready = false;

	cv_new_msg.notify_all();
	return msg;
}

/**
 * Delete last received message
 */
void thread_bridge::force_free_slave_input_thread()
{
	unique_lock<mutex> lock(mx_new_msg);
	if (is_msg_ready) {
		free(new_msg);
		new_msg = nullptr;
		new_msg_len = 0;
		is_msg_ready = false;
		cv_new_msg.notify_all();
	}
}

/**
 * Notify a new message received from the server
 *  
 * @param msg pointer to the message
 * @param msg_len message length
 */
void thread_bridge::notify_new_message(unsigned char* msg, size_t msg_len)
{
	unique_lock<mutex> lock(mx_new_msg);
	while (is_msg_ready) {
		cv_new_msg.wait(lock);
	}
	
	new_msg = msg;
	new_msg_len = msg_len;
	is_msg_ready = true;
	cv_new_msg.notify_all();
}

/**
 * Check if the client has received a request to talk from the server.
 * 
 * @param peer_username on success, it will contain the name of the user who sent the request.
 * 
 * @return 1 if there is a new request, -1 if there are no requests at all
 */
int thread_bridge::check_request_talk (string& peer_username)
{
	unique_lock<mutex> lock(mx_request_talk);
	if (!has_received_request) {
		return -1;
	}

	peer_username = request_username;
	request_username = "";
	has_received_request = false;

	return 1;
}

/**
 * Add a new received request to talk.
 * 
 * @param peer_username name of the user who sent the request
 */
void thread_bridge::add_request_talk(const string& peer_username)
{
	unique_lock<mutex> lock(mx_request_talk);
	has_received_request = true;
	request_username = peer_username;
}

int thread_bridge::get_talking_state()
{
	unique_lock<mutex> lock(mx_talk_status);
	return talk_status;
}

void thread_bridge::set_talking_state (int status)
{
	unique_lock<mutex> lock(mx_talk_status);
	talk_status = status;
}
