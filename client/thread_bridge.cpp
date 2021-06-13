#include "client.h"

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
 * @return the number of the other pending request to talk after removing the one sent by "peer_username", -1 if there are no requests at all
 */
int thread_bridge::check_request_talk (string& peer_username)
{
	unique_lock<mutex> lock(mx_request_talk);
	if (request_queue.size() == 0) {
		return -1;
	}

	peer_username = request_queue.front();
	request_queue.pop();
	return request_queue.size();
}

/**
 * Add a new received request to talk.
 * 
 * @param peer_username name of the user who sent the request
 * 
 * @return 1 on success, -1 if the client is already talking
 */
int thread_bridge::add_request_talk(const string& peer_username)
{
	unique_lock<mutex> lock1(mx_talk_status); 
	if (is_talking) { // TODO necessario?
		return -1;
	}
	lock1.unlock();
	
	unique_lock<mutex> lock2(mx_request_talk);
	request_queue.push(peer_username);
	return 1;
}

void thread_bridge::modify_talking_status (const bool new_status) // TODO necessario?
{
	unique_lock<mutex> lock(mx_talk_status);
	is_talking = new_status;
}