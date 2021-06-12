#include "client.h"

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

void thread_bridge::insert_new_message(unsigned char* msg, size_t msg_len)
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

bool thread_bridge::check_request_talk ()
{
	// TODO
}