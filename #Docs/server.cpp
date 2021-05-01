#include <thread>
#include <mutex>

using namespace std;

struct ??? {
	int socket;
	mutex out;
	mutex in;

	// chiave pubblica
};

class Server {
	// unordered_map (utente, sock); --> hash_map
	// mutex per hash map

public:
	// costruttore distruttore
	// getSocketOutput
	// releaseSocketOutput ???
};

class Thread {
	Server* server;

	// invia 	(crypto?)
	// ricevi 	(crypto?)

	// login
    // talk
    // show
    // logout
public:
    void operator()(Server*, ...); //--> ricevi comando, esegui

};

int main (int argc, char** argv)
{
	// configura server
	// configurazione socket listener

	// listen

	while (true) {
		// accept
		// crea nuovo thread
	}
}



















