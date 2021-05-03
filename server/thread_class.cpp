#include "server.h"

void ServerThread::run(Server* serv, const int socket, const sockaddr_in addr)
{
    server = serv;
}
