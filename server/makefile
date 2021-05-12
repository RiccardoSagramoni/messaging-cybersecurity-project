LFLAGS = -Wall -pthread -lcrypto -std=c++14
CFLAGS = -c -Wall -g -std=c++14

all: server.exe

server.exe: server.o server_class.o thread_class.o
	g++ $(LFLAGS) server.o server_class.o thread_class.o -o server.exe

server.o: server.cpp
	g++ $(CFLAGS) server.cpp

server_class.o: server_class.cpp
	g++ $(CFLAGS) server_class.cpp
	
thread_class.o: thread_class.cpp
	g++ $(CFLAGS) thread_class.cpp

clean:
	rm *.o server.exe
