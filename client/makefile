LFLAGS = -Wall -pthread -lcrypto -std=c++14 -Wno-unknown-pragmas
CFLAGS = -c -Wall -std=c++14 -Wno-unknown-pragmas

all: client.exe

client.exe: client.o client_class.o thread_bridge.o
	g++ $(LFLAGS) client.o client_class.o thread_bridge.o -o client.exe

client.o: client.cpp
	g++ $(CFLAGS) client.cpp

client_class.o: client_class.cpp
	g++ $(CFLAGS) client_class.cpp
	
thread_bridge.o: thread_bridge.cpp
	g++ $(CFLAGS) thread_bridge.cpp

clean:
	rm *.o client.exe
