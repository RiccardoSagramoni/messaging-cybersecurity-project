LFLAGS = -Wall -g -pthread -lcrypto -std=c++14 -Wno-unknown-pragmas
CFLAGS = -c -Wall -g -std=c++14 -Wno-unknown-pragmas

all: client.exe

client.exe: client.o client_class.o
	g++ $(LFLAGS) client.o client_class.o -o client.exe

client.o: client.cpp
	g++ $(CFLAGS) client.cpp

client_thread_class.o: client_thread_class.cpp
	g++ $(CFLAGS) client_thread_class.cpp

clean:
	rm *.o client.exe
