all: server.exe

server.exe: server.o server_class.o thread_class.o
	g++ -Wall -pthread -lcrypto server.o server_class.o thread_class.o -o server.exe

server.o: server.cpp
	g++ -c -Wall -g server.cpp

server_class.o: server_class.cpp
	g++ -c -Wall -g server_class.cpp
	
thread_class.o: thread_class.cpp
	g++ -c -Wall -g thread_class.cpp

clean:
	rm *.o server.exe
