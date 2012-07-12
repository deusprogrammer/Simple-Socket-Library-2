AR := ar cr
GXX := g++
FLAGS := -w -c

all: server_test client_test

simSock.o: simSock.cpp
	$(GXX) $(FLAGS) simSock.cpp

server_test: simSock.o server_example.cpp
	$(GXX) -w simSock.o server_example.cpp -o server_test -lssl

client_test: simSock.o client_example.cpp
	$(GXX) -w simSock.o client_example.cpp -o client_test -lssl

clean:
	rm -rf *.o *.a client_test server_test
