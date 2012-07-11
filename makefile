AR := ar cr
GXX := g++
FLAGS := -w -c

simSock.o: simSock.cpp
	$(GXX) $(FLAGS) simSock.cpp

clean:
	rm -rf *.o *.a
