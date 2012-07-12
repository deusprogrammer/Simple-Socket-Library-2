//CLIENT EXAMPLE
//A simple echo server client that implements SSL
#include "simSock.h"
#include <stdio.h>

int main() {
   SSLTCPSocket *client = new SSLTCPSocket(CLIENT);
   char buffer[1024] = "Hello";

   client->connect("127.0.0.1", "1337");

   client->write(buffer, 1024);
   client->read(buffer, 1024);
   client->close();

   printf("%s\n", buffer);

   return 0;
}
