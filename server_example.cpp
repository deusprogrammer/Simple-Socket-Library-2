//SERVER EXAMPLE 
//A simple echo server that implements SSL
#include "simSock.h"
#include <stdio.h>

int main() {
   SSLTCPSocket *listener = new SSLTCPSocket(LISTENER);
   Socket *client;
   char buffer[1024];
   char workBuffer[1024];

   listener->bind("1337");

   while (client = listener->accept()) {
      //Socket ready for read and write operations
      client->read(buffer, 1024);
      sprintf(workBuffer, "ECHO: %s\n", buffer);
      client->write(workBuffer, 1024);
      client->close();
   }

   return 0;
}
