#include "simSock.h"

bool Socket::setNoBlock() {
   int ret = -1;
   int flags;

   if (sock >= 0) {
      flags = fcntl(sock, F_GETFL, 0);
      ret = fcntl(sock, F_SETFL, flags | O_NONBLOCK);

      if (ret < 0) {
         perror("fcntl failed...");
      }
   }
   else {
      printf("Socket isn't initialized!\n");
   }

   return ret != -1;
}

bool TCPSocket::setNoBlock() {
   int ret = -1;
   int flags;

   if (sock >= 0) {
      flags = fcntl(sock, F_GETFL, 0);
      ret = fcntl(sock, F_SETFL, flags | O_NONBLOCK);

      if (ret < 0) {
         perror("fcntl failed...");
      }
   }
   else {
      printf("Socket isn't initialized!\n");
   }

   return ret != -1;
}

bool TCPSocket::connect(char* hostname, char* port) {
   if (endPoint != CLIENT)
      return false;

   SOCKET client;

   if (OpenClientSocket(&client, hostname, port, IPV4, TCP) == -1)
      return false;

   this->setFD(client);
}

bool TCPSocket::bind(char* port) {
   if (endPoint != LISTENER)
      return false;

   SOCKET server;

   if (OpenServerSocket(&server, port, IPV4, TCP) == -1)
      return false;

   this->sock = server;
}

Socket* TCPSocket::accept() {
   if (endPoint != LISTENER)
      return NULL;

   SOCKET client;

   client = AcceptConnection(sock);

   if (client == -1)
      return NULL;

   TCPSocket* tcpClient = new TCPSocket(SERVER);
   tcpClient->setFD(client);

   return tcpClient;
}

int TCPSocket::write(LPVOID data, int buf_sz) {
   if (LISTENER)
      return -1;

   //printf("IN TCPSocket::write()\n");
   return WriteSocket(sock, data, buf_sz);
}

int TCPSocket::read(LPVOID data, int buf_sz) {
   if (LISTENER)
      return -1;

   //printf("IN TCPSocket::read()\n");
   return ReadSocket(sock, data, buf_sz);
}

int TCPSocket::readLine(LPVOID data, int buf_sz) {
   if (LISTENER)
      return -1;

   //printf("IN TCPSocket::readLine()\n");
   return ReadLineSocket(sock, data, buf_sz);
}

void TCPSocket::close() {
   return CloseSocket(sock);
}

SSLTCPSocket::SSLTCPSocket(int endPoint) {
   sock = -1; 
   ssl = NULL;
   this->endPoint = endPoint;

   SSL_load_error_strings();
   SSL_library_init();
   OpenSSL_add_all_algorithms();

   switch (this->endPoint) {
   case CLIENT:
      tlsctx = SSL_CTX_new(SSLv23_client_method());
      break;
   case LISTENER:
      break;
   case SERVER:
   default:
      tlsctx = SSL_CTX_new(SSLv23_server_method());
      SSL_CTX_set_options(tlsctx, SSL_OP_SINGLE_DH_USE);
      SSL_CTX_use_certificate_file(tlsctx, "server.crt" , SSL_FILETYPE_PEM);
      SSL_CTX_use_PrivateKey_file(tlsctx, "server.key", SSL_FILETYPE_PEM);
      break;
   };
}

SSLTCPSocket::~SSLTCPSocket() {
   SSL_free(ssl);
   SSL_CTX_free(tlsctx);

   ERR_free_strings();
   EVP_cleanup();
}

bool SSLTCPSocket::setFD(SOCKET sock) {
   printf("SET FD TO %d\n", sock);

   this->sock = sock;

   if ((ssl = SSL_new(tlsctx)) == NULL) {
      fprintf(stderr, "SSL_new failed!\n");
      return false;
   }

   if (!SSL_set_fd(ssl, sock)) {
      fprintf(stderr, "SSL_set_fd failed!\n");

      SSL_shutdown(ssl);
      SSL_free(ssl);
      return false;
   }

   switch(endPoint) {
   case CLIENT:
      if (SSL_connect(ssl) <= 0) {
         SSL_shutdown(ssl);
         SSL_free(ssl);
         return false;
      }
      break;
   case LISTENER:
      break;
   case SERVER:
   default:
      if (SSL_accept(ssl) <= 0) {
         fprintf(stderr, "SSL_accept failed!\n");

         SSL_shutdown(ssl);
         SSL_free(ssl);
         return false;
      }
      break;
   };

   return true;
}

bool SSLTCPSocket::setNoBlock() {
   int ret = -1;
   int flags;

   if (sock >= 0) {
      flags = fcntl(sock, F_GETFL, 0);
      ret = fcntl(sock, F_SETFL, flags | O_NONBLOCK);

      if (ret < 0) {
         perror("fcntl failed...");
      }
   }
   else {
      printf("Socket isn't initialized!\n");
   }

   return ret != -1;
}

bool SSLTCPSocket::connect(char* hostname, char* port) {
   if (endPoint != CLIENT)
      return false;

   SOCKET client;

   if (OpenClientSocket(&client, hostname, port, IPV4, TCP) == -1)
      return false;

   this->setFD(client);
}

bool SSLTCPSocket::bind(char* port) {
   if (endPoint != LISTENER)
      return false;

   SOCKET server;

   if (OpenServerSocket(&server, port, IPV4, TCP) == -1)
      return false;

   this->sock = server;
}

Socket* SSLTCPSocket::accept() {
   if (endPoint != LISTENER)
      return NULL;

   SOCKET client;

   client = AcceptConnection(sock);

   if (client == -1)
      return NULL;

   SSLTCPSocket* sslClient = new SSLTCPSocket(SERVER);
   sslClient->setFD(client);

   return sslClient;
}

int SSLTCPSocket::write(LPVOID data, int buf_sz) {
   if (endPoint == LISTENER)
      return -1;

   //printf("IN SSLTCPSocket::write()\n");
   return SSL_write(ssl, data, buf_sz);
}

int SSLTCPSocket::read(LPVOID data, int buf_sz) {
   if (endPoint == LISTENER)
      return -1;

   //printf("IN SSLTCPSocket::read()\n");
   return (this->sslError = SSL_read(ssl, data, buf_sz));
}

int SSLTCPSocket::readLine(LPVOID data, int buf_sz) {
   if (endPoint == LISTENER)
      return -1;

   //printf("IN SSLTCPSocket::readline()\n");

   int i = 0;
   int result;
   char c[1];

   do{
      result = SSL_read(ssl, c, 1);
      *(((char*)data) + i) = c[0];
      i++;
   }while(c[0] != '\n' && i < buf_sz && result > 0);

   if(result <= 0) {
      this->sslError = result;
      return -1;
   }
   else
      return i;
}

void SSLTCPSocket::close() {
   SSL_shutdown(ssl);
   CloseSocket(sock);
}

#ifdef _WIN32

int InitializeWS() {
   WSAData wsaData;

   int iResult;

   // Initialize Winsock
   iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
   if (iResult != 0) {
      fprintf(stderr, "WSAStartup failed: %d\n", iResult);
      return -1;
   }

   return 0;
}

int CleanupWS() {
   WSACleanup();

   return 0;
}

#endif

#ifdef _WIN32
int OpenClientSocket(int *pSock, char *hostname, char *port, int ip_version, int type) {
   struct addrinfo *result = NULL,
                *ptr = NULL,
                hints;

   int iResult;

   ZeroMemory( &hints, sizeof(hints) );
   hints.ai_family = ip_version;
   if(type==TCP) {
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_protocol = IPPROTO_TCP;
   }
   else if(type==UDP) {
      hints.ai_socktype = SOCK_DGRAM;
      hints.ai_protocol = IPPROTO_UDP;
   }

   // Resolve the server address and port
   iResult = getaddrinfo(hostname, port, &hints, &result);
   if (iResult != 0) {
      fprintf(stderr, "Unable to resolve host: %s (%d)\n", hostname, WSAGetLastError());
       //WSACleanup();
      return -1;
   }

   *pSock = INVALID_SOCKET;

   // Attempt to connect to the first address returned by
   // the call to getaddrinfo
   ptr=result;

   // Create a SOCKET for connecting to server
   *pSock = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);

   if (*pSock == INVALID_SOCKET) {
      fprintf(stderr, "Error creating socket: %ld\n", WSAGetLastError());
      freeaddrinfo(result);
      //WSACleanup();
      return -1;
   }

   // Connect to server.
   iResult = connect(*pSock, ptr->ai_addr, (int)ptr->ai_addrlen);
   if (iResult == SOCKET_ERROR) {
      closesocket(*pSock);
      *pSock = INVALID_SOCKET;
   }

   freeaddrinfo(result);

   if (*pSock == INVALID_SOCKET) {
      fprintf(stderr, "Unable to connect to server: (%d)!\n", WSAGetLastError());
      //WSACleanup();
      return -1;
   }

   return 0;
}
#else
int OpenClientSocket(int *pSock, char *hostname, char *port, int ip_version, int type) {
   struct addrinfo *result = NULL,
            *ptr = NULL,
            hints;

   int iResult = 0;
   int sock;

   memset(&hints, 0, sizeof(addrinfo));
   hints.ai_family = ip_version;
   hints.ai_flags = AI_PASSIVE;

   if(type==TCP) {
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_protocol = IPPROTO_TCP;
   }
   else if(type==UDP) {
      hints.ai_socktype = SOCK_DGRAM;
      hints.ai_protocol = IPPROTO_UDP;
   }

   // Resolve the server address and port
   iResult = getaddrinfo(hostname, port, &hints, &result);
   if (iResult != 0) {
      fprintf(stderr, "Unable to resolve host: %s (%d)\n", hostname, errno);
      return -1;
   }

   // Attempt to connect to the first address returned by
   // the call to getaddrinfo
   ptr=result;

   // Create a SOCKET for connecting to server
   sock = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);

   if (sock == INVALID_SOCKET) {
      fprintf(stderr, "Error creating socket: %d\n", errno);
      freeaddrinfo(result);
      return -1;
   }

   // Connect to server.
   iResult = connect(sock, ptr->ai_addr, (int)ptr->ai_addrlen);
   if (iResult == SOCKET_ERROR) {
      close(sock);
      return -1;
   }

   freeaddrinfo(result);

   if (sock == INVALID_SOCKET) {
      fprintf(stderr, "Unable to connect to server: (%d)!\n", errno);
      return -1;
   }

   *pSock = sock;

   return 0;
}
#endif

#ifdef _WIN32
int OpenServerSocket(SOCKET *pSock, char *port, int ip_version, int type) {
   int iResult;

   struct addrinfo *result = NULL, *ptr = NULL, hints;

   ZeroMemory(&hints, sizeof (hints));
   hints.ai_family = ip_version;
   hints.ai_flags = AI_PASSIVE;

   if(type==TCP) {
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_protocol = IPPROTO_TCP;
   }
   else if(type==UDP) {
      hints.ai_socktype = SOCK_DGRAM;
      hints.ai_protocol = IPPROTO_UDP;
   }

   // Resolve the local address and port to be used by the server
   iResult = getaddrinfo(NULL, port, &hints, &result);
   if (iResult != 0) {
      fprintf(stderr, "getaddrinfo failed: %d\n", iResult);
      //WSACleanup();
      return -1;
   }

   *pSock = INVALID_SOCKET;

   // Create a SOCKET for the server to listen for client connections
   *pSock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);

   if (*pSock == INVALID_SOCKET) {
      fprintf(stderr, "Error at socket(): %ld\n", WSAGetLastError());
      freeaddrinfo(result);
      //WSACleanup();
      return -1;
   }

   // Setup the TCP listening socket
   iResult = bind(*pSock, result->ai_addr, (int)result->ai_addrlen);
   if (iResult == SOCKET_ERROR) {
      fprintf(stderr, "bind failed: %d\n", WSAGetLastError());
      freeaddrinfo(result);
      closesocket(*pSock);
      //WSACleanup();
      return -1;
   }

   freeaddrinfo(result);

   if(type!=UDP){
      if (listen(*pSock, SOMAXCONN ) == SOCKET_ERROR ) {
         fprintf(stderr, "Listen failed with error: %ld\n", WSAGetLastError() );
         closesocket(*pSock);
         //WSACleanup();
         return -1;
      }
   }

   return 0;
}
#else
int OpenServerSocket(SOCKET *pSock, char *port, int ip_version, int type) {
   int iResult = 0;
   int sock;

   struct addrinfo *result = NULL, *ptr = NULL, hints;

   memset(&hints, 0, sizeof(addrinfo));
   hints.ai_family = ip_version;
   hints.ai_flags = AI_PASSIVE;

   if(type==TCP) {
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_protocol = IPPROTO_TCP;
   }
   else if(type==UDP) {
      hints.ai_socktype = SOCK_DGRAM;
      hints.ai_protocol = IPPROTO_UDP;
   }

   // Resolve the local address and port to be used by the server
   iResult = getaddrinfo(NULL, port, &hints, &result);
   if (iResult != 0) {
      fprintf(stderr, "getaddrinfo failed: %d\n", errno);
      return -1;
   }

   // Create a SOCKET for the server to listen for client connections
   sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);

   if (sock == INVALID_SOCKET) {
      fprintf(stderr, "Error at socket(): %d\n", errno);
      freeaddrinfo(result);
      return -1;
   }

   // Setup the TCP listening socket
   iResult = bind(sock, result->ai_addr, (int)result->ai_addrlen);
   if (iResult == SOCKET_ERROR) {
      fprintf(stderr, "bind failed: %d\n", errno);
      freeaddrinfo(result);
      close(sock);
      return -1;
   }

   freeaddrinfo(result);

   //Start listening on socket
   if (listen(sock, SOMAXCONN ) == SOCKET_ERROR ) {
      fprintf(stderr, "Listen failed with error: %d\n", errno );
      close(sock);
      return -1;
   }

   *pSock = sock;

   return 0;
}
#endif

void CloseSocket(SOCKET sock) {
   #ifdef _WIN32
   closesocket(sock);
   #else
   close(sock);
   #endif
}

SOCKET AcceptConnection(SOCKET sock) {
   SOCKET client = INVALID_SOCKET;

   // Accept a client socket
   client = accept(sock, NULL, NULL);
   if (client == INVALID_SOCKET) {
      CloseSocket(sock);
      return -1;
   }

   return client;
}

int SendToSocket(SOCKET sock, LPVOID data, int len, sockaddr* to) {
   return sendto(sock, (char*)data, len, 0, to, sizeof(sockaddr));
}

int SendToSocket(SOCKET sock, LPVOID data, sockaddr* to) {
   int len = strlen((char*)data);
   return sendto(sock, (char*)data, len, 0, to, sizeof(sockaddr));
}

int RecvFromSocket(SOCKET sock, LPVOID data, int len, sockaddr* from) {
   unsigned int client_length = (int)sizeof(struct sockaddr_in);
   return recvfrom(sock, (char*)data, len, 0, from, (socklen_t*)&client_length);
}

int RecvFromSocket(SOCKET sock, LPVOID data, sockaddr* from) {
   unsigned int client_length = (int)sizeof(struct sockaddr_in);
   int len = strlen((char*)data);
   return recvfrom(sock, (char*)data, len, 0, from, (socklen_t*)&client_length);
}

int WriteSocket(SOCKET sock, LPVOID data, int buf_sz) {
   return send(sock, (char*)data, buf_sz, 0);
}

int WriteSocket(SOCKET sock, LPVOID data) {
   return send(sock, (char*)data, strlen((char*)data)+1, 0);
}

int ReadSocket(SOCKET sock, LPVOID data, int buf_sz) {
   return recv(sock, (char*)data, buf_sz, 0);
}

int ReadLineSocket(SOCKET sock, LPVOID data, int buf_sz) {
   int i = 0;
   int result;
   char c[1];

   do{
      result = recv(sock, c, 1, 0);
      *(((char*)data) + i) = c[0];
      i++;
   }while(c[0] != '\n' && i < buf_sz && result > 0);

   if(result <= 0)
      return -1;
   else
      return i;
}

unsigned long GetConnectedIP(SOCKET *pSock) {
   struct sockaddr_in sin;
   socklen_t len = sizeof(sin);

   if (getpeername(*pSock, (struct sockaddr*)&sin, &len) == -1) {
      return 0;
   }
   else {
      return sin.sin_addr.s_addr;
   }
}

char* GetIPAddressString(unsigned long ip) {
   IPAddress* address = (IPAddress*)&ip;

   char* ipString = new char[32];

   sprintf(ipString, "%d.%d.%d.%d", address->octet[0], address->octet[1], address->octet[2], address->octet[3]);

   return ipString;
}

bool SetSocketNoBlock(SOCKET sock) {
   int flags = fcntl(sock, F_GETFL, 0);
   return fcntl(sock, F_SETFL, flags | O_NONBLOCK);

}
