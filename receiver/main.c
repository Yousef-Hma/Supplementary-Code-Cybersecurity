#include <stdio.h>
#define _WIN32_WINNT 0x600  // Needed for the MinGW compiler
#include <winsock2.h>   // The header for Winsock
#include <ws2tcpip.h>   // Winsocks TCP/IP header
#include <windows.h>    // Stand windows header

char message[4096]; // 4kB buffer for received message

#define PORT "9032" // Port the application will be listening on

void anotherFunc()
{
    printf("This message is coming from another function.\n");
    return;
}

void processMessage()
{
    char senderName[64];
    char messageContent[128];

    // Extract the message
    strcpy(senderName, message);
    strcpy(messageContent, message+strlen(senderName)+1);
    // Display the formatted message
    printf("\n===========================================================================\n"
           "Message from: %.63s\n"
           "===========================================================================\n"
           "%.127s\n"
           "===========================================================================\n\n", senderName, messageContent);

           return;
}

int main()
{
    // Declare some variables that will be used by the program
    WSADATA wsaData; // Filled with information about Winsock version

    struct addrinfo addrHints;  // Used to tell Windows type of connection want to use
    struct addrinfo *addrUsed;  // Filled by Windows to give details of connection that can be used

    SOCKET listenSock;  // Socket used to listen for connections
    SOCKET dataSock;    // Socket used to handle the connection when it is made

    int i,j;

    // Initialise Winsock
    i = WSAStartup(MAKEWORD(2,2), &wsaData);

    if( i != 0 )
    {
        printf("WSAStartup failed with error: %d\n", i);
        exit(1);
    }

    printf("Setting up connection & address settings ... \n");

    // Set all variables in the addrInfo structure to zero
    memset(&addrHints, 0x00, sizeof(addrHints));

    // Specify what you would like the connection to be
    addrHints.ai_family = AF_INET;  // Use old-style IPVP IP addresses
    addrHints.ai_socktype = SOCK_STREAM;    // TCP compatible socket, SOCK_DGRAM = UDP
    addrHints.ai_protocol = IPPROTO_TCP;    // use the TCP protocol
    addrHints.ai_flags = AI_PASSIVE;    // a standard "listening" socket

    // Ask windows to setup the connection
    if((i = getaddrinfo(NULL,PORT, &addrHints, &addrUsed)) != 0)
    {
        printf("getaddrinfo failed with error: %d\n", i);
        WSACleanup();
        exit(1);
    }

    printf("Creating a socket to listen on ...\n");

    if((listenSock = socket(addrUsed->ai_family,
                            addrUsed ->ai_socktype,
                            addrUsed ->ai_protocol)) == -1)
    {
        printf("socket failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(addrUsed);
        WSACleanup();
        exit(1);
    }

    if(bind(listenSock, addrUsed ->ai_addr, addrUsed -> ai_addrlen) == -1)
    {
        printf("bind failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(addrUsed);
        closesocket(listenSock);
        WSACleanup();
        exit(1);
    }

    // Address settings no longer needed as connection has been initialised
    freeaddrinfo(addrUsed);

    printf("Setting socket to listen ...\n");
    if(listen(listenSock, SOMAXCONN) == -1)
    {
        printf("listen failed with error: %d\n", WSAGetLastError());
        closesocket(listenSock);
        WSACleanup();
        exit(1);
    }

    printf("Waiting to accept a connection ... \n");

    // The incoming connection is transferred from the listening socket to a new socket
    // this frees up the listening socket to keep listening for more connections
    dataSock = accept(listenSock, NULL, NULL);

    if(dataSock == INVALID_SOCKET)
    {
        printf("Accept failed with error: %d\n", WSAGetLastError());
        closesocket(listenSock);
        WSACleanup();
        return 1;
    }

    printf("Connection received, waiting for data ...\n");
    while(1)    // Infinite loop to receive data
    {
        // Try to receive up to 4kB of data
        i = recv (dataSock, message, 4096, 0);

        if (i>0)
        {
            // Print some message information
            processMessage();
            printf("\nMessage .... [%d Bytes]\n", i );
            for(j = 0; j<i; j++)
            {
                printf("%c ", message[j]);
            }
            printf("\n");
            for(j = 0; j<i; j++)
            {
                printf("%02x ", (unsigned char) message[j]);
            }
            printf("\n");
        }
        else if (i<0)
        {
            printf("recv failed with error: %d\n", WSAGetLastError());
            closesocket(dataSock);
            WSACleanup();
            exit(1);
        }
        else
        {
            printf("received empty message, exiting\n");
            break;
        }
    }

    closesocket(dataSock);
    closesocket(listenSock);
    WSACleanup();

    return 0;
}
