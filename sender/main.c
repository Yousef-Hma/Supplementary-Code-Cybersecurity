#define _WIN32_WINNT 0x600
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* headers define the Windows sockets functions (WinSock) */
#include <winsock2.h>
#include <ws2tcpip.h>
/* standard windows header  */
#include <windows.h>

#define PORT "9032"		/* port the application will be listening on */

void readInput( char *input ) {
    char *inptr, *outptr, hex[3];

    // read line from keyboard input
    gets( input );

    // need to convert any hexadecimal character codes to characters
    // This allows you to enter non-ascii characters in later exercises
    hex[2] = '\0';
    inptr = outptr = input;
    while( *inptr ) {
        if( *inptr == '\\' && *(inptr+1) == 'x' ) {
            hex[0] = *(inptr+2);
            hex[1] = *(inptr+3);
            *outptr++ = (char) strtol( hex, NULL, 16 );
            inptr += 4;
        } else {
            *outptr++ = *inptr++;
        }
    }

    *outptr = '\0';
}

int main( int argc, char **argv ) {
	WSADATA wsaData;			/* data structure will be filled with information about the version on Winsock on this PC */

	struct addrinfo addrHints;	/* used to tell Windows what we want to connect to */
	struct addrinfo *addrFound;	/* pointer to structures filled by windows with details of possible connections */

	SOCKET dataSock;			/* socket used to handle the connection when it is made */

	char buffer[4096];			/* 4kB buffer for data to transmit */
	char *msg;					/* pointer to message within buffer */
	char *username;				/* pointer to username within buffer */
	char option;

	int i;						/* for storing error codes */

	char usernameBuffer[1024];
	char ipv4Buffer[64];

	char *inptr, *outptr;
    char hex[3];

	printf( "Enter remote IP address: " );
	gets( ipv4Buffer );

	printf( "Enter username: " );
	readInput( usernameBuffer );

	/* 0. Initialise Winsock */
	printf( "\nInitialising Windows sockets...\n" );

	if( (i = WSAStartup( MAKEWORD(2,2), &wsaData )) != 0 ) {
		printf( "WSAStartup failed with error: %d\n", i );
		return 1;
	}

	/* 1. Ask Windows to initialise a structure that defines the address used for the connection */
	printf( "Setting up connection & address settings...\n" );
	memset( &addrHints, 0x00, sizeof(addrHints) ); 	/* set all variables in the addrInfo structure to zero */

	/* specify what you would like the connection to be */
	addrHints.ai_family = AF_INET;				/* You want an connection compatible with old-style IPV4 IP address family */
	addrHints.ai_socktype = SOCK_STREAM;		/* this means you want a TCP compatible socket, SOCK_DGRAM would specify a UDP compatible socket */
	addrHints.ai_protocol = IPPROTO_TCP;		/* use the TCP protocol */

	/* Ask windows to setup the connection */
	if( (i = getaddrinfo( ipv4Buffer, PORT, &addrHints, &addrFound )) != 0 ) {
		printf( "getaddrinfo failed with error: %d\n", i );
		WSACleanup();
		exit( 1 );
	}


	/* 2. Create the outgoing socket and connect to the remote application */
	printf( "Creating a socket and connecting...\n" );
	/* windows may have found a few possible connections, try to use each in turn until one works */
	do {
		/* create socket */
		if( (dataSock = socket( addrFound->ai_family, addrFound->ai_socktype, addrFound->ai_protocol )) == SOCKET_ERROR ) {
			printf( "socket creation failed (error = %d)\n", WSAGetLastError() );
			WSACleanup();
			exit( 1 );
		}

		/* try to connect to remote address */
		i = connect( dataSock, addrFound->ai_addr, (int) addrFound->ai_addrlen );

	} while( i == SOCKET_ERROR && (addrFound = addrFound->ai_next) ); /* if connection failed, try next connection */

	if( i == SOCKET_ERROR ) {
		/* tried all available addresses and no success */
		printf( "Unable to connect to %s:%s\n", ipv4Buffer, PORT );
		WSACleanup();
		exit( 1 );
	}

	/* username will always be first, followed by message */
	strcpy( buffer, usernameBuffer );
	username = &buffer[0];
	msg = &buffer[strlen(username)+1];

	hex[2] = '\0';

	printf( "Connected, enter messages to send...\n" );
	while( 1 ) {
		/* get message from user */
		printf( "\n: " );

        readInput( msg );

        printf( "Sending bytes: ");
		for( i = 0; i < strlen(username) + strlen(msg) + 2; i++ ) {
            printf( "%02x ", (unsigned char) buffer[i] );
        }

        if( (i = send( dataSock, buffer, (int)strlen(username)+strlen(msg)+2, 0 )) == SOCKET_ERROR ) {
            printf( "send failed with error: %d\n", WSAGetLastError()) ;
            closesocket( dataSock );
            WSACleanup();
            return 1;
        }
	}

	return 0;
}

