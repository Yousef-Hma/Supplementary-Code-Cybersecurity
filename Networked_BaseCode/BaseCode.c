#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

/* Use of global variable not ideal but it
 * makes some the examples much easier! */
char message[4096];


void anotherFunc()
{
    printf("This message is coming from another function!\n");
    return;
}

void processMessage() {
    char senderName[64];
    char messageContent[128];

    /* Extract the message */
    strcpy( senderName, message );
    strcpy( messageContent, message+strlen(senderName)+1 );

    /* Display the message */
    printf( "\n===============================================================================\n"
    "Message from: %.63s\n"
    "===============================================================================\n"
    "%.127s\n"
    "===============================================================================\n\n\n\n",
            senderName, messageContent );

    //*((unsigned int*) (&senderName[0]+ 76)) = 0x401350;

    return;
}


int readInput( char *input ) {
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

    return strlen( input );
}


int main() {

    int nameSize, contentSize;
    int i;
    int j = 0;

    /* Put the username and message into a buffer to simulate the data that
     * would be received in the networked application */
    printf( "Enter username: " );
    nameSize = readInput( message );
    printf( "Enter message: " );
    contentSize = readInput( message+strlen(message)+1  );

    /* Display information about the messsage */
    printf( "\nUsername: %s\n", message );
    printf( "Message: %s\n", message+strlen(message)+1 );

    printf( "\nBytes: " );
    for( i = 0; i < nameSize + contentSize + 2; i++ ) {
        printf( "%02x ", (unsigned char) message[i] );
    }
    printf( "\n[username=%d chars,   content=%d chars]\n\n", nameSize, contentSize );

    /* Call the process message function same as in Lab1 */
    processMessage( message );

    /* Some arbitrary commands to execute after the processMessage function
     * (this will make sense later!) */
    j = j + 1;
    j = j + 1;
    j = j + 1;
    printf( "The final value of j is %d\n", j );

    return 0;
}
