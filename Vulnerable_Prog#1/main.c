#include <stdio.h>
#include <stdlib.h>

// Function that displays inputs
void DisplayMessage()
{
    char Username[8]; // 8 bytes allocated for Username
    char Message[8];  // 8 bytes allocated for Message

    printf("Enter a username : "); // Prompt user for Username
    gets(Username);                // Copy Input into Username (Vulnerable Function)

    printf("Enter a message : ");  // Prompt user for Message
    scanf("%s", &Message);         // Copy Input into Message (Another vulnerable function)

    printf("\nUsername : %s\n", Username);
    printf("Message : %s\n", Message);
}

// Program Entry Point
int main()
{
    DisplayMessage(); // Call DisplayMessage(2) Function
}
