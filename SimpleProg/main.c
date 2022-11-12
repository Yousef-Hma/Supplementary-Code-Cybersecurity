
#include <stdio.h>  // Import I/O library

// Calculate the volume of a rectangle
int CalcVol(int length, int width, int height)
{
    int rectVol = length * width * height; // Calculate volume
    return rectVol; // Return calculated value
}

// Program entry point
int main()
{
    int length = 5, width = 0, height = 7, volume = 0; // Declare and initialize variables
    volume = CalcVol(length, width, height); // Call function and obtain returned value
    printf("Volume of the rectangle is %d", volume); // Print the volume

    return 0; // Exit program with no error
}
