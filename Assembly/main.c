/*
   Program: Inline Assembly Introduction
   Author : Yousef Abdalla
   Part of the Assembly Basics Folder
 					                    */

#include "stdio.h"

void sayHi(void) {
    printf("Hello!\n");
}

int Adder(int x, int y) {
    printf("%d+%d=\n", x, y);
    return x + y;
}

unsigned long get_stackBP(void) {
    __asm__("movl %ebp,%eax");
}


int main() {


    // ----------------------------------------- Comment back in one at a time -----------------------------------------

    // ----------------------------------------------- Output to C side ------------------------------------------------

/*------- 1st Start --------

     unsigned int pPeb;

    asm( "movl $10, %%eax;" // Set eax to 10
          "addl $1, %%eax;" // Add 1 to eax (=11)
          "imul $2, %%eax;" // Multiply eax by 2 (=22)
          "movl %%eax, %%ebx;" // Copy the 22 to ebx
         // "subl $2, %%ebx;" // Subtract 2 from ebx (ebx=20)
          "inc %%eax;" // Increment eax (=23)
          "dec %%eax;" // Decrement eax (=21)
          "movl %%eax, %0;" //Output to C side of program
          : "=r" (pPeb)
          );

     printf("%d", pPeb);

*///------- 1st End --------

    // --------------------------------------------------- Input from C side -------------------------------------------

/*------- 2nd Start --------

    int src = 3;
    int dst;

    asm ("mov %1, %0\n\t" // Move from source to destination
         "add $1, %0" // Add 1 to destination
    : "=r" (dst)
    : "r" (src));

    printf("%d\n", dst);

*///------- 2nd End --------

    // ----------------------------------------------- Example of Conditional Jump -------------------------------------

// ------- 3rd Start --------

    int state = 0;

    asm ("movl $1, %%eax;" // Store 1 in A
         "movl $2, %%ebx;" // Store 2 in B
         "movl $2, %%ecx;" // Store 2 in C
         "movl $4, %%edx;" // Store 4 in D
         "cmp %%ecx, %%ebx;" // Compare C and B
         "je equal;"        // Jump is equal
         "movl $3, %%eax;" // Jump over derail instruction

         "equal: ;"         // Label equal:
         "movl %%eax, %0;" // Move to C side of program
         : "=r" (state)

         );

    if (state == 1)
        printf("Equal");

//------- 3rd End --------

    // ----------------------------------------- Several Simple Examples Below -----------------------------------------

/*------- 4th Start --------

    int state = 0;
    int nill = 0;
    int staten = 0;
    long unsigned int funcAddr = (long unsigned int)&sayHi;

    //sayHi();

     // ----- Making a Loop ------

    asm ("movl $0, %%eax;" // Store 0 in A
         "movl $10, %%ebx;" // Store 10 in B
         "movl $5, %%ecx;" // Stored 5 in C
         "loop:"  // Start loop
         "inc %%eax;" // Inc A
         "cmp %%ebx, %%eax;" // Compare A to B
         "jl loop;" // Jump to label "loop:" if A is less than B
         "movl %%eax, %0;" // Output A to C side when loop is complete to validate
    : "=r" (state)
    );

     // ----- Push, Pop, & Call void function ------

     asm ("mov %1, %%edi;" // Move the address of sayHi() to Destination Index (note % instead of $)
          "push %%eax;" // Push A to Stack
          "push %%ecx;" // Push C to top of stack
          "call *%%edi;" // Call the function in Destination Index (i.e. Say Hello!)
          "pop %%ecx;" // Pop C back from top of stack (i.e. restore values previously saved on stack)
          "pop %%eax;" // Pop A back stack
         : "=r" (nill) // Compulsory line
         : "r" (funcAddr)); // Insert the C variable funcAddr to Assembly

     // ----- Testing the effect of a new Asm() block on register values ------ No effect

    asm ("subl $2, %%eax;" // Subtract 2 from A (=8)
         "push %%ecx;" // Push C into stack (5 at Stack)
         "movl %%eax, %%ecx;" // Overwrite C with contents of A (= 8) - To be overwritten again in next line
         "pop %%ecx;" // Restore value at top of stack into C (=5)
         "movl %%ecx, %0;"
       : "=r" (staten)
         );

        printf("%d %d", state, staten);

*///------- 4th End --------

    // ----------------------------------------- Call and pass parameter to function -----------------------------------

/*------- 5th Start --------

   int result = 0;
   long unsigned int funcAddr = (long unsigned int)&Adder;

    asm ("movl $3, %%ebx;" // Store 3 in B
         "movl $2, %%ecx;" // Stored 2 in C
         "movl %1, %%edi;" // Move the address of sayHi() to Destination Index
         "push %%ebx;" // Push B to Stack
         "push %%ecx;" // Push C to top of stack
         "call *%%edi;" // Call the function in Destination Index
         // "ret;"
         "movl %%eax, %0;" // Value returned is stored in eax
        : "=r" (result) // Compulsory line
        : "r" (funcAddr)); // Insert the C variable funcAddr to Assembly

        printf("%d", result);

*///------- 5th End --------

    // -------------------------------------- Obtain register address --------------------------------------------------
    /* Bonus */
    // printf("0x%x\n", get_stackBP());

    return 0;
}
