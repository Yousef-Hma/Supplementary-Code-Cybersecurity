#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

int main()
{
    DWORD pWinExec;

    asm(
        // Section 1: Find kernel.dll base address
            "xor %%eax, %%eax;"                 	// EAX = 0
            "movl %%fs:0x30(%%eax), %%ebx;"       	// EBX = PEB(Process Environment Block) // Using offset fs:0x30 (Segment:offset)
            "movl 0xc(%%ebx), %%ebx;"     			// EBX = PEB_LDR_DATA // using offset 0xc
            "movl 0x14(%%ebx), %%ebx;"     			// EBX = LDR->InMemoryOrderModuleList // using offset 0x14 (First list entry)
            "movl (%%ebx), %%ebx;"         			// EBX = second list entry (ntdll.dll) // in InMemoryOrderModuleList (offset 0x00)
            "movl (%%ebx), %%ebx;"                  // EBX = third list entry (kernel32.dll) // in InMemoryOrderModuleList (offset 0x00)
            "movl 0x10(%%ebx), %%ebx;"     			// EBX = base address of kernel32.dll // using offset 0x10 from EBX

        // Section 2: Get address of GetProcAddress
            "movl 0x3c(%%ebx), %%edx;"     			// EDX = Relative Virtual Memory (RVA) of the PE signature (base address + 0x3c)
            "addl %%ebx, %%edx;"           			// EDX = Address of PE signature = base address + RVA of PE signature
            "movl 0x78(%%ebx), %%edx;"              // EDX = RVA of Export Table = Address of PE + offset 0x78
            "addl %%ebx, %%edx;"                    // EDX = Address of Export Table = base address + RVA of export table
            "movl 0x20(%%ebx), %%esi;"              // ESI = RVA of Name Pointer Table = Address of Export Table + 0x20
            "addl %%ebx, %%esi;"                    // ESI = Address of Name Pointer Table = base address + RVA of Name Pointer Table
            "xor %%ecx, %%ecx;"                     // ECX = 0

            // Loop thru arrays to find function name starting with WinE
            // first 4 chars of WinExec Function name are WinE : 0x57 0x69 0x6E 0x45 -> 0x456E6957

            "loopSearch:"
            "inc %%ecx;"                            // ECX = 1
            "lodsl;"                        	    // Load next entry in list into EAX
            "addl %%ebx, %%eax;"                  	// EAX = Address of entry = base address + Address of Entry
            "cmpl $0x50746547, %%eax;"          	// Compare first byte to GetP
            "jne loopSearch;"                      	// Start over if not equal
            "cmpl $0x41636f72, 0x4(%%eax);"          	// Compare second byte to rocA
            "jne loopSearch;"                       // Start over if not equal

            "movl 0x24(%%edx), %%edi;"              // EDI = RVA of Ordinal Table = Address of Export Table + offset 0x24
            "addl %%ebx, %%edi;"                    // EDI = Address of Ordinal Table = base address + RVA of Ordinal Table
            "movw (%%edi,%%ecx,2), %%cx;"           // CX = Number of Function = Address of Ordinal Table + Counter * 2
            "dec %%ecx;"                            // Decrement ECX
            "movl 0x1c(%%edx), %%edi;"              // EDI = Offset address table
            "addl %%ebx, %%edi;"                    // EDI = Offset address table
            "movl (%%edi,%%ecx,4), %%edx;"          // EDX = Pointer(offset)
            "addl %%ebx, %%edx;"                    // EDX = getProcAddress
            "movl %%edx, %%ebp;"                    // Save getProcAddress in EBP for future purpose

        // Section 3: Use LoadLibrary to load User32.dll
            "xor %%ecx, %%ecx;"                     // ECX = 0
            "push %%ecx;"                           // Push ECX onto stack
            "push $0x41797261;"                     //
            "push $0x7262694c;"                     // AyrarbiLdaoL
            "push $0x64616f4c;"                     //
            "push %%esp;"                           //
            "push %%ebx;"                           // kernel32.dll
            "call %%edx;"                           // Call and find LoadLibraryA address

            "push $0x61616c6c;"                     //
            "subl $0x6161, 0x2(%%esp);"             // User32.dll
            "push $0x642e3233;"                     //
            "push $0x72657355;"                     //
            "push %%esp;"                           //
            "call %%eax;"                           // Call LoadLibrary and User32.dll

        // Section 4: Use GetProcAddress to find the address of MessageBox
            "push $0x6141786f;"                     // aAxo
            "subl $0x61, 0x3(%%esp);"               //
            "push $0x42656761;"                     // Bega
            "push $0x7373654d;"                     // sseM
            "push %%esp;"                           //
            "push %%eax;"                           // User32.dll
            "call %%ebp;"                           // GetProcAddress(User32.dll, MessageBoxA)

        // Section 5: Specify the function parameters
            "addl $0x10, %%esp;"
            "xor %%edx, %%edx;"
            "xor %%ecx, %%ecx;"
            "push %%edx;"
            "push $0x6b636148;"
            "movl %%esp,%%edi;"
            "push %%edx;"
            "push $0x656e6f44;"
            "movl %%esp,%%ecx;"

        // Section 6: Call the function
            "push %%edx;"
            "push %%edi;"
            "push %%ecx;"
            "push %%edx;"
            "call %%eax;"

            "movl %%eax, %0;" : "=r" (pWinExec)     // return computed address back to c code
       );

    printf( "\n MessageBoxA() address obtained from User32.dll export table using assembly only: 0x%x\n\n", pWinExec );

    return 0;
}
