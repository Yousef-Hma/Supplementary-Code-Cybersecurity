/* Code to read kernel32.dll export table when loaded into a 32bit program in c and assembly.
 *
 * P Evans 09/2020
 *
 * Refs:
 *  https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb
 *	https://docs.microsoft.com/en-gb/windows/win32/api/winternl/ns-winternl-peb_ldr_data
 *  
 *  https://msdn.microsoft.com/en-us/library/ms809762.aspx
 */

#include <stdio.h>
#include <Windows.h>

int main( int argc,char *argv[] ) {
   DWORD KERNEL32_BASE_ADDR;

	PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeaders;
    PIMAGE_EXPORT_DIRECTORY pExportDescriptor;

    DWORD* Address, *Name;
    WORD* Ordinal;

    DWORD pPeb, pLdr, pListEntry, pWinExec;

	WORD i;

   /* Get base address for executable and all loaded DLLs
    * This information is found in the Process Environment Block, located at
    * the address given by offset 0x030 in the FS segment. This address must be
    * obtained by reading the FS register:
    */
	asm(    "movl %%fs:0x30, %0;" : "=r"  (pPeb) );

    printf( "pPeb = 0x%x\n", pPeb );

    /* Get pointer to PEB_LDR_DATA from the PEB */
    pLdr = *((DWORD*) (pPeb + 0x0C));

    printf( "pLdr = 0x%x\n", pLdr );

    /* Rertieve 3rd entry in PEB_LDR_DATA  - kernel32.dll */
    printf( "Loaded modules.: \n" );

	pListEntry = *((DWORD*) (pLdr + 0x14));		//1 - executable
	pListEntry = *((DWORD*) pListEntry);	    //2 - nt.dll
	pListEntry = *((DWORD*) pListEntry);	    //3 - kernel32.dll

	KERNEL32_BASE_ADDR = *((DWORD*) (pListEntry+0x10));

    pDosHeader = (PIMAGE_DOS_HEADER) KERNEL32_BASE_ADDR;

	if( *((char*) pDosHeader) != 'M' || *((char*) pDosHeader+1) != 'Z' ) {
        printf( "Could not find DOS header at base address 0x%x, exiting\n", KERNEL32_BASE_ADDR );
        exit( 1 );
    }

    pNtHeaders = (PIMAGE_NT_HEADERS)(KERNEL32_BASE_ADDR+pDosHeader->e_lfanew );

	printf( "e_lfanew offset = 0x%x\n", (unsigned long) &pDosHeader->e_lfanew- (unsigned long)pDosHeader );

    printf( "Address of k32 = 0x%x\n", pDosHeader );
    printf( "Address of ntHeaders = 0x%x\n\n", pNtHeaders );

    pExportDescriptor=(PIMAGE_EXPORT_DIRECTORY)(KERNEL32_BASE_ADDR + pNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);

    printf( "Offset to DD VA = 0x%x\n\n", (unsigned long) &(pNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress) - (unsigned long) (pNtHeaders) );

    Address = 	(DWORD*) (KERNEL32_BASE_ADDR+pExportDescriptor->AddressOfFunctions);
    Name =		(DWORD*) (KERNEL32_BASE_ADDR+pExportDescriptor->AddressOfNames);
    Ordinal =	(WORD*) (KERNEL32_BASE_ADDR+pExportDescriptor->AddressOfNameOrdinals);

    printf( "Offset to address array = 0x%x\n", (unsigned long) &(pExportDescriptor->AddressOfFunctions) - (unsigned long) (pExportDescriptor) );
    printf( "Offset to name array = 0x%x\n", (unsigned long) &(pExportDescriptor->AddressOfNames) - (unsigned long) (pExportDescriptor) );
    printf( "Offset to ordinal array = 0x%x\n\n", (unsigned long) &(pExportDescriptor->AddressOfNameOrdinals) - (unsigned long) (pExportDescriptor) );

    printf( "Number of functions exported by kernel32.dll:%d\n", pExportDescriptor->NumberOfFunctions );
	/* In c example will print out entire dll export table */
    for( i = 0; i < pExportDescriptor->NumberOfFunctions; i++ ) {
        printf( "0x%x:  %s\n", KERNEL32_BASE_ADDR+Address[Ordinal[i]], KERNEL32_BASE_ADDR+Name[i] );
    }


    asm(    "xor %%eax, %%eax;"                 	// inclusion of eax when obtaining offset necesaary to eliminate null bytes in code
            "movl %%fs:0x30(%%eax), %%ebx;"       	// Get pointer to PEB
            "movl 0x0C(%%ebx), %%ebx;"     			// Get pointer to PEB_LDR_DATA
            "movl 0x14(%%ebx), %%ebx;"     			// Get pointer to first entry in InMemoryOrderModuleList
            "movl (%%ebx), %%ebx;"         			// Get pointer to second (should be ntdll.dll) entry in InMemoryOrderModuleList
            "movl (%%ebx), %%ebx;"
			"movl 0x10(%%ebx), %%eax;"     			// Address of kernel32.dll into eax

            "movl 0x3c(%%eax), %%edx;"     			// get offset to nt headers
            "addl %%eax, %%edx;"           			// nt header address

            "xor %%ebx, %%ebx;"
            "movb $0x78, %%bl;"
            "addl %%edx, %%ebx;"

            "movl (%%ebx), %%ebx;"          		// exportDirectoryVA
            "addl %%eax, %%ebx;"           			// pExportDirectory

            // Get VA of ordinal array
            "movl 0x24(%%ebx), %%edx;"
            "addl %%eax, %%edx;"					// add base address to get pointer
            "push %%ebx;"                   		// ebx contains address of export table, will need this later

            // Get VA of name array
            "movl 0x20(%%ebx), %%ebx;"
            "addl %%eax, %%ebx;"            		// add base address to get pointer

            // Loop thru arrays to find function name starting with WinE
            // first 4 chars of WinExec Function name are WinE : 0x57 0x69 0x6E 0x45 -> 0x456E6957
            "loopexp:"
            "movl (%%ebx), %%ecx;"              	// get pointer to next function name entry
            "leal (%%ecx), %%ecx;"              	// resolve name pointer to get first 4 bytes of name
            "addl %%eax, %%ecx;"                	// address is relative so add image base address to get absolute address of function name
            "movl (%%ecx), %%ecx;"              	// load value pointed to by ecx into eco (loads first 4 bytes of function name into ecx)
            "cmpl $0x456E6957, %%ecx;"          	// testing value in ecx - result used later
            "leal 0x04(%%ebx), %%ebx;"          	// advance function name pointer
            "leal 0x02(%%edx), %%edx;"          	// advance ordinal pointer
            "jne loopexp;"                         	// conditional jump: when compiled this translates to a short jump back to start of loop

            // rewind edx to value before last increment and load value it points to into edx
            "dec %%edx;"
            "dec %%edx;"
            "movl (%%edx), %%edx;"          		// lower 16 bits of edx now contain ordinal

            // wipe 16 most significant bits
            "shl $0x10, %%edx;"
            "shr $0x10, %%edx;"

            "pop %%ebx;"                      		// retrieve address of export table
            "movl 0x1c(%%ebx), %%ebx;"        		// get VA of address array
            "addl %%eax, %%ebx;"              		// get pointer to address array


            "addl %%edx, %%ebx;"                	// add on ordinal to get correct location in address array
            "addl %%edx, %%ebx;"					// (4x because 4 bytes per array entry - array of 32 bit numbers)
            "addl %%edx, %%ebx;"
            "addl %%edx, %%ebx;"

            "movl (%%ebx), %%edx;"            		// resolve pointer to get address VA
            "addl %%eax, %%edx;"              		// Add base address to get pointer to address array

            "movl %%edx, %0;" : "=r" (pWinExec)     // return computed address back to c code
            );

    printf( "\nWinExec() address obtained from kernel32.dll export table using assembly only: 0x%x\n\n", pWinExec );
	
	system( "pause" );

    return 0;
}
