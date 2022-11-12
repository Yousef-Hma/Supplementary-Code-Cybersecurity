/* Code to read 32bit executable's own PE header and Import Address Table in c and assembly.
 *
 * P Evans 04/2018
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
    /* To read Process Environment Block */
    DWORD pPeb, pLdr, pListEntry, pWinExec;

    /* To read PE header */
    DWORD IMAGE_BASE_ADDR = 0x0;
    DWORD dwImportDirectoryVA, dwImportDirectorySize;
    PIMAGE_NT_HEADERS pNtHeaders;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor;
    PIMAGE_THUNK_DATA pThunkData, pOriginalThunkData;
    PIMAGE_IMPORT_BY_NAME pImportByName;

   /* Get base address for executable and all loaded DLLs
    * This information is found in the Process Environment Block, located at
    * the address given by offset 0x030 in the FS segment. This address must be
    * obtained by reading the FS register:
    */

    /* Get pointer to the PEB */
    asm(    "movl $1, %%eax;" 
			"movl %%eax, %0;" : "=r"  (pPeb) );

    printf( "pPeb = 0x%x\n", pPeb );

    /* Get pointer to PEB_LDR_DATA from the PEB */
    pLdr = *((DWORD*) (pPeb + 0x0C));

    printf( "pLdr = 0x%x\n", pLdr );

    /* Iterate through linked list in PEB_LDR_DATA */
    printf( "Loaded modules.: \n" );
    for( pListEntry = *((DWORD*) (pLdr + 0x14)); *((DWORD*) (pListEntry+0x10)) != IMAGE_BASE_ADDR; pListEntry = *((DWORD*)pListEntry) ) {

        printf( "%Z@ 0x%x\n", ((DWORD*) (pListEntry+0x1C)), *((DWORD*) (pListEntry+0x10)) );

        /* First loaded module is the executable itself, remember its base address (it is almost certainly 0x00400000) */
        if( !IMAGE_BASE_ADDR ) IMAGE_BASE_ADDR = *((DWORD*) (pListEntry+0x10));
    }
    printf( "\n\n" );

    /* DOS header located at base address */
    pDosHeader = (PIMAGE_DOS_HEADER) IMAGE_BASE_ADDR;

    if( *((char*) pDosHeader) != 'M' || *((char*) pDosHeader+1) != 'Z' ) {
        printf( "Could not find DOS header at base address 0x%x, exiting\n", IMAGE_BASE_ADDR );
        exit( 1 );
    }

    /* Offset to PE header from image base address */
    pNtHeaders = (PIMAGE_NT_HEADERS)( (DWORD) IMAGE_BASE_ADDR+pDosHeader->e_lfanew );

    printf( "e_lfanew offset = 0x%x\n", (unsigned long) &pDosHeader->e_lfanew- (unsigned long)pDosHeader );

    if( *((char*)(&pNtHeaders->Signature)) != 'P' || *((char*)(&pNtHeaders->Signature) + 1) != 'E' ) {
        printf( "Cannot find valid PE header, exiting\n" );
        exit( 1 );
    }

    /* Offset from image base address where import directory is located (DataDirectory[1] is the import directory) */
    dwImportDirectoryVA = pNtHeaders->OptionalHeader.DataDirectory[1].VirtualAddress;

    /* What must be added to pNtHeaders to get addr of DataDirectory[1] */
    printf( "DD[1] offset = 0x%x\n", (unsigned long) &(pNtHeaders->OptionalHeader.DataDirectory[1]) - (unsigned long)pNtHeaders ); /* What must be added to address of first data directory to get VA of DD[1] */

    /* Offset of DataDirectory[1].VirtualAddress into DataDirectory[1] = 0x00 */
    printf( "VA offset = 0x%x\n", (unsigned long) &pNtHeaders->OptionalHeader.DataDirectory[1].VirtualAddress - (unsigned long)&pNtHeaders->OptionalHeader.DataDirectory[1] );

    /* Base address + virtual address gives actual address of first entry in import directory */
    pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR) (IMAGE_BASE_ADDR + dwImportDirectoryVA);

    printf( "pImportDescriptor = 0x%x\n", pImportDescriptor );

    printf( "first thunk offset = 0x%x\n", (unsigned long) &(pImportDescriptor->FirstThunk)-(unsigned long)pImportDescriptor );
    printf( "original first thunk offset = 0x%x\n", (unsigned long)  &(pImportDescriptor->OriginalFirstThunk)-(unsigned long)pImportDescriptor );

    printf( "pThunkData = 0x%x\n", (unsigned long)IMAGE_BASE_ADDR +  pImportDescriptor->FirstThunk );
    printf( "pOriginalThunkData = 0x%x\n", (unsigned long) IMAGE_BASE_ADDR + pImportDescriptor->OriginalFirstThunk );

    /* Loop through each entry in the import directory (1 per loaded DLL) */
    for( ; pImportDescriptor->Characteristics; pImportDescriptor++ ) {
        printf( "\nImported Module: %s\n", IMAGE_BASE_ADDR+pImportDescriptor->Name );

        /* Loop through functions imported from this module - this is the Import Address Table.
         * Only functions that were actually used by this executable will be included in this table
         *
         * pImportDescriptor->OriginalFirstThunk: First item in an array of pointers to imported functions.
         * These point to an IMAGE_IMPORT_BY_NAME structure where the first two bytes can be ignored
         * and the remaining bytes form a NULL terminated string containing the exported function name.
         * The pointers are virtual addresses and so are relative to the image base address.
         *
         * pImportDescriptor->FirstThunk: First item in an array of pointers to imported functions. In the executable (on disk)
         * this array is identical to the OriginalFirstThunk array (virtual address pointer to function name structures) but
         * Windows will have overwritten these pointers with the actual (and absolute) memory addresses of the functions when
         * the executable was loaded into memory.
         *
         * Therefore these two arrays combined give the function name -> memory address mapping.
         */

        for(    pThunkData = (PIMAGE_THUNK_DATA) (IMAGE_BASE_ADDR+pImportDescriptor->FirstThunk),
                pOriginalThunkData = (PIMAGE_THUNK_DATA) (IMAGE_BASE_ADDR+pImportDescriptor->OriginalFirstThunk);
                pThunkData->u1.AddressOfData;
                pThunkData++, pOriginalThunkData++ ) {
            printf( " - 0x%x : %s\n", pThunkData->u1.AddressOfData, IMAGE_BASE_ADDR+pOriginalThunkData->u1.AddressOfData+2 );
         }
    }

	 /* Another example: obtaining the address of a particular function (WinExec) */
    asm(    "movl %%fs:0x30, %%ebx;"       // Get pointer to PEB
            "movl 0x0C(%%ebx), %%ebx;"     // Get pointer to PEB_LDR_DATA
            "movl 0x14(%%ebx), %%ebx;"     // Get pointer to first entry in InMemoryOrderModuleList

			"movl 0x10(%%ebx), %%eax;"     // Image base address into eax
            "movl 0x3c(%%eax), %%edx;"     // get offset to nt headers
            "addl %%eax, %%edx;"           // nt header address

            "xor %%ebx, %%ebx;"
            "movb $0x80, %%bl;"
            "addl %%edx, %%ebx;"
            "movl (%%ebx), %%ebx;"     // dwImportDirectoryVA

            "addl %%eax, %%ebx;"           // pImportDescriptor

            // making the assumption that K32 is the first module that exports functions

            // Get VA of first thunk array -> edx
            "movl 0x10(%%ebx), %%edx;"
            "addl %%eax, %%edx;"

            // Get VA of original first thunk array ->ebx
            "movl (%%ebx), %%ebx;"
            "addl %%eax, %%ebx;"

            // Loop thru arrays to find function name starting with WinE
            // first 4 chars of WinExec Function name are WinE : 0x57 0x69 0x6E 0x45 -> 0x456E6957
            "loop:"
            "movl (%%ebx), %%ecx;"              // get pointer to next function name entry
            "leal 0x02(%%ecx), %%ecx;"          // function names starts 2 bytes after pointer
            "addl %%eax, %%ecx;"                // address is relative so add image base address to get absolute address of function name
            "movl (%%ecx), %%ecx;"              // load value pointed to by ecx into eco (loads first 4 bytes of function name into ecx)
            "cmpl $0x456E6957, %%ecx;"          // testing value in ecx - result used later
            "leal 0x04(%%ebx), %%ebx;"          // advance function name pointer
            "leal 0x04(%%edx), %%edx;"          // advance function address pointer
            "jne loop;"                         // conditional jump: when compiled this translates to a "jne -0x17" instruction

            // rewind edx to value before last increment and load value it points to into edx
            "dec %%edx;"
            "dec %%edx;"
            "dec %%edx;"
            "dec %%edx;"

            "movl (%%edx), %%edx;"

            "movl %%edx, %0;" : "=r" (pWinExec)     // return computed address back to c code
            );

    printf( "\nWinExec() address obtained from executable import table using assembly only: 0x%x\n", pWinExec );

     /* Add calls to functions that you want to appear in the IAT below... */
    WinExec( "", 0x05 );
	system( "pause" );

    return 0;
}
