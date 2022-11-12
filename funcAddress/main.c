/* Code to read 32bit executable's own PE header and Import Address Table
 *
 * P Evans 04/2018
 *
 * Refs:
 *  https://msdn.microsoft.com/en-us/library/windows/desktop/aa813706(v=vs.85).aspx
 *  https://msdn.microsoft.com/en-us/library/windows/desktop/aa813708(v=vs.85).aspx
 *
 *  https://msdn.microsoft.com/en-us/library/ms809762.aspx
 */

#include <windows.h>
#include <stdio.h>


int main(int argc,char *argv[]) {
    /* To read Process Environment Block */
    DWORD pPeb, pLdr, pListEntry, pk32;

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
    asm(    "movl %%fs:0x30, %0;" : "=r"  (pPeb) );


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

    if( *((char*)(&pNtHeaders->Signature)) != 'P' || *((char*)(&pNtHeaders->Signature) + 1) != 'E' ) {
        printf( "Cannot find valid PE header, exiting\n" );
        exit( 1 );
    }

    /* Offset from image base address where import directory is located (DataDirectory[1] is the import directory) */
    dwImportDirectoryVA = pNtHeaders->OptionalHeader.DataDirectory[1].VirtualAddress;

    /* Base address + virtual address gives actual address of first entry in import directory */
    pImportDescriptor = IMAGE_BASE_ADDR + dwImportDirectoryVA;

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

        for(    pThunkData = IMAGE_BASE_ADDR+pImportDescriptor->FirstThunk,
                pOriginalThunkData = IMAGE_BASE_ADDR+pImportDescriptor->OriginalFirstThunk;
                pThunkData->u1.AddressOfData;
                pThunkData++, pOriginalThunkData++ ) {
            printf( " - 0x%x : %s\n", pThunkData->u1.AddressOfData, IMAGE_BASE_ADDR+pOriginalThunkData->u1.AddressOfData+2 );
         }
    }


	 /* Another example: obtaining the base address for kernel32.dll from import directory using pure assembly
	  *  - If you search for examples of shellcode online you'll find that many look very similar to this at the beginning. */
    asm(    "movl %%fs:0x30, %%ebx;"       // Get pointer to PEB
            "movl 0x0C(%%ebx), %%ebx;"     // Get pointer to PEB_LDR_DATA
            "movl 0x14(%%ebx), %%ebx;"     // Get pointer to first entry in InMemoryOrderModuleList
            "movl (%%ebx), %%ebx;"         // Get pointer to second (should be ntdll.dll) entry in InMemoryOrderModuleList
            "movl (%%ebx), %%ebx;"         // Get pointer to third (should be kernel32.dll) entry in InMemoryOrderModuleList
            "movl 0x10(%%ebx), %%ecx;"     // Get kernel32.dll base address from InMemoryOrderModuleList entry - this could then be used to guess the location of a particular function, i.e. WinExec
            "movl %%ecx, %0;" : "=r" (pk32)     // return computed address back to c code
            );

    printf( "\nkernel32.dll address obtained using assembly only: 0x%x\n", pk32 );

     /* Add calls to functions that you want to appear in the IAT below... */
    WinExec( "", 0x05 );
	system( "pause" );

    return 0;
}


