#define STRICT
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <Imagehlp.h>

#include "Disasm.h"
#include "Asm.h"

#ifndef _PATCHER_H_
#define _PATCHER_H_



#define ALIGN(X,Y)		((((X)%(Y))==0) ? (X) : ((X) + (Y)-((X)%(Y))))
#define ADDR0(rva)		getAddressFromRVA((rva), dos_header, num_sections, section_headers)
#define ADDRI(rva,i)	((BYTE *)dos_header+section_headers[(i)].PointerToRawData+((DWORD)(rva))-section_headers_old[(i)].VirtualAddress)
#define ADDR(rva)		ADDRI(rva, sectIdx)
#define SECT_IDX0(rva)	getSectionIndex((rva), num_sections, section_headers);
#define SECT_IDX(rva)	getSectionIndex((rva), num_sections, section_headers_old)
#define RVA_DELTA(i)	section_headers[(i)].VirtualAddress - section_headers_old[(i)].VirtualAddress
#define SECT_ALIGN		nt_header_old->OptionalHeader.SectionAlignment
#define FILE_ALIGN		nt_header_old->OptionalHeader.FileAlignment

typedef struct _OFF_PATCH_LIST {
	BYTE *point;
	int delta;
	BYTE numBytes;
	struct _OFF_PATCH_LIST *next;
} OFF_PATCH_LIST;

typedef enum {
	EXIT,	// patch code is executed right before a call to ExitProcess() or exit() or _exit
	ENTRY,	// patch code is executed before the PE
} EXEC_POINT;

typedef struct _PATCH {
	BYTE *code;
	DWORD codeSize;
	DWORD codeRVA;
	BYTE jmpto[5];
	BYTE *jmpback;
	DWORD jmpbackSize;
	BYTE* entryPoint;
	BYTE* targetPoint;
	EXEC_POINT execPt;
	OFF_PATCH_LIST *offPatchList;
	RELOCS relocs;
} PATCH;

#define INIT_PATCH(p)		(memset((p), 0x0, sizeof(PATCH)))
															// worst case
#define MAX_PATCH_SZ(p)		((p)->codeSize + 5+15+5 + 1)	// 5+15 for what we replace at AddressOfEntryPoint, 
															// +5 for the jmp-back
															// +1 for 0xCC (int 3)
#define TOTAL_PATCH_SZ(p)	((p)->codeSize + (p)->jmpbackSize + 1) // +1 for 0xCC (int 3)
#define PATCH_FITS_IN_PADDING(p, codeHdr) ((codeHdr)->Misc.VirtualSize < (codeHdr)->SizeOfRawData &&\
											MAX_PATCH_SZ(p) < (codeHdr)->SizeOfRawData - (codeHdr)->Misc.VirtualSize)

typedef struct _PE_HEADERS_PTRS {
	PIMAGE_DOS_HEADER dos_header;
	PIMAGE_NT_HEADERS nt_header;
	PIMAGE_SECTION_HEADER section_headers;
	int number_of_sections;
} PE_HEADERS_PTRS;

typedef struct _DELAY_IMPORT_DESCRIPTOR {
	DWORD Attributes;
	DWORD RVAtoDLLName;
	DWORD RVAtoHMODULE;
	DWORD RVAtoIAT;
	DWORD RVAtoINT;
	DWORD RVAtoBIAT;
	DWORD RVAtoUIAT;
	DWORD TimeDateStamp;
} DELAY_IMPORT_DESCRIPTOR;

void *loadFile(const char *filename, DWORD *fileSize);

//PIMAGE_DOS_HEADER getMappedFile(const char *filename, __int32 * fileSize);

PIMAGE_NT_HEADERS skipDosStub(const PIMAGE_DOS_HEADER dos_ptr);

BOOL getPEHeaders(LPCVOID base, PE_HEADERS_PTRS *headers);

int init(LPCVOID base, PE_HEADERS_PTRS *headers, PIMAGE_DOS_HEADER *dos_header = 0,
	PIMAGE_NT_HEADERS *nt_header = 0, PIMAGE_SECTION_HEADER *section_headers = 0, DWORD *num_sections = 0);

int getSectionIndex(
	const unsigned rva, 
	const int number_of_sections, 
	const PIMAGE_SECTION_HEADER sections);

inline BYTE *getAddressFromRVA(
	DWORD rva, 
	void *base, 
	const int number_of_sections, 
	const PIMAGE_SECTION_HEADER sections) {
	int sectIdx = getSectionIndex(rva, number_of_sections, sections);
	return (BYTE *)base + sections[sectIdx].PointerToRawData + 
		(rva - sections[sectIdx].VirtualAddress);
}

BOOL repairExportDirectory(
	const PIMAGE_DOS_HEADER dos_header, 
	DWORD dirIdx, DWORD sectIdx, 
	PIMAGE_SECTION_HEADER section_headers, 
	PIMAGE_SECTION_HEADER section_headers_old);

BOOL repairImportDirectory(
	const PIMAGE_DOS_HEADER dos_header, 
	DWORD dirIdx, DWORD sectIdx, 
	PIMAGE_SECTION_HEADER section_headers, 
	PIMAGE_SECTION_HEADER section_headers_old);

BOOL repairRsrcDirectory(
	const PIMAGE_DOS_HEADER dos_header, 
	DWORD dirIdx, DWORD sectIdx, 
	PIMAGE_SECTION_HEADER section_headers, 
	PIMAGE_SECTION_HEADER section_headers_old);

BOOL repairRelocDirectory(
	const PIMAGE_DOS_HEADER dos_header, 
	DWORD dirIdx, DWORD sectIdx, 
	PIMAGE_SECTION_HEADER section_headers, 
	PIMAGE_SECTION_HEADER section_headers_old);

BOOL repairDebugDirectory(
	const PIMAGE_DOS_HEADER dos_header, 
	DWORD dirIdx, DWORD sectIdx, 
	PIMAGE_SECTION_HEADER section_headers, 
	PIMAGE_SECTION_HEADER section_headers_old);

BOOL repairDelayIDirectory(
	const PIMAGE_DOS_HEADER dos_header, 
	DWORD dirIdx, DWORD sectIdx, 
	PIMAGE_SECTION_HEADER section_headers, 
	PIMAGE_SECTION_HEADER section_headers_old);

BOOL repairCLIDirectory(
	const PIMAGE_DOS_HEADER dos_header, 
	DWORD dirIdx, DWORD sectIdx, 
	PIMAGE_SECTION_HEADER section_headers, 
	PIMAGE_SECTION_HEADER section_headers_old);

BOOL repairDataDirectory(
	const PIMAGE_DOS_HEADER dos_header, 
	DWORD dirIdx, DWORD sectIdx, 
	PIMAGE_SECTION_HEADER section_headers, 
	PIMAGE_SECTION_HEADER section_headers_old);

DWORD writeDataToFile(
	const char *outFilename, 
	LPCVOID data, 
	DWORD bytesToWrite, 
	DWORD fileOffset = 0);

BOOL hasRelocInRVARange(
	const BYTE *relocs, 
	const DWORD relocsSize,
	const DWORD rva0, 
	const DWORD len);

BOOL removeReloc(LPVOID base, DWORD rva);

void hookPEEntryPoint(PATCH *patch, REL_REFERENCES *relRefs);

void addRRDToOPL(const REL_REF_DEST *rrd, PATCH *patch, int delta);

void buildRelRefOPL(REL_REFERENCES *refs, PATCH *patch);

bool applyOPL(PATCH* patch);

void inline freePatch(PATCH *patch)
{
	OFF_PATCH_LIST *ptr = patch->offPatchList;
	OFF_PATCH_LIST *ptr_back;
	while (ptr != NULL)
	{
		ptr_back = ptr;
		ptr = ptr->next;
		free(ptr_back);
	}
	if (!IsBadReadPtr(patch->jmpback, sizeof(BYTE *)))
		free(patch->jmpback);
	if (patch->code)
		free(patch->code);
	if (patch->relocs.offsets)
		free(patch->relocs.offsets);
	if (patch->relocs.types)
		free(patch->relocs.types);
	memset(patch, 0x0, sizeof(PATCH));
}

PIMAGE_SECTION_HEADER getCodeSectionHeader(LPCVOID base);
BYTE *getCopyOfSection(LPCVOID base, DWORD sectIdx);
int extendPETextSection(LPVOID *base, DWORD *size, DWORD additionalSize = 0, BYTE filler = 0xCC);
int extendPESection(LPVOID *base, DWORD *size, const DWORD sectIdx, DWORD additionalSize, BYTE filler = 0x0);
int appendToPESection(LPVOID *base, DWORD *size, const DWORD sectIdx, LPCVOID data, const DWORD dataSize, BYTE filler = 0x0);
int replacePESection(LPVOID *base, DWORD *size, const DWORD sectIdx, LPCVOID newSection, const DWORD newSectionSize, BYTE filler = 0x0);
int patchRelocs(LPVOID *base, DWORD *size, PATCH *patch);
DWORD getPatchVA(LPCVOID base, const DWORD patchCodeSize);
void replaceAllGetPC(INSTRUCTION **iHeadPtr, DWORD *numInstr, LPCVOID base);
DWORD getFuncVA(LPCVOID base, const char * const funcName);
DWORD addImport(LPVOID *base, DWORD *size, const char * const dllName, const char * const funcName, const WORD hint);
int patchPEInMemory(LPVOID *base, DWORD *size, PATCH *patch);

int hideCertificate(LPCVOID base);

#endif