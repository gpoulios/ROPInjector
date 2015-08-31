
#include "ROP.h"
#include <assert.h>

const char *INSTR_TYPES[NUM_INSTR_TYPES] = { "LOADS", "LOAD_REG", "LOAD_RM", "ADD_IMM", "SUB_IMM", \
"MUL_IMM", "DIV_IMM", "MOV_REG_IMM", "MOV_REG_REG", "MOV_RM_IMM", "MOV_REG_RM", \
"MOV_RM_REG", "ADD_REG", "SUB_REG", "MUL_REG", "DIV_REG", "XCHG_REG_REG", \
"XCHG_REG_RM", "GPUSH_IMM", "GPUSH_REG", "UNDEFINED" };

const BOOL SUPPORTS_OPER_SZ[] = {
	TRUE, // LOADS,			// lods m8/16/32 (load string), op1 is eax, op2 is esi, op3 is size of op1 in bytes (1, 2, or 4)
	FALSE, // LOAD_REG,		// pop regA, op1 is regA
	FALSE, // LOAD_RM,		// pop [regA], op1 is regA
	TRUE, // ADD_IMM,		// op1 is the register, op2 is imm, op3 is size of op1 in bytes (1, 2, or 4)
	TRUE, // SUB_IMM,		// op1 is the register, op2 is imm, op3 is size of op1 in bytes (1, 2, or 4)
	FALSE, // MUL_IMM,		// regA = regB * imm, op1 is regA, op2 is regB, op3 == imm
	FALSE, // DIV_IMM,		// op1 is the register, op2 is imm, op3 is size of op1 in bytes (1, 2, or 4)
	TRUE, // MOV_REG_IMM,	// op1 is the register, op2 is imm, op3 is size of op1 in bytes (1, 2, or 4)
	TRUE, // MOV_REG_REG,	// mov regA, regB, op1 is regA, op2 is regB, op3 is size of op1 in bytes (1, 2, or 4)
	TRUE, // MOV_RM_IMM,	// mov [regA], imm, op1 is regA, op2 is imm, op3 is size of op1 in bytes (1, 2, or 4)
	TRUE, // MOV_REG_RM,	// mov regA, [regB], op1 is regA, op2 is regB, op3 is size of op1 in bytes (1, 2, or 4)
	TRUE, // MOV_RM_REG,	// mov [regA], regB, op1 is regA, op2 is regB, op3 is size of op1 in bytes (1, 2, or 4)
	FALSE, // ADD_REG,		// regA = regA+regB+x, op1 is regA, op2 is regB, op3 is x
	FALSE, // SUB_REG,		// regA = regA-regB-x, op1 is regA, op2 is regB, op3 is x
	FALSE, // MUL_REG,		// mul regA, regB, op1 is regA, op2 is regB
	FALSE, // DIV_REG,		// regA = regB / regC, op1 is regA, op2 is regB, op3 is regC (signed integer division using edx:eax)
	TRUE, // XCHG_REG_REG,	// xchg regA, regB, op1 is regA, op2 is regB, op3 is size of op1 in bytes (1, 2, or 4)
	TRUE, // XCHG_REG_RM,	// xchg regA, [regB], op1 is regA, op2 is regB, op3 is size of op1 in bytes (1, 2, or 4)
	FALSE, //GPUSH_IMM,		// push imm32, op1 is imm32
	FALSE, //GPUSH_REG,		// push reg32, op1 is reg32
	TRUE, // UNDEFINED,
};

#define MAX_STACK_WASTE			0x100 // bytes

GADGET_END *getCandGadgets(LPCVOID base)
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
	PIMAGE_SECTION_HEADER codeHdr = &(section_headers[codeSecIdx]);
	BYTE *code = ADDR0(codeHdr->VirtualAddress);
	DWORD codeLen = (codeHdr->Misc.VirtualSize < codeHdr->SizeOfRawData) ? 
		codeHdr->Misc.VirtualSize : codeHdr->SizeOfRawData;
	if (codeLen < 2)
		return NULL;

	DWORD codeBase = imageBase + codeHdr->VirtualAddress;

	// will need to avoid relocs
	BOOL hasRelocs = TRUE;
	if ((nt_header->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED))
		hasRelocs = FALSE;
	PIMAGE_DATA_DIRECTORY relocDir = &(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
	if (!relocDir->Size)
		hasRelocs = FALSE;

	// find candidate gadgets
	DWORD countAlloced = 100;
	DWORD count = 0;
	GADGET_END *gends = (GADGET_END *)calloc(countAlloced, sizeof(GADGET_END));
	BYTE reg;

	for (DWORD offset = 2; offset < codeLen; offset++)
	{
		if (count >= countAlloced)
		{
			countAlloced *= 2;
			gends = (GADGET_END *)realloc(gends, countAlloced*sizeof(GADGET_END));
			memset(gends + countAlloced / 2, 0, (countAlloced / 2)*sizeof(GADGET_END));
		}


		// test these a priori
		bool isJmp = code[offset-1] == 0xFF				// jmp regA
			&&	MODRM_GET_MOD(code[offset]) == 0x3		// case: jmp regA
			&& MODRM_GET_OPEXT(code[offset]) == 0x4
			&& MODRM_GET_RM_RAW(code[offset]) != REG_ESP;


		// actual setting happens here
		if (code[offset] == 0xC3)							// ret
		{
			gends[count].va = offset + codeBase;
			gends[count].numIns = 1;
			gends[count].size = 1;
			SET_REG(gends[count].regWrites, REG_ESP);
			gends[count].type = RET;
			count++;
		}
		else if (code[offset] == 0xC2 && offset < codeLen-2 && 
			*((WORD *)(code + offset + 1)) < MAX_STACK_WASTE)// retn
		{
			gends[count].va = offset + codeBase;
			gends[count].numIns = 1;
			gends[count].size = 3;
			SET_REG(gends[count].regWrites, REG_ESP);
			gends[count].stackAdvAftRet = *((WORD *)(code + offset + 1));
			gends[count].type = RETN;
			count++;
		}
		else if (isJmp)
		{
			// is there a LOAD instruction preceeding?
			reg = MODRM_GET_RM_RAW(code[offset]);
			if (code[offset-2] == 0x58 + reg)				// pop regA
			{
				gends[count].va = offset-2 + codeBase;
				gends[count].numIns = 2;
				SET_REG2(gends[count].regWrites, REG_ESP, reg);
			}
			else if (offset > 5 && code[offset-3] == 0x24 && // SIB == [esp]
				code[offset-5] == 0x8B &&					// mov
				MODRM_GET_REG_RAW(code[offset-4]) == reg &&		// mov regA, [esp]
				code[offset-2] >= 0x58 && code[offset-2] < 0x60) // pop regB (no need to check regB != regA because of previous <if> statement)
			{
				gends[count].va = offset - 5 + codeBase;
				gends[count].numIns = 3;
				SET_REG3(gends[count].regWrites, REG_ESP, reg, (code[offset-2] - 0x58));
				gends[count].stackAdvBefRet = 1;
			}
			else if (code[offset-3] >= 0x58 && code[offset-3] < 0x60 &&	// pop X
				code[offset-2] >= 0x90 && code[offset-2] < 0x98 &&		// xchg eax, Y
				(	(code[offset-2] == 0x90 && code[offset-3] - 0x58 == reg) ||		// Y == eax	AND X == regA (nop case)
					(code[offset-3] == 0x58 && code[offset-2] - 0x90 == reg) ||		// X == eax	AND Y == regA
					(code[offset-2] - code[offset-3] == 0x38 && reg == REG_EAX)		// X == Y	AND	eax == regA
				))
			{
				gends[count].va = offset - 3 + codeBase;
				gends[count].numIns = 3;
				SET_REG2(gends[count].regWrites, REG_ESP, reg);
				SET_REG2(gends[count].regWrites, REG_EAX, code[offset-2] - 0x90);
			}
			else if (
				code[offset-4] >= 0x58 && code[offset-4] < 0x60 &&		// pop regB
				code[offset-3] == 0x8B &&								// mov
				MODRM_GET_MOD(code[offset-2]) == MOD_REG &&				// mov X, Y
				MODRM_GET_REG_RAW(code[offset - 2]) == reg &&					// X == regA
				MODRM_GET_RM_RAW(code[offset - 2]) == (code[offset - 4] - 0x58))// Y == regB
			{
				gends[count].va = offset - 4 + codeBase;
				gends[count].numIns = 3;
				SET_REG3(gends[count].regWrites, REG_ESP, reg, code[offset-4] - 0x58);
			}
			else // no LOAD instruction, just jmp reg
			{	 // jmp regA can be also be used without a <LOAD regA> gadget
				 // (noone should then change the value of regA until the jmp instr.)
				gends[count].va = offset - 1 + codeBase;
				gends[count].numIns = 1;
			}

			gends[count].size = (BYTE) (offset + codeBase - gends[count].va + 1);
			gends[count].type = JMP;
			gends[count].reg = MODRM_GET_RM_RAW(code[offset]);

			if (hasRelocs && hasRelocInRVARange((BYTE *)ADDR0(relocDir->VirtualAddress),
												relocDir->Size, gends[count].va - imageBase, 
												gends[count].size))
				memset(gends + count, 0, sizeof(GADGET_END));
			else
				count++;
		}
	}

	gends = (GADGET_END *)realloc(gends, (count+1)*sizeof(GADGET_END));
	memset(gends + count, 0, sizeof(GADGET_END));
	return gends;
}

inline BOOL isSameOrWorseEnding(GADGET_END *e, GADGET *gdg)
{
	return gdg && ((e->type == gdg->ending->type &&  /* exactly the same with this ending having more or equal stack junk */ \
		(e->stackAdvAftRet + e->stackAdvBefRet) >= (gdg->ending->stackAdvAftRet + gdg->ending->stackAdvBefRet)) \
		|| (GEND_NO_LOAD(e) && !GEND_NO_LOAD(gdg->ending))						/* this ending has no loader inst. */ \
		|| (e->numIns >= gdg->ending->numIns && e->size >= gdg->ending->size))	/* this ending is longer */
		;
}

inline BOOL newGdgIsWorse(GADGET *newGdg, GADGET *gdg)
{
	if (!gdg)
		return FALSE;

	const BOOL HAS_WORSE_EPILOGUE = G_HAS_FLAG(newGdg, STD_EPILOGUE) && !G_HAS_FLAG(gdg, STD_EPILOGUE);
	const BOOL HAS_SAME_OR_WORSE_EPILOGUE = HAS_WORSE_EPILOGUE || (G_HAS_FLAG(newGdg, STD_EPILOGUE) == G_HAS_FLAG(gdg, STD_EPILOGUE));
	const BOOL HAS_EQUAL_OR_MORE_INS = newGdg->numIns >= gdg->numIns;

	return ((isSameOrWorseEnding(newGdg->ending, gdg) && HAS_SAME_OR_WORSE_EPILOGUE && HAS_EQUAL_OR_MORE_INS)
			|| HAS_WORSE_EPILOGUE
			|| (gdg && (COUNT_REGS(newGdg->regWrites) >= COUNT_REGS(gdg->regWrites)) && HAS_SAME_OR_WORSE_EPILOGUE));	
}

/*
 * This one can be optimized a bit (two nested loops 
 * for each gdg makes for exponential complexity)
 */
GADGET *parseGadgets(LPCVOID base, GADGET_END *endings, const BYTE maxdepth)
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
	PIMAGE_SECTION_HEADER codeHdr = &(section_headers[codeSecIdx]);
	BYTE *codeStart = ADDR0(codeHdr->VirtualAddress);
	DWORD codeLen = (codeHdr->Misc.VirtualSize < codeHdr->SizeOfRawData) ?
		codeHdr->Misc.VirtualSize : codeHdr->SizeOfRawData;
	if (codeLen < 2)
		return NULL;

	// will need to avoid relocs
	BOOL hasRelocs = TRUE;
	if ((nt_header->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED))
		hasRelocs = FALSE;
	PIMAGE_DATA_DIRECTORY relocDir = &(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
	if (!relocDir->Size)
		hasRelocs = FALSE;

	// count endings
	DWORD numEnds = 0;
	GADGET_END *e = endings;
	while ((e++)->va) numEnds++;
	if (!numEnds) // nothing to parse
		return NULL;

	// alloc mem for gadgets
	DWORD countAlloced = numEnds + 1, count = 0;	// count always points to the NULL terminating gadget (the one following the last)
	long loaders[8] = { -1,-1,-1,-1,-1,-1,-1,-1 };	// indices to all the loader gdgs for chaining with other's not having one
	long movEbpEspIdx = -1;
	GADGET *gdgs = (GADGET *)calloc(countAlloced, sizeof(GADGET));
	GADGET *gdg;
	
	// prepare for disassembly
	DISASSEMBLY d;
	const BYTE *endcode, *curInst;
	DWORD depth, instr_len;
	
	for (e = endings; e->va; e++) // per ending
	{	
		const BOOL NO_LOADER = GEND_NO_LOAD(e);
		BOOL endModifiesEFlags = FALSE;
		BOOL endCheckedForEFlagsModif = FALSE;
		endcode = ADDR0(e->va - imageBase);
		depth = 0;
		while (++depth < maxdepth && endcode - depth > codeStart) // per depth per ending
		{
			const BYTE * const c = endcode - depth;	// go backwards <depth> bytes
			instr_len = 0;
			d.Address = (DWORD)c;

			// disassemble forward until <endcode> (the ret instr.)
			do {
				curInst = c + instr_len;
				FlushDecoded(&d);
				Decode(&d, (char *)c, &instr_len);
				instr_len++;

				if (((BYTE)(curInst[0] ^ 0xF3) < 2 && !d.PrefixSize && d.OpcodeSize == 1) ||	// malformed rep(*)
					curInst[0] == 0xF4 ||														// hlt
					(_strnicmp(d.Assembly, "???", 3) == 0) ||
					(_strnicmp(d.Remarks, "Invalid Instruction", 19) == 0) ||
					(_strnicmp(d.Remarks, "Illegal Instruction", 19) == 0))
					instr_len = depth+1; // break
				
				d.Address += instr_len;
			} while (instr_len < depth);

			if (instr_len != depth) // did not run into return
				continue;

			DWORD numIns = 0;
			INSTRUCTION *iHead = analyze(c, depth + e->size, &numIns);
			if (iHead == NULL)
				continue;

			INSTRUCTION *in = iHead;

			// further filtering of bad instructions in gadget
			for (DWORD i = 0; i < numIns - e->numIns; i++, in = in->next)
			{
				// If at least on external branch || push.
				// Ideally we'd like to now when an instruction writers to stack (not possible)
				if (IS_BRANCH(in) || isPush(in) || isPriviledged(in)
					||
					(NO_LOADER && (CONTAINS_REG(in->regWrites, e->reg) // writes on jmpreg
						|| (CONTAINS_REG(in->regReads, e->reg) && HAS_MODRM(in) // read indirect on jmpreg
						&& MODRM_GET_MOD(*(in->data + OFFSET_TO_MODRM(in))) != MOD_REG)))
					)
				{
					free(iHead);
					goto next_depth;
				}
			}


			if (!endCheckedForEFlagsModif)
			{
				for (in = iHead + numIns - e->numIns; in && !endModifiesEFlags; in = in->next)
					endModifiesEFlags = endModifiesEFlags || modifiesEFlags(in);
				endCheckedForEFlagsModif = TRUE;
			}

			// don't want to run into a reloc
			if (hasRelocs && hasRelocInRVARange((BYTE *)ADDR0(relocDir->VirtualAddress),
												relocDir->Size, e->va - depth - imageBase, depth))
			{
				free(iHead);
				goto next_depth;
			}


			// at this point a gadget has been found (useful or not; at least it doesn't have illegal instructions in it)

			// check for equal gadgets
			for (gdg = gdgs; gdg < gdgs + count; gdg++)
			{
				if (iHead->data[0] == gdg->ins->data[0]
					&& numIns == gdg->numIns
					&& equalInstr(iHead, gdg->ins, numIns - e->numIns))
				{
					if (isSameOrWorseEnding(e, gdg))
					{
						free(iHead);
						goto next_depth;
					}
					break;
				}
			}
			
			// if we didn't find one that is equal, append the gadget to the end of the array
			if (gdg == gdgs + count)
			{
				if (count >= countAlloced)
				{
					countAlloced *= 2;
					gdgs = (GADGET *)realloc(gdgs, countAlloced*sizeof(GADGET));
					memset(gdgs + countAlloced / 2, 0, (countAlloced / 2)*sizeof(GADGET));
					gdg = gdgs + count;
				}
				count++;
			}
			else
				memset(gdg, 0, sizeof(GADGET));

			gdg->va = e->va - depth;
			gdg->ins = iHead;
			gdg->numIns = numIns;
			gdg->ending = e;
			
			classifyGadget(gdg);


			GADGET *newGdg = gdg;
			if (newGdg->gi.type != UNDEFINED)
			{ // is there one of the same type?
				for (gdg = gdgs; gdg < gdgs + count; gdg++)
				{
					if (gdg != newGdg && gdg->gi.type == newGdg->gi.type &&
						gdg->gi.operand1 == newGdg->gi.operand1 &&
						gdg->gi.operand2 == newGdg->gi.operand2 &&
						gdg->gi.operand3 == newGdg->gi.operand3 &&
						// if regWrites of one is subset of regWrites of the other
						(((gdg->regWrites | newGdg->regWrites) == gdg->regWrites)
						|| ((gdg->regWrites | newGdg->regWrites) == newGdg->regWrites))
						)
					{
						const BOOL isWorse = newGdgIsWorse(newGdg, gdg);
						if (isWorse)
						{
#ifdef VDEBUG_MODE
							puts("---------Dropping:----------");
							printGadget(newGdg);
							puts("----------For:--------------");
							printGadget(gdg);
#endif
							free(newGdg->ins);
						}
						else
						{
#ifdef VDEBUG_MODE
							puts("---------Replacing:----------");
							printGadget(gdg);
							puts("----------With:--------------");
							printGadget(newGdg);
#endif
							free(gdg->ins);
							memcpy(gdg, newGdg, sizeof(GADGET)); // move it at the slot where the worse is
						}

						// newGdg now points to an empty slot

						count--; // always points to the NULL terminating gadget (the one following the last)
						if (newGdg != gdgs + count) // move the last one in the empty slot
							memcpy(newGdg, gdgs + count, sizeof(GADGET));
						memset(gdgs + count, 0, sizeof(GADGET));

						if (isWorse) // nothing left to do
							goto next_depth;

						newGdg = gdg;
						break;
					}
				}
			}

			// update the <loaders> index if this is a LOAD_REG
			if (newGdg->gi.type == LOAD_REG)
			{
				gdg = loaders[newGdg->gi.operand1] > -1 ? (gdgs + loaders[newGdg->gi.operand1]) : NULL;
				if (!newGdgIsWorse(newGdg, gdg))
					loaders[newGdg->gi.operand1] = newGdg - gdgs;
			}
			else if (newGdg->gi.type == MOV_REG_REG
					&& newGdg->gi.operand1 == REG_EBP
					&& newGdg->gi.operand2 == REG_ESP
					&& newGdg->gi.operand3 == 4
					&& ((newGdg->stackAdvance + newGdg->ending->stackAdvBefRet + newGdg->ending->stackAdvAftRet)==0))
			{
				gdg = movEbpEspIdx > -1 ? (gdgs + movEbpEspIdx) : NULL;
				if (!newGdgIsWorse(newGdg, gdg))
					movEbpEspIdx = newGdg - gdgs;
			}

			if (!G_HAS_FLAG(newGdg, MODIF_EFLAGS) && endModifiesEFlags)
				G_SET_FLAG(newGdg, MODIF_EFLAGS);

		next_depth:;
		}

		// done searching (endings) for gadgets
	}
	
	// pair gadgets having endings without loader with loader-gadgets
	// and  gadgets having standard epilogue with mov ebp, esp loaders
	for (gdg = gdgs; gdg < gdgs + count; gdg++)
	{
		const BOOL NO_LOADER = GEND_NO_LOAD(gdg->ending);
		const BOOL HAS_STDE = G_HAS_FLAG(gdg, STD_EPILOGUE);
		if (NO_LOADER && HAS_STDE) // can't help it
			continue;
		else if (NO_LOADER
			&& loaders[gdg->ending->reg] > -1
			&& !GEND_NO_LOAD((gdgs + loaders[gdg->ending->reg])->ending)) // reg is not being written has been checked above (depths loop)
		{
			gdg->loader = gdgs + loaders[gdg->ending->reg];
		}
		else if (HAS_STDE
			&& !G_HAS_FLAG(gdg, MODIF_EBSP_BEF_STDE) // ebp/esp not being modified before std epilogue
			&& movEbpEspIdx > -1
			&& !GEND_NO_LOAD((gdgs + movEbpEspIdx)->ending))
		{
			gdg->loader = gdgs + movEbpEspIdx;
		}
#ifdef VDEBUG_MODE
		if (gdg->loader)
		{
			puts("---------Pairing:----------");
			printGadget(gdg->loader);
			puts("---------With:----------");
			printGadget(gdg);
		}
#endif
	}

	gdgs = (GADGET *)realloc(gdgs, (count+1)*sizeof(GADGET));
	memset(gdgs + count, 0, sizeof(GADGET));
	return gdgs;
}

#define MAX_CHAIN_SIZE	10 // i.e., per call on buildChainHead and buildChainTail together

// c: whether to init the stack oper. chain at the prologue (TRUE) or at the epilogue (FALSE).
// TODO 5: if (readsEFlags(gi->i) && G_HAS_FLAG(gdg, MODIF_EFLAGS)) return ENC_FAIL_EFLAGS
#define ENCODER_PROLOGUE(c)	int res = ENC_FAIL;				\
							STACK_OPER *chain = NULL;		\
							BYTE freeRegs = gi->i->freeRegs;\
							SET_REG(freeRegs, REG_ESP);		\
							if ((GEND_NO_LOAD(gdg->ending) || G_HAS_FLAG(gdg, STD_EPILOGUE)) && !gdg->loader) \
								goto enc_epilogue;			\
							if ((gdg->ending->regWrites & ~freeRegs) \
								|| (gdg->loader && ((gdg->loader->regWrites & ~freeRegs) ||(gdg->loader->ending->regWrites & ~freeRegs))) \
								|| (GEND_NO_LOAD(gdg->ending) && (!CONTAINS_REG(freeRegs, gdg->ending->reg))) \
								|| (G_HAS_FLAG(gdg, STD_EPILOGUE) && (!CONTAINS_REG(freeRegs, REG_EBP))) \
								)							\
							{								\
								res = ENC_FAIL_FREEREG;		\
								goto enc_epilogue;			\
							}								\
							DWORD countAlloced = 0;			\
							DWORD si = 0;					\
							if (c) {						\
								countAlloced = MAX_CHAIN_SIZE; \
								chain = (STACK_OPER *)calloc(countAlloced, sizeof(STACK_OPER)); \
								buildChainHead(gdg, chain, &si); \
							}
#define ENCODER_CHK_REGS	BYTE regWrites = gdg->regWrites | (gdg->loader ? gdg->loader->regWrites : 0);\
							if (regWrites & ~freeRegs)		\
							{								\
								res = ENC_FAIL_FREEREG;		\
								goto enc_epilogue;			\
							}

#define ENCODER_EPILOGUE enc_epilogue:						\
							if (resCode)					\
								*resCode = res;				\
							if (res < ENC_SUCCESS)			\
							{								\
								if (chain)					\
									free(chain);			\
								chain = NULL;				\
							}								\
							else							\
							{								\
								if (!chain) {				\
									countAlloced = MAX_CHAIN_SIZE; \
									chain = (STACK_OPER *)calloc(countAlloced, sizeof(STACK_OPER)); \
									buildChainHead(gdg, chain, &si); \
								}							\
								buildChainTail(gdg, chain, &si); \
							}								\
							return chain;					


#define PUSH_GDG_VA		chain[*index].type = PUSH_VA;			\
						chain[*index].data = gdg->va;			\
						(*index)++;
#define PUSH_LDR_VA		chain[*index].type = PUSH_VA;			\
						chain[*index].data = gdg->loader->va;	\
						(*index)++;
#define PUSH_NXT_VA		chain[*index].type = CHAIN;				\
						(*index)++;
#define ADV_BEF_RET(gdg)if ((gdg)->stackAdvance || (gdg)->ending->stackAdvBefRet)						\
						{																				\
							chain[*index].type = ADVANCE;												\
							chain[*index].offset = (gdg)->stackAdvance + (gdg)->ending->stackAdvBefRet; \
							(*index)++;																	\
						}
#define ADV_AFT_RET(gdg)if ((gdg)->ending->stackAdvAftRet)												\
						{																				\
							chain[*index].type = ADVANCE;												\
							chain[*index].offset = (gdg)->ending->stackAdvAftRet;						\
							(*index)++;																	\
						}
#define PUSH_IMM(imm)	chain[si].type = PUSH_IMM;														\
						chain[si].data = (imm);															\
						si++;


void buildChainHead(const GADGET * const gdg, STACK_OPER * const chain, DWORD * const index)
{
	DWORD secondIdx = (*index) + 1;
	for (long i = (*index)-1; i >= 0; i--)
	{
		if (chain[i].type == CHAIN) 
		{
			secondIdx = (*index);
			*index = i;
			break;
		}
	}
	if (G_HAS_FLAG(gdg, STD_EPILOGUE))
	{
		PUSH_LDR_VA
		*index = secondIdx;
		PUSH_GDG_VA
		PUSH_NXT_VA
		ADV_AFT_RET(gdg)
	}
	else if (GEND_NO_LOAD(gdg->ending))
	{
		PUSH_LDR_VA
		*index = secondIdx;
		PUSH_NXT_VA
		ADV_BEF_RET(gdg->loader)
		PUSH_GDG_VA
		ADV_AFT_RET(gdg->loader)
	}
	else
	{
		PUSH_GDG_VA
		*index = secondIdx;
	}
}

void buildChainTail(const GADGET * const gdg, STACK_OPER * const chain, DWORD * const index)
{
	if (G_HAS_FLAG(gdg, STD_EPILOGUE)){}
	else if (GEND_NO_LOAD(gdg->ending))
	{
		ADV_BEF_RET(gdg)
	}
	else
	{
		ADV_BEF_RET(gdg)
		PUSH_NXT_VA
		ADV_AFT_RET(gdg)
	}
	chain[*index].type = NOP;
}

// any UNDEFINED
DEF_ENCODER(encodeExact)
{
	ENCODER_PROLOGUE(FALSE)
	DWORD sizeOfGdgCode;
	BYTE *gdgCode = getCode(gdg->ins, &sizeOfGdgCode, gdg->numIns - gdg->ending->numIns);
	if (sizeOfGdgCode == gi->i->totalSize
		&& !memcmp(gdgCode, gi->i->data, sizeOfGdgCode)) // exactly the same
		res = ENC_SUCCESS;
	free(gdgCode);
	ENCODER_EPILOGUE
}

// any UNDEFINED-SAFE
DEF_ENCODER(encodeApprox)
{
	ENCODER_PROLOGUE(FALSE)
	INSTRUCTION *in = gdg->ins;
	BYTE regWrites = gdg->loader ? gdg->loader->regWrites : 0;
	for (DWORD i = 0; (i < gdg->numIns - gdg->ending->numIns); i++, in = in->next)
	{
		if (res != ENC_SUCCESS && (in->totalSize == gi->i->totalSize) && equalInstr(in, gi->i, 1))
			res = ENC_SUCCESS;
		else
		{
			regWrites |= in->regWrites;
			if (regWrites & ~freeRegs)
			{
				res = ENC_FAIL_FREEREG;
				break;
			}
		}
	}
	ENCODER_EPILOGUE
}

//LOADS,		// lods m8/16/32 (load string), op1 is eax, op2 is esi, op3 is size of op1 in bytes (1, 2, or 4)
//DIV_IMM,		// op1 is the register, op2 is imm, op3 is size of op1 in bytes (1, 2, or 4)
//MOV_REG_IMM,	// op1 is the register, op2 is imm, op3 is size of op1 in bytes (1, 2, or 4)
//MOV_RM_REG,	// mov [regA], regB, op1 is regA, op2 is regB, op3 is size of op1 in bytes (1, 2, or 4)
//MOV_RM_IMM,	// mov [regA], imm, op1 is regA, op2 is imm, op3 is size of op1 in bytes (1, 2, or 4)
//MOV_REG_RM,	// mov regA, [regB], op1 is regA, op2 is regB, op3 is size of op1 in bytes (1, 2, or 4)
//MUL_REG,		// mul regA, regB, op1 is regA, op2 is regB
//DIV_REG,		// regA = regB / regC, op1 is regA, op2 is regB, op3 is regC (signed integer division using edx:eax)
DEF_ENCODER(encodeMatchAll)
{
	ENCODER_PROLOGUE(FALSE)
	ENCODER_CHK_REGS
	if (gi->type == gdg->gi.type &&
		gi->operand1 == gdg->gi.operand1 &&
		gi->operand2 == gdg->gi.operand2 &&
		gi->operand3 == gdg->gi.operand3)
		res = ENC_SUCCESS;
	ENCODER_EPILOGUE
}

//LOAD_REG,		// pop regA, op1 is regA
DEF_ENCODER(encodeLoadReg)
{
	ENCODER_PROLOGUE(TRUE)
	ENCODER_CHK_REGS
	switch (gi->type)
	{
	case MOV_REG_IMM:
		if (gi->operand1 == gdg->gi.operand1 &&
			gi->operand3 == 4)
		{
			res = ENC_SUCCESS;
			PUSH_IMM(gi->operand2);
		}
		break;
	}
	ENCODER_EPILOGUE
}

//LOAD_RM,		// pop [regA], op1 is regA
DEF_ENCODER(encodeLoadRm)
{
	ENCODER_PROLOGUE(TRUE)
	ENCODER_CHK_REGS
	switch (gi->type)
	{
	case MOV_RM_IMM:
		if (gi->operand1 == gdg->gi.operand1 &&
			gi->operand3 == 4)
		{
			res = ENC_SUCCESS;
			PUSH_IMM(gi->operand2);
		}
		break;
	}
	ENCODER_EPILOGUE
}

//ADD_IMM,		// op1 is the register, op2 is imm, op3 is size of op1 in bytes (1, 2, or 4)
//SUB_IMM,		// op1 is the register, op2 is imm, op3 is size of op1 in bytes (1, 2, or 4)
DEF_ENCODER(encodeAddSubImm)
{
	ENCODER_PROLOGUE(TRUE)
	ENCODER_CHK_REGS
	switch (gi->type)
	{
	case ADD_IMM:
	case SUB_IMM:
		if (gi->operand2 == 0 &&
			gi->operand1 == gdg->gi.operand1 &&
			gi->operand2 == gdg->gi.operand2 &&
			gi->operand3 == gdg->gi.operand3)
		{
			res = ENC_SUCCESS;
			break;
		}
		int sign = gi->type == SUB_IMM ? -1 : 1;
		long imm = sign*gi->operand2;
		int signGdg = gdg->gi.type == SUB_IMM ? -1 : 1;
		long immGdg = signGdg*gdg->gi.operand2;
		if (gi->operand1 == gdg->gi.operand1 &&
			gi->operand3 == gdg->gi.operand3 &&
			imm * immGdg > 0 &&					  // same sign + no 0
			immGdg*((long)(imm / immGdg)) == imm) // division without remainder (also tests imm>=gdg.imm)
		{
			for (long a = immGdg; a != imm; a += immGdg)
			{
				if (si >= countAlloced - MAX_CHAIN_SIZE)
				{
					countAlloced += MAX_CHAIN_SIZE;
					chain = (STACK_OPER *)realloc(chain, countAlloced * sizeof(STACK_OPER));
					memset(chain + si, 0, (countAlloced - si)*sizeof(STACK_OPER));
				}
				buildChainTail(gdg, chain, &si);
				buildChainHead(gdg, chain, &si);
			}
			res = ENC_SUCCESS;
		}
		break;
	}
	ENCODER_EPILOGUE
}

//MUL_IMM,		// regA = regB * imm, op1 is regA, op2 is regB, op3 == imm
DEF_ENCODER(encodeMulImm)
{
	STACK_OPER *ch;
	if (ch = encodeMatchAll(gdg, gi, resCode))
		return ch;

	ENCODER_PROLOGUE(FALSE)
	ENCODER_CHK_REGS
	switch (gi->type)
	{
	case MOV_REG_IMM:	// imul regA, regX, 0 -> mov regA, 0 (classifies also for xor regA, regA / and regA, 0x0)
		if (gi->operand1 == gdg->gi.operand1 &&
			gi->operand2 == 0 && gdg->gi.operand3 == 0 &&
			gi->operand3 == 4)
			res = ENC_SUCCESS;
		break;
	case SUB_REG:		// imul regA, regX, 0 -> sub regA, regA-0
		if (gi->operand1 == gi->operand2 && gi->operand3 == 0 &&
			gi->operand1 == gdg->gi.operand1 && 
			gdg->gi.operand3 == 0)
			res = ENC_SUCCESS;
		break;
	case ADD_REG:		// imul regA, regA, 2 -> add regA, regA+0
		if (gi->operand1 == gi->operand2 && gi->operand3 == 0 &&
			gdg->gi.operand1 == gdg->gi.operand2 && gdg->gi.operand3 == 2 &&
			gi->operand1 == gdg->gi.operand1)
			res = ENC_SUCCESS;
		break;
	case MOV_REG_REG:	// imul regA, regB, 1 -> mov regA, regB
		if (gi->operand1 == gdg->gi.operand1 &&
			gi->operand2 == gdg->gi.operand2 &&
			gdg->gi.operand3 == 1)
			res = ENC_SUCCESS;
		break;
	case ADD_IMM:
	case SUB_IMM: 		// imul regA, regA, 1 -> add/sub regA, 0
		if (gi->operand1 == gdg->gi.operand1 &&
			gdg->gi.operand1 == gdg->gi.operand2 && gdg->gi.operand3 == 1 && // is NOP
			gi->operand2 == 0 &&
			gdg->gi.operand1 == gdg->gi.operand2)
			res = ENC_SUCCESS;
		break;
	case XCHG_REG_REG: 	// imul regA, regA, 1 -> xchg regA, regA
		if (gi->operand1 == gi->operand2 &&
			gdg->gi.operand1 == gdg->gi.operand2 && gdg->gi.operand3 == 1 && // is NOP
			gi->operand1 == gdg->gi.operand1 &&
			gi->operand2 == 0)
			res = ENC_SUCCESS;
		break;
	}
	ENCODER_EPILOGUE
}

//MOV_REG_REG,	// mov regA, regB, op1 is regA, op2 is regB, op3 is size of op1 in bytes (1, 2, or 4)
DEF_ENCODER(encodeMovRegReg)
{
	STACK_OPER *ch;
	if (ch = encodeMatchAll(gdg, gi, resCode))
		return ch;

	ENCODER_PROLOGUE(FALSE)
	ENCODER_CHK_REGS
	switch (gi->type)
	{
	case MUL_IMM: // imul regA, regB, 1 -> mov regA, regB
		if (gi->operand1 == gdg->gi.operand1 &&
			gi->operand2 == gdg->gi.operand2 &&
			gi->operand3 == 1 &&
			gdg->gi.operand3 == 4)
			res = ENC_SUCCESS;
		break;
	}
	ENCODER_EPILOGUE
}

//ADD_REG,		// regA = regA+regB+x, op1 is regA, op2 is regB, op3 is x
DEF_ENCODER(encodeAddReg)
{
	STACK_OPER *ch;
	if (ch = encodeMatchAll(gdg, gi, resCode))
		return ch;

	ENCODER_PROLOGUE(FALSE)
	ENCODER_CHK_REGS
	switch (gi->type)
	{
	case MUL_IMM: // imul regA, regA, 2 -> add regA, regA+0
		if (gi->operand1 == gi->operand2 && gi->operand3 == 2 &&
			gdg->gi.operand1 == gdg->gi.operand2 && gdg->gi.operand3 == 0 &&
			gi->operand1 == gdg->gi.operand1)
			res = ENC_SUCCESS;
		break;
	}
	ENCODER_EPILOGUE
}

//SUB_REG,		// regA = regA-regB-x, op1 is regA, op2 is regB, op3 is x
DEF_ENCODER(encodeSubReg)
{
	STACK_OPER *ch;
	if (ch = encodeMatchAll(gdg, gi, resCode))
		return ch;

	ENCODER_PROLOGUE(FALSE)
	ENCODER_CHK_REGS
	switch (gi->type)
	{
	case MOV_REG_IMM: // mov regA, 0 / xor regA,regA / and regA, 0x0 -> sub regA, regA-0
		if (gi->operand2 == 0 &&
			gdg->gi.operand1 == gdg->gi.operand2 && gdg->gi.operand3 == 0 &&
			gi->operand1 == gdg->gi.operand1)
			res = ENC_SUCCESS;
		break;
	case MUL_IMM: // imul regA, regX, 0 -> sub regA, regA+0
		if (gi->operand3 == 0 &&
			gdg->gi.operand1 == gdg->gi.operand2 && gdg->gi.operand3 == 0 &&
			gi->operand1 == gdg->gi.operand1)
			res = ENC_SUCCESS;
		break;
	}
	ENCODER_EPILOGUE
}

//XCHG_REG_REG,	// xchg regA, regB, op1 is regA, op2 is regB, op3 is size of op1 in bytes (1, 2, or 4)
DEF_ENCODER(encodeXchgRegReg)
{
	ENCODER_PROLOGUE(FALSE)
	ENCODER_CHK_REGS
	switch (gi->type)
	{
	case XCHG_REG_REG:
		if (gi->operand3 == gdg->gi.operand3 &&
			((gi->operand1 == gdg->gi.operand1 && gi->operand2 == gdg->gi.operand2) ||
			 (gi->operand1 == gdg->gi.operand2 && gi->operand2 == gdg->gi.operand1)))
			res = ENC_SUCCESS;
		break;
	case MOV_REG_REG:
		BOOL isSrcRegFree = !(gi->i->next && !CONTAINS_REG(gi->i->next->freeRegs, gi->operand2));
		if (isSrcRegFree && 
			gi->operand3 == gdg->gi.operand3 &&
			((gi->operand1 == gdg->gi.operand1 && gi->operand2 == gdg->gi.operand2) ||
			(gi->operand1 == gdg->gi.operand2 && gi->operand2 == gdg->gi.operand1)))
			res = ENC_SUCCESS;
		break;
	}
	ENCODER_EPILOGUE
}

//XCHG_REG_RM,	// xchg regA, [regB], op1 is regA, op2 is regB, op3 is size of op1 in bytes (1, 2, or 4)
DEF_ENCODER(encodeXchgRegRm)
{
	STACK_OPER *ch;
	if (ch = encodeMatchAll(gdg, gi, resCode))
		return ch;

	ENCODER_PROLOGUE(FALSE)
	ENCODER_CHK_REGS
	switch (gi->type)
	{
	case MOV_RM_REG:
		BOOL isSrcRegFree = !(gi->i->next && !CONTAINS_REG(gi->i->next->freeRegs, gi->operand2));
		if (isSrcRegFree &&
			gi->operand3 == gdg->gi.operand3 &&
			gi->operand1 == gdg->gi.operand2 && 
			gi->operand2 == gdg->gi.operand1)
			res = ENC_SUCCESS;
		break;
	}
	ENCODER_EPILOGUE
}

//GPUSH_IMM,	// push imm32, op1 is imm32
//GPUSH_REG,	// push reg32, op1 is reg32
DEF_ENCODER(encodePush)
{
	ENCODER_PROLOGUE(FALSE)
	ENCODER_CHK_REGS
	if (gi->type == gdg->gi.type &&
		gi->operand1 == gdg->gi.operand1 &&
		gi->operand2 == gdg->gi.operand2 &&
		gi->operand3 == gdg->gi.operand3)
		res = ENC_SUCCESS;
enc_epilogue:
	if (resCode)
		*resCode = res;
	if (res == ENC_SUCCESS)
	{
		countAlloced = MAX_CHAIN_SIZE;
		chain = (STACK_OPER *)calloc(countAlloced, sizeof(STACK_OPER));
		buildChainHead(gdg, chain, &si);
		buildChainTail(gdg, chain, &si);
		chain[si].type = ADVANCE;
		chain[si].offset = 4;
		si++;
		chain[si].type = NOP;
	}
	else
		chain = NULL;
	return chain;
}

// [regA] indirect addressing mode with all possible variations
#define IND_NO_DISP_SS (HAS_MODRM(in) && \
			((MODRM_GET_MOD(modRm) == MOD_IND && MODRM_GET_RM(in, modRm) != REG_ESP && MODRM_GET_RM(in, modRm) != REG_EBP)		\
			|| (HAS_SIB(in) && (MODRM_GET_MOD(modRm) == MOD_IND || MODRM_GET_MOD(modRm) == MOD_IND_DISP32) &&			\
				SIB_GET_SS(sib) == 0 && SIB_GET_INDEX(sib) == REG_ESP && disp == 0 && !SIB_IS_DISP_ONLY(modRm, sib))	\
			|| (!HAS_SIB(in) && (MODRM_GET_MOD(modRm) == MOD_IND_DISP8 || MODRM_GET_MOD(modRm) == MOD_IND_DISP32) && disp == 0)))


void classifyGadget(GADGET *gdg)
{	
	INSTRUCTION *in = gdg->ins;
	BYTE allRegWritesSoFar = 0;
	BYTE regWritesAfter = 0; // after the usefull instruction
	BOOL hasUsefulInstr = FALSE, hasUnsafeMemOp = FALSE, hasOtherPopBefore = FALSE;
	for (DWORD i = 0; (i < gdg->numIns-gdg->ending->numIns && !hasUnsafeMemOp); i++, in = in->next)
	{
		BYTE op1 = *(in->data + OFFSET_TO_OPCODE(in));
		BYTE op2 = *(in->data + OFFSET_TO_OPCODE(in) + 1);
		BYTE modRm = *(in->data + OFFSET_TO_MODRM(in));
		BYTE sib = *(in->data + OFFSET_TO_SIB(in));
		long disp = getDisp(in);
		long imm = getImm(in);

		BOOL found = FALSE;
		long gop1=0, gop2=0, gop3=0;
		INSTR_TYPE type = UNDEFINED; // gadget type
		INSTRUCTION *gin = in; // gadget instruction
		ENCODER encoder = NULL;


//LOADS,			// lods m8/16/32 (load string), op1 is eax, op2 is esi, op3 is size of op1 in bytes (1, 2, or 4)
		if (op1 == 0xAC || op1 == 0xAD)
		{
			if (hasUsefulInstr)
				hasUnsafeMemOp = TRUE;
			else
			{
				gop1 = REG_EAX;
				gop2 = REG_ESI;
				gop3 = SIZEOF_OPERAND(in);
				type = LOADS;
				found = TRUE;
				encoder = encodeMatchAll;
			}
		}
//LOAD_REG,			// pop regA, op1 is regA
		else if (isPopReg(in))
		{
			if (op1 == 0x8F)
				gop1 = MODRM_GET_RM(in, modRm);
			else
				gop1 = 0x58 ^ op1;

			if (hasUsefulInstr)
			{
				if (gop1 == REG_ESP)
					hasUnsafeMemOp = TRUE;
				else // keep the previous one
				{
					gdg->stackAdvance += 4;
					SET_REG(regWritesAfter, gop1);
				}
			}
			else
			{
				found = TRUE;
				type = LOAD_REG;
				encoder = encodeLoadReg;
			}
		}
//LOAD_RM,		// pop [regA], op1 is regA
		else if (op1 == 0x8F && IND_NO_DISP_SS)
		{
			if (HAS_SIB(in))
				gop1 = SIB_GET_BASE(sib);
			else
				gop1 = MODRM_GET_RM(in, modRm);

			if (hasUsefulInstr) // just about any indirect addressing [regA] is unsafe
				hasUnsafeMemOp = TRUE;
			else 
			{
				found = TRUE;
				type = LOAD_RM;
				encoder = encodeLoadRm;
			}
		}
//ADD_IMM,		// op1 is the register, op2 is imm, op3 is size of op1 in bytes (1, 2, or 4)
		else if (op1 == 0x04 || op1 == 0x05 // add eax/al, imm8/16/32
				|| (op1 >= 0x80 && op1 <= 0x83 && (IS_MODREG_OPEXT(modRm, 0x0)
												|| (IS_MODREG_OPEXT(modRm, 0x6) && imm == 0)	// xor r/m8/16/32, 0
												|| (IS_MODREG_OPEXT(modRm, 0x7) && imm == 0)	// cmp r/m8/16/32, 0
												))
				|| (op1 >= 0x40 && op1 <= 0x47) // inc reg32
				|| ((op1 == 0xFE || op1 == 0xFF) && IS_MODREG_OPEXT(modRm, 0x0)) // inc r/m8/16/32
				|| ((op1 == 0x84 || op1 == 0x85) && IS_MODREG_EQREGS(modRm)) // test  regA, regA
				|| ((op1 == 0xA8 || op1 == 0xA9) && imm == -1) // test al/ax/eax, 0xFF/0xFFFF/0xFFFFFFFF
				|| ((op1 == 0xF6 || op1 == 0xF7) && (IS_MODREG_OPEXT(modRm, 0x0) || IS_MODREG_OPEXT(modRm, 0x1)) && imm == -1) // test r/m8/16/32, 0xFF/0xFFFF/0xFFFFFFFF
				|| (op1 >= 0x08 && op1 <= 0x0B && IS_MODREG_EQREGS(modRm)) // or regA, regA
				|| (op1 >= 0x20 && op1 <= 0x23 && IS_MODREG_EQREGS(modRm)) // and regA, regA
			)
		{
			gop3 = op1 == 0x83 ? (4-2*IS_16BIT_OPERAND(in)) : SIZEOF_OPERAND(in); // we're interested in the dest. reg size
			if (op1 == 0x04 || op1 == 0x05)
			{
				gop1 = REG_EAX;
				gop2 = imm;
			}
			else if (op1 >= 0x80 && op1 <= 0x83)
			{
				gop1 = MODRM_GET_RM(in, modRm);
				gop2 = imm;
			}
			else if (op1 >= 0x40 && op1 <= 0x47)
			{
				gop1 = op1 ^ 0x40;
				gop2 = 1;
			}
			else if (op1 == 0x84 || op1 == 0x85 || op1 == 0xF6 || op1 == 0xF7
				|| (op1 >= 0x08 && op1 <= 0x0B) || (op1 >= 0x20 && op1 <= 0x23))
			{
				gop1 = MODRM_GET_RM(in, modRm);
				gop2 = 0;
			}
			else if (op1 == 0xA8 || op1 == 0xA9)
			{
				gop1 = REG_EAX;
				gop2 = 0;
			}
			else
			{
				gop1 = MODRM_GET_RM(in, modRm);
				gop2 = 1;
			}


			if (hasUsefulInstr)
			{	// mov reg, [esp]; add esp, x; x >= 4
				if (gdg->gi.type == MOV_REG_RM && gdg->gi.operand2 == REG_ESP && gop1 == REG_ESP && 
					gop2 >= 4 && gop3 == 4)
				{
					found = TRUE;
					gop1 = gdg->gi.operand1;
					gop2 = 0;
					gop3 = 0;
					type = LOAD_REG;
					gin = gdg->gi.i;
					encoder = encodeLoadReg;
					gdg->stackAdvance += (WORD)(gop2 - 4);
				}
				// add/sub regA, regB; add regA, imm
				else if ((gdg->gi.type == ADD_REG || gdg->gi.type == SUB_REG) &&
					gdg->gi.operand1 == gop1 && gop3 == 4 &&
					!CONTAINS_REG(regWritesAfter, gop1))
				{
					found = TRUE;
					gop3 = gop2; // the imm
					gop1 = gdg->gi.operand1;
					gop2 = gdg->gi.operand2;
					type = gdg->gi.type;
					gin = gdg->gi.i;
					encoder = gdg->encode;
					if (gdg->gi.type == SUB_REG)
						gop3 *= -1;
				}
				else if (gop1 == REG_ESP)
				{
					if (gop2 >= 0 && gop3 == 4)
						gdg->stackAdvance += (WORD) gop2;
					else
						hasUnsafeMemOp = TRUE;
				}
				else // keep the one found earlier
					SET_REG(regWritesAfter, gop1);
			}
			else
			{
				found = TRUE;
				type = ADD_IMM;
				encoder = encodeAddSubImm;
			}
		}
//SUB_IMM,		// op1 is the register, op2 is imm, op3 is size of op1 in bytes (1, 2, or 4)
		else if (op1 == 0x2C || op1 == 0x2D
			|| (op1 >= 0x80 && op1 <= 0x83 && IS_MODREG_OPEXT(modRm, 0x5))
			|| (op1 >= 0x48 && op1 <= 0x4F) // dec reg32
			|| ((op1 == 0xFE || op1 == 0xFF) && IS_MODREG_OPEXT(modRm, 0x1)) // dec r/m8/16/32
			)
		{
			gop3 = op1 == 0x83 ? (4-2*IS_16BIT_OPERAND(in)) : SIZEOF_OPERAND(in);  // we're interested in the dest. reg size
			if (op1 == 0x2C || op1 == 0x2D)
			{
				gop1 = REG_EAX;
				gop2 = imm;
			}
			else if (op1 >= 0x80 && op1 <= 0x83)
			{
				gop1 = MODRM_GET_RM(in, modRm);
				gop2 = imm;
			}
			else if (op1 >= 0x48 && op1 <= 0x4F)
			{
				gop1 = op1 ^ 0x48;
				gop2 = 1;
			}
			else
			{
				gop1 = MODRM_GET_RM(in, modRm);
				gop2 = 1;
			}

			if (hasUsefulInstr)
			{
				if (gdg->gi.type == MOV_REG_RM && gdg->gi.operand2 == REG_ESP && gop2 <= -4 && gop3 == 4)
				{
					found = TRUE;
					gop1 = gdg->gi.operand1;
					gop2 = 0;
					gop3 = 0;
					type = LOAD_REG;
					gin = gdg->gi.i;
					encoder = encodeLoadReg;
					gdg->stackAdvance += (WORD)(-1 * (gop2 + 4));
				}
				else if ((gdg->gi.type == ADD_REG || gdg->gi.type == SUB_REG) &&
					gdg->gi.operand1 == gop1 && gop3 == 4 &&
					!CONTAINS_REG(regWritesAfter, gop1))
				{
					found = TRUE;
					gop3 = gop2; // the imm
					gop1 = gdg->gi.operand1;
					gop2 = gdg->gi.operand2;
					type = gdg->gi.type;
					gin = gdg->gi.i;
					encoder = gdg->encode;
					if (gdg->gi.type == SUB_REG)
						gop3 *= -1;
				}
				else if (gop1 == REG_ESP)
				{
					if (gop2 <= 0 && gop3 == 4)
						gdg->stackAdvance += (WORD)(-1 * gop2);
					else
						hasUnsafeMemOp = TRUE;
				}
				else // keep the one found earlier
					SET_REG(regWritesAfter, gop1);
			}
			else
			{
				found = TRUE;
				type = SUB_IMM;
				encoder = encodeAddSubImm;
			}
		}
//MUL_IMM,			// regA = regB * imm, op1 is regA, op2 is regB, op3 == imm
		else if ((op1 == 0x69 || op1 == 0x6B 
				|| ((op1 == 0xC1 || op1 == 0xD1) && (IS_MODREG_OPEXT(modRm, 0x4) || IS_MODREG_OPEXT(modRm, 0x6))) // shl/sal
				) 
			&& MODRM_GET_MOD(modRm) == MOD_REG
			)
		{
			if (op1 == 0x69 || op1 == 0x6B)
			{
				gop1 = MODRM_GET_REG(in, modRm);
				gop2 = MODRM_GET_RM(in, modRm);
				gop3 = imm;
			}
			else
			{
				gop1 = MODRM_GET_RM(in, modRm);
				gop2 = gop1;
				if (op1 == 0xD1)
					gop3 = 2;
				else
					gop3 = 2 << imm;
			}

			if (hasUsefulInstr)
			{
				if (gop1 == REG_ESP)
					hasUnsafeMemOp = TRUE;
				else // keep the one found earlier
					SET_REG(regWritesAfter, gop1);
			}
			else
			{
				found = TRUE;
				type = MUL_IMM;
				encoder = encodeMulImm;
			}
		}
//DIV_IMM,			// op1 is the register, op2 is imm, op3 is size of op1 in bytes (1, 2, or 4)
		else if (((op1 == 0xC0 || op1 == 0xC1 || op1 == 0xD0 || op1 == 0xD1) && 
				(IS_MODREG_OPEXT(modRm, 0x5) || IS_MODREG_OPEXT(modRm, 0x7))) // shr/sar
			)
		{
			gop1 = MODRM_GET_RM(in, modRm);
			gop3 = op1 == 0xC1 ? (4-2*IS_16BIT_OPERAND(in)) : SIZEOF_OPERAND(in);
			if (op1 == 0xD0 || op1 == 0xD1)
				gop2 = 2;
			else
				gop2 = 2 << imm;

			if (hasUsefulInstr)
			{
				if (gop1 == REG_ESP)
					hasUnsafeMemOp = TRUE;
				else // keep the one found earlier
					SET_REG(regWritesAfter, gop1);
			}
			else
			{
				found = TRUE;
				type = DIV_IMM;
				encoder = encodeMatchAll;
			}
		}
//MOV_REG_IMM,		// op1 is the register, op2 is imm, op3 is size of op1 in bytes (1, 2, or 4)
		else if (((op1 >= 0xB0 && op1 <= 0xBF)
			|| ((op1 == 0xC6 || op1 == 0xC7) && IS_MODREG_OPEXT(modRm, 0x0)) // mov r/m8/16/32, imm8/16/32
			|| ((op1 == 0x69 || op1 == 0x6B) && imm == 0) // imul regA, regX, 0
			|| ((op1 >= 0x30 && op1 <= 0x33) && IS_MODREG_EQREGS(modRm)) // xor regA, regA
			|| ((op1 == 0x25 || (op1 >= 0x80 && op1 <= 0x83 && IS_MODREG_OPEXT(modRm, 0x4))) && imm == 0) // and regA, 0
			|| ((op1 == 0x0D || (op1 >= 0x80 && op1 <= 0x83 && IS_MODREG_OPEXT(modRm, 0x1))) && imm == -1) // or regA, 0xFFFFFFFF
			|| ((op1 == 0x29 || op1 == 0x2B) && IS_MODREG_EQREGS(modRm)) // sub regA, regA
			))
		{
			gop2 = imm;
			gop3 = op1 == 0x83 ? (4 - 2*IS_16BIT_OPERAND(in)) : SIZEOF_OPERAND(in);
			if (op1 == 0xC6 || op1 == 0xC7 || (op1 >= 0x80 && op1 <= 0x83))
				gop1 = MODRM_GET_RM(in, modRm);
			else if (op1 >= 0xB0 && op1 <= 0xB7)
				gop1 = op1 ^ 0xB0;
			else if (op1 >= 0xB8 && op1 <= 0xBF)
				gop1 = op1 ^ 0xB8;
			else if (op1 == 0x69 || op1 == 0x6B
				|| op1 == 0x31 || op1 == 0x33
				|| op1 == 0x29 || op1 == 0x2B
				)
			{
				gop1 = MODRM_GET_REG(in, modRm);
				gop2 = 0;
			}
			else if (op1 == 0x25 || op1 == 0x0D)
				gop1 = REG_EAX;
			
			if (hasUsefulInstr)
			{
				if (gop1 == REG_ESP)
					hasUnsafeMemOp = TRUE;
				else // keep the one found earlier
					SET_REG(regWritesAfter, gop1);
			}
			else
			{
				found = TRUE;
				type = MOV_REG_IMM;
				encoder = encodeMatchAll;
			}
		}

//MOV_REG_REG,		// mov regA, regB, op1 is regA, op2 is regB, op3 is size of op1 in bytes (1, 2, or 4)
//MOV_REG_RM,		// mov regA, [regB], op1 is regA, op2 is regB, op3 is size of op1 in bytes (1, 2, or 4)
//MOV_RM_REG,		// mov [regA], regB, op1 is regA, op2 is regB, op3 is size of op1 in bytes (1, 2, or 4)
		else if ((op1 >= 0x88 && op1 <= 0x8B && disp == 0)
			|| ((op1 == 0x69 || op1 == 0x6B) && imm == 1) // imul regA, regX, 1
			)
		{
			gop1 = MODRM_GET_REG(in, modRm);
			gop2 = MODRM_GET_RM(in, modRm);
			gop3 = (op1 == 0x6B) ? (4-2*IS_16BIT_OPERAND(in)) : SIZEOF_OPERAND(in);
			type = MOV_REG_REG;
			encoder = encodeMovRegReg;

			if (op1 == 0x69 || op1 == 0x6B)
				found = TRUE;
			else
			{
				if (!GET_DIRECTION(in))
				{
					gop1 = MODRM_GET_RM(in, modRm);
					gop2 = MODRM_GET_REG(in, modRm);
				}

				if (MODRM_GET_MOD(modRm) == MOD_REG)
					found = TRUE;
				else if (IND_NO_DISP_SS)
				{
					if (HAS_SIB(in))
					{
						if (GET_DIRECTION(in))
							gop2 = SIB_GET_BASE(sib); // MOV_REG_RM
						else
							gop1 = SIB_GET_BASE(sib); // MOV_RM_REG
					}

					if (GET_DIRECTION(in))
						type = MOV_REG_RM;
					else
						type = MOV_RM_REG;
					encoder = encodeMatchAll;
					found = TRUE;
				}
			}

			BOOL isStdEpilogue = found && gop3 == 4 &&
								type == MOV_REG_REG && gop1 == REG_ESP && gop2 == REG_EBP		// mov esp, ebp
								&& in->next	&& isPopReg(in->next) && in->next->data[0] == 0x5D	// next is pop ebp
								&& i == (gdg->numIns - gdg->ending->numIns - 2)					// next is last
								&& !GEND_NO_LOAD(gdg->ending);									// ending must have a loader (we'll later pair 
																								// this gdg with a loader that movs ebp, esp)

			if (hasUsefulInstr)
			{
				if (isStdEpilogue)
				{
					G_SET_FLAG(gdg, STD_EPILOGUE);
					if (CONTAINS_REG(allRegWritesSoFar, REG_EBP) || // lose our saved value of esp
						CONTAINS_REG(allRegWritesSoFar, REG_ESP))	// uses the stack and we can't chain it using <mov ebp, esp; ret>
						G_SET_FLAG(gdg, MODIF_EBSP_BEF_STDE);		//							(or it will land in some <imm> value)
				}

				found = FALSE;
				if (type != MOV_REG_REG || // just about any indirect addressing [regA] is unsafe
					(gop1 == REG_ESP && !isStdEpilogue)) // because we don't know the amount moved (except for std-epilogue)
					hasUnsafeMemOp = TRUE;
				else // keep the one found earlier
					SET_REG(regWritesAfter, gop1);
			}
		}
//MOV_RM_IMM,		// mov [regA], imm, op1 is regA, op2 is imm, op3 is size of op1 in bytes (1, 2, or 4)
		else if (IND_NO_DISP_SS && (
			((op1 == 0xC6 || op1 == 0xC7) && MODRM_GET_OPEXT(modRm) == 0x0) // mov r/m8/16/32, imm8/16/32
			|| (op1 >= 0x80 && op1 <= 0x82 && IS_MODREG_OPEXT(modRm, 0x4) && imm == 0) // and [regA], 0
			|| (op1 >= 0x80 && op1 <= 0x82 && IS_MODREG_OPEXT(modRm, 0x1) && imm == 0xFFFFFFFF) // or [regA], 0xFFFFFFFF
			))
		{
			gop1 = MODRM_GET_RM(in, modRm);
			gop3 = SIZEOF_OPERAND(in);
			if (HAS_SIB(in))
				gop1 = SIB_GET_BASE(sib);

			if (op1 == 0xC6 || op1 == 0xC7)
				gop2 = imm;
			else if (op1 == 0x81)
			{
				if (MODRM_GET_OPEXT(modRm) == 0x4)
					gop2 = 0;
				else
					gop2 = 0xFFFFFFFF;
			}

			if (hasUsefulInstr) // just about any indirect addressing [regA] is unsafe
				hasUnsafeMemOp = TRUE;
			else
			{
				type = MOV_RM_IMM;
				encoder = encodeMatchAll;
				found = TRUE;
			}
		}
//ADD_REG,		// regA = regA+regB+x, op1 is regA, op2 is regB, op3 is x
		else if ((op1 == 0x01 || op1 == 0x03) && MODRM_GET_MOD(modRm) == MOD_REG)
		{
			if (GET_DIRECTION(in))
			{
				gop1 = MODRM_GET_REG(in, modRm);
				gop2 = MODRM_GET_RM(in, modRm);
			}
			else
			{
				gop1 = MODRM_GET_RM(in, modRm);
				gop2 = MODRM_GET_REG(in, modRm);
			}

			type = ADD_REG;
			encoder = encodeAddReg;

			if (hasUsefulInstr)
			{
				if ((gdg->gi.type == ADD_IMM || gdg->gi.type == SUB_IMM)
					&& gdg->gi.operand1 == gop1 && gdg->gi.operand3 == 4)
				{
					found = TRUE;
					gop3 = gdg->gi.operand2;
					if (gdg->gi.type == SUB_IMM)
						gop3 *= -1;
				}
				else if (gop1 == REG_ESP) // because we don't know the amount added
					hasUnsafeMemOp = TRUE;
				else // keep the one found earlier
					SET_REG(regWritesAfter, gop1);
			}
			else
				found = TRUE;
		}
//SUB_REG,		// regA = regA-regB-x, op1 is regA, op2 is regB, op3 is x
		else if ((op1 == 0x29 || op1 == 0x2B) && MODRM_GET_MOD(modRm) == MOD_REG)
		{
			if (GET_DIRECTION(in))
			{
				gop1 = MODRM_GET_REG(in, modRm);
				gop2 = MODRM_GET_RM(in, modRm);
			}
			else
			{
				gop1 = MODRM_GET_RM(in, modRm);
				gop2 = MODRM_GET_REG(in, modRm);
			}

			type = SUB_REG;
			encoder = encodeSubReg;

			if (hasUsefulInstr)
			{
				if ((gdg->gi.type == ADD_IMM || gdg->gi.type == SUB_IMM)
					&& gdg->gi.operand1 == gop1 && gdg->gi.operand3 == 4)
				{
					found = TRUE;
					gop3 = gdg->gi.operand2;
					if (gdg->gi.type == ADD_IMM)
						gop3 *= -1;
				}
				else if (gop1 == REG_ESP) // because we don't know the amount added
					hasUnsafeMemOp = TRUE;
				else // keep the one found earlier
					SET_REG(regWritesAfter, gop1);
			}
			else
				found = TRUE;
		}
//MUL_REG,		// mul regA, regB, op1 is regA, op2 is regB
		else if (
			(op1 == 0x0F && op2 == 0xAF && MODRM_GET_MOD(modRm) == MOD_REG)
			|| (op1 == 0xF7 && IS_MODREG_OPEXT(modRm, 0x5))
			)
		{
			if (op1 == 0x0F)
				gop1 = MODRM_GET_REG(in, modRm);
			else
				gop1 = REG_EAX;
			gop2 = MODRM_GET_RM(in, modRm);

			if (hasUsefulInstr) // because we don't know the multiplier 
			{
				if (gop1 == REG_ESP)
					hasUnsafeMemOp = TRUE;
				else // keep the one found earlier
					SET_REG(regWritesAfter, gop1);
			}
			else
			{
				type = MUL_REG;
				encoder = encodeMatchAll;
				found = TRUE;
			}
		}
//DIV_REG,		// regA = regB / regC, op1 is regA, op2 is regB, op3 is regC (signed integer division using edx:eax)
		else if (op1 == 0xF7 && IS_MODREG_OPEXT(modRm, 0x7))
		{
			gop1 = REG_EAX;
			gop2 = REG_EAX;
			gop3 = MODRM_GET_RM(in, modRm);

			if (hasUsefulInstr) // because we don't know the divider
			{
				if (gop1 == REG_ESP)
					hasUnsafeMemOp = TRUE;
				else // keep the one found earlier
					SET_REG(regWritesAfter, gop1);
			}
			else
			{
				type = DIV_REG;
				encoder = encodeMatchAll;
				found = TRUE;
			}
		}
//XCHG_REG_REG,	// xchg regA, regB, op1 is regA, op2 is regB, op3 is size of op1 in bytes (1, 2, or 4)
//XCHG_REG_RM,	// xchg regA, [regB], op1 is regA, op2 is regB, op3 is size of op1 in bytes (1, 2, or 4)
		else if (op1 == 0x86 || op1 == 0x87
			|| (op1 > 0x90 && op1 <= 0x97)
			)
		{
			gop3 = SIZEOF_OPERAND(in);
			if (op1 > 0x90 && op1 <= 0x97)
			{
				gop1 = REG_EAX;
				gop2 = op1 ^ 0x90;
				type = XCHG_REG_REG;
				encoder = encodeXchgRegReg;
				found = TRUE;
			}
			else
			{
				gop1 = MODRM_GET_REG(in, modRm);
				gop2 = MODRM_GET_RM(in, modRm);
				if (MODRM_GET_MOD(modRm) == MOD_REG)
				{
					type = XCHG_REG_REG;
					encoder = encodeXchgRegReg;
					found = TRUE;
				}
				else if (IND_NO_DISP_SS)
				{
					if (HAS_SIB(in))
						gop2 = SIB_GET_BASE(sib);

					type = XCHG_REG_RM;
					encoder = encodeXchgRegRm;
					found = TRUE;
				}
			}

			if (hasUsefulInstr)
			{
				found = FALSE;
				if (gop1 == REG_ESP || gop2 == REG_ESP || type == XCHG_REG_RM)
					hasUnsafeMemOp = TRUE;
				else // keep the one found earlier
					SET_REG(regWritesAfter, gop1);
			}
		}
//GPUSH_IMM,		// mov [esp+x], imm32: op1 is imm32, x >= 4
		else if (op1 == 0xC7 && IS_32BIT_OPERAND(in) && MODRM_GET_OPEXT(modRm) == 0x0 // mov r/m32, imm32
			&& (MODRM_GET_MOD(modRm) == MOD_IND_DISP8 || MODRM_GET_MOD(modRm) == MOD_IND_DISP32)
			&& HAS_SIB(in) && SIB_GET_BASE(sib) == REG_ESP && SIB_GET_INDEX(sib) == REG_ESP 
			&& SIB_GET_SS(sib) == 0 && !GEND_NO_LOAD(gdg->ending) && 
			disp == 4 + gdg->ending->stackAdvBefRet + gdg->ending->stackAdvAftRet)
		{
			gop1 = imm;
			gop2 = 0;
			gop3 = 4;
			if (hasUsefulInstr ||  // just about any indirect addressing [regA] is unsafe
				(i != (gdg->numIns - gdg->ending->numIns - 1))) // this is the last instruction
				hasUnsafeMemOp = TRUE;
			else
			{
				type = GPUSH_IMM;
				encoder = encodePush;
				found = TRUE;
				G_SET_FLAG(gdg, LAST_IN_CHAIN); // can't be chained
			}
		}
//GPUSH_REG,		// mov [esp+x], reg: op1 is reg, x >= 4
		else if (op1 == 0x89 && IS_32BIT_OPERAND(in) // mov r/m32, reg32
			&& (MODRM_GET_MOD(modRm) == MOD_IND_DISP8 || MODRM_GET_MOD(modRm) == MOD_IND_DISP32)
			&& HAS_SIB(in) && SIB_GET_BASE(sib) == REG_ESP && SIB_GET_INDEX(sib) == REG_ESP
			&& SIB_GET_SS(sib) == 0 && !GEND_NO_LOAD(gdg->ending) && 
			disp == 4 + gdg->ending->stackAdvBefRet + gdg->ending->stackAdvAftRet)
		{
			gop1 = MODRM_GET_REG_RAW(modRm);
			gop2 = 0;
			gop3 = 4;
			if (hasUsefulInstr // just about any indirect addressing [regA] is unsafe
				|| (i != (gdg->numIns - gdg->ending->numIns - 1))) // this is not the last instruction
				hasUnsafeMemOp = TRUE;
			else
			{
				type = GPUSH_REG;
				encoder = encodePush;
				found = TRUE;
				G_SET_FLAG(gdg, LAST_IN_CHAIN); // can't be chained
			}
		}
// other types of pops before the useful instruction (if any)
		else if (isPop(in) && !hasUsefulInstr)
		{
			hasOtherPopBefore = TRUE; // if we find a usefulInstr we'll have to cancel it later
		}
		else if (op1 == 0xFC) // cld
		{
			G_CLEAR_FLAG(gdg, SETS_DF);
			G_SET_FLAG(gdg, CLEARS_DF);
		}
		else if (op1 == 0xFD) // std
		{
			G_CLEAR_FLAG(gdg, CLEARS_DF);
			G_SET_FLAG(gdg, SETS_DF);
		}
		else if (hasUsefulInstr)
			regWritesAfter |= in->regWrites;

		allRegWritesSoFar |= in->regWrites;
		
		if (found && !hasUnsafeMemOp && 
			(OFFSET_TO_OPCODE(in) == 0 || (SUPPORTS_OPER_SZ[type] && IS_16BIT_OPERAND(in) && OFFSET_TO_OPCODE(in) == 1))
			&& !hasOtherPopBefore)
		{
			hasUsefulInstr = TRUE;
			gdg->gi.type = type;
			gdg->gi.operand1 = gop1;
			gdg->gi.operand2 = gop2;
			gdg->gi.operand3 = gop3;
			gdg->gi.i = gin;
			gdg->encode = encoder;
		}
		else if (hasUnsafeMemOp || hasOtherPopBefore || readsIndOrwritesToMem(in)
			// special case of test reg,reg (ADD_IMM(reg,0)) and flags modified afterwards, thus rendering it useless
			|| (hasUsefulInstr && gdg->gi.type == ADD_IMM && gdg->gi.operand2 == 0 && modifiesEFlags(in)))
		{
			hasUsefulInstr = FALSE;
			hasUnsafeMemOp = TRUE;
			gdg->gi.type = UNDEFINED;
			gdg->gi.operand1 = 0;
			gdg->gi.operand2 = 0;
			gdg->gi.operand3 = 0;
			gdg->gi.i = gdg->ins;
			gdg->encode = encodeExact;

			if (!G_HAS_FLAG(gdg, MODIF_EFLAGS) && modifiesEFlags(in))
				G_SET_FLAG(gdg, MODIF_EFLAGS);
		}
		else if (!G_HAS_FLAG(gdg, MODIF_EFLAGS) && modifiesEFlags(in))
		{
			G_SET_FLAG(gdg, MODIF_EFLAGS);
		}
	}

	// encode by searching in the instruction list without worrying about intermediate unsafe instructions
	if (!hasUsefulInstr && !hasUnsafeMemOp)
	{
		gdg->gi.type = UNDEFINED;
		gdg->encode = encodeApprox;
	}

	// calculate writes to registers (except for the usefull instruction)
	gdg->regWrites = 0;
	in = gdg->ins;
	for (DWORD i = 0; (i < gdg->numIns - gdg->ending->numIns); i++, in = in->next)
	{
		if (gdg->gi.type == UNDEFINED || in != gdg->gi.i)
			gdg->regWrites |= in->regWrites;
	}

	// check if the destination register is being written afterwards
	switch (gdg->gi.type)
	{
	case LOAD_RM:
	case MOV_RM_IMM:
	case MOV_RM_REG:
	case UNDEFINED:
		break;
	default:
		if (CONTAINS_REG(regWritesAfter, gdg->gi.operand1) 
			|| CONTAINS_REG(gdg->ending->regWrites ^ (1 << REG_ESP), gdg->gi.operand1))
		{
			hasUnsafeMemOp = TRUE;
			gdg->gi.type = UNDEFINED;
			gdg->gi.operand1 = 0;
			gdg->gi.operand2 = 0;
			gdg->gi.operand3 = 0;
			gdg->gi.i = gdg->ins;
			gdg->encode = encodeExact;
		}
		break;
	}

#ifdef VDEBUG_MODE
	puts("");
	printGadget(gdg);
#endif

#undef IND_NO_DISP
}

void printGadget(GADGET *gdg)
{
	printf("Gadget with %d instructions:\n", gdg->numIns - gdg->ending->numIns);
	printIDisassembly(gdg->ins, gdg->numIns, gdg->va);
	printf("Type: %s(%d, %d, %d)%s\n", INSTR_TYPES[gdg->gi.type],
		gdg->gi.operand1, gdg->gi.operand2, gdg->gi.operand3,
		(((gdg->gi.type == UNDEFINED && gdg->encode == encodeApprox) ? "-SAFE" : "")));
	if (gdg->gi.type != UNDEFINED)
	{
		printf("Index of useful instruction is: [%d]\n", gdg->gi.i->index);
		if (G_HAS_FLAG(gdg, STD_EPILOGUE))
			puts("Followed by standard epilogue");
	}
	if (gdg->regWrites)
	{
		printf("Writes to registers: ");
		for (BYTE reg = 0; reg < 8; reg++) {
			if (CONTAINS_REG(gdg->regWrites, reg))
				printf("%s ", REG[2][reg]);
		}
		printf("\n");
	}
	printf("Stack advance: %d bytes, ending before/after ret: %d/%d\n", gdg->stackAdvance, gdg->ending->stackAdvBefRet, gdg->ending->stackAdvAftRet);
}

BOOL classifyInstruction(GINSTRUCTION *gi)
{
	INSTRUCTION *in = gi->i;
	BYTE op1 = *(in->data + OFFSET_TO_OPCODE(in));
	BYTE op2 = *(in->data + OFFSET_TO_OPCODE(in) + 1);
	BYTE modRm = *(in->data + OFFSET_TO_MODRM(in));
	BYTE sib = *(in->data + OFFSET_TO_SIB(in));
	long disp = getDisp(in);
	long imm = getImm(in);

	BOOL found = FALSE;
	long gop1 = 0, gop2 = 0, gop3 = 0;
	INSTR_TYPE type = UNDEFINED; // gadget type

	//LOADS,			// lods m8/16/32 (load string), op1 is eax, op2 is esi, op3 is size of op1 in bytes (1, 2, or 4)
	if (op1 == 0xAC || op1 == 0xAD)
	{
		gop1 = REG_EAX;
		gop2 = REG_ESI;
		gop3 = SIZEOF_OPERAND(in);
		type = LOADS;
		found = TRUE;
	}
	//LOAD_REG,			// pop regA, op1 is regA
	else if (isPopReg(in))
	{
		if (op1 == 0x8F)
			gop1 = MODRM_GET_RM(in, modRm);
		else
			gop1 = 0x58 ^ op1;

		found = TRUE;
		type = LOAD_REG;
	}
	//LOAD_RM,		// pop [regA], op1 is regA
	else if (op1 == 0x8F && IND_NO_DISP_SS)
	{
		if (HAS_SIB(in))
			gop1 = SIB_GET_BASE(sib);
		else
			gop1 = MODRM_GET_RM(in, modRm);

		found = TRUE;
		type = LOAD_RM;
	}
	//ADD_IMM,		// op1 is the register, op2 is imm, op3 is size of op1 in bytes (1, 2, or 4)
	else if (op1 == 0x04 || op1 == 0x05 // add eax/al, imm8/16/32
		|| (op1 >= 0x80 && op1 <= 0x83 && (IS_MODREG_OPEXT(modRm, 0x0)
										|| (IS_MODREG_OPEXT(modRm, 0x6) && imm == 0)	// xor r/m8/16/32, 0
										|| (IS_MODREG_OPEXT(modRm, 0x7) && imm == 0)	// cmp r/m8/16/32, 0
										))
		|| (op1 >= 0x40 && op1 <= 0x47) // inc reg32
		|| ((op1 == 0xFE || op1 == 0xFF) && IS_MODREG_OPEXT(modRm, 0x0)) // inc r/m8/16/32
		|| ((op1 == 0x84 || op1 == 0x85) && IS_MODREG_EQREGS(modRm)) // test  regA, regA
		|| ((op1 == 0xA8 || op1 == 0xA9) && imm == -1) // test al/ax/eax, 0xFF/0xFFFF/0xFFFFFFFF
		|| ((op1 == 0xF6 || op1 == 0xF7) && (IS_MODREG_OPEXT(modRm, 0x0) || IS_MODREG_OPEXT(modRm, 0x1)) && imm == -1) // test r/m8/16/32, 0xFF/0xFFFF/0xFFFFFFFF
		|| (op1 >= 0x08 && op1 <= 0x0B && IS_MODREG_EQREGS(modRm)) // or regA, regA
		|| (op1 >= 0x20 && op1 <= 0x23 && IS_MODREG_EQREGS(modRm)) // and regA, regA
		)
	{
		gop3 = op1 == 0x83 ? (4-2*IS_16BIT_OPERAND(in)) : SIZEOF_OPERAND(in); // we're interested in the dest. reg size
		if (op1 == 0x04 || op1 == 0x05)
		{
			gop1 = REG_EAX;
			gop2 = imm;
		}
		else if (op1 >= 0x80 && op1 <= 0x83)
		{
			gop1 = MODRM_GET_RM(in, modRm);
			gop2 = imm;
		}
		else if (op1 >= 0x40 && op1 <= 0x47)
		{
			gop1 = op1 ^ 0x40;
			gop2 = 1;
		}
		else if (op1 == 0x84 || op1 == 0x85 || op1 == 0xF6 || op1 == 0xF7
			|| (op1 >= 0x08 && op1 <= 0x0B) || (op1 >= 0x20 && op1 <= 0x23))
		{
			gop1 = MODRM_GET_RM(in, modRm);
			gop2 = 0;
		}
		else if (op1 == 0xA8 || op1 == 0xA9)
		{
			gop1 = REG_EAX;
			gop2 = 0;
		}
		else
		{
			gop1 = MODRM_GET_RM(in, modRm);
			gop2 = 1;
		}

		found = TRUE;
		type = ADD_IMM;
	}
	//SUB_IMM,		// op1 is the register, op2 is imm, op3 is size of op1 in bytes (1, 2, or 4)
	else if (op1 == 0x2C || op1 == 0x2D
		|| (op1 >= 0x80 && op1 <= 0x83 && IS_MODREG_OPEXT(modRm, 0x5))
		|| (op1 >= 0x48 && op1 <= 0x4F) // dec reg32
		|| ((op1 == 0xFE || op1 == 0xFF) && IS_MODREG_OPEXT(modRm, 0x1)) // dec r/m8/16/32
		)
	{
		gop3 = op1 == 0x83 ? (4-2*IS_16BIT_OPERAND(in)) : SIZEOF_OPERAND(in); // we're interested in the dest. reg size
		if (op1 == 0x2C || op1 == 0x2D)
		{
			gop1 = REG_EAX;
			gop2 = imm;
		}
		else if (op1 >= 0x80 && op1 <= 0x83)
		{
			gop1 = MODRM_GET_RM(in, modRm);
			gop2 = imm;
		}
		else if (op1 >= 0x48 && op1 <= 0x4F)
		{
			gop1 = op1 ^ 0x48;
			gop2 = 1;
		}
		else
		{
			gop1 = MODRM_GET_RM(in, modRm);
			gop2 = 1;
		}

		found = TRUE;
		type = SUB_IMM;
	}
	//MUL_IMM,			// regA = regB * imm, op1 is regA, op2 is regB, op3 == imm
	else if ((op1 == 0x69 || op1 == 0x6B
		|| ((op1 == 0xC1 || op1 == 0xD1) && (IS_MODREG_OPEXT(modRm, 0x4) || IS_MODREG_OPEXT(modRm, 0x6))) // shl/sal
		)
		&& MODRM_GET_MOD(modRm) == MOD_REG
		)
	{
		if (op1 == 0x69 || op1 == 0x6B)
		{
			gop1 = MODRM_GET_REG(in, modRm);
			gop2 = MODRM_GET_RM(in, modRm);
			gop3 = imm;
		}
		else
		{
			gop1 = MODRM_GET_RM(in, modRm);
			gop2 = gop1;
			if (op1 == 0xD1)
				gop3 = 2;
			else
				gop3 = 2 << imm;
		}

		found = TRUE;
		type = MUL_IMM;
	}
	//DIV_IMM,			// op1 is the register, op2 is imm, op3 is size of op1 in bytes (1, 2, or 4)
	else if (((op1 == 0xC0 || op1 == 0xC1 || op1 == 0xD0 || op1 == 0xD1) &&
		(IS_MODREG_OPEXT(modRm, 0x5) || IS_MODREG_OPEXT(modRm, 0x7))) // shr/sar
		)
	{
		gop1 = MODRM_GET_RM(in, modRm);
		gop3 = op1 == 0xC1 ? (4-2*IS_16BIT_OPERAND(in)) : SIZEOF_OPERAND(in);
		if (op1 == 0xD0 || op1 == 0xD1)
			gop2 = 2;
		else
			gop2 = 2 << imm;

		found = TRUE;
		type = DIV_IMM;
	}
	//MOV_REG_IMM,		// op1 is the register, op2 is imm, op3 is size of op1 in bytes (1, 2, or 4)
	else if (((op1 >= 0xB0 && op1 <= 0xBF)
		|| ((op1 == 0xC6 || op1 == 0xC7) && IS_MODREG_OPEXT(modRm, 0x0)) // mov r/m8/16/32, imm8/16/32
		|| ((op1 == 0x69 || op1 == 0x6B) && imm == 0) // imul regA, regX, 0
		|| ((op1 >= 0x30 && op1 <= 0x33) && IS_MODREG_EQREGS(modRm)) // xor regA, regA
		|| ((op1 == 0x25 || (op1 >= 0x80 && op1 <= 0x83 && IS_MODREG_OPEXT(modRm, 0x4))) && imm == 0) // and regA, 0
		|| ((op1 == 0x0D || (op1 >= 0x80 && op1 <= 0x83 && IS_MODREG_OPEXT(modRm, 0x1))) && imm == -1) // or regA, 0xFFFFFFFF
		|| ((op1 == 0x29 || op1 == 0x2B) && IS_MODREG_EQREGS(modRm)) // sub regA, regA
		))
	{
		gop2 = imm;
		gop3 = op1 == 0x83 ? (4 - 2*IS_16BIT_OPERAND(in)) : SIZEOF_OPERAND(in);
		if (op1 == 0xC6 || op1 == 0xC7 || (op1 >= 0x80 && op1 <= 0x83))
			gop1 = MODRM_GET_RM(in, modRm);
		else if (op1 >= 0xB0 && op1 <= 0xB7)
			gop1 = op1 ^ 0xB0;
		else if (op1 >= 0xB8 && op1 <= 0xBF)
			gop1 = op1 ^ 0xB8;
		else if (op1 == 0x69 || op1 == 0x6B
			|| op1 == 0x31 || op1 == 0x33
			|| op1 == 0x29 || op1 == 0x2B
			)
		{
			gop1 = MODRM_GET_REG(in, modRm);
			gop2 = 0;
		}
		else if (op1 == 0x25 || op1 == 0x0D)
			gop1 = REG_EAX;

		found = TRUE;
		type = MOV_REG_IMM;
	}

	//MOV_REG_REG,		// mov regA, regB, op1 is regA, op2 is regB, op3 is size of op1 in bytes (1, 2, or 4)
	//MOV_REG_RM,		// mov regA, [regB], op1 is regA, op2 is regB, op3 is size of op1 in bytes (1, 2, or 4)
	//MOV_RM_REG,		// mov [regA], regB, op1 is regA, op2 is regB, op3 is size of op1 in bytes (1, 2, or 4)
	else if ((op1 >= 0x88 && op1 <= 0x8B)
		|| ((op1 == 0x69 || op1 == 0x6B) && imm == 1) // imul regA, regX, 1
		)
	{
		gop1 = MODRM_GET_REG(in, modRm);
		gop2 = MODRM_GET_RM(in, modRm);
		gop3 = (op1 == 0x6B) ? (4-2*IS_16BIT_OPERAND(in)) : SIZEOF_OPERAND(in);
		type = MOV_REG_REG;

		if (op1 == 0x69 || op1 == 0x6B)
			found = TRUE;
		else
		{
			if (!GET_DIRECTION(in))
			{
				gop1 = MODRM_GET_RM(in, modRm);
				gop2 = MODRM_GET_REG(in, modRm);
			}

			if (MODRM_GET_MOD(modRm) == MOD_REG)
				found = TRUE;
			else if (IND_NO_DISP_SS)
			{
				if (HAS_SIB(in))
				{
					if (GET_DIRECTION(in))
						gop2 = SIB_GET_BASE(sib); // MOV_REG_RM
					else
						gop1 = SIB_GET_BASE(sib); // MOV_RM_REG
				}

				type = GET_DIRECTION(in) ? MOV_REG_RM : MOV_RM_REG;
				found = TRUE;
			}
		}
	}
	//MOV_RM_IMM,		// mov [regA], imm, op1 is regA, op2 is imm, op3 is size of op1 in bytes (1, 2, or 4)
	else if (IND_NO_DISP_SS && (
		((op1 == 0xC6 || op1 == 0xC7) && MODRM_GET_OPEXT(modRm) == 0x0) // mov r/m8/16/32, imm8/16/32
		|| (op1 >= 0x80 && op1 <= 0x82 && IS_MODREG_OPEXT(modRm, 0x4) && imm == 0) // and [regA], 0
		|| (op1 >= 0x80 && op1 <= 0x82 && IS_MODREG_OPEXT(modRm, 0x1) && imm == 0xFFFFFFFF) // or [regA], 0xFFFFFFFF
		))
	{
		gop1 = MODRM_GET_RM(in, modRm);
		gop3 = SIZEOF_OPERAND(in);
		if (HAS_SIB(in))
			gop1 = SIB_GET_BASE(sib);

		if (op1 == 0xC6 || op1 == 0xC7)
			gop2 = imm;
		else if (op1 == 0x81)
		{
			if (MODRM_GET_OPEXT(modRm) == 0x4)
				gop2 = 0;
			else
				gop2 = 0xFFFFFFFF;
		}

		type = MOV_RM_IMM;
		found = TRUE;
	}
	//ADD_REG,		// regA = regA+regB+x, op1 is regA, op2 is regB, op3 is x
	else if ((op1 == 0x01 || op1 == 0x03) && MODRM_GET_MOD(modRm) == MOD_REG)
	{
		if (GET_DIRECTION(in))
		{
			gop1 = MODRM_GET_REG(in, modRm);
			gop2 = MODRM_GET_RM(in, modRm);
		}
		else
		{
			gop1 = MODRM_GET_RM(in, modRm);
			gop2 = MODRM_GET_REG(in, modRm);
		}

		type = ADD_REG;
		found = TRUE;
	}
	//SUB_REG,		// regA = regA-regB-x, op1 is regA, op2 is regB, op3 is x
	else if ((op1 == 0x29 || op1 == 0x2B) && MODRM_GET_MOD(modRm) == MOD_REG)
	{
		if (GET_DIRECTION(in))
		{
			gop1 = MODRM_GET_REG(in, modRm);
			gop2 = MODRM_GET_RM(in, modRm);
		}
		else
		{
			gop1 = MODRM_GET_RM(in, modRm);
			gop2 = MODRM_GET_REG(in, modRm);
		}

		type = SUB_REG;
		found = TRUE;
	}
	//MUL_REG,		// mul regA, regB, op1 is regA, op2 is regB
	else if (
		(op1 == 0x0F && op2 == 0xAF && MODRM_GET_MOD(modRm) == MOD_REG)
		|| (op1 == 0xF7 && IS_MODREG_OPEXT(modRm, 0x5))
		)
	{
		if (op1 == 0x0F)
			gop1 = MODRM_GET_REG(in, modRm);
		else
			gop1 = REG_EAX;
		gop2 = MODRM_GET_RM(in, modRm);

		type = MUL_REG;
		found = TRUE;
	}
	//DIV_REG,		// regA = regB / regC, op1 is regA, op2 is regB, op3 is regC (signed integer division using edx:eax)
	else if (op1 == 0xF7 && IS_MODREG_OPEXT(modRm, 0x7))
	{
		gop1 = REG_EAX;
		gop2 = REG_EAX;
		gop3 = MODRM_GET_RM(in, modRm);

		type = DIV_REG;
		found = TRUE;
	}
	//XCHG_REG_REG,	// xchg regA, regB, op1 is regA, op2 is regB, op3 is size of op1 in bytes (1, 2, or 4)
	//XCHG_REG_RM,	// xchg regA, [regB], op1 is regA, op2 is regB, op3 is size of op1 in bytes (1, 2, or 4)
	else if (op1 == 0x86 || op1 == 0x87
		|| (op1 > 0x90 && op1 <= 0x97)
		)
	{
		gop3 = SIZEOF_OPERAND(in);
		if (op1 > 0x90 && op1 <= 0x97)
		{
			gop1 = REG_EAX;
			gop2 = op1 ^ 0x90;
			type = XCHG_REG_REG;
			found = TRUE;
		}
		else
		{
			gop1 = MODRM_GET_REG(in, modRm);
			gop2 = MODRM_GET_RM(in, modRm);
			if (MODRM_GET_MOD(modRm) == MOD_REG)
			{
				type = XCHG_REG_REG;
				found = TRUE;
			}
			else if (IND_NO_DISP_SS)
			{
				if (HAS_SIB(in))
					gop2 = SIB_GET_BASE(sib);

				type = XCHG_REG_RM;
				found = TRUE;
			}
		}
	}
	//GPUSH_IMM,		// push imm32: op1 is imm32
	else if (op1 == 0x68 && IS_32BIT_OPERAND(in))
	{
		gop1 = imm;
		gop2 = 0;
		gop3 = 4;
		type = GPUSH_IMM;
		found = TRUE;
	}
	//GPUSH_REG,		// push reg32: op1 is reg
	else if (op1 >= 0x50 && op1 <= 0x57 && IS_32BIT_OPERAND(in))
	{
		gop1 = 0x50 ^ op1;
		gop2 = 0;
		gop3 = 4;
		type = GPUSH_REG;
		found = TRUE;
	}


	if (found &&
		(OFFSET_TO_OPCODE(in) == 0 || (SUPPORTS_OPER_SZ[type] && // ...and prefix is for operand size only
									IS_16BIT_OPERAND(in) && OFFSET_TO_OPCODE(in) == 1)))
	{
		gi->type = type;
		gi->operand1 = gop1;
		gi->operand2 = gop2;
		gi->operand3 = gop3;
	}
	else
	{
		gi->type = UNDEFINED;
		gi->operand1 = 0;
		gi->operand2 = 0;
		gi->operand3 = 0;
	}
	
	return type != UNDEFINED;

#undef IND_NO_DISP
}

CCNest *getCCNests(LPCVOID base)
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
	PIMAGE_SECTION_HEADER codeHdr = &(section_headers[codeSecIdx]);
	BYTE *code = ADDR0(codeHdr->VirtualAddress);
	DWORD codeLen = (codeHdr->Misc.VirtualSize < codeHdr->SizeOfRawData) ?
		codeHdr->Misc.VirtualSize : codeHdr->SizeOfRawData;
	if (codeLen < 2)
		return NULL;

	DWORD codeBase = imageBase + codeHdr->VirtualAddress;
	CCNest *cur = (CCNest *) calloc(1, sizeof(CCNest));
	CCNest *head = cur, *prev;
	DWORD ccStart;
	DWORD cnt;

	for (DWORD offset = 0; offset < codeLen - 6; offset++)
	{
		if (code[offset] == 0x8B 
			&& code[offset + 1] == 0xE5
			&& code[offset + 2] == 0x5D)	// std. epilogue (mov esp, ebp; pop ebp; ret(n))
		{
			if (code[offset + 3] == 0xC2	// followed by retn
				&& *((WORD *)(code + offset + 4)) < MAX_STACK_WASTE
				&& code[offset + 6] == 0xCC)
				ccStart = offset + 6;
			else if (code[offset + 3] == 0xC3 && code[offset + 4] == 0xCC) // followed by ret
				ccStart = offset + 4;
			else // followed by nothing
				ccStart = 0;
		}
		else if (code[offset] == 0xCC)
			ccStart = offset;
		else if ((code[offset] == 0xC3 && code[offset+1] == 0xCC)	// ret
			|| (code[offset] == 0xC2								// retn
				&& *((WORD *)(code + offset + 1)) < MAX_STACK_WASTE
				&& code[offset + 3] == 0xCC))
		{
			ccStart = offset + (code[offset] == 0xC3 ? 1 : 3);

			// search backwards for pops
			while (offset - 1 >= 0 && FITS_CHAR(ccStart - offset + 16) &&
				(code[offset - 1] >= 0x58) && (code[offset - 1] <= 0x5F))
				offset--;
		}
		else
			ccStart = 0;

		if (ccStart)
		{
			cnt = 0;
			while (code[ccStart + cnt] == 0xCC) cnt++;

			cur->start = code + offset;
			if (cnt > CCSZ_OVERHEAD(cur))	
			{
				cur->va = codeBase + offset;
				cur->end = code + ccStart + cnt;
				cur->next = (CCNest *)calloc(1, sizeof(CCNest));
				prev = cur;
				cur = cur->next;
			}

			offset = ccStart + cnt;
		}
	}

	if (head == cur)
	{
		free(head);
		head = NULL;
	}
	else
	{
		prev->next = NULL;
		free(cur);
	}
	return head;
}

CCNest *convPaddingToCC(LPCVOID base)
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
	PIMAGE_SECTION_HEADER codeHdr = &(section_headers[codeSecIdx]);
	BYTE *code = ADDR0(codeHdr->VirtualAddress);
	DWORD codeLen = (codeHdr->Misc.VirtualSize < codeHdr->SizeOfRawData) ?
		codeHdr->Misc.VirtualSize : codeHdr->SizeOfRawData;
	if (codeLen < 2)
		return NULL;

	DWORD codeBase = imageBase + codeHdr->VirtualAddress;

	if (codeHdr->Misc.VirtualSize < codeHdr->SizeOfRawData) // expand the file alignment padding
	{
		CCNest *cc = (CCNest *)calloc(1, sizeof(CCNest));
		cc->va = codeBase + codeHdr->Misc.VirtualSize;
		cc->start = code + codeHdr->Misc.VirtualSize;
		cc->end = code + codeHdr->SizeOfRawData;

		for (DWORD i = codeHdr->Misc.VirtualSize; i < codeHdr->SizeOfRawData; i++)
			code[i] = 0xCC;
		codeHdr->Misc.VirtualSize = codeHdr->SizeOfRawData;
		codeLen = codeHdr->SizeOfRawData;
		return cc;
	}

	return NULL;
}

CCNest *getNestFor(DWORD szNeeded, CCNest *head, BYTE **ccStart)
{
	CCNest *cc = head;
	while (cc)
	{
		*ccStart = cc->start;
		while (**ccStart != 0xCC)
			(*ccStart)++;

		if ((DWORD)(cc->end - *ccStart) < szNeeded + CCSZ_OVERHEAD(cc))
			cc = cc->next;
		else
			break;
	}
	return cc;
}

BYTE *assembleGadget(GINSTRUCTION *gi, DWORD *length, DWORD stackAdvAfter)
{
#define EXACT_COPY	do {\
						code = (BYTE *)malloc(gi->i->totalSize * sizeof(BYTE));\
						memcpy(code, gi->i->data, gi->i->totalSize);\
						len = gi->i->totalSize;\
					} while(0);

	BYTE *code = NULL;
	DWORD len = 0;
	switch (gi->type)
	{
	case LOADS:
	case ADD_IMM:
	case SUB_IMM:
	case MUL_IMM:
	case DIV_IMM:
	case MOV_REG_REG:
	case MOV_REG_RM:
	case ADD_REG:
	case SUB_REG:
	case MUL_REG:
	case DIV_REG:
	case XCHG_REG_REG:
	case XCHG_REG_RM:
	case UNDEFINED:
		EXACT_COPY
		break;
	case MOV_REG_IMM:
		if (gi->operand3 == 4)
		{
			code = (BYTE *)malloc(1 * sizeof(BYTE));
			code[0] = 0x58 + (BYTE)gi->operand1; // pop reg
			len = 1;
		}
		else
			EXACT_COPY
		break;
	case MOV_RM_IMM:
		if (gi->operand3 == 4)
		{
			code = (BYTE *)malloc(2 * sizeof(BYTE));
			code[0] = 0x8F; // pop [reg]
			code[1] = MAKE_MODRM(MOD_IND, 0x0, gi->operand1);
			len = 2;
		}
		else
			EXACT_COPY
		break;
	case GPUSH_IMM:
		len = 4 * sizeof(BYTE) + sizeof(DWORD);
		code = (BYTE *)malloc(len);
		code[0] = 0xC7;
		code[1] = 0x44;
		code[2] = 0x24;
		code[3] = 0x04 + stackAdvAfter;
		*((long *)(code + 4)) = gi->operand1;
		break;
	case GPUSH_REG:
		len = 4 * sizeof(BYTE);
		code = (BYTE *)malloc(len);
		code[0] = 0x89;
		code[1] = MAKE_MODRM(MOD_IND_DISP8, gi->operand1, REG_ESP);
		code[2] = MAKE_SIB(0, REG_ESP, REG_ESP);
		code[3] = 0x04 + stackAdvAfter;
		break;
	default:
		break;
	}

	if (length)
		*length = len;
	return code;
}

void repeatPUSHADV(STACK_OPER *chain, long *chainIdx, INSTRUCTION **i)
{
#define ADVANCE_I do { \
					(*i)->next = (*i) + 1;\
					(*i)->next->index = (*i)->index+1;\
					(*i) = (*i)->next;\
				} while (0);

	DWORD times = 1, numOper = 1;
	INSTRUCTION *dst;
	BYTE freeRegs = chain[*chainIdx].freeRegs;
	if (freeRegs)
	{
#define EQUAL_OPER(idx1, idx2) (chain[idx1].freeRegs == chain[idx2].freeRegs\
							&& chain[idx1].type == chain[idx2].type\
							&& chain[idx1].data == chain[idx2].data\
							&& chain[idx2].type != NOP && chain[idx2].type != CHAIN\
							&& chain[idx2].freeRegs == freeRegs)

		times = 0;
		for (numOper = 1; times <= 1 && numOper <= 4 && ((*chainIdx) - (long)numOper + 1) >= 0; numOper++)
		{
			times = 0;
			BOOL equal;
			do {
				equal = TRUE;
				for (BYTE i = 0; equal && i < numOper; i++)
					equal = EQUAL_OPER((*chainIdx) - i, (*chainIdx) - times*numOper - i);

				if (equal) 
					times++;
			} while (equal && ((*chainIdx) - ((long)times+1)*(long)numOper + 1) >= 0);
		}
		numOper--;
#undef EQUAL_OPER
	}
	
	BYTE reg = REG_EAX;
	// 4 is the minimum instr. overhead for looping (see mov, dec, jnz below)
	BOOL loop = times > 1 && (times*numOper >= 4);
	if (loop)
	{
		while (reg < 8 && !CONTAINS_REG(freeRegs, reg)) reg++;
		assert(reg < 8);

		setMOV_REG_IMM32(*i, reg, times);
		ADVANCE_I
		dst = *i;
	}

	for (DWORD d = 0; d < numOper; d++)
	{
		switch (chain[(*chainIdx)-d].type)
		{
		case PUSH_VA:
			setPUSH_IMM32(*i, chain[(*chainIdx)-d].data);
			SET_CONTAINS_VA(*i);
			(*i)->directVA = 1;
			break;
		case PUSH_IMM:
			setPUSH_IMM32(*i, chain[(*chainIdx)-d].data);
			break;
		case ADVANCE:
			setSUB_REG_IMM(*i, REG_ESP, chain[(*chainIdx)-d].offset);
			break;
		default:
			assert(FALSE);
		}
		if (!loop)
			break;

		if (d < numOper - 1)
			ADVANCE_I
	}

	if (loop)
	{
		ADVANCE_I
		setDEC_REG(*i, reg);
		ADVANCE_I
		setCOND_JMP_REL_to(JNZ, dst, *i, dst);
		(*chainIdx) -= (times*numOper - 1);
	}
#undef ADVANCE_I
}

INSTRUCTION *compileROPChain(STACK_OPER *chain, DWORD chainSize, DWORD index0 = 0)
{
	INSTRUCTION *iHead = (INSTRUCTION *)calloc(chainSize+4, sizeof(INSTRUCTION));
	INSTRUCTION *i = iHead, *call = NULL, *jmp;
	long offset;
	BYTE aggrFreeRegs = 0xFF;
	BYTE aggrRegReads = 0x00;
	BYTE aggrRegWrites = 0x00;
	for (long chainIdx = chainSize - 1; chainIdx >= 0; chainIdx--)
	{
		aggrRegReads |= chain[chainIdx].regReads;
		aggrRegWrites |= chain[chainIdx].regWrites;
		aggrFreeRegs &= chain[chainIdx].freeRegs;
	}

	for (long chainIdx = chainSize - 1; chainIdx >= 0; chainIdx--)
	{
		i->jmp = NULL;
		i->index = (i - iHead) + index0;
		i->freeRegs = aggrFreeRegs;

		switch (chain[chainIdx].type)
		{
		case PUSH_VA:
		case PUSH_IMM:
			repeatPUSHADV(chain, &chainIdx, &i);
			break;
		case ADVANCE:
			offset = chain[chainIdx].offset;
			while (chainIdx - 1 >= 0
				&& chain[chainIdx].type == chain[chainIdx - 1].type
				&& chain[chainIdx].data == chain[chainIdx - 1].data)
			{
				offset += chain[chainIdx - 1].offset;
				chainIdx--;
			}
			if (offset != chain[chainIdx].offset)
				setSUB_REG_IMM(i, REG_ESP, offset);
			else
				repeatPUSHADV(chain, &chainIdx, &i);
			break;
		case CHAIN:
			assert(!call);
			call = i;
			call->next = call + 1;
			call->totalSize = 5;
			jmp = call->next;
			jmp->index = (jmp - iHead) + index0;
			i = jmp;
			break;
		default:
			assert(FALSE);
			break;
		}

		i->next = i + 1; 
		i = i->next;
	}
	i->next = NULL;
	i->index = (i - iHead) + index0;
	setRET(i);
	SET_INJ_GDG_CALL(i); // so that it is not considered an external branch (affects free registers)
	i->regReads = aggrRegReads;
	i->regWrites = aggrRegWrites;
	i->freeRegs = aggrFreeRegs;

	call->jmp = jmp->next;
	jmp->jmp = i+1;

	setJMP_REL_to(jmp); // the end of <jmp> list
	setCALL_REL_to(call, call, jmp->next);
	return iHead;
}

long ropCompile(INSTRUCTION **iHeadPtr, DWORD *numInstr, GADGET_END **gendsPtr, GADGET **gadgetsPtr, 
	LPVOID *base, DWORD *size, DWORD *numGdgsInjected, DWORD *numGdgSegments, DWORD *numReplByInj)
{
	if (numGdgsInjected)
		*numGdgsInjected = 0;
	if (numGdgSegments)
		*numGdgSegments = 0;
	if (numReplByInj)
		*numReplByInj = 0;
	if ((!gadgetsPtr || !gadgetsPtr[0]) && (!base || !(*base)))
		return 0;

	long numInsRepl = 0;

	GADGET_END *gend;
	GADGET *gdg;
	STACK_OPER *chain = NULL, *ch;
	DWORD chainSize = 0;
	int encResCode;

	DWORD numGdgs = 0;
	for (gdg = *gadgetsPtr; gdg->va; gdg++, numGdgs++);

	DWORD numGends = 0;
	for (gend = *gendsPtr; gend->va; gend++, numGends++);


	// set jmp sources for later use
	analyzeJmpSrcs(*iHeadPtr);

	CCNest *nextCC = NULL;
	if (base && *base)
	{
		// find all 0xCC nests for later injection of gadgets
		nextCC = getCCNests(*base);
		if (!nextCC)
			nextCC = convPaddingToCC(*base);
		if (!nextCC)
		{
			extendPETextSection(base, size);
			nextCC = getCCNests(*base);
		}
	}
	CCNest *ccNestHead = nextCC;


	BYTE regReads, regWrites, freeRegs;
	GINSTRUCTION gi;
	INSTRUCTION *i = *iHeadPtr;
	INSTRUCTION *iStart;
	BYTE dfStatus = -1; // -1: undefined, 0: cleared, 1: set
	BOOL prevWasLast = FALSE; // prev gdg was last in the chain and should be closed (e.g. a push)
	while (i && numInsRepl >= 0) {
		if (((GET_READS(i, REG_ESP) || GET_WRITES(i, REG_ESP) || isPush(i)) && // non-ROP-able instructions
					!(isPushImm32(i) || (isPushReg32(i) && i->data[0] != 0x54)))
			|| IS_BRANCH(i) 
			|| isPopReg(i) || isPriviledged(i)
			)
		{
			ch = NULL;
		}
		else
		{
			gi.i = i;
			regReads = i->regReads;
			regWrites = i->regWrites;
			freeRegs = i->freeRegs;
			// mark ESP as non-free to prevent compileROPChain() from using it later
			UNSET_REG(freeRegs, REG_ESP);

			classifyInstruction(&gi);
			ch = NULL;
			GADGET *bestGdg = NULL;
			STACK_OPER *bestCh = NULL;
			DWORD bestNumInstrEst; // the estimated complexity (in num instr.) of the "best" ROP chain
			for (gdg = *gadgetsPtr; gdg->va; gdg++)
			{
				if (dfStatus > -1 &&
					((dfStatus == 0 && G_HAS_FLAG(gdg, SETS_DF)) || (dfStatus == 1 && G_HAS_FLAG(gdg, CLEARS_DF))))
					continue;

				if ((ch = gdg->encode(gdg, &gi, &encResCode)) != NULL)
				{
					DWORD numInstrEst = getNumVAs(ch) * gdg->numIns;
					if (!bestGdg || (numInstrEst < bestNumInstrEst))
					{
						if (bestCh)
							free(bestCh);

						bestCh = ch;
						bestNumInstrEst = numInstrEst;
						bestGdg = gdg;
					}
				}
			}

			if (bestGdg)
			{
				ch = bestCh;
				gdg = bestGdg;
			}

			if (!ch)
			{
				// TODO 4: permutations of gi? maybe will need array of gdgs
			}

			if (!ch && nextCC)
			{
				DWORD szNeeded = 0;
				DWORD szJmps = 4;
				BYTE *codeToInj = assembleGadget(&gi, &szNeeded);

				BYTE *ccStart;
				CCNest *cc = getNestFor(szNeeded, nextCC, &ccStart);

				if (!cc)
				{
					nextCC = ccNestHead;
					ccNestHead = convPaddingToCC(*base); // try squeezing some space out of the 0-padding
					if (ccNestHead)
					{
						ccNestHead->next = nextCC;
						nextCC = ccNestHead;
						assert(nextCC);
					}
					else // if unsuccessful, extend the text section
					{
						if (nextCC)
							freeCCNests(nextCC);
						extendPETextSection(base, size);
						ccNestHead = getCCNests(*base);
						nextCC = ccNestHead;
						assert(nextCC);
					}
					cc = getNestFor(szNeeded, nextCC, &ccStart);
				}

				if (cc) // if there is available space
				{
					// allocate some space for the gadget + ending
					gdg = newGadget(gadgetsPtr, &numGdgs);
					gend = newGadgetEnd(gendsPtr, &numGends, *gadgetsPtr);

					DWORD l = 0;
					DWORD retOffset = 0;
					if (cc->start[0] == 0xCC) // write function prologue
					{
						cc->start[l++] = 0x55;	// push ebp
						cc->start[l++] = 0x8B;	// mov ebp, esp
						cc->start[l++] = 0xEC;
						memcpy(cc->start + l, codeToInj, szNeeded);
						gdg->va = cc->va + l;
						gdg->ins = analyze(cc->start + l, szNeeded, &(gdg->numIns));
						gdg->gi.i = gdg->ins;
						l += szNeeded;

						gend->va = cc->va + l;
						cc->start[l++] = 0xEB;	// jmp 3
						cc->start[l++] = 0x03;
						cc->start[l++] = 0x8B;	// mov esp, ebp
						cc->start[l++] = 0xE5;
						cc->start[l++] = 0x5D;	// pop ebp
						cc->start[l++] = 0xC3;	// ret

						gend->type = RET;
						SET_REG(gend->regWrites, REG_ESP);
						gend->size = 6;

						cc->va += l;
						cc->start += l;
					}
					else
					{
						// find offset to RET(N)
						if (*(ccStart - 1) != 0xC3)
							retOffset = ccStart - 3 - cc->start;
						else
							retOffset = ccStart - 1 - cc->start;
						const DWORD initRetOffset = retOffset;

						if (!retOffset)
							szJmps -= 2; // no need for 2nd jmp-to-ret

						// find last byte before 0xCC
						const long lastByte = ccStart - 1 - cc->start;

						// move all bytes szNeeded places ahead
						for (long idx = lastByte; idx >= 0; idx--)
							cc->start[idx + szNeeded + szJmps] = cc->start[idx];
						retOffset += (szNeeded + szJmps);

						gend->type = (cc->start[retOffset] == 0xC2) ? RETN : RET;
						SET_REG(gend->regWrites, REG_ESP);
						gend->stackAdvAftRet = (gend->type == RETN) ? *((WORD *)(cc->start + retOffset + 1)) : 0;
						if (gend->stackAdvAftRet && gi.type == GPUSH_IMM || gi.type == GPUSH_REG)
							codeToInj = assembleGadget(&gi, &szNeeded, gend->stackAdvAftRet);

						// re-assemble
						cc->start[l++] = 0xEB;	// 1st jmp-to-epilogue
						cc->start[l++] = (char)(szNeeded + szJmps - 2);
						memcpy(cc->start + l, codeToInj, szNeeded);
						gdg->va = cc->va + l;
						gdg->ins = analyze(cc->start + l, szNeeded, &(gdg->numIns));
						gdg->gi.i = gdg->ins;
						l += szNeeded;

						gend->va = cc->va + l;
						if (retOffset - l)
						{
							cc->start[l++] = 0xEB;	// 2nd jmp-to-ret
							cc->start[l++] = (char)(retOffset - l - 1);
						}

						// l now points to function epilogue
						gend->size = (BYTE) (retOffset + ((gend->type == RETN) ? 3 : 1) - (l - szJmps + 2));

						if (*(cc->start - 2) == 0xEB &&	// previous instruction jmps-to-ret (typical if we've reused this nest's epilogue):
							*(cc->start - 1) == initRetOffset)	// we can't reuse this epilogue after this correction
						{										// (we'll lose track of that jmp)
							*(cc->start - 1) = (BYTE)retOffset; // adjust previous jmp-to-ret
							cc->va += lastByte + szNeeded + szJmps + 1; // and stop re-using this epilogue
							cc->start += lastByte + szNeeded + szJmps + 1;
						}
						else
						{
							cc->va += l;
							cc->start += l;
						}
					}

					ccStart = cc->start; // need to recalculate because of injected gadget
					while (*ccStart != 0xCC && ccStart < cc->end-1)
						ccStart++;
					if ((DWORD)(cc->end - ccStart) <= CCSZ_OVERHEAD(cc))
					{
						if (nextCC == cc)
							nextCC = cc->next;
						removeCCNest(ccNestHead, cc);
						if (cc == ccNestHead)
							ccNestHead = nextCC;

						if (!nextCC)
						{
							freeCCNests(ccNestHead);
							extendPETextSection(base, size);
							ccNestHead = getCCNests(*base);
							nextCC = ccNestHead;
						}
					}

					gdg->ending = gend;
					gdg->stackAdvance = 0;
					gdg->flags = 0;
					gdg->loader = NULL;
					SET_REG(gdg->regWrites, REG_ESP);

					classifyGadget(gdg);
					G_SET_FLAG(gdg, INJECTED);

					ch = gdg->encode(gdg, &gi, &encResCode);
					assert(ch);

					if (numGdgsInjected)
						(*numGdgsInjected)++;
				}
				free(codeToInj);
			}
		}

		// this is still not entirely correct since it doesn't consider int.branches
		if (i->data[0] == 0xFC && i->totalSize == 1)
			dfStatus = 0;
		else if (i->data[0] == 0xFD && i->totalSize == 1)
			dfStatus = 1;


		BOOL hasNew = (BOOL)ch;
		BOOL hasPrev = (BOOL)chain;
		BOOL isJmpTgt = (BOOL)(i->jmpSrcs);

		if (hasPrev && (!hasNew || prevWasLast || isJmpTgt)) // if not a jmpTgt we'll chain this new to the previous
		{
			INSTRUCTION *newI = compileROPChain(chain, chainSize, iStart->index);
			puts("[.] Replacing:");
			printIDisassembly(iStart, i - iStart);
			puts("[.] with:");
			printIDisassembly(newI);

			DWORD curInstrIdx = i - *iHeadPtr;
			DWORD prevNumInstr = *numInstr;
			INST_RANGE_LIST range;
			range.start = iStart;
			range.end = i - 1;
			range.next = NULL;
			if (!replaceInstrRange(iHeadPtr, numInstr, &range, newI))
				numInsRepl = -2;
			else
				i = (*iHeadPtr) + curInstrIdx + (*numInstr) - prevNumInstr;

			free(newI);
			free(chain);
			chain = NULL;
			iStart = NULL;
			chainSize = 0;
		}

		if (hasNew && numInsRepl > -1) // gadget has been found to encode <i>
		{
			numInsRepl++;
			if (G_HAS_FLAG(gdg, INJECTED) && numReplByInj)
				(*numReplByInj)++;

			if (!chain)
			{
				if (numGdgSegments) // first one in this segment
					(*numGdgSegments)++;

				chain = ch;
				for (chainSize = 0; chain[chainSize].type != NOP; chainSize++)
				{
					chain[chainSize].regReads = regReads;
					chain[chainSize].regWrites = regWrites;
					chain[chainSize].freeRegs = freeRegs;
				}
				iStart = i;
			}
			else // chain it to the previous
			{
				DWORD idxChainOper = chainSize - 1;
				for (; chain[idxChainOper].type != CHAIN; idxChainOper--);
#ifdef DEBUG_MODE
				assert(idxChainOper >= 0 && idxChainOper < chainSize);
				assert(ch[0].type == PUSH_VA && ch[0].data);
#endif

				// find new <ch> size and set the free regs
				DWORD chSize = 0;
				for (; ch[chSize].type != NOP; chSize++)
				{
					ch[chSize].regReads = regReads;
					ch[chSize].regWrites = regWrites;
					ch[chSize].freeRegs = freeRegs;
				}
				chSize--; // for the CHAIN operation

				// realloc/extend current <chain> and copy
				chain = (STACK_OPER *)realloc(chain, (chainSize + chSize)*sizeof(STACK_OPER));
				memcpy(chain + idxChainOper, ch, 1 * sizeof(STACK_OPER)); // fist operation into <chain>'s CHAIN operation
				memcpy(chain + chainSize, ch + 1, chSize*sizeof(STACK_OPER));

				chainSize += chSize;
				free(ch);
			}
		}

		prevWasLast = G_HAS_FLAG(gdg, LAST_IN_CHAIN);

		i = i->next;
	}

	if (chain)
		free(chain);

	freeJmpSrcs(*iHeadPtr);
	freeCCNests(ccNestHead);
	return numInsRepl;
}