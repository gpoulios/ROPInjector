#include "Asm.h"

#pragma pack(push, 1)		
BYTE is8bit[0x100] =	{
		/*	_0 _1 _2 _3 _4 _5 _6 _7 _8 _9 _A _B _C _D _E _F */ 
/* 0x0_*/	 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0,
/* 0x1_*/	 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0,
/* 0x2_*/	 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1,
/* 0x3_*/	 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1,
/* 0x4_*/	 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/* 0x5_*/	 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/* 0x6_*/	 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, // 0x6B is special case: op1,2=reg32, op3=imm8
/* 0x7_*/	 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
/* 0x8_*/	 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, // 0x83 is special case: op1=reg32, op2=imm8
/* 0x9_*/	 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1,
/* 0xA_*/	 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,
/* 0xB_*/	 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0,
/* 0xC_*/	 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0xC1 is special case: op1=reg32, op2=imm8
/* 0xD_*/	 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0,
/* 0xE_*/	 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1,
/* 0xF_*/	 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0
};

BYTE is8bitExt[0x100] =	{
		/*	_0 _1 _2 _3 _4 _5 _6 _7 _8 _9 _A _B _C _D _E _F */ 
/* 0x0_*/	 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/* 0x1_*/	 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/* 0x2_*/	 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/* 0x3_*/	 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/* 0x4_*/	 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/* 0x5_*/	 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/* 0x6_*/	 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/* 0x7_*/	 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/* 0x8_*/	 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/* 0x9_*/	 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
/* 0xA_*/	 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/* 0xB_*/	 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0,
/* 0xC_*/	 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/* 0xD_*/	 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/* 0xE_*/	 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/* 0xF_*/	 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

BYTE modifEFlags[0x100] = {
			/*	_0 _1 _2 _3 _4 _5 _6 _7 _8 _9 _A _B _C _D _E _F */
	/* 0x0_*/	 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0,
	/* 0x1_*/	 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1,
	/* 0x2_*/	 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	/* 0x3_*/	 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	/* 0x4_*/	 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	/* 0x5_*/	 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	/* 0x6_*/	 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0,
	/* 0x7_*/	 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	/* 0x8_*/	 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	/* 0x9_*/	 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0,
	/* 0xA_*/	 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1,
	/* 0xB_*/	 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	/* 0xC_*/	 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0,
	/* 0xD_*/	 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 2, // 0xDB is special case (opExt == 5 || 6), 0xDF opExt == 5 || 6
	/* 0xE_*/	 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	/* 0xF_*/	 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, // 0xFF is special case (opExt == 0 || 1)
};


const char *REG[3][8] = {
    {"al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"},
    {"ax", "cx", "dx", "bx", "sp", "bp", "si", "di"},
    {"eax","ecx","edx","ebx","esp","ebp","esi","edi"} 
};
#pragma pack(pop)


/* Literally equal (not semantically)
 */
bool equalInstr(const INSTRUCTION *iHead1, const INSTRUCTION *iHead2, DWORD numInstr)
{
	DWORD cnt = 0;
	const INSTRUCTION *i1 = iHead1, *i2 = iHead2;
	while (i1 && i2 && cnt < numInstr)
	{
		if (i1->totalSize != i2->totalSize)
			return FALSE;
		for (DWORD i = 0; i < i1->totalSize; i++)
		{
			if (i1->data[i] != i2->data[i])
				return FALSE;
		}

		i1 = i1->next;
		i2 = i2->next;
		cnt++;
	}
	return cnt == numInstr || (i1 == NULL && i2 == NULL);
}

bool isPushImm32(const INSTRUCTION * const i)
{
	return *(i->data + OFFSET_TO_OPCODE(i)) == 0x68 && IS_32BIT_OPERAND(i);
}

bool isPushReg32(const INSTRUCTION * const i)
{
	BYTE op1 = *(i->data + OFFSET_TO_OPCODE(i));
	return (op1 >= 0x50) && (op1 <= 0x57) && IS_32BIT_OPERAND(i);
}

bool isPush(const INSTRUCTION * const i)
{
	BYTE op1 = *(i->data + OFFSET_TO_OPCODE(i));
	BYTE op2 = *(i->data + OFFSET_TO_OPCODE(i) + 1);

	return (op1 == 0x06) || (op1 == 0x0E) || (op1 == 0x16)
		|| (op1 == 0x1E) || (op1 == 0x0E)
		|| ((op1 >= 0x50) && (op1 <= 0x57))
		|| (op1 == 0x60) || (op1 == 0x68) || (op1 == 0x6A)
		|| (op1 == 0x9C) || (op1 == 0xFF && MODRM_GET_OPEXT(op2) == 0x6)
		|| (op1 == 0x0F && (op2 == 0xA0 || op2 == 0xA8));
}

bool isPop(const INSTRUCTION * const i)
{
	BYTE op1 = *(i->data + OFFSET_TO_OPCODE(i));
	BYTE op2 = *(i->data + OFFSET_TO_OPCODE(i) + 1);

	return (op1 == 0x07) || (op1 == 0x17) || (op1 == 0x1F)
		|| ((op1 >= 0x58) && (op1 <= 0x5F))
		|| (op1 == 0x61) || (op1 == 0x8F) || (op1 == 0x9D)
		|| (op1 == 0x0F && (op2 == 0xA1 || op2 == 0xA9));
}

bool isPopReg(const INSTRUCTION * const i)
{
	BYTE op1 = *(i->data + OFFSET_TO_OPCODE(i));
	BYTE modRm = *(i->data + OFFSET_TO_MODRM(i));

	return ((op1 >= 0x58) && (op1 <= 0x5F))
		|| (op1 == 0x8F && MODRM_GET_MOD(modRm) == MOD_REG);
}

bool isPopRegRM(const INSTRUCTION * const i)
{
	return *(i->data + OFFSET_TO_OPCODE(i)) == 0x8F || isPopReg(i);
}

bool isPriviledged(const INSTRUCTION * const i)
{
	BYTE op1 = *(i->data + OFFSET_TO_OPCODE(i));
	BYTE op2 = *(i->data + OFFSET_TO_OPCODE(i) + 1);
	BYTE op3 = *(i->data + OFFSET_TO_OPCODE(i) + 2);

	return	op1 == 0x62
		|| (op1 >= 0x6C && op1 <= 0x6F)			// ins*, outs*
		|| (op1 >= 0xCA && op1 <= 0xCF)			// retf, int, into, iret
		|| (op1 >= 0xE4 && op1 <= 0xE7)			// in, out
		|| (op1 >= 0xEC && op1 <= 0xEF)			// in, out
		|| (op1 == 0xFA && op1 == 0xFB)			// in, out
		|| (op1 == 0x0F && (
			(op2 == 0x00 && (MODRM_GET_REG(i, op3) == 0x2 || MODRM_GET_REG(i, op3) == 0x3))
			|| (op2 == 0x01)
			|| (op2 >= 0x06 && op2 <= 0x09)
			|| (op2 >= 0x20 && op2 <= 0x23)
			|| (op2 >= 0x30 && op2 <= 0x33) || (op2 == 0x35)
			|| (CONTAINS_PREFIX(i, 0x66) && op2 == 0x38 && (op3 == 0x80 || op3 == 0x81))
			|| (op2 == 0x78) || (op2 == 0x79)
			|| (op2 == 0xC7)
			))
		;
}

/*
 * e.g. pop is, push isn't,
 * mov eax, ebx is, mov eax, [ebx] isn't (because it might cause Access Violation)
 */
bool readsIndOrwritesToMem(const INSTRUCTION * const i)
{
	BYTE op1 = *(i->data + OFFSET_TO_OPCODE(i));
	BYTE op2 = *(i->data + OFFSET_TO_OPCODE(i) + 1);
	BYTE modRm = *(i->data + OFFSET_TO_MODRM(i));
	BOOL indAddr = HAS_MODRM(i) && MODRM_GET_MOD(modRm) != MOD_REG;

	return indAddr 
		|| isPush(i)
		|| (op1 == 0x62)					// bound
		|| (op1 == 0x8F && indAddr)			// pop r/m16/32
		|| (op1 >= 0x6E && op1 <= 0x6F)		// outs
		|| (op1 >= 0xA0 && op1 <= 0xA7)		// movs, cmps
		|| (op1 >= 0xAA && op1 <= 0xAF)		// stos, lods, scas
		|| (op1 == 0xC8 || op1 == 0xC9)		// enter, leave
		// 0x0F instructions should be covered by indAddr
		;
}

bool modifiesEFlags(const INSTRUCTION * const i)
{
	BYTE op1 = *(i->data + OFFSET_TO_OPCODE(i));
	BYTE op2 = *(i->data + OFFSET_TO_OPCODE(i) + 1);
	BYTE op3 = *(i->data + OFFSET_TO_OPCODE(i) + 2);
	BYTE modRm = *(i->data + OFFSET_TO_MODRM(i));

	BYTE mod = modifEFlags[op1];
	if (mod == 2)
	return ((op1 == 0xDB || op1 == 0xDF) && (MODRM_GET_OPEXT(modRm) == 5 || MODRM_GET_OPEXT(modRm) == 6))
		|| (op1 == 0xFF && (MODRM_GET_OPEXT(modRm) == 0 || MODRM_GET_OPEXT(modRm) == 1));
	return mod
		|| (op1 == 0xF0 && (
		(op2 == 0x00 && MODRM_GET_OPEXT(modRm) >= 4)
		|| (op2 == 0x01 && MODRM_GET_OPEXT(modRm) == 0)
		|| op2 == 0x02 || op2 == 0x03
		|| (op2 >= 0x20 && op2 <= 0x23)
		|| op2 == 0x2E || op2 == 0x2F || op2 == 0x34
		|| (op2 == 0x38 && (op3 == 0x17 || op3 == 0x80 || op3 == 0x81))
		|| (op2 == 0x3A && (op3 >= 0x60 && op3 <= 0x62))
		|| op2 == 0x78 || op2 == 0x79
		|| (op2 >= 0xA3 && op2 <= 0xA5)
		|| (op2 >= 0xAB && op2 <= 0xAD)
		|| (op2 >= 0xAF && op2 <= 0xB1)
		|| op2 == 0xB3 || op2 == 0xB8
		|| (op2 >= 0xBA && op2 <= 0xBD)
		|| op2 == 0xC0 || op2 == 0xC1
		|| (op2 == 0xC7 && MODRM_GET_OPEXT(modRm) >= 6)
		));
}

bool containsRelOffset(const BYTE *code, const DISASSEMBLY *disas) 
{
	BYTE *op = (BYTE *)GET_OPCODE(*disas,code);
	if (*op == 0xEB || *op == 0xE8 || *op == 0xE9 || // call rel32, jmp rel8/32
		(*op >= 0x70 && *op <= 0x7F) || // j* rel8
		(*op >= 0xE0 && *op <= 0xE3) || 
		(*op == 0x0F && (*(op+1) >= 0x80 && *(op+1) <= 0x8F)))
		return TRUE;

	return FALSE;
}

int getRelOffset(const DISASSEMBLY *disas, const BYTE *code)
{
	BYTE offsetToOperands = (BYTE) OFFSET_TO_OPERANDS((*disas),code);
	BYTE operandSize = (BYTE) disas->OpcodeSize + disas->PrefixSize - offsetToOperands;
	if (operandSize == sizeof(char))
		return *((char *)(code + offsetToOperands));
	else if (operandSize == sizeof(short))
		return *((short *)(code + offsetToOperands));
	return *((int *)(code + offsetToOperands));
}

void setRelOffset(const DISASSEMBLY *disas, const BYTE *code, int offset) 
{
	BYTE offsetToOperands = OFFSET_TO_OPERANDS((*disas),code);
	BYTE operandSize = (BYTE) disas->OpcodeSize + disas->PrefixSize - offsetToOperands;
	if (operandSize == sizeof(char))
		*((char *)(code + offsetToOperands)) = offset;
	else if (operandSize == sizeof(short))
		*((short *)(code + offsetToOperands)) = offset;
	else
		*((int *)(code + offsetToOperands)) = offset;
}

void addToRelOffset(const DISASSEMBLY *disas, BYTE *code, int delta) 
{
	int offset = getRelOffset(disas, code);
	setRelOffset(disas, code, offset + delta);
}

REL_REF_DEST *getRelRefDest(const BYTE *code, const REL_REFERENCES *relRefs)
{
	DWORD i = getIndexOfRelRefDest((const REL_REF_DEST *)relRefs->dests, relRefs->numDests, code);
	if (i == relRefs->numDests || relRefs->dests[i].addr != code)
		return NULL;
	return &(relRefs->dests[i]);
}

/*
*	Assumes ordered <arr> in ascending order.
*	In case <addr> is found in <arr>, returns its index.
*	In case it is not found returns the index that <addr>
*	should be placed inside <arr> to maintain it in ascending order.
*/
int getIndexOfRelRefDest(const REL_REF_DEST *arr, DWORD len, const BYTE *addr)
{
	if (len == 0) // special cases 
		return 0;
	else if (addr < arr[0].addr)
		return 0;
	else if (addr > arr[len-1].addr)
		return len;

	DWORD l = 0, r = len-1;
	DWORD i;

	while(l <= r)
	{
		i = (l + r)/2;
		if (addr < arr[i].addr)
			r = i - 1;
		else if (addr > arr[i].addr)
			l = i + 1;
		else
			return i;
	}
	return l;
}

void connectRelRefSrcDest(REL_REF_SRC *rrs, REL_REF_DEST *rrd)
{
	rrs->dest = rrd;
	rrd->numSources++;
	if (rrd->numSources == 1)
	{
		rrd->sources = (REL_REF_SRC **) malloc(sizeof(REL_REF_SRC *));
		rrd->sources[0] = rrs;
		return;
	}

	rrd->sources = (REL_REF_SRC **) realloc(rrd->sources, rrd->numSources*sizeof(REL_REF_SRC *));
	rrd->sources[rrd->numSources-1] = rrs;
}

REL_REFERENCES *getAllRelReferences(const BYTE *code, DWORD sizeOfText)
{
	DISASSEMBLY disas;				// Creates a disas Struct
	disas.Address = (DWORD)code;	// code;
    FlushDecoded(&disas);			// reset all content

	REL_REFERENCES *references = (REL_REFERENCES *) malloc(sizeof(REL_REFERENCES));
	references->numSources = 0x1000;
	references->sources = (REL_REF_SRC *) malloc(references->numSources*sizeof(REL_REF_SRC));
	references->numDests = references->numSources;
	references->dests = (REL_REF_DEST *) malloc(references->numDests*sizeof(REL_REF_DEST));

	BYTE offsetToOperands = 0;
	DWORD instr_len = 0, numFoundSources = 0, numFoundDests = 0, i;
	int offset;
	BYTE *destaddr;
	REL_REF_SRC *rrs;
	REL_REF_DEST *rrd;
#ifdef VDEBUG_MODE
	puts("Analyzing relative references:");
#endif
    for(BYTE *c = (BYTE *)code; c < code+sizeOfText; c += instr_len, instr_len = 0)
    {
        Decode(&disas, (char *)c, &instr_len);
		instr_len++;

		if (containsRelOffset(c, &disas)) 
		{
			numFoundSources++;
#ifdef VDEBUG_MODE
			if (numFoundSources % 10000 == 0)
				printf(" (%d relative reference offsets to %d destinations)\n", numFoundSources, numFoundDests);
#endif

			if (numFoundSources > references->numSources)
			{
				references->numSources *= 2;
				references->sources = (REL_REF_SRC *) realloc(references->sources, 
					references->numSources*sizeof(REL_REF_SRC));
			}

			offset = getRelOffset(&disas, c);
			rrs = references->sources + numFoundSources-1;
			rrs->addr = c;

			destaddr = c + disas.OpcodeSize + disas.PrefixSize + offset;
			i = getIndexOfRelRefDest((const REL_REF_DEST *)(references->dests), numFoundDests, destaddr);
			if (i == numFoundDests || references->dests[i].addr != destaddr)
			{
				numFoundDests++;
				if (numFoundDests > references->numDests)
				{
					references->numDests *= 2;
					references->dests = (REL_REF_DEST *) realloc(references->dests, 
						references->numDests*sizeof(REL_REF_DEST));
				}
				// keep it sorted in ascending order
				memmove(references->dests+i+1, references->dests + i, (numFoundDests-1-i)*sizeof(REL_REF_DEST));
				references->dests[i].addr = destaddr;
				references->dests[i].numSources = 0;
			}
			rrd = &(references->dests[i]);

			connectRelRefSrcDest(rrs, rrd);

#ifdef VDEBUG_MODE
			// Show Decoded instruction, size, remarks...
			printDisassembly(disas);
#endif
		}

		// Calculate total Size of an instruction + Prefixes, and
		// Fix the address of IP 
		disas.Address += disas.OpcodeSize + disas.PrefixSize;
		// Clear all information
        FlushDecoded(&disas);
    }

	references->sources = (REL_REF_SRC *) realloc(references->sources, numFoundSources*sizeof(REL_REF_SRC));
	references->numSources = numFoundSources;
	references->dests = (REL_REF_DEST *) realloc(references->dests, numFoundDests*sizeof(REL_REF_DEST));
	references->numDests = numFoundDests;

	return references;
}

void freeRelReferences(REL_REFERENCES *refs)
{
	for (DWORD d = 0; d < refs->numDests; d++)
		free(refs->dests[d].sources);
	free(refs->sources);
	free(refs->dests);
	free(refs);
}


/*
 * use freeRegFreeRanges(INST_RANGE_LIST **) to free this array of lists
 *
 * WARNING: 
 * assumes: 
 *   -that calls/int/sysenters are to external code, as well as the code following
 *    the one currently analyzed (iHead), all write on the registers, and thus
 *    we never expect to get their (the regs') values back.
 */
INST_RANGE_LIST **getFreeRegRanges(INSTRUCTION *iHead)
{
	INST_RANGE_LIST **rangesH = (INST_RANGE_LIST **)malloc(8*sizeof(INST_RANGE_LIST*)); // head of the list
	INST_RANGE_LIST *rangesT[8];														// tail of the list
	for (DWORD reg = 0; reg < 8; reg++)
	{
		rangesH[reg] = (INST_RANGE_LIST *)malloc(sizeof(INST_RANGE_LIST));
		rangesH[reg]->start = NULL;
		rangesH[reg]->end = NULL;
		rangesH[reg]->next = NULL;
		rangesT[reg] = rangesH[reg];
	}

	DWORD numBranches = 0x100;
	DWORD branchIdx = -1;
	INSTRUCTION **intBranch = (INSTRUCTION **)malloc(numBranches*sizeof(INSTRUCTION *));


#define ON_INSTR_READ(i,reg)				\
	do {									\
		if (lastWasSet[reg]) {				\
			rangesT[reg] = addIRangeToList(rangesT[reg]); }	\
		rangesT[reg]->start = i;			\
		lastWasSet[reg] = FALSE;			\
	} while(0)								\

#define ON_INSTR_SET(i,reg)					\
	do {									\
		rangesT[reg]->end = i;				\
		lastWasSet[reg] = TRUE;				\
	} while(0)								\


	/*
	 * At this point we will not deal with internal branches.
	 * We save them (intBranch[]) and process them later in another loop separately.
	 */
	
	BOOL lastWasSet[8] = { TRUE }; // assume WRITE on top
	INSTRUCTION *i = iHead;
	DWORD numInstr = 0;
	while (i)
	{
		numInstr++;

		if (IS_BRANCH_INT(i) && (i->jmp != NULL)) // leave a ? on these; will be treated later
		{
			branchIdx++;
			if (branchIdx == numBranches)
			{
				numBranches *= 2; 
				intBranch = (INSTRUCTION **)realloc(intBranch, numBranches*sizeof(INSTRUCTION *));
			}
			intBranch[branchIdx] = i; // will use these later

			if (IS_BRANCH_CALL(i)) // assume a READ on esp in this case
				ON_INSTR_READ(i,REG_ESP);
		}

		// assume for all external branches : WRITEs in all regs (except esp/ebp)
		if (IS_BRANCH_EXT(i))
			for (DWORD reg = 0; reg < 8; reg++)
				if (reg == REG_ESP || reg == REG_EBP)// assume a READ on esp, ebp
					ON_INSTR_READ(i,reg);
				else						// assume all writes, (provided that cdecl is used), 
					ON_INSTR_SET(i,reg);	// since noone ever expects to find back the regs after a call/jmp_ext


		for (DWORD reg = 0; reg < 8; reg++)
			if (GET_READS(i,reg))		// the order here is important, 
				ON_INSTR_READ(i,reg);	// if both R/W: we take the READ
			else if (GET_SETS(i, reg))
				ON_INSTR_SET(i,reg);

		i = i->next;
	}


	/*
	 * Now it's time to process the internal branches.
	 */
	
	numBranches = branchIdx+1; 
	INST_RANGE_LIST *r;
	INSTRUCTION *into;
	DWORD takenJumpsAlloced = 1000;
	INSTRUCTION **takenJumps = (INSTRUCTION **)malloc(takenJumpsAlloced*sizeof(INSTRUCTION *));
	DWORD takenJumpsIdx = 0;

	for (branchIdx = 0; branchIdx < numBranches; branchIdx++)
	{
		for (DWORD reg = 0; reg < 8; reg++) 
		{
			if ((r = getRange(rangesH[reg], intBranch[branchIdx])) == NULL) 
				continue; // nothing to be done if there is no free range for this instruction

			into = intBranch[branchIdx]; 
			takenJumpsIdx = 0;
			while (into != NULL)
			{
				if (JUMPS_INTO(r,into))
					break; // jumps back into the range in question
				
				/* ...if we loop (because we always take conditional jumps),
				*    stop: the register is free
				*/
				for (DWORD idx = 0; idx < takenJumpsIdx; idx++)
					if (*(takenJumps + idx) == into)
						goto no_range_repair;

				// store this jump for later reference...
				*(takenJumps + takenJumpsIdx) = into;
				takenJumpsIdx++;
				if (takenJumpsIdx == takenJumpsAlloced)
				{
					takenJumpsAlloced += 1000;
					takenJumps = (INSTRUCTION **)realloc(takenJumps, takenJumpsAlloced*sizeof(INSTRUCTION *));
				}

				into = into->jmp;

				do {
					if (IS_BRANCH_EXT(into) || (IS_BRANCH_INT(into) && JUMPS_INTO(r,into))
						|| GET_SETS(into,reg))
						goto no_range_repair; // ext. assume all writes || int. and jumps back into the range in question
					else if (GET_READS(into,reg))
						goto range_repair;
					else if (IS_BRANCH_INT(into))
					{
						INST_RANGE_LIST *rangeInNext = getRange(rangesH[reg], into->next);
						if (!IS_BRANCH_COND(into) || (getRange(rangesH[reg], into->next) != NULL))
							break; // -> jump into and continue the same process
						else
						{
range_repair:				r->start = intBranch[branchIdx];
no_range_repair:			into = NULL;
							break;
						}
					}
					// otherwise go to next
				} while ((into = into->next) != NULL); // end of instructions iteration
			} // end of jumps iteration
		} // end of registers iteration
	} // end of branches iteration

#undef ON_INSTR_READ
#undef ON_INSTR_WRITE

	free(intBranch);
	free(takenJumps);


	/*
	 * Deal with special case like ranges starting at the end of the instruction list.
	 */

	for (DWORD reg = 0; reg < 8; reg++)
	{
		// filter out ranges starting at the last instruction
		if (rangesT[reg]->start && (rangesT[reg]->start->index == numInstr-1))
		{
			if (rangesH[reg] != rangesT[reg]) 
			{
				r = rangesH[reg];	
				while (r->next != rangesT[reg])
					r = r->next;
				free(rangesT[reg]);
				r->next = NULL;
				rangesT[reg] = r;
			}
			else // special case
			{
				free(rangesH[reg]);
				rangesH[reg] = NULL;
			}
		}
		// extend this to the end: assume external code will write to the regs
		else if (lastWasSet[reg] && (reg != REG_ESP) && (reg != REG_EBP))
			rangesT[reg]->end = NULL;
	}

	return rangesH;
}

INST_RANGE_LIST *addIRangeToList(INST_RANGE_LIST *rangeList)
{
	if (!rangeList->end) // we are on the Head of the list
		return rangeList;

	rangeList->next = (INST_RANGE_LIST *)malloc(sizeof(INST_RANGE_LIST));
	rangeList->next->next = NULL;
	rangeList->next->end = NULL;
	return rangeList->next;
}

INST_RANGE_LIST *getRange(const INST_RANGE_LIST *rangeList, const INSTRUCTION *i)
{
	INST_RANGE_LIST *r = (INST_RANGE_LIST *)rangeList;
	DWORD end = (r && r->end) ? r->end->index : 0xFFFFFFFF;
	while (r && (!r->start || (i->index > r->start->index))) 
	{	// ranges are exclusive
		if (i->index < end) 
			return r;

		r = r->next;
		if (r)
			end = (r->end) ? r->end->index : 0xFFFFFFFF;
	}
	return NULL;
}

void freeRegFreeRanges(INST_RANGE_LIST **ranges)
{
	INST_RANGE_LIST *next, *range;
	for (DWORD reg = 0; reg < 8; reg++)
	{
		range = ranges[reg];
		while (range)
		{
			next = range->next;
			free(range);
			range = next;
		}
	}
	free(ranges);
}

BYTE getFreeRegisters(const INST_RANGE_LIST **rangesH, const INSTRUCTION *i)
{
	BYTE freeRegs = 0x0;
	for (DWORD reg = 0; reg < 8; reg++)
	{
		if (getRange(rangesH[reg], i))
			SET_REG(freeRegs, reg);
	}
	return freeRegs;
}

/* 
 * assumes:
 *	-dVA = Base VA of e.g. Code Section - Base Real address of malloc'ed code chunk 
 */
INSTRUCTION *analyze(const BYTE *code, DWORD length, DWORD *numInstr, DWORD dVA)
{

#ifdef VDEBUG_MODE
	puts("analyzing...");
#endif
	/*
	 * mallocing in this way gives us an arraylist.
	 * (useful for binary searching etc)
	 */
	DWORD countAlloced = 1000, idx = 0;
	INSTRUCTION *iHead = (INSTRUCTION *) calloc(countAlloced, sizeof(INSTRUCTION));
	INSTRUCTION *i = iHead;
	DISASSEMBLY d;							
	d.Address = (DWORD)code;
	for(DWORD offset = 0; offset < length; idx++, offset++)
    {
		if (idx == countAlloced)
		{
			countAlloced += 1000;
			iHead = (INSTRUCTION *) realloc(iHead, countAlloced*sizeof(INSTRUCTION));
			memset(iHead + idx, 0, 1000);
			i = iHead + idx;
		}

		// Decode instruction
		FlushDecoded(&d);
        Decode(&d, (char *)code, &offset);		

#ifdef VDEBUG_MODE
		printf("[%3d]\t", idx);
		printDisassembly(d);
#endif
		d.Address += d.PrefixSize + d.OpcodeSize;

		i->totalSize = (BYTE) (d.PrefixSize + d.OpcodeSize);
		memcpy(i->data, code + offset - i->totalSize + 1, i->totalSize);
		i->index = idx;
		i->next = iHead + idx + 1;
		SET_OFFSET_TO_OPCODE(i,d.PrefixSize);

		i = i->next;
	}
	(iHead + idx - 1)->next = NULL; // terminate the list
	countAlloced = idx;
	iHead = (INSTRUCTION *)realloc(iHead, countAlloced*(sizeof(INSTRUCTION)));
	*numInstr = countAlloced;

	if (!analyzeInstr(iHead))
	{
		free(iHead);
		return NULL;
	}
	// TODO: search all direct VA's with the help of dVA to find any potential ->jmp pointers

	return iHead;
}

/*
 * assumes:
 *	- <totalSize>, <OFFSET_TO_OPCODE>, <index> and <next> have been set
 */
bool analyzeInstr(INSTRUCTION *iHead)
{
	INSTRUCTION *i = iHead;
	while (i)
	{
		setOffsetsAndRegAccess(i);
		if (isBranch(i))
		{
			SET_BRANCH(i);
			if (isBranchRel(i))
				SET_BRANCH_REL(i);
			else
				SET_BRANCH_ABS(i);

			bool isJmpCnd = isJmpCond(i);

			if (isCall(i))
				SET_BRANCH_CALL(i);
			else if (isJmpCnd || isJmpUncond(i))
			{
				SET_BRANCH_JMP(i);
				if (isJmpCnd)
					SET_BRANCH_COND(i);
			} // else is ret/sysenter/exit/int etc
		}
		i = i->next;
	}


	i = iHead;
	while (i)
	{
		if (!setIntBranchTarget(iHead, i))
			return FALSE;

		if (i->jmp == NULL)
			UNSET_BRANCH_INT(i);
		else
			SET_BRANCH_INT(i);

		i = i->next;
	}

	INST_RANGE_LIST **freeRegRanges = getFreeRegRanges(iHead);
	i = iHead;
	while (i)
	{
		i->freeRegs = getFreeRegisters((const INST_RANGE_LIST **)freeRegRanges, i);
		i = i->next;
	}
	freeRegFreeRanges(freeRegRanges);

	return TRUE;
}

/*
 * WARNING: not dealing with vmx etc
 *
 * assumes:
 * - OFFSET_TO_OPCODE(i) has been set
 */
bool hasModRegRm(const INSTRUCTION *i)
{
	const BYTE op1 = *(i->data + OFFSET_TO_OPCODE(i));
	const BYTE op2 = *(i->data + OFFSET_TO_OPCODE(i) + 1);
	const BYTE op3 = *(i->data + OFFSET_TO_OPCODE(i) + 2);

	return	((op1 >= 0x00) && (op1 <= 0x03))  // add (has more)
		||	((op1 >= 0x08) && (op1 <= 0x0B))	// or
		||	(op1 == 0x0F && (		((op2 == 0x00) && (MODRM_GET_OPEXT(op3) <= 5)) // sldt, str, lldt, ltr, verr, verw
								||	((op2 == 0x01) && (MODRM_GET_OPEXT(op3) == 6)) // lmsw
								||	(op2 == 0x0D)					// MS says prefetchw, coder32 says NOP
								||	(op2 >= 0x10 && op2 <= 0x17)	// sse1/2 instructions
								||	(op2 >= 0x28 && op2 <= 0x2F)
								||	(op2 >= 0x38 && op2 <= 0x3A)
								||	(op2 >= 0x40 && op2 <= 0x4F)	// cmov*
								||	(op2 >= 0x51 && op2 <= 0x70)	// sse1/2 instructions
								||	(op2 >= 0x74 && op2 <= 0x76)
								||	(op2 >= 0x78 && op2 <= 0x7F)
								||	(op2 >= 0x90 && op2 <= 0x9F)	// set*
								||	(op2 >= 0xA3 && op2 <= 0xA7)	// bt, shld, xbts, ibts
								||	(op2 >= 0xAB && op2 <= 0xAD)	// bts, shrd
								||	(op2 >= 0xAF)
								))
		|| ((op1 >= 0x10) && (op1 <= 0x13))
		|| ((op1 >= 0x18) && (op1 <= 0x1B))
		|| ((op1 >= 0x20) && (op1 <= 0x23))
		|| ((op1 >= 0x28) && (op1 <= 0x2B))
		|| ((op1 >= 0x30) && (op1 <= 0x33))
		|| ((op1 >= 0x38) && (op1 <= 0x3B))
		|| (op1 == 0x62)
		|| (op1 == 0x63)
		|| (op1 == 0x69)
		|| (op1 == 0x6B)
		|| ((op1 >= 0x80) && (op1 <= 0x8F))
		|| (op1 == 0xC0) || (op1 == 0xC1)
		|| ((op1 >= 0xC4) && (op1 <= 0xC7))
		|| ((op1 >= 0xD0) && (op1 <= 0xD3))
		|| ((op1 >= 0xD8) && (op1 <= 0xDF)) // FP related
		|| (op1 == 0xF6)
		|| (op1 == 0xF7)
		|| (op1 == 0xFE)
		|| (op1 == 0xFF)
		;
}

/*
 * assumes:
 * - OFFSET_TO_OPCODE/MODRM has been set
 * - HAS_F_2B_OPCODE has ben set
 */
bool hasOpcodeExt(const INSTRUCTION *i)
{
	const BYTE op1 = *(i->data + OFFSET_TO_OPCODE(i));
	const BYTE op2 = *(i->data + OFFSET_TO_OPCODE(i) + 1);

	return	((op1 >= 0x80) && (op1 <= 0x83))
		||	(op1 == 0xC0) || (op1 == 0xC1)
		||	((op1 >= 0xD0) && (op1 <= 0xD3))
		||	((op1 >= 0xD8) && (op1 <= 0xDF))
		||	(op1 == 0xF6) || (op1 == 0xF7)
		||	(op1 == 0xFE) || (op1 == 0xFF)
		||	(HAS_F_2B_OPCODE(i) && (
					(op2 == 0x00) || (op2 == 0x01)
				||	(op2 == 0x18) || (op2 == 0x1F)
				||	((op2 >= 0x71) && (op2 <= 0x73))
				||	((op2 >= 0x90) && (op2 <= 0x9F))
				||	(op2 == 0xAE) || (op2 == 0xBA)
				||	(op2 == 0xC7)
				)
			)
		;
}

/*
 * assumes:
 * - OFFSET_TO_OPCODE/MODRM/SIB/DISP(i) has been set 
 */
void setImmOffset(INSTRUCTION *i)
{
	const BYTE op1 = *(i->data + OFFSET_TO_OPCODE(i));
	const BYTE op2 = *(i->data + OFFSET_TO_OPCODE(i) + 1);
	const BYTE modRm = *(i->data + OFFSET_TO_MODRM(i));

	if (	((((op1 & 0x7) == 0x04) || ((op1 & 0x7) == 0x05)) 
			&& (op1 != 0x0F) && (op1 < 0x3D) )
		||	((op1 >= 0x68) && (op1 <= 0x6B))
		||	((op1 >= 0x70) && (op1 <= 0x83))
		||	(op1 == 0xA8) || (op1 == 0xA9)
		||	(op1 >= 0xB0 && op1 <= 0xC2)
		||	(op1 >= 0xC6 && op1 <= 0xC8)
		||	(op1 == 0xCA)
		||	(op1 == 0xD4) || (op1 == 0xD5)
		||	((op1 >= 0xE0) && (op1 <= 0xE9))
		||	(op1 == 0xEB)
		||	(HAS_2B_OPCODE(i)
			&&	(((op2 >= 0x80) && (op2 <= 0x8F))
				|| (op2 == 0xA4) 
				|| (op2 == 0xAC)
				|| (op2 == 0xBA)
				) )
		)
	{
		if (HAS_MODRM(i))
		{
			if (HAS_DISP(i))
				SET_OFFSET_TO_IMM(i, OFFSET_TO_DISP(i) + MODRM_SIZEOF_DISP(modRm));
			else if (HAS_SIB(i))
				SET_OFFSET_TO_IMM(i, OFFSET_TO_SIB(i) + 1);
			else
				SET_OFFSET_TO_IMM(i, OFFSET_TO_MODRM(i) + 1);
		}
		else
			SET_OFFSET_TO_IMM(i, OFFSET_TO_OPCODE(i) + SIZEOF_OPCODE(i));
	}
}

/*
 * assumes:
 * - OFFSET_TO_OPCODE(i) has been set
 */
void set8bitFlag(INSTRUCTION *i)
{
	const BYTE *op1 = i->data + OFFSET_TO_OPCODE(i);
	const BYTE *op2 = op1 + 1;
	if ((!HAS_2B_OPCODE(i) && is8bit[*op1]) ||
		(HAS_2B_OPCODE(i) && is8bitExt[*op2]))
		SET_8BIT_OPERAND(i);
}

/*
 * assumes:
 * - OFFSET_TO_OPCODE/MODRM/SIB/DISP(i) has been set
 */
void setContainsVA(INSTRUCTION *i)
{
	const BYTE *op1 = i->data + OFFSET_TO_OPCODE(i);
	const BYTE *op2 = op1 + 1;
	const BYTE *modRm = i->data + OFFSET_TO_MODRM(i);

	if (HAS_MODRM(i))
	{
		if (MODRM_GET_MOD(*modRm) != MOD_REG)	// register indirect addressing mode
			SET_CONTAINS_VA(i);					// register is usedin some [s*reg+b] form
		if ((MODRM_GET_MOD(*modRm) == MOD_IND) && (MODRM_GET_RM(i, *modRm) == 0x5))
			i->directVA = OFFSET_TO_MODRM(i) + 1;	// displacement-only mode
	}
}

/*
 * assumes:
 * - OFFSET_TO_MODRM(i) has been set, and instruction has the MODRM byte
 * - HAS_F_2B_OPCODE has ben set
 */
void analyzeModRegRm(INSTRUCTION *i)
{
	BYTE offsetToModRegRM = OFFSET_TO_MODRM(i);
	const BYTE *modRm = i->data + offsetToModRegRM;
	if (MODRM_HAS_SIB(*modRm))
		SET_HAS_SIB(i);

	if (MODRM_HAS_DISP(*modRm))
		if (HAS_SIB(i))
			SET_OFFSET_TO_DISP(i, OFFSET_TO_SIB(i) + 1);
		else
			SET_OFFSET_TO_DISP(i, offsetToModRegRM + 1);

	if (hasOpcodeExt(i))
		SET_OPCODE_EXT(i);
}

/*
 * assumes:
 * - OFFSET_TO_OPCODE(i) has been set
 */
bool setOffsetsAndRegAccess(INSTRUCTION *i)
{
	BYTE offsetToOpcode = OFFSET_TO_OPCODE(i);
	const BYTE *op1 = i->data + offsetToOpcode;

	SET_F_2B_OPCODE(i);
	
	if (hasModRegRm(i))
	{
		SET_OFFSET_TO_MODRM(i, offsetToOpcode + SIZEOF_OPCODE(i));
		analyzeModRegRm(i);
	}
	setImmOffset(i);
	set8bitFlag(i);
	setContainsVA(i);
	setRegAccessByOpcode(i);

	return TRUE;
}


/*
 * WARNING: NOT including interrupts/sysenters here!
 */
bool isCall(const INSTRUCTION *i)
{
	const BYTE *op1 = i->data + OFFSET_TO_OPCODE(i);
	const BYTE *op2 = op1 + 1;
	return	(*op1 == 0x9A)									// call far direct
		||	(*op1 == 0xE8)									// call rel32
		||	((*op1 == 0xFF) && ((*op2 & 0x30) == 0x10))		// call(f) reg32/mem32 (REG field contains opcode extension)
		;
}


bool isJmpUncond(const INSTRUCTION *i)
{	
	const BYTE *op1 = i->data + OFFSET_TO_OPCODE(i);
	const BYTE *op2 = op1 + 1;
	return	((*op1 >= 0xE9) && (*op1 <= 0xEB))				// jmp rel32, jmp far direct, jmp rel8
		|| ((*op1 == 0xFF) && ((*op2 & 0x30) == 0x20))		// call(f) reg32/mem32 (REG field contains opcode extension)
		|| ((*op1 == 0x0F) && (*op2 == 0xB8) && !CONTAINS_PREFIX(i, 0xF3))	// jmpe rel32
		;
}

/*
 * assumes: 
 *	-flag INSTR_2B_OPCODE has been set 
 */
bool isJmpCond(const INSTRUCTION *i)
{	
	const BYTE *op1 = i->data + OFFSET_TO_OPCODE(i);
	const BYTE *op2 = op1 + 1;
	return	((*op1 >> 4) == 0x7)											// j* rel8
		||	((*op1 >= 0xE0) && (*op1 <= 0xE3))								// loop* rel8, 0xE3 == jecxz rel8
		||	(HAS_F_2B_OPCODE(i) && ((*op2 >> 4) == 0x8))					// j* rel32
		;
}

/*
 *
 * assumes: 
 *	-flag INSTR_2B_OPCODE has been set 
 */
bool isBranch(const INSTRUCTION *i)
{	
	const BYTE *op1 = i->data + OFFSET_TO_OPCODE(i);
	const BYTE *op2 = op1 + 1;

	return	((*op1 >> 4) == 0x7)											// j* rel8
		||	(*op1 == 0x9A)													// call far direct
		||	(*op1 == 0xC2) || (*op1 == 0xC3)								// retn (imm)
		||	((*op1 >= 0xCA) && (*op1 <= 0xCF))								// retf (imm), int 3/imm, into, iret
		||	((*op1 >= 0xE0) && (*op1 <= 0xE3))								// loop* rel8, 0xE3 == jecxz rel8
		||	((*op1 >= 0xE8) && (*op1 <= 0xEB))								// call, jmp rel32, jmp far direct, jmp rel8
		||	((*op1 == 0x0F) && ((*op2 >> 4) == 0x8))						// j* rel32
		||	(*op1 == 0xF1)													// int1
		||	((*op1 == 0xFF) &&	(		((*op2 & 0x30) == 0x10)				// call(f) reg32/mem32 (REG field contains opcode extension)
									||	((*op2 & 0x30) == 0x20)	))			// jmp(f) reg32/mem32	(REG field contains opcode extension)
		||	((*op1 == 0x0F) && (*op2 == 0xB8) && !CONTAINS_PREFIX(i, 0xF3))	// jmpe rel32
		||	((*op1 == 0x0F) && ((*op2 == 0x34) || (*op2 == 0x35)))			// sysenter/exit
		;
}

/*
 * assumes: 
 *	-flag INSTR_2B_OPCODE has been set 
 */
bool isBranchRel(const INSTRUCTION *i)
{
	const BYTE *op1 = i->data + OFFSET_TO_OPCODE(i);
	const BYTE *op2 = op1 + 1;

	return	((*op1 >> 4) == 0x7)											// j* rel8
		||	((*op1 >= 0xE0) && (*op1 <= 0xE3))								// loop* rel8, 0xE3 == jecxz rel8
		||	(HAS_F_2B_OPCODE(i) && ((*op2 >> 4) == 0x8))					// j* rel32
		||	(*op1 == 0xE8) || (*op1 == 0xE9) || (*op1 == 0xEB)				// call, jmp rel32, jmp rel8
		||	(HAS_F_2B_OPCODE(i) && (*op2 == 0xB8) && !CONTAINS_PREFIX(i, 0xF3))	// jmpe rel32
		;
}

/*
 * assumes: 
 *  -branches using Register Addresing mode in any way (in/direct, SIB) are 
 *   assumed to target external code
 *  -OFFSET_TO_OPCODE has been set
 *	-OFFSET_TO_MOD_REG_RM byte has been set (if instr. has the mod_reg_rm byte)
 *	-flag INSTR_2B_OPCODE has been set 
 */

bool setIntBranchTarget(const INSTRUCTION *iHead, INSTRUCTION *i)
{
	const BYTE *op1 = i->data + OFFSET_TO_OPCODE(i);
	const BYTE *op2 = op1 + 1;
	const BYTE *modRm = i->data + OFFSET_TO_MODRM(i);
	long relOff = 0; 

	i->jmp = NULL;

	//	j* rel8			   || loop* rel8, 0xE3 == jecxz rel8	 || jmp rel8
	if ((*op1 >> 4 == 0x7) || ((*op1 >= 0xE0) && (*op1 <= 0xE3)) || (*op1 == 0xEB))
		relOff = *((char *)(op1 + 1));
	else if (HAS_F_2B_OPCODE(i) && (((*op2 >> 4) == 0x8)					// j* rel32
					|| ((*op2 == 0xB8) && !CONTAINS_PREFIX(i, 0xF3))))		// jmpe rel32
		if (IS_16BIT_OPERAND(i))
			relOff = *((short *)(op2 + 1));
		else
			relOff = *((long *)(op2 + 1));
	else if ((*op1 == 0xE8) || (*op1 == 0xE9))								// call, jmp rel32					
		if (IS_16BIT_OPERAND(i))
			relOff = *((short *)(op1 + 1));
		else
			relOff = *((long *)(op1 + 1));
	else if (HAS_MODRM(i) && (MODRM_GET_MOD(*modRm) == MOD_IND) && (MODRM_GET_RM(i, *modRm) == 0x5)) // disp. only
	{
		i->directVA = OFFSET_TO_MODRM(i) + 1;
		return TRUE;
	}
	else
		return TRUE; // no branch or branch using registers

	int targetIdx = getIndexOfInstr(i, relOff);
	switch (targetIdx) 
	{
		case -2: // refers to instruction inside but in its middle 
			return FALSE;
		case -1: // refers to instruction outside
			return TRUE;
		default:
			i->jmp = (INSTRUCTION *)iHead + targetIdx;
	}
	return TRUE; 
}

void analyzeJmpSrcs(INSTRUCTION *iHead)
{
	for (INSTRUCTION *in = iHead; in; in = in->next)
	{
		if (in->jmp)
		{
			INSTRUCTION *target = in->jmp;
			long numJmpSrcs = -1;
			while (target->jmpSrcs && *(target->jmpSrcs + (++numJmpSrcs)));
			numJmpSrcs = (numJmpSrcs < 0) ? 0 : numJmpSrcs;

			if (!numJmpSrcs)
				target->jmpSrcs = (INSTRUCTION **)calloc(2, sizeof(INSTRUCTION *));
			else
				target->jmpSrcs = (INSTRUCTION **)realloc(target->jmpSrcs, (numJmpSrcs + 2)*sizeof(INSTRUCTION *));
			*(target->jmpSrcs + numJmpSrcs) = in;
			*(target->jmpSrcs + numJmpSrcs + 1) = NULL;
		}
	}
}

void freeJmpSrcs(INSTRUCTION *iHead)
{
	for (INSTRUCTION *i = iHead; i; i = i->next)
	{
		if (i->jmpSrcs)
		{
			free(i->jmpSrcs);
			i->jmpSrcs = NULL;
		}
	}
}

/*
*	will find the (relative to pi) index of instruction at relative offset <relOff>
*	from <pi>.
*
*	returns: 
*	-1 when <relOff> refers to instruction outside the given ones, or
*	-2 when <relOff> refers to instruction inside the given ones, 
*	 but in the middle of it
*/
int getIndexOfInstr(const INSTRUCTION *pi, const long relOff)
{
	const INSTRUCTION *i = (relOff > 0) ? pi->next : pi;
	if (!i)
		return -1;

	const char sign = (relOff > 0) ? 1 : -1;
	long rem = relOff;
	for (int idx = i->index; (idx >= 0) && (rem*relOff > 0); idx+=sign, i+=sign) 
	{
		rem -= sign * i->totalSize;

		if ((sign > 0) && i->next == NULL)
			return -1; // refers to external instruction
	}

	// changed signum means it is inside but in the middle of an instruction
	if (rem*sign < 0)
		return -2;

	// same sign, but not 0, so it refers to external instrunction
	if (rem)
		return -1;

	return (relOff > 0) ? i->index : (i+1)->index;
}

/*
 * returns signed long values
 */
long getImm(const INSTRUCTION * const i)
{
	if (!HAS_IMM(i))
		return 0;

	if (IS_8BIT_OPERAND(i))
		return (char)(*(i->data + OFFSET_TO_IMM(i)));
	else if (IS_16BIT_OPERAND(i))
		return *((short *)(i->data + OFFSET_TO_IMM(i)));
	else 
		return *((long *)(i->data + OFFSET_TO_IMM(i)));
}

DWORD getUImm(const INSTRUCTION * const i)
{
	if (!HAS_IMM(i))
		return 0;

	if (IS_8BIT_OPERAND(i))
		return (BYTE)(*(i->data + OFFSET_TO_IMM(i)));
	else if (IS_16BIT_OPERAND(i))
		return *((WORD *)(i->data + OFFSET_TO_IMM(i)));
	else
		return *((DWORD *)(i->data + OFFSET_TO_IMM(i)));
}

/*
 * returns 2 on overflow
 */
int setImm(INSTRUCTION *i, long imm)
{
	if (!HAS_IMM(i))
	{
		puts("[-] Error: called setImm on an instruction that contains no immediate value:");
		printInstruction(i);
		return 1;
	}

	if (IS_8BIT_OPERAND(i))
	{
		if ((char)imm != imm)
		{
			puts("[-] Error: overflow when setting imm. on 8-bit offset:");
			printInstruction(i);
			return 2;
		}

		*((char *)(i->data + OFFSET_TO_IMM(i))) = (char)imm;
	}
	else if (IS_16BIT_OPERAND(i))
	{
		if ((short)imm != imm)
		{
			puts("[-] Error: overflow when setting imm. on 16-bit offset:");
			printInstruction(i);
			return 2;
		}

		*((short *)(i->data + OFFSET_TO_IMM(i))) = (short)imm;
	}
	else
		*((long *)(i->data + OFFSET_TO_IMM(i))) = imm;

	return 0;
}


/*
 * returns signed long values
 */
long getDisp(const INSTRUCTION *i) 
{
	if (!HAS_DISP(i))
		return 0;

	const BYTE *modRm = i->data + OFFSET_TO_MODRM(i); 
	BYTE sizeOfDisp = MODRM_SIZEOF_DISP(*modRm);
	switch (sizeOfDisp)
	{
	case 0:
		return 0;
	case 1:
		return (char)(*(i->data + OFFSET_TO_DISP(i)));
	case 2:
		return *((short *)(i->data + OFFSET_TO_DISP(i)));
	default:
		return *((long *)(i->data + OFFSET_TO_DISP(i)));
	}
}

/*
 * returns 2 on overflow
 */
int setDisp(INSTRUCTION *i, long disp)
{
	if (!HAS_DISP(i))
	{
		puts("[-] Error: called setDisp on an instruction that contains no SIB displacement:");
		printInstruction(i);
		return 1;
	}

	const BYTE *modRm = i->data + OFFSET_TO_MODRM(i); 
	BYTE sizeOfDisp = MODRM_SIZEOF_DISP(*modRm);
	if (sizeOfDisp == 1)
	{
		if ((char)disp != disp)
		{
			puts("[-] Error: overflow when setting disp. on 8-bit operand:");
			goto overflow;
		}

		*((char *)(i->data + OFFSET_TO_DISP(i))) = (char)disp;
	}
	else if (sizeOfDisp == 2)
	{
		if ((short)disp != disp)
		{
			puts("[-] Error: overflow when setting disp. on 16-bit operand:");
			goto overflow;
		}

		*((short *)(i->data + OFFSET_TO_DISP(i))) = (short)disp;
	}
	else
		*((long *)(i->data + OFFSET_TO_DISP(i))) = disp;

	return 0;

overflow:
	printInstruction(i);
	return 2;
}

BYTE *getCode(const INSTRUCTION *iHead, DWORD *sizeOfCode, DWORD maxNumInstr)
{
	const INSTRUCTION *i = iHead;	
	*sizeOfCode = 0;
	DWORD mallocedSize = 1000;
	BYTE *code = (BYTE *)malloc(mallocedSize);
	DWORD cnt = 0;

	while (i && (cnt++ < maxNumInstr))
	{
		if (*sizeOfCode + i->totalSize >= mallocedSize) 
		{
			mallocedSize += 1000;
			code = (BYTE *)realloc(code, mallocedSize);
		}
		memcpy(code + (*sizeOfCode), i->data, i->totalSize);
		*sizeOfCode += i->totalSize;
		i = i->next;
	}	


	if (!(*sizeOfCode))
	{
		free(code);
		return NULL;
	}

	code = (BYTE *)realloc(code, *sizeOfCode);
	return code;
}
/*
 * Will set the array of offsets in the bytecode of iHead list
 * pointing to the VAs found in these instructions. 
 *
 * For each INSTRUCTION i, an offset is added to the <RELOCS.offsets> array
 * if the INSTR_CONTAINS_VA bit is set in i->flags and i->directVA 
 * is not null.
 *
 * Will also set the <RELOCS.types> array according to the following:
 *  - If an instruction has the INSTR_PUSH_PC flag set its reloc type will be INTERNAL
 *  - Otherwise, it will be EXTERNAL
 */
void setRelocs(const INSTRUCTION *iHead, RELOCS *relocs)
{
	const INSTRUCTION *i = iHead;
	relocs->count = 0;
	while (i)
	{
		if (CONTAINS_VA(i) && i->directVA)
			relocs->count++;
		i = i->next;
	}

	if (!relocs->count)
		return;

	i = iHead;
	relocs->offsets = (DWORD *)malloc(relocs->count*sizeof(DWORD));
	relocs->types = (RELOC_TYPE *)calloc(relocs->count, sizeof(RELOC_TYPE));
	DWORD idx = 0;
	DWORD instr_offset = 0;
	while (i)
	{
		if (CONTAINS_VA(i) && i->directVA)
		{
			relocs->offsets[idx] = instr_offset + i->directVA;
			if (IS_PUSH_PC(i))
				relocs->types[idx] = INTERNAL;
			idx++;
		}
		instr_offset += i->totalSize;
		i = i->next;
	}
}

bool replaceJECXZ(INSTRUCTION **iHeadPtr, DWORD *numInstr, INSTRUCTION **iPtr)
{
	INSTRUCTION *i = *iPtr;
	long imm = getImm(i);

	INSTRUCTION *replacement = (INSTRUCTION *)calloc(2, sizeof(INSTRUCTION));
	replacement->next = replacement + 1;

	setTEST_REG(replacement, REG_ECX);
	setCOND_JMP_REL32(replacement->next, 0x84, imm); // 0x84: jump if equal

	if (imm < 0)
	{
		long sizeDelta = replacement->totalSize + replacement->next->totalSize - i->totalSize;
		setImm(replacement->next, imm - sizeDelta);
	}

	replacement->index = i->index;
	if (!replaceInstr(iHeadPtr, numInstr, replacement, i->index))
	{
		free(replacement);
		return FALSE;
	}
	*iPtr = *iHeadPtr + replacement->index + 1;

	free(replacement);
	return TRUE;
}

bool replaceLOOPD(INSTRUCTION **iHeadPtr, DWORD *numInstr, INSTRUCTION **iPtr)
{
	INSTRUCTION *i = *iPtr;
	long imm = getImm(i);

	INSTRUCTION *replacement = (INSTRUCTION *)calloc(3, sizeof(INSTRUCTION));
	replacement->next = replacement + 1;
	replacement->next->next = replacement + 2;

	setDEC_REG(replacement, REG_ECX);
	setTEST_REG(replacement->next, REG_ECX);
	setCOND_JMP_REL32(replacement->next->next, 0x85, imm); // 0x85: jnz

	if (imm < 0)
	{
		long sizeDelta = replacement->totalSize + replacement->next->totalSize 
						+ replacement->next->next->totalSize - i->totalSize;
		setImm(replacement->next->next, imm - sizeDelta);
	}

	replacement->index = i->index;
	if(!replaceInstr(iHeadPtr, numInstr, replacement, i->index))
	{
		free(replacement);
		return FALSE;
	}		
	*iPtr = *iHeadPtr + replacement->index + 2;

	free(replacement);
	return TRUE;
}

bool replaceLOOPZ_NZ(INSTRUCTION **iHeadPtr, DWORD *numInstr, INSTRUCTION **iPtr, bool loopIfZero)
{
	INSTRUCTION *i = *iPtr;
	long imm = getImm(i);

	INSTRUCTION *replacement = (INSTRUCTION *)calloc(2, sizeof(INSTRUCTION));
	replacement->next = replacement + 1;

	setCOND_JMP_REL8(replacement, 0x74+loopIfZero, 0x2); // if loopIfZero we skip to the next LOOP instr.
	setLOOPD(replacement->next, (char)imm); // covnersion is safe: loop is always on rel8 offset

	if (imm < 0)
	{
		long sizeDelta = replacement->totalSize + replacement->next->totalSize - i->totalSize;
		setImm(replacement->next, imm - sizeDelta);
	}

	replacement->index = i->index;
	if(!replaceInstr(iHeadPtr, numInstr, replacement, i->index))
	{
		free(replacement);
		return FALSE;
	}
	*iPtr = *iHeadPtr + replacement->index + 1;

	free(replacement);
	return replaceLOOPD(iHeadPtr, numInstr, iPtr);
}


/*
* replaces a push [reg] with a mov reg, [reg]; push reg
*/
bool toDirectPUSH(INSTRUCTION **iHeadPtr, DWORD *numInstr, INSTRUCTION **iPtr)
{
	INSTRUCTION *replacement = (INSTRUCTION *)calloc(2, sizeof(INSTRUCTION));
	INSTRUCTION *i = *iPtr;
	BYTE *modRm = i->data + OFFSET_TO_MODRM(i);
	BYTE reg = MODRM_GET_RM(i, *modRm);
	replacement->index = i->index;
	replacement->next = replacement + 1;

	setMOV_REG_RM32(replacement, MOD_IND, reg, reg);// mov reg, [reg]
	setPUSH_REG32(replacement->next, reg);			// push reg

	if (!replaceInstr(iHeadPtr, numInstr, replacement, i->index))
	{
		free(replacement);
		return FALSE;
	}
	*iPtr = *iHeadPtr + replacement->index + 1;

	free(replacement);
	return TRUE;
}


/*
* replaces a pop [reg] with a ...
*/
bool toDirectPOP(INSTRUCTION **iHeadPtr, DWORD *numInstr, INSTRUCTION **iPtr)
{
	INSTRUCTION *replacement = (INSTRUCTION *)calloc(2, sizeof(INSTRUCTION));
	INSTRUCTION *i = *iPtr;
	BYTE *op1 = i->data + OFFSET_TO_OPCODE(i);
	//BYTE *modRm = i->data + OFFSET_TO_MODRM(i);
	//BYTE reg = MODRM_GET_RM(i, *modRm);
	//replacement->index = i->index;
	//replacement->next = replacement + 1;

	// ...

	//if (!replaceInstr(iHeadPtr, numInstr, replacement, i->index))
	//{
	//	free(replacement);
	//	return FALSE;
	//}
	//*iPtr = *iHeadPtr + replacement->index + 1;

	//free(replacement);
	//return TRUE;

	printf("[-] Error: pop [r/m16/32] (%02X) instruction substitution has not yet been implemented (index:%d)\n",
		*op1, i->index);
	return FALSE;
}

bool replacePUSHAD(INSTRUCTION **iHeadPtr, DWORD *numInstr, INSTRUCTION **iPtr)
{
	INSTRUCTION *riHead = (INSTRUCTION *)calloc(9, sizeof(INSTRUCTION));
	INSTRUCTION *ri, *i = *iPtr;

	for (BYTE idx = 0; idx < 9; idx++)
	{
		ri = riHead+idx;
		ri->index = i->index + idx;
		if (idx != 8)
			ri->next = ri + 1;
	}

	ri = riHead;
	setMOV_SIB_DISP8_REG(ri++, REG_ESP, REG_ESP, 0, REG_ESP, -0x14);
	setPUSH_REG32(ri++, REG_EAX);
	setPUSH_REG32(ri++, REG_ECX);
	setPUSH_REG32(ri++, REG_EDX);
	setPUSH_REG32(ri++, REG_EBX);
	setSUB_RM32_IMM8(ri++, MOD_REG, REG_ESP, 4);
	setPUSH_REG32(ri++, REG_EBP);
	setPUSH_REG32(ri++, REG_ESI);
	setPUSH_REG32(ri, REG_EDI);

	if(!replaceInstr(iHeadPtr, numInstr, riHead, i->index))
	{
		free(riHead);
		return FALSE;
	}
	*iPtr = *iHeadPtr + ri->index;

	free(riHead);
	return TRUE;
}

bool replacePOPAD(INSTRUCTION **iHeadPtr, DWORD *numInstr, INSTRUCTION **iPtr)
{
	INSTRUCTION *riHead = (INSTRUCTION *)calloc(9, sizeof(INSTRUCTION));
	INSTRUCTION *ri, *i = *iPtr;

	for (BYTE idx = 0; idx < 9; idx++)
	{
		ri = riHead+idx;
		ri->index = i->index + idx;
		if (idx != 8)
			ri->next = ri + 1;
	}

	ri = riHead;
	setPOP_REG32(ri++, REG_EDI);
	setPOP_REG32(ri++, REG_ESI);
	setPOP_REG32(ri++, REG_EBP);
	setADD_RM32_IMM8(ri++, MOD_REG, REG_ESP, 4);
	setPOP_REG32(ri++, REG_EBX);
	setPOP_REG32(ri++, REG_EDX);
	setPOP_REG32(ri++, REG_ECX);
	setPOP_REG32(ri++, REG_EAX);
	setMOV_REG_SIB_DISP8(ri, REG_ESP, REG_ESP, REG_ESP, 0, -0x14);

	if(!replaceInstr(iHeadPtr, numInstr, riHead, i->index))
	{
		free(riHead);
		return FALSE;
	}
	*iPtr = *iHeadPtr + ri->index;

	free(riHead);
	return TRUE;
}

bool replacePUSH_REG_IMM(INSTRUCTION **iHeadPtr, DWORD *numInstr, INSTRUCTION **iPtr)
{
	INSTRUCTION *replacement = (INSTRUCTION *)calloc(2, sizeof(INSTRUCTION));
	INSTRUCTION *i = *iPtr;
	BYTE *op1 = i->data + OFFSET_TO_OPCODE(i);
	replacement->index = i->index;
	replacement->next = replacement+1;

	if ((*op1 >= 0x50) && (*op1 <= 0x57))
	{// flip them because of the special case for MOV [ESP], ESP; 
		setMOV_SIB_DISP8_REG(replacement, REG_ESP, REG_ESP, 0x0, (*op1)-0x50, -4);
		setSUB_RM32_IMM8(replacement->next, MOD_REG, REG_ESP, 0x4);
	}
	else if ((*op1 == 0x68) || (*op1 == 0x6A))
	{
		setSUB_RM32_IMM8(replacement, MOD_REG, REG_ESP, 0x4);
		setMOV_SIB_IMM32(replacement->next, REG_ESP, REG_ESP, 0x0, getImm(i));
	}
	else
		return FALSE;

	if(!replaceInstr(iHeadPtr, numInstr, replacement, i->index))
	{
		free(replacement);
		return FALSE;
	}
	*iPtr = *iHeadPtr + replacement->index + 1;

	free(replacement);
	return TRUE;
}

bool replacePOP_REG(INSTRUCTION **iHeadPtr, DWORD *numInstr, INSTRUCTION **iPtr)
{
	INSTRUCTION *replacement = (INSTRUCTION *)calloc(2, sizeof(INSTRUCTION));
	INSTRUCTION *i = *iPtr;
	BYTE *op1 = i->data + OFFSET_TO_OPCODE(i);
	replacement->index = i->index;
	replacement->next = replacement+1;

	setMOV_REG_SIB(replacement, (*op1)-0x58, REG_ESP, REG_ESP, 0);
	setADD_RM32_IMM8(replacement->next, MOD_REG, REG_ESP, 0x4);
	
	if(!replaceInstr(iHeadPtr, numInstr, replacement, i->index))
	{
		free(replacement);
		return FALSE;
	}
	*iPtr = *iHeadPtr + replacement->index + 1;

	free(replacement);
	return TRUE;
}

bool toDirectPUSHPOP(INSTRUCTION **iHeadPtr, DWORD *numInstr)
{
	INSTRUCTION *i = *iHeadPtr;
	BYTE *op1, *op2, *modRm;
	while (i)
	{
		op1 = i->data + OFFSET_TO_OPCODE(i);
		op2 = op1 + 1;
		modRm = i->data + OFFSET_TO_MODRM(i);

		if ((*op1 == 0xFF) && MODRM_GET_OPEXT(*modRm) == 0x6)
		{
			if (!toDirectPUSH(iHeadPtr, numInstr, &i))
				return FALSE;
		}
		else if ((*op1 == 0x8F) && MODRM_GET_OPEXT(*modRm) == 0x0)
		{
			if (!toDirectPOP(iHeadPtr, numInstr, &i))
				return FALSE;
		}

		i = i->next;
	}
	return TRUE;
}

bool replaceAllPUSHPOPAD(INSTRUCTION **iHeadPtr, DWORD *numInstr)
{
	INSTRUCTION *i = *iHeadPtr;
	BYTE *op1;
	while (i)
	{
		op1 = i->data + OFFSET_TO_OPCODE(i);
		if ((*op1 == 0x60) && !replacePUSHAD(iHeadPtr, numInstr, &i))
			return FALSE;
		else if ((*op1 == 0x61) && !replacePOPAD(iHeadPtr, numInstr, &i))
			return FALSE;
		i = i->next;
	}
	return TRUE;
}

bool replaceAllPUSHPOP(INSTRUCTION **iHeadPtr, DWORD *numInstr)
{
	INSTRUCTION *i = *iHeadPtr;
	BYTE *op1, *op2, *modRm;
	while (i)
	{
		op1 = i->data + OFFSET_TO_OPCODE(i);
		op2 = op1 + 1;
		modRm = i->data + OFFSET_TO_MODRM(i);

		if (((*op1 >= 0x50) && (*op1 <= 0x57)) || (*op1 == 0x68) || (*op1 == 0x6A))
		{
			if (!replacePUSH_REG_IMM(iHeadPtr, numInstr, &i))
				return FALSE;
		}
		else if ((*op1 >= 0x58) && (*op1 <= 0x5F))
		{
			if (!replacePOP_REG(iHeadPtr, numInstr, &i))
				return FALSE;
		}
		else if ((*op1 == 0x06) || (*op1 == 0x07) || (*op1 == 0x0E) || 
				(*op1 == 0x16) || (*op1 == 0x17) || (*op1 == 0x1E) || (*op1 == 0x1F) || 
				(*op1 == 0x9C) || (*op1 == 0x9D) || 
				(HAS_F_2B_OPCODE(i) &&
					(  
						(*op2 == 0xA0) || (*op2 == 0xA1) || (*op2 == 0xA8) || (*op2 == 0xA9)
					)))
		{
			printf("[-] Error: push/pop SR (%02X) instruction substitution has not yet been implemented (index:%d)\n", 
					*op1, i->index);
			return FALSE;
		}

		i = i->next;
	}
	return TRUE;
}


/*
 * will replace a rel8 or rel16 jump/call to a rel32
 */
int makeRel32Branch(INSTRUCTION **iHeadPtr, DWORD *numInstr, INSTRUCTION **iPtr)
{
	INSTRUCTION *i = *iPtr;
	const BYTE *op1 = i->data + OFFSET_TO_OPCODE(i);
	const BYTE *op2 = op1 + 1;
	long imm, sizeDelta;


	if (IS_32BIT_OPERAND(i))
		return 0;

	imm = getImm(i);

	INSTRUCTION *replacement = (INSTRUCTION *)calloc(1, sizeof(INSTRUCTION));
	memcpy(replacement, i, sizeof(INSTRUCTION));
	replacement->next = NULL;
	replacement->offsets = 0;
	CLEAR_8BIT_OPERAND(replacement);

	int res = 0;
	if ((*op1 >> 4) == 0x7)	// j* rel8
	{		
		setCOND_JMP_REL32(replacement, *op1 + 0x10, imm);
	
		if (imm < 0)
		{
			sizeDelta = replacement->totalSize - i->totalSize;
			setImm(replacement, imm - sizeDelta);
		}

		if (!replaceInstr(iHeadPtr, numInstr, replacement, i->index))
			res = 3;
		else
			*iPtr = *iHeadPtr + replacement->index;
	}
	else if (HAS_F_2B_OPCODE(i) && ((*op2 >> 4) == 0x8)) // j* rel32
	{
		setCOND_JMP_REL32(replacement, *op2, imm);

		if (imm < 0)
		{
			sizeDelta = replacement->totalSize - i->totalSize;
			setImm(replacement, imm - sizeDelta);
		}

		if (!replaceInstr(iHeadPtr, numInstr, replacement, i->index))
			res = 3;
		else
			*iPtr = *iHeadPtr + replacement->index;
	}
	else if ((*op1 == 0xE8) || (*op1 == 0xE9)) // call, jmp rel32:  0x66 prefix removal
	{
		replacement->data[0] = i->data[OFFSET_TO_OPCODE(i)];
		replacement->totalSize = 5;
		SET_OFFSET_TO_IMM(replacement, 1);
		setImm(replacement, imm);

		if (imm < 0)
		{
			sizeDelta = replacement->totalSize - i->totalSize;
			setImm(replacement, imm - sizeDelta);
		}

		if (!replaceInstr(iHeadPtr, numInstr, replacement, i->index))
			res = 3;
		else
			*iPtr = *iHeadPtr + replacement->index;
	}
	else if (*op1 == 0xEB) // jmp rel8
	{
		replacement->data[0] = 0xE9;
		replacement->totalSize = 5;
		SET_OFFSET_TO_IMM(replacement, 1);
		setImm(replacement, imm);

		if (imm < 0)
		{
			sizeDelta = replacement->totalSize - i->totalSize;
			setImm(replacement, imm - sizeDelta);
		}

		if (!replaceInstr(iHeadPtr, numInstr, replacement, i->index))
			res = 3;
		else
			*iPtr = *iHeadPtr + replacement->index;
	}
	else if (HAS_F_2B_OPCODE(i) && (*op2 == 0xB8) && !CONTAINS_PREFIX(i, 0xF3)) // jmpe rel32
	{
		replacement->data[0] = 0x0F;
		replacement->data[1] = 0xB8;
		replacement->totalSize = 6;
		SET_OFFSET_TO_IMM(replacement, 2);
		setImm(replacement, imm);

		if (imm < 0)
		{
			sizeDelta = replacement->totalSize - i->totalSize;
			setImm(replacement, imm - sizeDelta);
		}

		if (!replaceInstr(iHeadPtr, numInstr, replacement, i->index))
			res = 3;
		else
			*iPtr = *iHeadPtr + replacement->index;
	}
	else if (*op1 == 0xE3) // jecxz
	{
		if (!replaceJECXZ(iHeadPtr, numInstr, iPtr))
			res = 3;
	}
	else if (*op1 == 0xE2) // loopd
	{
		if (!replaceLOOPD(iHeadPtr, numInstr, iPtr))
			res = 3;
	}
	else if ((*op1 == 0xE0) || (*op1 == 0xE1)) // loopz/nz rel8
	{
		if (!replaceLOOPZ_NZ(iHeadPtr, numInstr, iPtr, (*op1 == 0xE1)))
			res = 3;
	}
	else
	{
		printInstruction(i);
		printf("[-] Error: converting to 32-bit rel. offset of a non-rel. branch instruction @makeRel32Branch\n");
		res = 2;
	}

	free(replacement);
	return res;
}


bool makeAllRel32Braches(INSTRUCTION **iHeadPtr, DWORD *numInstr)
{
	/* 
	 * First we pick up the longest range, so that we avoid
	 * overflowing it when repairing others before we make it a 32-bit one.
	 *
	 * FIXME: in case there are 2 or more offsets one overlapping another,
	 *		  and both are close to overflowing, there is a high chance that
	 *		  repairing the first one will overflow the second, and cause this function to fail.
	 */

	INSTRUCTION *i = *iHeadPtr;
	INSTRUCTION *maxOffsetI = i;
	long maxOffset = 0, offset;
	while (i)
	{
		if (IS_BRANCH_REL(i) && !IS_32BIT_OPERAND(i))
		{
			offset = getImm(i);
			if (offset < 0)
				offset *= -1;

			if (offset > maxOffset)
			{
				maxOffset = offset;
				maxOffsetI = i;
			}
		}

		i = i->next;
	}

	if (makeRel32Branch(iHeadPtr, numInstr, &maxOffsetI) >= 2)
		return FALSE;


	i = *iHeadPtr;
	while (i)
	{
		if (IS_BRANCH_REL(i) && !IS_32BIT_OPERAND(i))
			if (makeRel32Branch(iHeadPtr, numInstr, &i) >= 2)
				return FALSE;
		i = i->next;
	}
	return TRUE;
}

/*
 * will repair relative branches inside [iHead, range->start) U (range->end, +oo]
 * <INSTRUCTION.jmp> fields will be repaired by <iDelta>
 * relative offsets in instructions will be repaired by <dataDelta>
 *
 * returns FALSE on overflow.
 */
bool repairRelBranchesOverRange(INSTRUCTION **iHeadPtr, DWORD *numInstr, 
					const INST_RANGE_LIST *range, long iDelta, long dataDelta)
{
	INSTRUCTION *i = *iHeadPtr;
	INSTRUCTION *target;
	long delta = dataDelta;
	char sign = 0; // no interleave

	while (i)
	{
		// don't modify the inserted instructions' jumps
		if (i->jmp && ((i < range->start) || (i > range->end)))
		{
			target = i->jmp;

			delta = dataDelta;

			// if the target is after the inserted code
			if (i->jmp > range->end)
				i->jmp = i->jmp + iDelta; // repair the pointer

			if ((i < range->start) && (target > range->end))
				sign = +1;
			else if ((i > range->end) && (target < range->start))
				sign = -1;
			else if ((target <= range->end) && (target >= range->start))
			{
				i->jmp = range->start;
				
				if (i > range->end)
				{					
					for (DWORD idx = 0; idx <= i->index - range->start->index; idx++)
						delta += (i-idx)->totalSize;
					delta = getImm(i) + delta;					
				}
				else
				{
					delta = 0;
					for (DWORD idx = 1; idx < range->start->index - i->index; idx++)
						delta += (i+idx)->totalSize;
					delta = getImm(i) - delta;
				}
				sign = -1;
			}
			else
				sign = 0;

			if (IS_BRANCH_REL(i) && sign) 
			{
				if (!HAS_IMM(i))
				{
					printf("[-] Error when repairing instruction's relative branches: no IMM for rel. branch\n");
					return FALSE;
				}

				if (setImm(i, getImm(i) + delta*sign))
					return FALSE;
			}
		}

		i = i->next;
	}

	return TRUE;
}

/*
 * !does not repair absolute VAs!
 * assumes 
 *	- that iHead and newI are allocated in an array fashion
 *	  (no need for NULL terminator though)
 *	- <totalSize>, <OFFSET_TO_OPCODE>, <index> and <next> have been set
 */
bool insertAllInstr(INSTRUCTION **iHeadPtr, 
					DWORD *numInstr, 
					const INSTRUCTION *newI,
					DWORD index)
{
	DWORD numNew = 0;
	DWORD dataSizeNew = 0;
	INSTRUCTION *i;
	const INSTRUCTION *cI = newI;
	while (cI) 
	{
		numNew++;
		dataSizeNew += cI->totalSize;
		cI = cI->next;
	}
	if (!numNew)
		return TRUE;


	INST_RANGE_LIST range;
	range.start = (*iHeadPtr + index);
	range.end = range.start-1; // hack to make it count range.start as well
	if (!repairRelBranchesOverRange(iHeadPtr, numInstr, &range, numNew, dataSizeNew))
		return FALSE;


	*numInstr += numNew;
	long delta = (long) *iHeadPtr;
	*iHeadPtr = (INSTRUCTION *) realloc(*iHeadPtr, (*numInstr) * sizeof(INSTRUCTION));
	delta = ((long) (*iHeadPtr)) - delta;

	memmove((*iHeadPtr) + index + numNew, (*iHeadPtr) + index, (*numInstr - numNew - index)*sizeof(INSTRUCTION));
	memcpy((*iHeadPtr) + index, newI, numNew * sizeof(INSTRUCTION));

	for (DWORD idx = 0; idx < *numInstr; idx++)
	{
		i = (*iHeadPtr) + idx;
		i->index = idx;
		i->next = i+1;
		if (i->jmp && (idx < index || idx >= index + numNew))
			i->jmp = (INSTRUCTION *)(((char *)(i->jmp)) + delta);
	}	
	i->next = NULL;

	if (!analyzeInstr(*iHeadPtr))
	{
		printf("[-] Error when reanalyzing instructions\n");
		return FALSE;
	}
	return TRUE;
}

/*
 * !does not repair absolute VAs!
 *	- that iHead and newI are allocated in an array fashion
 *	  (no need for NULL terminator though)
 *	- <totalSize>, <OFFSET_TO_OPCODE>, <index> and <next> have been set
 *
 * will replace into [range->start, range->end] the instruction list <newI>
 */
bool replaceInstrRange(INSTRUCTION **iHeadPtr, 
					DWORD *numInstr, 
					const INST_RANGE_LIST * const range, // inclusive bounds in this case
					const INSTRUCTION * const newI)
{
	INSTRUCTION *i;

	DWORD numNew = 0;
	DWORD dataSizeNew = 0;
	const INSTRUCTION *cI = newI;
	while (cI) 
	{
		numNew++;
		dataSizeNew += cI->totalSize;
		cI = cI->next;
	}
	if (!numNew)
		return TRUE;

	DWORD numOld = range->end - range->start + 1;
	DWORD dataSizeOld = 0;
	cI = range->start;
	while (cI != range->end) 
	{
		dataSizeOld += cI->totalSize;
		cI = cI->next;
	}
	dataSizeOld += cI->totalSize;

	long iDelta = numNew - numOld;
	long dataDelta = dataSizeNew - dataSizeOld;

	if (!repairRelBranchesOverRange(iHeadPtr, numInstr, range, iDelta, dataDelta))
		return FALSE;

	*numInstr += iDelta;
	INSTRUCTION *iHeadNew = (INSTRUCTION *)calloc((*numInstr), sizeof(INSTRUCTION));
	long delta = (long)iHeadNew - (long)(*iHeadPtr);

	if (range->start->index)
		memcpy(iHeadNew, *iHeadPtr, range->start->index*sizeof(INSTRUCTION));

	memcpy(iHeadNew + range->start->index, newI, 
		numNew*sizeof(INSTRUCTION));

	if (range->end->next)
		memcpy(iHeadNew + range->start->index + numNew, 
			range->end->next, 
			((*numInstr) - numNew - range->start->index)*sizeof(INSTRUCTION));

	for (DWORD idx = 0; idx < *numInstr; idx++)
	{
		i = iHeadNew + idx;
		i->index = idx;
		i->next = i+1;
		if (i->jmp && (idx < range->start->index || idx > range->start->index + numNew))
			i->jmp = (INSTRUCTION *)(((char *)(i->jmp)) + delta);
	}	
	i->next = NULL;

	free(*iHeadPtr);
	*iHeadPtr = iHeadNew;

	if (!analyzeInstr(iHeadNew))
		return FALSE;

	return TRUE;
}

bool replaceInstr(INSTRUCTION **iHeadPtr, 
					DWORD *numInstr, 
					const INSTRUCTION * const newI,
					DWORD index)
{
	INST_RANGE_LIST range;
	range.start = (*iHeadPtr) + index;
	range.end = range.start;
	range.next = NULL;
	return replaceInstrRange(iHeadPtr, numInstr, &range, newI);
}

/*
 * assumes:
 *	-all instr. flags are set
 *	-flat model, all the segment registers map to the same address space (Win-style)
 *
 * Remember to free the returned result
 */
INSTRUCTION *unrollSIBDisp(const INSTRUCTION *i, BOOL preserveFlags)
{
	if (!HAS_MODRM(i))					// must always have modrm
		return (INSTRUCTION *)i;
	if (!(HAS_DISP(i) || HAS_SIB(i)))	// check for valid modes
		return (INSTRUCTION *)i;

	const BYTE *modRm = i->data + OFFSET_TO_MODRM(i);
	const BYTE *sib = HAS_SIB(i) ? (i->data + OFFSET_TO_SIB(i)) : NULL;
	BOOL hasBase = FALSE;
	BOOL hasIndex = FALSE;
	long disp = getDisp(i);
	BYTE ss = 0, base = 0, index = 0;

	if (MODRM_IS_DISP_ONLY(*modRm)) // check for valid modes
		return (INSTRUCTION *)i;

	if (HAS_SIB(i))
	{
		if (SIB_HAS_INDEX(*sib))
		{
			ss = SIB_GET_SS(*sib);
			index = SIB_GET_INDEX(*sib);
			hasIndex = TRUE;
		}
		if (!SIB_IS_DISP_ONLY(*modRm, *sib)) // DISP_ONLY mode has no base
		{
			base = SIB_GET_BASE(*sib);
			hasBase = TRUE;
		}
	}
	else // everything without SIB and except 32-bit displacement-only mode (MOD==0x0, R/M=0x5)
	{
		index = MODRM_GET_RM(i, *modRm);
		hasIndex = TRUE;
	}

	// either smth to displace or smth to scale
	if (!((disp && (hasBase || hasIndex)) || ss))
		return (INSTRUCTION *)i;


	// see if it sets one of index or base
	INSTRUCTION *iTest = (INSTRUCTION *)calloc(1, sizeof(INSTRUCTION));
	memcpy(iTest, i, sizeof(INSTRUCTION));
	iTest->regReads = 0x0;
	iTest->regWrites = 0x0;
	iTest->freeRegs = 0x0;
	*(iTest->data + OFFSET_TO_MODRM(i)) = (MODRM_GET_REG(i, *modRm) << 3) | 0x5; // simulate a 32-bit disp. only mode on REG field
	iTest->totalSize = OFFSET_TO_SIB(i);
	setRegAccessByOpcode(iTest);
	BYTE regsSet = GET_REG_SETS(iTest);
	free(iTest);


	if (!i->freeRegs && !regsSet)
		return (INSTRUCTION *)i;

	// the free register that will be used in place of
	// the index/base reg. that is used in indirect addressing mode
	BYTE fReg = -1;
	if (regsSet)
	{
		if (hasIndex && (regsSet & (1 << index))) // prefer index or base, as we'll save one MOV
			fReg = index;
		else if (hasBase && (regsSet & (1 << base)))
			fReg = base;
		else
			while (!((1 << ++fReg) & regsSet));
	}
	else
	{
		while (!IS_FREE_REG(i, ++fReg)); // order of preference
		if (fReg == REG_ESP && (i->freeRegs ^ REG_ESP))
			while (!IS_FREE_REG(i, ++fReg));
		if (fReg == REG_EBP && (i->freeRegs ^ REG_EBP))
			while (!IS_FREE_REG(i, ++fReg));
	}

	INSTRUCTION *iNew = (INSTRUCTION *)calloc(20, sizeof(INSTRUCTION));
	BYTE curI = 0;

	if (preserveFlags)
		setPUSHFD(iNew + curI++);

	if (hasBase && fReg == base)
	{
		if (hasIndex)
		{
			if (ss > 1) // [base+index*ss]
			{
				if (IS_FREE_REG(i, index))
					setSHL_RM32_IMM8((iNew + curI++), index, ss);
				else
					for (DWORD j = 0; j < (1 << ss)-1; j++)
						setADD_REG_RM32((iNew + curI++), MOD_REG, fReg, index);
			}
			setADD_REG_RM32((iNew + curI++), MOD_REG, fReg, index);
		}
	}
	else if (hasIndex)
	{
		if (fReg != index) // set fReg = index
			setMOV_REG_RM32((iNew + curI++), MOD_REG, fReg, index);
		if (ss)	// shift index left by ss (scale)
			setSHL_RM32_IMM8((iNew + curI++), fReg, ss);
		if (hasBase) // add base to index
			setADD_REG_RM32((iNew + curI++), MOD_REG, fReg, base);
	}
	else if (fReg != base) // (hasBase)
		setMOV_REG_RM32((iNew + curI++), MOD_REG, fReg, base);
	
	if (disp) // add disp to index or base
		setADD_REG_IMM((iNew + curI++), fReg, disp);

	if (preserveFlags)
		setPOPFD(iNew + curI++);

	// copy the initial mov instruction to current
	memcpy((iNew + curI++), i, sizeof(INSTRUCTION));
	INSTRUCTION *modedI = iNew + curI - 1;

	BYTE *modRmNew = modedI->data + OFFSET_TO_MODRM(modedI);
	MODRM_SET_MOD(*modRmNew, MOD_IND);
	MODRM_SET_RM(*modRmNew, fReg);
	CLEAR_HAS_SIB(modedI);
	SET_OFFSET_TO_DISP(modedI, 0x0);
	modedI->totalSize = OFFSET_TO_MODRM(modedI) + 1;

	if (fReg == REG_ESP) // add SIB byte
	{
		SET_HAS_SIB(modedI);
		BYTE *sibNew = modedI->data + OFFSET_TO_MODRM(modedI) + 1;
		SIB_SET_SS(*sibNew, 0);
		SIB_SET_INDEX(*sibNew, REG_ESP);
		SIB_SET_BASE(*sibNew, fReg);
		modedI->totalSize++;
	}
	else if (fReg == REG_EBP) // add disp8 byte
	{
		MODRM_SET_MOD(*modRmNew, MOD_IND_DISP8); // no [ebp] mode, hence [ebp+disp8]
		SET_OFFSET_TO_DISP(modedI, OFFSET_TO_MODRM(modedI) + 1);
		*((BYTE *)(modedI->data + OFFSET_TO_DISP(modedI))) = 0x0;
		modedI->totalSize++;
	}
	
	if (HAS_IMM(i))
	{	
		SET_OFFSET_TO_IMM(modedI, modedI->totalSize);
		memcpy(modedI->data + OFFSET_TO_IMM(modedI), i->data + OFFSET_TO_IMM(i), SIZEOF_IMM(i));
		modedI->totalSize += SIZEOF_IMM(i);
	}

	for (BYTE in = 0; in < curI - 1; in++)
	{
		(iNew + in)->index = in;
		(iNew + in)->next = iNew + in + 1;
	}
	(iNew + curI - 1)->index = curI - 1;
	(iNew + curI - 1)->next = NULL;

	return (INSTRUCTION *)realloc(iNew, curI*sizeof(INSTRUCTION));
}


/* 
 * assumes:
 *	- that iHead is allocated as an array (NULL-terminated)
 */
bool unrollAllSIBDisp(INSTRUCTION **iHeadPtr, DWORD *numInstr, BOOL preserveFlags)
{
	INSTRUCTION *i = *iHeadPtr;
	INSTRUCTION *tmp;
	INSTRUCTION *ri;
	while (i) {
		ri = unrollSIBDisp(i, preserveFlags);
		if (ri && (ri != i))	// it might return back <i>, so take care of this, 
								// and don't try to free it bellow
		{
			ri->index = i->index; // save for later use because current iHeadPtr will be free'd
			if (!replaceInstr(iHeadPtr, numInstr, ri, i->index))
			{
				free(ri);
				return FALSE;
			}

			i = (*iHeadPtr) + ri->index;
			tmp = ri; // advance ri (using tmp) to find the last injected instruction
			while ((tmp = tmp->next) != NULL) i++;

			free(ri);
		}
		i = i->next;
	};

	return TRUE;
}
