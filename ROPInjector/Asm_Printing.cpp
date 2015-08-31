

#include "Asm.h"


void printDisassembly(DISASSEMBLY d)
{
	printf("%08X: %-20s %s /%d ; %s\n",d.Address,
			                        d.Opcode,
									d.Assembly,
									d.OpcodeSize+d.PrefixSize,
									d.Remarks
        );
}

void printIDisassembly(const INSTRUCTION * const iHead, const DWORD numInstr, const DWORD baseAddr)
{
    DISASSEMBLY d;
    d.Address = baseAddr;
	const INSTRUCTION *i = iHead;
	DWORD offset = 0;
	for (int index = 0; index < numInstr && i; index++, i = i->next)
    {
		FlushDecoded(&d);
		offset = 0;
        Decode(&d, (char *)i->data, &offset);
        
		printf("[%3d]\t", i->index);
		printDisassembly(d);
        d.Address += d.OpcodeSize + d.PrefixSize;
    }
}

void printInstruction(const INSTRUCTION * const i) 
{
	DISASSEMBLY d;
	FlushDecoded(&d);
	d.Address = (DWORD)(i->data);
	DWORD ilen = 0;
	Decode(&d, (char *)(i->data), &ilen);	

	printf("[%2d] ", i->index);
	printDisassembly(d);

	printf("size:\t\t%d\n", i->totalSize);
	if (i->regReads)
	{
		printf("reads:\t\t");
		for (BYTE reg = 0; reg < 8; reg++) {
			if (GET_READS(i, reg))
				printf ("%s ", REG[2][reg]);
		}
		printf("\n");
	}

	if (i->regWrites)
	{
		printf("writes:\t\t");
		for (BYTE reg = 0; reg < 8; reg++) {
			if (GET_WRITES(i, reg))
				printf ("%s ", REG[2][reg]);
		}
		printf("\n");
	}

	if (i->freeRegs)
	{
		printf("free:\t\t");
		for (BYTE reg = 0; reg < 8; reg++) {
			if (IS_FREE_REG(i,reg))
				printf ("%s ", REG[2][reg]);
		}
		printf("\n");
	}

	if (i->flags)
		printf("flags:\t\t0x%08X\n", i->flags);

	printf("offsets:\tOPCODE:%d, MODRM:%d, SIB:%d, DISP:%d:0x%08X, IMM:%d:0x%08X\n",
		OFFSET_TO_OPCODE(i),
		OFFSET_TO_MODRM(i), 
		OFFSET_TO_SIB(i),
		OFFSET_TO_DISP(i), getDisp(i),
		OFFSET_TO_IMM(i), getImm(i));

	if (i->jmp)
		printf("jumps to:\t%d\n", i->jmp->index);

	if (i->directVA)
		printf("refers to:\t0x%08X\n", *((DWORD *)(i->data + i->directVA)));
}

void printAllInstructions(const INSTRUCTION *iHead)
{
	const INSTRUCTION *i = iHead;
	while(i)
	{
		printInstruction(i);
		i = i->next;
	}
}

void printFreeRanges(const INST_RANGE_LIST **freeRegRanges)
{
	const INST_RANGE_LIST *r;
	for (BYTE reg = 0; reg < 8; reg++) 
	{
		printf("%s: ", REG[2][reg]);
		r = freeRegRanges[reg];
		while (r) 
		{
			if (!r->start)
				printf("(-oo,");
			else
				printf("(%d,", r->start->index);

			if (!r->end)
				printf("+oo) ");
			else
				printf("%d) ", r->end->index);

			r = r->next;
		}
		printf("\n");
	}
}