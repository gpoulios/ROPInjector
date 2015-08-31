
#define STRICT
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

#include "Patcher.h"
#include "Disasm.h"
#include "Asm.h"

#ifndef _ROP_H_
#define _ROP_H_


typedef enum {
	RET,			// ret (0xC3)
	RETN,			// retn (0xC2)
	JMP,			// jmp reg 
} GEND_TYPE;

// ending has no load instruction (useful in jmp cases)
#define GEND_NO_LOAD(e)		((e)->numIns == 1 && (e)->type == JMP)


typedef enum {
	LOADS,			// lods m8/16/32 (load string), op1 is eax, op2 is esi, op3 is size of op1 in bytes (1, 2, or 4)
	LOAD_REG,		// pop regA, op1 is regA
	LOAD_RM,		// pop [regA], op1 is regA
	ADD_IMM,		// op1 is the register, op2 is imm, op3 is size of op1 in bytes (1, 2, or 4)
	SUB_IMM,		// op1 is the register, op2 is imm, op3 is size of op1 in bytes (1, 2, or 4)
	MUL_IMM,		// regA = regB * imm, op1 is regA, op2 is regB, op3 == imm
	DIV_IMM,		// op1 is the register, op2 is imm, op3 is size of op1 in bytes (1, 2, or 4)
	MOV_REG_IMM,	// op1 is the register, op2 is imm, op3 is size of op1 in bytes (1, 2, or 4)
	MOV_REG_REG,	// mov regA, regB, op1 is regA, op2 is regB, op3 is size of op1 in bytes (1, 2, or 4)
	MOV_RM_IMM,		// mov [regA], imm, op1 is regA, op2 is imm, op3 is size of op1 in bytes (1, 2, or 4)
	MOV_REG_RM,		// mov regA, [regB], op1 is regA, op2 is regB, op3 is size of op1 in bytes (1, 2, or 4)
	MOV_RM_REG,		// mov [regA], regB, op1 is regA, op2 is regB, op3 is size of op1 in bytes (1, 2, or 4)
	ADD_REG,		// regA = regA+regB+x, op1 is regA, op2 is regB, op3 is x
	SUB_REG,		// regA = regA-regB-x, op1 is regA, op2 is regB, op3 is x
	MUL_REG,		// mul regA, regB, op1 is regA, op2 is regB
	DIV_REG,		// regA = regB / regC, op1 is regA, op2 is regB, op3 is regC (signed integer division using edx:eax)
	XCHG_REG_REG,	// xchg regA, regB, op1 is regA, op2 is regB, op3 is size of op1 in bytes (1, 2, or 4)
	XCHG_REG_RM,	// xchg regA, [regB], op1 is regA, op2 is regB, op3 is size of op1 in bytes (1, 2, or 4)
	GPUSH_IMM,		// push imm32, op1 is imm32
	GPUSH_REG,		// push reg32, op1 is reg32
	UNDEFINED,
} INSTR_TYPE;

#define NUM_INSTR_TYPES		21
extern const char *INSTR_TYPES[];

typedef enum {
	NOP = 0,
	PUSH_VA,		
	PUSH_IMM,
	ADVANCE,		// subtract from the stack
	CHAIN,			// chain with last
} STACK_OPER_TYPE;


#pragma pack(push, 1)

typedef struct _GINSTRUCTION { // the intermediate representation we'll use
	INSTR_TYPE type;
	long operand1;
	long operand2;
	long operand3;
	INSTRUCTION *i;
} GINSTRUCTION;


typedef struct _STACK_OPER {
	STACK_OPER_TYPE type;
	union{
		long data;
		long offset;
	};
	BYTE regReads;	// we need these to be transfered from the replaced instruction
	BYTE regWrites;	// to the replacement instruction
	BYTE freeRegs;
} STACK_OPER;


typedef struct _GADGET_END {
	DWORD va;		// offset in the .text section of the PE file
	DWORD numIns;	// num of instructions in this ending (starting from the one pointed to by "va")
	BYTE size;		// size in bytes of the ending
	BYTE regWrites; // the registers it modifies right before the actual jump/ret (N/A to "ret"-type endings)
	WORD stackAdvBefRet;	// the number of bytes the stack is advanced before the actual return (e.g. as in pop regA; ret; -> this would be 4)
	WORD stackAdvAftRet;	// the number of bytes the stack is advanced after the actual return (e.g. retn 0400; -> this would be 4)
	//long addrDelta;	// should be added to targeted address when pushed to stack (in case that is modified be ret'ed to)
	GEND_TYPE type;
	BYTE reg;		// the register used when this ending is of type JMP
} GADGET_END;

#define G_IS_COMP(g)		((g)->loader)

#define STD_EPILOGUE		0x1		// gdg useful instruction is followed by mov esp, ebp; pop ebp; right before ending
#define MODIF_EBSP_BEF_STDE	0x2		// gdg has std epilogue but modifies the value of ebp before it
#define MODIF_EFLAGS		0x4		// gdg modifies at least one of eFlags (considering only non-useful instructions of gdgs)
#define INJECTED			0x8		// gdg has been artificially injected to the PE file
#define SETS_DF				0x10	// gdg sets the DF
#define CLEARS_DF			0x20	// gdg clears the DF
#define LAST_IN_CHAIN		0x40	// gdg must be last instruction in chain
#define G_SET_FLAG(g,f)		((g)->flags |= (f))
#define G_HAS_FLAG(g,f)		((g)->flags & (f))
#define G_CLEAR_FLAG(g,f)	((g)->flags &= ~f)

typedef struct _GADGET GADGET;

#define ENCODER_RETYPE		STACK_OPER *
#define ENCODER_INARGS		(const GADGET * const gdg, const GINSTRUCTION * const gi, int *resCode)

typedef ENCODER_RETYPE(*ENCODER) ENCODER_INARGS;
#define	DEF_ENCODER(name)	ENCODER_RETYPE name ENCODER_INARGS

#define ENC_FAIL_FREEREG	-2
#define	ENC_FAIL			-1
#define ENC_SUCCESS			0

struct _GADGET {
	GINSTRUCTION gi;	// the parsed instructions; <GADGET->gi.i> points to the actual useful instruction in GADGET->ins
	ENCODER encode;
	DWORD flags;
	BYTE regWrites;		// this is excluding the ending, and excluding any regWrites by the useful instruction in <gi.i>
	WORD stackAdvance;	// stack advance after the actual (useful) instruction (excluding ending.stackAdvBefRet)
	DWORD va;
	INSTRUCTION *ins;	// gadget instructions including ending
	DWORD numIns;		// num.	gadget instructions including ending
	GADGET_END *ending;
	GADGET *loader;		// if this gdg's ending has no loader, then this field is set to point to one
};

typedef struct _CCNest CCNest;
struct _CCNest {
	DWORD va;
	BYTE *start;		// inclusive
	BYTE *end;			// exclusive
	CCNest *next;
};

#pragma pack(pop)

// min. 0xCC bytes required for pro/epilogue and 1 jmp rel -> 9
// min. 0xCC bytes required when pro/epilogue is already there:
//		if <start> points to 0xC2/0xC3 -> 1 jmp rel for regular code to jmp over gadget	-> 2
//		else +1 jmp rel for gadget code to jmp over function epilogue to RET(N) instruction -> 4
#define CCSZ_OVERHEAD(cc)	((DWORD)((cc)->start[0] == 0xCC ? 9 : (((cc)->start[0] == 0xC2 || (cc)->start[0] == 0xC3) ? 2 : 4)))

// will not free ending
inline void freeGadget(GADGET *gdg, BOOL isArray = FALSE) // will not free ending
{
	GADGET *g = gdg;
	do {
		if (g->ins)
		{
			free(g->ins);
			g->ins = NULL;
			g->gi.i = NULL;
		}
		g++;
	} while (isArray && g->va);

	free(gdg);
}
inline void freeGadgets(GADGET *gdg) { freeGadget(gdg, TRUE); } 

// will take care of <loader> pointers
inline GADGET *newGadget(GADGET **gadgetsPtr, DWORD *numGdgs)
{
	for (GADGET *g = *gadgetsPtr; g->va; g++)
	{
		if (g->loader)
			g->loader = (GADGET *)(g->loader - (*gadgetsPtr) + 1); // store index here as a fake pointer
	}
	*gadgetsPtr = (GADGET *)realloc(*gadgetsPtr, (*numGdgs + 2)*sizeof(GADGET));
	GADGET *gdg = *gadgetsPtr + *numGdgs;
	memset(gdg, 0, 2 * sizeof(GADGET));
	(*numGdgs)++;

	for (GADGET *g = *gadgetsPtr; g->va; g++)
	{
		if (g->loader)
			g->loader = (*gadgetsPtr) + (DWORD)(g->loader) - 1; // retrieve loader
	}
	return gdg;
}

inline void freeCCNests(CCNest *head)
{
	CCNest *next = head, *cur;
	while (next)
	{
		cur = next;
		next = next->next;
		free(cur);
	}
}

inline BOOL removeCCNest(CCNest *head, CCNest *item)
{
	if (item == head)
	{
		free(head);
		return TRUE;
	}

	for (CCNest *cur = head; cur && cur->next; cur = cur->next)
	{
		if (cur->next == item)
		{
			cur->next = cur->next->next;
			free(item);
			return TRUE;
		}
	}
	return FALSE;
}

/*
 * find gadget endings (e.g. ret(n), pop X; jmp X).
 * returns an array of null-terminated GADGET_ENDs.
 */
GADGET_END *getCandGadgets(LPCVOID base);

inline GADGET_END *newGadgetEnd(GADGET_END **gendsPtr, DWORD *numGends, GADGET *gadgets)
{
	for (GADGET *g = gadgets; g && g->va; g++)
	{
		if (g->ending)
			g->ending = (GADGET_END *)(g->ending - (*gendsPtr) + 1); // store index here as a fake pointer
	}

	*gendsPtr = (GADGET_END *)realloc(*gendsPtr, (*numGends + 2)*sizeof(GADGET_END));
	GADGET_END *gend = *gendsPtr + *numGends;
	memset(gend, 0, 2 * sizeof(GADGET_END));
	(*numGends)++;

	for (GADGET *g = gadgets; g && g->va; g++)
	{
		if (g->ending)
			g->ending = (*gendsPtr) + (DWORD)(g->ending) - 1; // retrieve ending
	}

	return gend;
}

/*
 * parse gadget endings into usefull gadgets (if any)
 * returns an array of null-terminated GADGETs.
 */
GADGET *parseGadgets(LPCVOID base, GADGET_END *endings, const BYTE maxdepth = 10);

/*
 * will set up the <gi>, <flags>, <regWrites>, <encode()> and <popsBefore/After> fields 
 * of a gadget that has been initialized
 */
void classifyGadget(GADGET *gdg);

void printGadget(GADGET *gdg);

BOOL classifyInstruction(GINSTRUCTION *gi);

CCNest *getCCNests(LPCVOID base);

BYTE *assembleGadget(GINSTRUCTION *gi, DWORD *length = NULL, DWORD stackAdvAfter = 0); // length [out] in bytes

/* -will try to inject the missing gadgets in <base> (unless NULL)
 * -will only inject gadgets to PE file pointed to by <base> if <gadgets> == NULL
 * -will return the total number of instructions replaced by <gadgets>
 * -will return the number of gadgets injected in base in <numGdgsInjected>
 */
long ropCompile(INSTRUCTION **iHeadPtr, DWORD *numInstr, GADGET_END **gendsPtr, GADGET **gadgetsPtr,
	LPVOID *base = NULL, DWORD *size = NULL, DWORD *numGdgsInjected = NULL, DWORD *numGdgSegments = NULL, DWORD *numReplByInj = NULL);

inline DWORD getNumVAs(const STACK_OPER * const chain)
{
	DWORD numPUSHVAs = 0;
	for (DWORD i = 0; chain[i].type != NOP; i++)
	{
		if (chain[i].type == PUSH_VA)
			numPUSHVAs++;
	}
	return numPUSHVAs;
}

#endif