#define STRICT
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

#include "Disasm.h"

#ifndef _MY_ASM_H_
#define _MY_ASM_H_

/* decide whether to dump verbose debug-output */
//#define VDEBUG_MODE
#define DEBUG_MODE
#ifdef VDEBUG_MODE
	#define DEBUG_MODE
#endif

#define FITS_CHAR(l)					((l) <= 127 && (l) >= -128)


#define GET_OPCODE(disas,c)				c + (disas).PrefixSize
										//	+ at least 1 byte opcode + 1 more if 0x0F extension
#define OFFSET_TO_OPERANDS(disas,c)		(disas).PrefixSize + 1 + ((c[(disas).PrefixSize] == 0x0F) ? 1 : 0)

extern const char *REG[3][8];

typedef struct _LIST { // should move in another header, prob. util.h or something
	void *item;
	struct _LIST* next;
} LIST;

typedef struct _REL_REF_SRC {
	BYTE *addr; 
	struct _REL_REF_DEST *dest;
} REL_REF_SRC;

typedef struct _REL_REF_DEST {
	BYTE *addr; 
	REL_REF_SRC **sources;
	DWORD numSources; 
} REL_REF_DEST;

typedef struct _REL_REFERENCES {
	REL_REF_DEST *dests;
	DWORD numDests;
	REL_REF_SRC *sources;
	DWORD numSources;
} REL_REFERENCES;


typedef enum { EXTERNAL, INTERNAL } RELOC_TYPE;

typedef struct _RELOCS {
	DWORD count;
	DWORD *offsets; // from PATCH.code beginning
	RELOC_TYPE *types;
} RELOCS;


#define MOD_IND						0x0 // indirect addressing 
#define MOD_IND_DISP8				0x1
#define MOD_IND_DISP32				0x2
#define MOD_REG						0x3

#define MAKE_MODRM(mod,reg,rm)		((BYTE)(((mod) << 6) | ((reg) << 3) | (rm)))

#define MODRM_GET_MOD(modRm)		(((modRm) >> 6) & 0x3)
#define MODRM_GET_REG_RAW(modRm)	(((modRm) >> 3) & 0x7)
#define MODRM_GET_REG(i,modRm)		(getActualReg(i, MODRM_GET_REG_RAW(modRm)))
#define MODRM_GET_OPEXT(modRm)		(((modRm) >> 3) & 0x7) // opcode extension
#define MODRM_GET_RM_RAW(modRm)		((modRm) & 0x7)
#define MODRM_GET_RM(i,modRm)		(MODRM_GET_MOD(modRm) == MOD_REG ? getActualReg(i, MODRM_GET_RM_RAW(modRm)) : MODRM_GET_RM_RAW(modRm))
#define MODRM_IS_DISP_ONLY(modRm)	((MODRM_GET_MOD(modRm) == 0x0) && (MODRM_GET_RM_RAW(modRm) == 0x5))
#define MODRM_IS_DISP8(modRm)		(MODRM_GET_MOD(modRm) == 0x1)
#define MODRM_IS_DISP32(modRm)		(MODRM_GET_MOD(modRm) == 0x2 || MODRM_IS_DISP_ONLY(modRm))
#define MODRM_HAS_SIB(modRm)		((MODRM_GET_MOD(modRm) != 0x3) && (MODRM_GET_RM_RAW(modRm) == 0x4))
#define MODRM_HAS_DISP(modRm)		(MODRM_IS_DISP8(modRm) || MODRM_IS_DISP32(modRm))
#define MODRM_SIZEOF_DISP(modRm)	(((MODRM_GET_MOD(modRm) == 0x0) && (MODRM_GET_RM_RAW(modRm) == 0x5)) ? 4 : \
									(MODRM_HAS_DISP(modRm) ? (MODRM_GET_MOD(modRm)*MODRM_GET_MOD(modRm)) : 0))

#define IS_MODREG_EQREGS(modRm)		(MODRM_GET_REG_RAW(modRm) == MODRM_GET_RM_RAW(modRm) && MODRM_GET_MOD(modRm) == MOD_REG)
#define IS_MODREG_OPEXT(modRm,opEx)	(MODRM_GET_OPEXT(modRm) == (opEx) && MODRM_GET_MOD(modRm) == MOD_REG)

#define MODRM_SET_MOD(modRm,mod)	((modRm) = ((modRm) & 0x3F) | ((mod) << 6))
#define MODRM_SET_REG(modRm,reg)	((modRm) = ((modRm) & 0xC7) | ((reg) << 3))
#define MODRM_SET_RM(modRm,rm)		((modRm) = ((modRm) & 0xF8) | (rm))

#define SIB_GET_SS(sib)				(((sib) >> 6) & 0x3)
#define SIB_GET_INDEX(sib)			(((sib) >> 3) & 0x7)
#define SIB_GET_BASE(sib)			((sib) & 0x7)
#define SIB_HAS_INDEX(sib)			(SIB_GET_INDEX(sib) != REG_ESP)
#define SIB_IS_BASE_ONLY(modRm,sib)	((MODRM_GET_MOD(modRm) == 0x0) && (SIB_GET_BASE(sib) != 0x5))
#define SIB_IS_DISP_ONLY(modRm,sib)	((MODRM_GET_MOD(modRm) == 0x0) && (SIB_GET_BASE(sib) == 0x5))
#define SIB_SET_SS(sib,ss)			((sib) = ((sib) & 0x3F) | ((ss) << 6))
#define SIB_SET_INDEX(sib,reg)		((sib) = ((sib) & 0xC7) | ((reg) << 3))
#define SIB_SET_BASE(sib,reg)		((sib) = ((sib) & 0xF8 | (reg)))
#define SIB_HAS_DISP(modRm,sib)		((MODRM_GET_MOD(modRm) == 0x1) || (MODRM_GET_MOD(modRm) == 0x2) || \
									((MODRM_GET_MOD(modRm) == 0x0) && SIB_GET_BASE(sib) == 0x5))

#define MAKE_SIB(ss,idx,base)		((BYTE)(((ss) << 6) | ((idx) << 3) | (base)))

#define CONTAINS_REG(f,reg)			((f) & (0x1 << (reg)))
#define SET_REG(f,reg)				((f) |= (0x1 << (reg)))
#define SET_REG2(f,reg1,reg2)		((f) |= (0x1 << (reg1)) | (0x1 << (reg2)))
#define SET_REG3(f,reg1,reg2,reg3)	((f) |= (0x1 << (reg1)) | (0x1 << (reg2)) | (0x1 << (reg3)))
#define UNSET_REG(f,reg)			((f) &= ((0x1 << (reg)) ^ 0xFF))
#define COUNT_REGS(f)				(0 + (CONTAINS_REG(f,REG_EAX) ? 1 : 0)	\
									+ (CONTAINS_REG(f,REG_ECX) ? 1 : 0)		\
									+ (CONTAINS_REG(f,REG_EDX) ? 1 : 0)		\
									+ (CONTAINS_REG(f,REG_EBX) ? 1 : 0)		\
									+ (CONTAINS_REG(f,REG_EDX) ? 1 : 0)		\
									+ (CONTAINS_REG(f,REG_ESP) ? 1 : 0)		\
									+ (CONTAINS_REG(f,REG_EBP) ? 1 : 0)		\
									+ (CONTAINS_REG(f,REG_ESI) ? 1 : 0)		\
									+ (CONTAINS_REG(f,REG_EDI) ? 1 : 0))		

/*
 * INSTRUCTION
 */


#define GET_READS(i,reg)			(CONTAINS_REG((i)->regReads,(reg)))
#define GET_WRITES(i,reg)			(CONTAINS_REG((i)->regWrites,(reg)))
#define GET_REG_SETS(i)				(!IS_32BIT_OPERAND(i) ? 0 : ((i)->regWrites & ~((i)->regReads))) // without being read
#define GET_SETS(i,reg)				(CONTAINS_REG(GET_REG_SETS(i),(reg))) // without being read
#define	IS_FREE_REG(i,reg)			(CONTAINS_REG((i)->freeRegs,(reg)))
#define SET_READS(i,reg)			(SET_REG((i)->regReads, reg))
#define SET_READSALL(i)				((i)->regReads = 0xFF)
#define SET_WRITES(i,reg)			(SET_REG((i)->regWrites, reg))
#define SET_WRITESALL(i)			((i)->regWrites = 0xFF)
#define SET_FREE_REG(i,reg)			(SET_REG((i)->freeRegs, reg))

#define INSTR_SIB					0x1		// <flags> field
#define INSTR_BRANCH				0x2
#define INSTR_BRANCH_JMP			0x4
#define INSTR_BRANCH_COND			0x8
#define INSTR_BRANCH_REL			0x10
#define INSTR_BRANCH_INT			0x20	// (internal) whether it jumps into the code segment being analyzed
#define INSTR_CONTAINS_VA			0x40
#define INSTR_2B_OPCODE				0x80	// for the 0x0F opcode extention
#define INSTR_OPCODE_EXT			0x100	// for the ModRm opcode extention, see <MODRM_GET_OPEXT()>
#define INSTR_8BIT_OPERAND			0x200

#define INVALID_VA					0x400
#define RESERVED					0x800
#define INJECTED_GDG_CALL			0x1000 // typical ret initiating gadget chain
#define INSTR_PUSH_PC				0x2000 // mark meaning this instruction will push the VA address of the instr. following the next


#define OFFSET_TO_OPCODE(i)			((i)->offsets >> 12)
#define OFFSET_TO_MODRM(i)			(((i)->offsets & 0x0F00) >> 8)
#define OFFSET_TO_DISP(i)			(((i)->offsets & 0x00F0) >> 4)
#define OFFSET_TO_IMM(i)			((i)->offsets & 0x000F)
#define OFFSET_TO_SIB(i)			(HAS_SIB(i) ? (OFFSET_TO_MODRM(i) + 1) : 0)

#define SET_OFFSET_TO_OPCODE(i,o)	((i)->offsets = ((i)->offsets & 0x0FFF) | (((o) & 0x0F) << 12))
#define SET_OFFSET_TO_MODRM(i,o)	((i)->offsets = ((i)->offsets & 0xF0FF) | (((o) & 0x0F) << 8))
#define SET_OFFSET_TO_DISP(i,o)		((i)->offsets = ((i)->offsets & 0xFF0F) | (((o) & 0x0F) << 4))
#define SET_OFFSET_TO_IMM(i,o)		((i)->offsets = ((i)->offsets & 0xFFF0) | ((o) & 0x0F))

#define CONTAINS_PREFIX(i,p)		(((OFFSET_TO_OPCODE(i) > 0) && ((i)->data[0] == p)) || \
									((OFFSET_TO_OPCODE(i) > 1) && ((i)->data[1] == p)) || \
									((OFFSET_TO_OPCODE(i) > 2) && ((i)->data[2] == p)) || \
									 ((OFFSET_TO_OPCODE(i) > 3) && ((i)->data[3] == p)) )

#define GET_DIRECTION(i)			((*((i)->data + OFFSET_TO_OPCODE(i)) & 0x2) >> 1)

#define CLEAR_HAS_SIB(i)			((i)->flags &= ~INSTR_SIB)
#define SET_HAS_SIB(i)				((i)->flags |= INSTR_SIB)
#define SET_BRANCH(i)				((i)->flags |= INSTR_BRANCH)
#define SET_BRANCH_CALL(i)			((i)->flags &= ~INSTR_BRANCH_JMP)
#define SET_BRANCH_JMP(i)			((i)->flags |= INSTR_BRANCH_JMP)
#define SET_BRANCH_COND(i)			((i)->flags |= INSTR_BRANCH_COND)
#define SET_BRANCH_REL(i)			((i)->flags |= INSTR_BRANCH_REL)
#define SET_BRANCH_ABS(i)			((i)->flags &= ~INSTR_BRANCH_REL)
#define SET_BRANCH_INT(i)			((i)->flags |= INSTR_BRANCH_INT)
#define UNSET_BRANCH_INT(i)			((i)->flags &= ~INSTR_BRANCH_INT)
#define SET_CONTAINS_VA(i)			((i)->flags |= INSTR_CONTAINS_VA)
#define SET_F_2B_OPCODE(i)			((i)->flags |= (HAS_2B_OPCODE(i) ? INSTR_2B_OPCODE : 0x0))
#define SET_OPCODE_EXT(i)			((i)->flags |= INSTR_OPCODE_EXT)
#define SET_8BIT_OPERAND(i)			((i)->flags |= INSTR_8BIT_OPERAND)
#define CLEAR_8BIT_OPERAND(i)		((i)->flags &= ~INSTR_8BIT_OPERAND)

#define SET_INVALID_VA(i)			((i)->flags |= INVALID_VA)
#define SET_RESERVED_FLAG(i)		((i)->flags |= RESERVED)
#define SET_INJ_GDG_CALL(i)			((i)->flags |= INJECTED_GDG_CALL)
#define SET_PUSH_PC(i)				((i)->flags |= INSTR_PUSH_PC)

#define HAS_MODRM(i)				OFFSET_TO_MODRM(i)
#define HAS_DISP(i)					OFFSET_TO_DISP(i)
#define HAS_IMM(i)					OFFSET_TO_IMM(i)

#define HAS_SIB(i)					((i)->flags & INSTR_SIB)
#define IS_BRANCH(i)				((i)->flags & INSTR_BRANCH)
#define IS_BRANCH_CALL(i)			(IS_BRANCH(i) && (!((i)->flags & INSTR_BRANCH_JMP)))
#define IS_BRANCH_JMP(i)			(IS_BRANCH(i) && ((i)->flags & INSTR_BRANCH_JMP))
#define IS_BRANCH_COND(i)			(IS_BRANCH(i) && ((i)->flags & INSTR_BRANCH_COND))
#define IS_BRANCH_REL(i)			(IS_BRANCH(i) && ((i)->flags & INSTR_BRANCH_REL))
#define IS_BRANCH_ABS(i)			(IS_BRANCH(i) && (!((i)->flags & INSTR_BRANCH_REL)))
#define IS_BRANCH_INT(i)			(IS_BRANCH(i) && ((i)->flags & INSTR_BRANCH_INT))
#define IS_BRANCH_EXT(i)			(IS_BRANCH(i) && !((i)->flags & INSTR_BRANCH_INT) && !IS_INJ_GDG_CALL(i))
#define CONTAINS_VA(i)				((i)->flags & INSTR_CONTAINS_VA)
#define HAS_2B_OPCODE(i)			(((i)->data[OFFSET_TO_OPCODE(i)] == 0x0F) ?	1 : 0)
#define HAS_F_2B_OPCODE(i)			((i)->flags & INSTR_2B_OPCODE)
#define SIZEOF_OPCODE(i)			(1 + HAS_2B_OPCODE(i))
#define HAS_OPCODE_EXT(i)			((i)->flags & INSTR_OPCODE_EXT)
#define IS_8BIT_OPERAND(i)			((i)->flags & INSTR_8BIT_OPERAND)
#define IS_16BIT_OPERAND(i)			(CONTAINS_PREFIX(i,0x66) || *((i)->data + OFFSET_TO_OPCODE(i)) == 0xC2)
#define IS_32BIT_OPERAND(i)			(!IS_8BIT_OPERAND(i) && !IS_16BIT_OPERAND(i))
#define SIZEOF_OPERAND(i)			(IS_8BIT_OPERAND(i) ? 1 : (IS_16BIT_OPERAND(i) ? 2 : 4))
#define SIZEOF_IMM(i)				SIZEOF_OPERAND(i)
#define IS_8BIT_ADDRMODE(i)			(IS_8BIT_OPERAND(i) && (HAS_2B_OPCODE(i) || \
										(*((i)->data + OFFSET_TO_OPCODE(i)) != 0x6B\
											&& *((i)->data + OFFSET_TO_OPCODE(i)) != 0x83\
											&& *((i)->data + OFFSET_TO_OPCODE(i)) != 0xC1)))


#define JUMPS_INTO(r,i)				((i)->jmp && \
									(((r)->start) ? ((i)->jmp->index > (r)->start->index) : 1) && \
									(((r)->end) ? ((i)->jmp->index < (r)->end->index) : 1))

#define HAS_INVALID_VA(i)			((i)->flags & INVALID_VA)
#define HAS_RESERVED_FLAG(i)		((i)->flags & RESERVED)
#define IS_INJ_GDG_CALL(i)			((i)->flags & INJECTED_GDG_CALL)
#define IS_INJ_FOR_REG(i)			(IS_INJ_RESTORE_REG(i) || IS_INJ_SAVE_REG(i))
#define IS_PUSH_PC(i)				((i)->flags & INSTR_PUSH_PC)

#define INIT_INSTR(i)				(memset((i), 0x0, sizeof(INSTRUCTION)))

#pragma pack(push, 1)
typedef struct _INSTRUCTION {
	BYTE data[16];

	/* 4bits each:  | to-opcode | to-ModRegRM | to-displacement | to-immediate | */
	WORD offsets; 
	BYTE regReads;
	BYTE regWrites;
	BYTE freeRegs;
	DWORD index;

	/* must always be set when INSTR_BRANCH_INT is set */
	struct _INSTRUCTION *jmp; 
	struct _INSTRUCTION *next;

	/* index into <data> to direct VA reference from this instruction; 0 for NULL */
	BYTE directVA;

	DWORD flags;
	BYTE totalSize;
	union {
		LPVOID other;
		struct _INSTRUCTION **jmpSrcs;
	};
} INSTRUCTION;
#pragma pack(pop)

typedef struct _INST_RANGE_LIST {
	INSTRUCTION *start; // exclusive
	INSTRUCTION *end;	// exclusive
	struct _INST_RANGE_LIST *next;
} INST_RANGE_LIST;


// on REGister addressing modes the last 4 regs on 8bit instructions map to the lower 4 regs
inline BYTE getActualReg(const INSTRUCTION * const i, long reg)
{
	if (reg >= REG_ESP && IS_8BIT_ADDRMODE(i) && *(i->data + OFFSET_TO_OPCODE(i)) != 0xAC) // 0xAC is special case
		return (BYTE)reg - 4;
	return (BYTE)reg;
}

bool				equalInstr(const INSTRUCTION *iHead1, const INSTRUCTION *iHead2, DWORD numInstr=0xFFFFFFFF);
bool				isPushImm32(const INSTRUCTION * const i);
bool				isPushReg32(const INSTRUCTION * const i);
bool				isPush(const INSTRUCTION * const i);
bool				isPop(const INSTRUCTION * const i);
bool				isPopReg(const INSTRUCTION * const i);
bool				isPopRegRM(const INSTRUCTION * const i);
bool				isPriviledged(const INSTRUCTION * const i);
bool				readsIndOrwritesToMem(const INSTRUCTION * const i);
bool				modifiesEFlags(const INSTRUCTION * const i);

bool				containsRelOffset(const BYTE * linear, const DISASSEMBLY *disas);
int					getRelOffset(const DISASSEMBLY *disas, const BYTE *code);
void				setRelOffset(const DISASSEMBLY *disas, const BYTE *code, int offset);
void				addToRelOffset(const DISASSEMBLY *disas, BYTE *code, int delta);
inline BYTE*		getAddrFromRelOffset(const DISASSEMBLY *disas, const BYTE *code) 
					{ return (BYTE *)code + disas->OpcodeSize+disas->PrefixSize + getRelOffset(disas, code); }

REL_REF_DEST*		getRelRefDest(const BYTE *code, const REL_REFERENCES *relRefs);
int					getIndexOfRelRefDest(const REL_REF_DEST *arr, DWORD len, const BYTE *addr);
void				connectRelRefSrcDest(const REL_REF_SRC *rrs, const REL_REF_DEST *rrd);
REL_REFERENCES*		getAllRelReferences(const BYTE *code, DWORD sizeOfText);
void				freeRelReferences(REL_REFERENCES *refs);

INST_RANGE_LIST**	getFreeRegRanges(INSTRUCTION *i);
inline INST_RANGE_LIST *addIRangeToList(INST_RANGE_LIST *rangeList);
INST_RANGE_LIST*	getRange(const INST_RANGE_LIST *rangeList, const INSTRUCTION *i);
void				freeRegFreeRanges(INST_RANGE_LIST **ranges);
BYTE				getFreeRegisters(const INST_RANGE_LIST **ranges, const INSTRUCTION *i);

INSTRUCTION*		analyze(const BYTE *code, DWORD length, DWORD *numInstr, DWORD dVA = 0);
bool				analyzeInstr(INSTRUCTION *iHead);
bool				hasModRegRm(const INSTRUCTION *i);
bool				hasOpcodeExt(const INSTRUCTION *i);
void				setImmOffset(INSTRUCTION *i);
void				set8bitFlag(INSTRUCTION *i);
void				setContainsVA(INSTRUCTION *i);
void				analyzeModRegRm(INSTRUCTION *i);
void				setRegAccessByOpcode(INSTRUCTION *i); /* Asm_RegAccess.cpp */
bool				setOffsetsAndRegAccess(INSTRUCTION *i);
inline bool			isCall(const INSTRUCTION *i);
inline bool			isJmpUncond(const INSTRUCTION *i);
inline bool			isJmpCond(const INSTRUCTION *i);
inline bool			isBranch(const INSTRUCTION *i);
inline bool			isBranchRel(const INSTRUCTION *i);
inline bool			isBranchAbs(const INSTRUCTION *i)
					{ return isBranch(i) && !isBranchRel(i); }
bool				setIntBranchTarget(const INSTRUCTION *iHead, INSTRUCTION *i);
void				analyzeJmpSrcs(INSTRUCTION *iHead);
void				freeJmpSrcs(INSTRUCTION *iHead); // call this after any call to analyzeJmpSrcs()
int					getIndexOfInstr(const INSTRUCTION *pi, const long relOff);

long				getImm(const INSTRUCTION *i);
DWORD				getUImm(const INSTRUCTION * const i);
int					setImm(INSTRUCTION *i, long imm);
long				getDisp(const INSTRUCTION *i);
int					setDisp(INSTRUCTION *i, long disp);

BYTE*				getCode(const INSTRUCTION *iHead, DWORD *sizeOfCode, DWORD maxNumInstr=0xFFFFFFFF);
void				setRelocs(const INSTRUCTION *iHead, RELOCS *relocs);

bool				replaceJECXZ(INSTRUCTION **iHeadPtr, DWORD *numInstr, INSTRUCTION **iPtr);
bool				replaceLOOPD(INSTRUCTION **iHeadPtr, DWORD *numInstr, INSTRUCTION **iPtr);
bool				replaceLOOPZ_NZ(INSTRUCTION **iHeadPtr, DWORD *numInstr, INSTRUCTION **iPtr, bool loopIfZero);

int					makeRel32Branch(INSTRUCTION **iHeadPtr, DWORD *numInstr, INSTRUCTION **iPtr);
bool				makeAllRel32Braches(INSTRUCTION **iHeadPtr, DWORD *numInstr);

bool				repairRelBranchesOverRange(INSTRUCTION **iHeadPtr, DWORD *numInstr, 
						const INST_RANGE_LIST *range, long iDelta, long dataDelta);
bool				insertAllInstr(INSTRUCTION **iHeadPtr, DWORD *numInstr, 
							const INSTRUCTION *newI, DWORD index);
bool				replaceInstrRange(INSTRUCTION **iHeadPtr, DWORD *numInstr, 
							const INST_RANGE_LIST * const range, // inclusive bounds in this case
							const INSTRUCTION * const newI);
bool				replaceInstr(INSTRUCTION **iHeadPtr, DWORD *numInstr, 
							const INSTRUCTION * const newI, DWORD index);

bool				toDirectPUSH(INSTRUCTION **iHeadPtr, DWORD *numInstr, INSTRUCTION **iPtr);
bool				toDirectPOP(INSTRUCTION **iHeadPtr, DWORD *numInstr, INSTRUCTION **iPtr);
bool				replacePUSHAD(INSTRUCTION **iHeadPtr, DWORD *numInstr, INSTRUCTION **iPtr);
bool				replacePUSH_REG_IMM(INSTRUCTION **iHeadPtr, DWORD *numInstr, INSTRUCTION **iPtr);
bool				replacePOPAD(INSTRUCTION **iHeadPtr, DWORD *numInstr, INSTRUCTION **iPtr);
bool				replacePOP_REG(INSTRUCTION **iHeadPtr, DWORD *numInstr, INSTRUCTION **iPtr);
bool				toDirectPUSHPOP(INSTRUCTION **iHeadPtr, DWORD *numInstr);
bool				replaceAllPUSHPOPAD(INSTRUCTION **iHeadPtr, DWORD *numInstr);
bool				replaceAllPUSHPOP(INSTRUCTION **iHeadPtr, DWORD *numInstr);

INSTRUCTION*		unrollSIBDisp(const INSTRUCTION *i, BOOL preserveFlags = FALSE);
bool				unrollAllSIBDisp(INSTRUCTION **iHeadPtr, DWORD *numInstr, BOOL preserveFlags = FALSE);



/* Asm_Assemble.cpp */

typedef enum {
	JO,
	JNO,
	JB,
	JNAE = 2,
	JC = 2,
	JNB,
	JAE = 3,
	JNC = 3,
	JZ,
	JE = 4,
	JNZ,
	JNE = 5,
	JBE,
	JNA = 6,
	JNBE,
	JA = 7,
	JS,
	JNS,
	JP,
	JPE = 0xA,
	JNP,
	JPO = 0xB,
	JL,
	JNGE = 0xC,
	JNL,
	JGE = 0xD,
	JLE,
	JNG = 0xE,
	JNLE,
	JG = 0xF
} CJMP_TYPE;

long				getOffsetFrom(INSTRUCTION *iHead, INSTRUCTION *src = NULL, INSTRUCTION *dst = NULL);
void				setSHL_RM32_IMM8(INSTRUCTION *i, BYTE reg, BYTE imm);
void				setSHR_RM32_IMM8(INSTRUCTION *i, BYTE reg, BYTE imm);
void				setADD_RM32_REG(INSTRUCTION *i, BYTE mod, BYTE reg, BYTE rm);
void				setADD_REG_RM32(INSTRUCTION *i, BYTE mod, BYTE reg, BYTE rm);
void				setADD_REG_IMM(INSTRUCTION *i, BYTE reg, long imm);
void				setADD_REG_IMM32(INSTRUCTION *i, BYTE reg, long imm);
void				setADD_RM32_IMM8(INSTRUCTION *i, BYTE mod, BYTE rm, char imm);
void				setSUB_RM32_REG(INSTRUCTION *i, BYTE mod, BYTE reg, BYTE rm);
void				setSUB_REG_RM32(INSTRUCTION *i, BYTE mod, BYTE reg, BYTE rm);
void				setSUB_REG_IMM(INSTRUCTION *i, BYTE reg, long imm);
void				setSUB_REG_IMM32(INSTRUCTION *i, BYTE reg, long imm);
void				setSUB_RM32_IMM8(INSTRUCTION *i, BYTE mod, BYTE rm, char imm);
void				setSUB_RM32_IMM8(INSTRUCTION *i, BYTE mod, BYTE rm, char imm);
void				setMOV_SIB_DISP8_REG(INSTRUCTION *i, BYTE base, BYTE idx, BYTE ss, BYTE reg, char disp);
void				setMOV_REG_SIB_DISP8(INSTRUCTION *i, BYTE reg, BYTE base, BYTE idx, BYTE ss, char disp);
void				setMOV_SIB_REG(INSTRUCTION *i, BYTE base, BYTE idx, BYTE ss, BYTE reg);
void				setMOV_REG_SIB(INSTRUCTION *i, BYTE reg, BYTE base, BYTE idx, BYTE ss);
void				setMOV_SIB_IMM32(INSTRUCTION *i, BYTE base, BYTE idx, BYTE ss, long imm32);
void				setMOV_RM32_REG(INSTRUCTION *i, BYTE mod, BYTE rm, BYTE reg);
void				setMOV_REG_RM32(INSTRUCTION *i, BYTE mod, BYTE reg, BYTE rm);
void				setMOV_RM32_DISP32_REG(INSTRUCTION *i, BYTE reg, BYTE rm, long disp);
void				setP_MOV_DISP32_REG(INSTRUCTION *i, BYTE prefix, BYTE reg, long disp);
void				setMOV_REG_RM32_DISP32(INSTRUCTION *i, BYTE reg, BYTE rm, long disp);
void				setP_MOV_REG_DISP32(INSTRUCTION *i, BYTE prefix, BYTE reg, long disp);
void				setMOV_RM32_IMM32(INSTRUCTION *i, BYTE mod, BYTE rm, long imm32);
void				setMOV_REG_IMM8(INSTRUCTION *i, BYTE reg, char imm8);
void				setMOV_REG_IMM32(INSTRUCTION *i, BYTE reg, long imm32);
void				setMOV_REG_IMM(INSTRUCTION *i, BYTE reg, long imm);
void				setPUSH_REG32(INSTRUCTION *i, BYTE reg);
void				setPUSH_IMM32(INSTRUCTION *i, long imm32);
void				setPUSHFD(INSTRUCTION *i);
void				setPOP_REG32(INSTRUCTION *i, BYTE reg);
void				setPOPFD(INSTRUCTION *i);
void				setCOND_JMP_REL32(INSTRUCTION *i, BYTE op2, long rel32);
void				setCOND_JMP_REL8(INSTRUCTION *i, BYTE op1, char rel8);
void				setCOND_JMP_REL(INSTRUCTION *i, CJMP_TYPE type, long rel);
void				setCOND_JMP_REL_to(CJMP_TYPE type, INSTRUCTION *iHead, INSTRUCTION *src = NULL, INSTRUCTION *dst = NULL);
void				setLOOPD(INSTRUCTION *i, char rel8);
void				setCMP_REG_IMM32(INSTRUCTION *i, BYTE reg, long imm32);
void				setTEST_REGX_REGY(INSTRUCTION *i, BYTE regX, BYTE regY);
void				setTEST_REG(INSTRUCTION *i, BYTE reg);
void				setDEC_REG(INSTRUCTION *i, BYTE reg);
void				setRET(INSTRUCTION *i);
void				setJECXZ_IMM8(INSTRUCTION *i, char rel8);
void				setJMP_REL8(INSTRUCTION *i, char rel8);
void				setJMP_REL32(INSTRUCTION *i, long rel32);
void				setJMP_REL(INSTRUCTION *i, long rel);
void				setJMP_REL_to(INSTRUCTION *iHead, INSTRUCTION *src = NULL, INSTRUCTION *dst = NULL);
void				setJMP_REL32_to(INSTRUCTION *iHead, INSTRUCTION *src = NULL, INSTRUCTION *dst = NULL);
void				setCALL_REL(INSTRUCTION *i, long rel32);
void				setCALL_REL_to(INSTRUCTION *iHead, INSTRUCTION *src = NULL, INSTRUCTION *dst = NULL);
void				setCALL_IND(INSTRUCTION *i, DWORD addr);


/*Asm_Printing.cpp */

inline void			printDisassembly(DISASSEMBLY d);
void				printIDisassembly(const INSTRUCTION * const iHead, const DWORD numInstr = 0xFFFFFFFF, const DWORD baseAddr = 0x0);
inline void			printInstrShort(const INSTRUCTION * const i, const DWORD baseAddr = 0x0) { printIDisassembly(i, 1, baseAddr); };
void				printInstruction(const INSTRUCTION * const i);
void				printAllInstructions(const INSTRUCTION * const iHead);
void				printFreeRanges(const INST_RANGE_LIST **freeRegs);

#endif
