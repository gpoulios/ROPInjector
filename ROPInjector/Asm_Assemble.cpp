

#include "Asm.h"

/*
 * TODO:
 * These should have been generic so that they are more 
 * reusable. They are now easier to use, but if at any time 
 * the generics are written, these should probably become macros.
 * e.g. should be something like addModRM(INSTRUCTION *i, mod, reg, rm, ss, idx, base, disp)
 * that performs all the appropriate checks to determine if SIB or DISP, or 8/16/32-bit is needed.
 *
 * or, maybe use an assembler at some point?
 */


/* -<src> inclusive, <dst> exclusive (just like it happens with rel jmps/calls
 * -Assumes i->totalSize and i->next is set for all instructions in <iHead>
 * -Assumes <iHead> is the source, if src is NULL or not found in <iHead>
 * -Assumes tgt is the instr. following the <iHead> list, if target is not found in <i> or NULL
 */
long getOffsetFrom(INSTRUCTION *iHead, INSTRUCTION *src, INSTRUCTION *dst)
{
	if (!src)
		src = iHead;
	long srcOffsetFromHead = 0;
	long dstOffsetFromHead = 0;
	BOOL srcFound = FALSE;
	BOOL dstFound = FALSE;
	for (INSTRUCTION *i = iHead; i && !(srcFound && dstFound); i = i->next)
	{
		if (i == src)
		{
			srcFound = TRUE;
			srcOffsetFromHead += i->totalSize;
		}
		else if (!srcFound)
			srcOffsetFromHead += i->totalSize;

		if (i == dst)
			dstFound = TRUE;
		else if (!dstFound)
			dstOffsetFromHead += i->totalSize;
	}

	if (!srcFound)
		srcOffsetFromHead = iHead->totalSize;

	return dstOffsetFromHead - srcOffsetFromHead;
}

void setSHL_RM32_IMM8(INSTRUCTION *i, BYTE reg, BYTE imm)
{
	i->data[0] = 0xC1;
	i->data[1] = MAKE_MODRM(MOD_REG,0x6,reg);
	i->data[2] = imm;
	i->totalSize = 3;
	i->offsets = 0;
	SET_OFFSET_TO_OPCODE(i,0);
	SET_OFFSET_TO_MODRM(i,1);
	SET_OFFSET_TO_IMM(i,2);
	SET_8BIT_OPERAND(i);
}

void setSHR_RM32_IMM8(INSTRUCTION *i, BYTE reg, BYTE imm)
{
	i->data[0] = 0xC1;
	i->data[1] = MAKE_MODRM(MOD_REG,0x5,reg);
	i->data[2] = imm;
	i->totalSize = 3;
	i->offsets = 0;
	SET_OFFSET_TO_OPCODE(i,0);
	SET_OFFSET_TO_MODRM(i,1);
	SET_OFFSET_TO_IMM(i,2);
	SET_8BIT_OPERAND(i);
}

void setADD_RM32_REG(INSTRUCTION *i, BYTE mod, BYTE reg, BYTE rm)
{
	i->data[0] = 0x01;
	i->data[1] = MAKE_MODRM(mod, reg, rm);
	i->totalSize = 2;
	i->offsets = 0;
	SET_OFFSET_TO_OPCODE(i,0);
	SET_OFFSET_TO_MODRM(i,1);
	SET_OFFSET_TO_IMM(i,2);
}

void setADD_REG_RM32(INSTRUCTION *i, BYTE mod, BYTE reg, BYTE rm)
{
	i->data[0] = 0x03;
	i->data[1] = MAKE_MODRM(mod, reg, rm);
	i->totalSize = 2;
	i->offsets = 0;
	SET_OFFSET_TO_OPCODE(i,0);
	SET_OFFSET_TO_MODRM(i,1);
}

void setADD_REG_IMM(INSTRUCTION *i, BYTE reg, long imm)
{
	if (FITS_CHAR(imm))
		setADD_RM32_IMM8(i, MOD_REG, reg, (char)imm);
	else
		setADD_REG_IMM32(i, reg, imm);
}

void setADD_REG_IMM32(INSTRUCTION *i, BYTE reg, long imm)
{
	i->data[0] = 0x81;
	i->data[1] = MAKE_MODRM(MOD_REG,0x0,reg);
	*((long *)(i->data + 2)) = imm;
	i->totalSize = 6;
	i->offsets = 0;
	SET_OFFSET_TO_OPCODE(i,0);
	SET_OFFSET_TO_MODRM(i,1);
	SET_OFFSET_TO_IMM(i,2);
}

void setADD_RM32_IMM8(INSTRUCTION *i, BYTE mod, BYTE rm, char imm)
{
	i->data[0] = 0x83;
	i->data[1] = MAKE_MODRM(mod,0x0,rm);
	*((char *)(i->data + 2)) = imm;
	i->totalSize = 3;
	i->offsets = 0;
	SET_OFFSET_TO_OPCODE(i,0);
	SET_OFFSET_TO_MODRM(i,1);
	SET_OFFSET_TO_IMM(i,2);
	SET_8BIT_OPERAND(i);
}

void setSUB_RM32_REG(INSTRUCTION *i, BYTE mod, BYTE reg, BYTE rm)
{
	i->data[0] = 0x29;
	i->data[1] = MAKE_MODRM(mod, reg, rm);
	i->totalSize = 2;
	i->offsets = 0;
	SET_OFFSET_TO_OPCODE(i,0);
	SET_OFFSET_TO_MODRM(i,1);
}

void setSUB_REG_RM32(INSTRUCTION *i, BYTE mod, BYTE reg, BYTE rm)
{
	i->data[0] = 0x2B;
	i->data[1] = MAKE_MODRM(mod, reg, rm);
	i->totalSize = 2;
	i->offsets = 0;
	SET_OFFSET_TO_OPCODE(i,0);
	SET_OFFSET_TO_MODRM(i,1);
}

void setSUB_REG_IMM(INSTRUCTION *i, BYTE reg, long imm)
{
	if (FITS_CHAR(imm))
		setSUB_RM32_IMM8(i, MOD_REG, reg, (char)imm);
	else
		setSUB_REG_IMM32(i, reg, imm);
}

void setSUB_REG_IMM32(INSTRUCTION *i, BYTE reg, long imm)
{
	i->data[0] = 0x81;
	i->data[1] = MAKE_MODRM(MOD_REG,0x5,reg);
	*((long *)(i->data + 2)) = imm;
	i->totalSize = 6;
	i->offsets = 0;
	SET_OFFSET_TO_OPCODE(i,0);
	SET_OFFSET_TO_MODRM(i,1);
	SET_OFFSET_TO_IMM(i,2);
}

void setSUB_RM32_IMM8(INSTRUCTION *i, BYTE mod, BYTE rm, char imm)
{
	i->data[0] = 0x83;
	i->data[1] = MAKE_MODRM(mod,0x5,rm);
	*((char *)(i->data + 2)) = imm;
	i->totalSize = 3;
	i->offsets = 0;
	SET_OFFSET_TO_OPCODE(i,0);
	SET_OFFSET_TO_MODRM(i,1);
	SET_OFFSET_TO_IMM(i,2);
	SET_8BIT_OPERAND(i);
}

// TODO: create a master function that encodes ANY mov instruction 
//		just provide <base> <idx> and <ss>, and if (<idx> and <ss> == 0) or <base>!=ESP, 
//		then don't use SIB.
void setMOV_SIB_DISP8_REG(INSTRUCTION *i, BYTE base, BYTE idx, BYTE ss, BYTE reg, char disp)
{
	i->data[0] = 0x89;
	i->data[1] = MAKE_MODRM(MOD_IND_DISP8, reg, 0x4);
	i->data[2] = MAKE_SIB(ss, idx, base);
	*((char *)(i->data + 3)) = disp;
	i->totalSize = 4;
	i->offsets = 0;
	SET_OFFSET_TO_OPCODE(i,0);
	SET_OFFSET_TO_MODRM(i,1);
	SET_OFFSET_TO_DISP(i,3);
}

void setMOV_REG_SIB_DISP8(INSTRUCTION *i, BYTE reg, BYTE base, BYTE idx, BYTE ss, char disp)
{
	i->data[0] = 0x8B;
	i->data[1] = MAKE_MODRM(MOD_IND_DISP8, reg, 0x4);
	i->data[2] = MAKE_SIB(ss, idx, base);
	*((char *)(i->data + 3)) = disp;
	i->totalSize = 4;
	i->offsets = 0;
	SET_OFFSET_TO_OPCODE(i,0);
	SET_OFFSET_TO_MODRM(i,1);
	SET_OFFSET_TO_DISP(i,3);
}

void setMOV_SIB_REG(INSTRUCTION *i, BYTE base, BYTE idx, BYTE ss, BYTE reg)
{
	i->data[0] = 0x89;
	i->data[1] = MAKE_MODRM(MOD_IND, reg, 0x4);
	i->data[2] = MAKE_SIB(ss, idx, base);
	i->totalSize = 3;
	i->offsets = 0;
	SET_OFFSET_TO_OPCODE(i,0);
	SET_OFFSET_TO_MODRM(i,1);
}

void setMOV_REG_SIB(INSTRUCTION *i, BYTE reg, BYTE base, BYTE idx, BYTE ss)
{
	i->data[0] = 0x8B;
	i->data[1] = MAKE_MODRM(MOD_IND, reg, 0x4);
	i->data[2] = MAKE_SIB(ss, idx, base);
	i->totalSize = 3;
	i->offsets = 0;
	SET_OFFSET_TO_OPCODE(i,0);
	SET_OFFSET_TO_MODRM(i,1);
}

void setMOV_SIB_IMM32(INSTRUCTION *i, BYTE base, BYTE idx, BYTE ss, long imm32)
{
	i->data[0] = 0xC7;
	i->data[1] = MAKE_MODRM(MOD_IND,0x0,0x4);
	i->data[2] = MAKE_SIB(ss, idx, base);
	*((long *)(i->data + 3)) = imm32;
	i->totalSize = 7;
	i->offsets = 0;
	SET_OFFSET_TO_OPCODE(i,0);
	SET_OFFSET_TO_MODRM(i,1);
	SET_OFFSET_TO_IMM(i,3);
}

void setMOV_RM32_REG(INSTRUCTION *i, BYTE mod, BYTE rm, BYTE reg)
{
	i->data[0] = 0x89;
	i->data[1] = MAKE_MODRM(mod,reg,rm);
	i->totalSize = 2;
	i->offsets = 0;
	SET_OFFSET_TO_OPCODE(i,0);
	SET_OFFSET_TO_MODRM(i,1);
}

void setMOV_REG_RM32(INSTRUCTION *i, BYTE mod, BYTE reg, BYTE rm)
{
	i->data[0] = 0x8B;
	i->data[1] = MAKE_MODRM(mod,reg,rm);
	i->totalSize = 2;
	i->offsets = 0;
	SET_OFFSET_TO_OPCODE(i,0);
	SET_OFFSET_TO_MODRM(i,1);
}

void setMOV_RM32_DISP32_REG(INSTRUCTION *i, BYTE reg, BYTE rm, long disp)
{
	i->data[0] = 0x89;
	i->data[1] = MAKE_MODRM(MOD_IND_DISP32,reg,rm);
	*((long *)(i->data + 2)) = disp;
	i->totalSize = 6;
	i->offsets = 0;
	SET_OFFSET_TO_OPCODE(i,0);
	SET_OFFSET_TO_MODRM(i,1);
	SET_OFFSET_TO_DISP(i,2);
}

void setP_MOV_DISP32_REG(INSTRUCTION *i, BYTE prefix, BYTE reg, long disp)
{
	i->data[0] = prefix;
	i->data[1] = 0x89;
	i->data[2] = MAKE_MODRM(MOD_IND,reg,0x5);
	*((long *)(i->data + 3)) = disp;
	i->totalSize = 7;
	i->offsets = 0;
	SET_OFFSET_TO_OPCODE(i,1);
	SET_OFFSET_TO_MODRM(i,2);
	SET_OFFSET_TO_DISP(i,3);
}

void setMOV_REG_RM32_DISP32(INSTRUCTION *i, BYTE reg, BYTE rm, long disp)
{
	i->data[0] = 0x8B;
	i->data[1] = MAKE_MODRM(MOD_IND_DISP32,reg,rm);
	*((long *)(i->data + 2)) = disp;
	i->totalSize = 6;
	i->offsets = 0;
	SET_OFFSET_TO_OPCODE(i,0);
	SET_OFFSET_TO_MODRM(i,1);
	SET_OFFSET_TO_DISP(i,2);
}

void setP_MOV_REG_DISP32(INSTRUCTION *i, BYTE prefix, BYTE reg, long disp)
{
	i->data[0] = prefix;
	i->data[1] = 0x8B;
	i->data[2] = MAKE_MODRM(MOD_IND,reg,0x5);
	*((long *)(i->data + 3)) = disp;
	i->totalSize = 7;
	i->offsets = 0;
	SET_OFFSET_TO_OPCODE(i,1);
	SET_OFFSET_TO_MODRM(i,2);
	SET_OFFSET_TO_DISP(i,3);
}

void setMOV_RM32_IMM32(INSTRUCTION *i, BYTE mod, BYTE rm, long imm32)
{
	i->data[0] = 0xC7;
	i->data[1] = MAKE_MODRM(mod,0x0,rm);
	*((long *)(i->data + 2)) = imm32;
	i->totalSize = 6;
	i->offsets = 0;
	SET_OFFSET_TO_OPCODE(i,0);
	SET_OFFSET_TO_MODRM(i,1);
	SET_OFFSET_TO_IMM(i,2);
}

void setMOV_REG_IMM8(INSTRUCTION *i, BYTE reg, char imm8)
{
	i->data[0] = 0xB0 + reg;
	*((char *)(i->data + 1)) = imm8;
	i->totalSize = 2;
	SET_OFFSET_TO_OPCODE(i, 0);
	SET_OFFSET_TO_IMM(i, 1);
	SET_8BIT_OPERAND(i);
}

void setMOV_REG_IMM32(INSTRUCTION *i, BYTE reg, long imm32)
{
	i->data[0] = 0xB8 + reg;
	*((long *)(i->data + 1)) = imm32;
	i->totalSize = 5;
	SET_OFFSET_TO_OPCODE(i, 0);
	SET_OFFSET_TO_IMM(i, 1);
}

void setMOV_REG_IMM(INSTRUCTION *i, BYTE reg, long imm)
{
	if (FITS_CHAR(imm))
		setMOV_REG_IMM8(i, reg, (char)imm);
	else
		setMOV_REG_IMM32(i, reg, imm);
}

void setPUSH_REG32(INSTRUCTION *i, BYTE reg)
{
	i->data[0] = 0x50 + reg;
	i->totalSize = 1;
	SET_OFFSET_TO_OPCODE(i,0);
}

void setPUSH_IMM32(INSTRUCTION *i, long imm32)
{
	i->data[0] = 0x68;
	*((long *)(i->data + 1)) = imm32;
	i->totalSize = 5;
	SET_OFFSET_TO_OPCODE(i, 0);
	SET_OFFSET_TO_IMM(i, 1);
}

void setPUSHFD(INSTRUCTION *i)
{
	i->data[0] = 0x9C;
	i->totalSize = 1;
	SET_OFFSET_TO_OPCODE(i,0);
}

void setPOP_REG32(INSTRUCTION *i, BYTE reg)
{
	i->data[0] = 0x58 + reg;
	i->totalSize = 1;
	SET_OFFSET_TO_OPCODE(i,0);
}

void setPOPFD(INSTRUCTION *i)
{
	i->data[0] = 0x9D;
	i->totalSize = 1;
	SET_OFFSET_TO_OPCODE(i,0);
}

void setCOND_JMP_REL32(INSTRUCTION *i, BYTE op2, long rel32)
{
	i->data[0] = 0x0F;
	i->data[1] = op2;
	*((long *)(i->data + 2)) = rel32;
	i->totalSize = 6;
	SET_F_2B_OPCODE(i);
	SET_OFFSET_TO_OPCODE(i,0);
	SET_OFFSET_TO_IMM(i, 2);
}

void setCOND_JMP_REL8(INSTRUCTION *i, BYTE op1, char rel8)
{
	i->data[0] = op1;
	*((char *)(i->data + 1)) = rel8;
	i->totalSize = 2;
	SET_OFFSET_TO_OPCODE(i,0);
	SET_OFFSET_TO_IMM(i,1);
	SET_8BIT_OPERAND(i);
}

void setCOND_JMP_REL(INSTRUCTION *i, CJMP_TYPE type, long rel)
{
	BOOL considersThisSize = TRUE;
	if (rel < 0 && i->totalSize == 0)
		considersThisSize = FALSE;

	if (!considersThisSize)
		rel -= 2;

	if (FITS_CHAR(rel))
		setCOND_JMP_REL8(i, 0x70 + type, (char)rel);
	else
		setCOND_JMP_REL32(i, 0x80 + type, rel - (!considersThisSize ? 4 : 0));
}

void setCOND_JMP_REL_to(CJMP_TYPE type, INSTRUCTION *iHead, INSTRUCTION *src, INSTRUCTION *dst)
{
	INSTRUCTION *actualSrc = src == NULL ? iHead : src;
	setCOND_JMP_REL(actualSrc, type, getOffsetFrom(iHead, src, dst));
	if (dst)
		actualSrc->jmp = dst;
}

void setLOOPD(INSTRUCTION *i, char rel8)
{
	i->data[0] = 0xE2;
	*((char *)(i->data + 1)) = rel8;
	i->totalSize = 2;
	SET_OFFSET_TO_OPCODE(i,0);
	SET_OFFSET_TO_IMM(i,1);
	SET_8BIT_OPERAND(i);
}

void setCMP_REG_IMM32(INSTRUCTION *i, BYTE reg, long imm32)
{
	i->data[0] = 0x81;
	i->data[1] = MAKE_MODRM(0x3, 0x7, reg);
	*((long *)(i->data + 2)) = imm32;
	i->totalSize = 6;
	SET_OFFSET_TO_OPCODE(i,0);
	SET_OFFSET_TO_MODRM(i,1);
	SET_OFFSET_TO_IMM(i,2);
}

void setTEST_REGX_REGY(INSTRUCTION *i, BYTE regX, BYTE regY)
{
	i->data[0] = 0x85;
	i->data[1] = MAKE_MODRM(0x3, regX, regY);
	i->totalSize = 2;
	SET_OFFSET_TO_OPCODE(i,0);
	SET_OFFSET_TO_MODRM(i,1);
}

void setTEST_REG(INSTRUCTION *i, BYTE reg)
{
	setTEST_REGX_REGY(i, reg, reg);
}

void setDEC_REG(INSTRUCTION *i, BYTE reg)
{
	i->data[0] = 0x48 + reg;
	i->totalSize = 1;
	SET_OFFSET_TO_OPCODE(i,0);
}

void setRET(INSTRUCTION *i)
{
	i->data[0] = 0xC3;
	i->totalSize = 1;
	SET_OFFSET_TO_OPCODE(i, 0);
}

void setJECXZ_IMM8(INSTRUCTION *i, char rel8)
{
	i->data[0] = 0xE3;
	*((char *)(i->data + 1)) = rel8;
	i->totalSize = 2;
	SET_OFFSET_TO_OPCODE(i,0);
	SET_OFFSET_TO_IMM(i,1);
	SET_8BIT_OPERAND(i);
}

void setJMP_REL8(INSTRUCTION *i, char rel8)
{
	i->data[0] = 0xEB;
	*((char *)(i->data + 1)) = rel8;
	i->totalSize = 2;
	SET_OFFSET_TO_OPCODE(i, 0);
	SET_OFFSET_TO_IMM(i, 1);
	SET_8BIT_OPERAND(i);
}

void setJMP_REL32(INSTRUCTION *i, long rel32)
{
	i->data[0] = 0xE9;
	*((long *)(i->data + 1)) = rel32;
	i->totalSize = 5;
	SET_OFFSET_TO_OPCODE(i, 0);
	SET_OFFSET_TO_IMM(i, 1);
}

void setJMP_REL(INSTRUCTION *i, long rel)
{
	BOOL considersThisSize = TRUE;
	if (rel < 0 && i->totalSize == 0)
		considersThisSize = FALSE;
	
	if (!considersThisSize)
		rel -= 2;

	if (FITS_CHAR(rel))
		setJMP_REL8(i, (char)rel);
	else
		setJMP_REL32(i, rel - (!considersThisSize ? 3 : 0));
}

void setJMP_REL_to(INSTRUCTION *iHead, INSTRUCTION *src, INSTRUCTION *dst)
{
	INSTRUCTION *actualSrc = src == NULL ? iHead : src;
	setJMP_REL(actualSrc, getOffsetFrom(iHead, src, dst));
	if (dst)
		actualSrc->jmp = dst;
}

void setJMP_REL32_to(INSTRUCTION *iHead, INSTRUCTION *src, INSTRUCTION *dst)
{
	INSTRUCTION *actualSrc = src == NULL ? iHead : src;
	setJMP_REL32(actualSrc, getOffsetFrom(iHead, src, dst));
	if (dst)
		actualSrc->jmp = dst;
}

void setCALL_REL(INSTRUCTION *i, long rel32)
{
	i->data[0] = 0xE8;
	*((long *)(i->data + 1)) = rel32;
	i->totalSize = 5;
	SET_OFFSET_TO_OPCODE(i, 0);
	SET_OFFSET_TO_IMM(i, 1);
}

void setCALL_REL_to(INSTRUCTION *iHead, INSTRUCTION *src, INSTRUCTION *dst) 
{
	INSTRUCTION *actualSrc = src == NULL ? iHead : src;
	setCALL_REL(actualSrc, getOffsetFrom(iHead, src, dst));
	if (dst)
		actualSrc->jmp = dst;
}

void setCALL_IND(INSTRUCTION *i, DWORD addr)
{
	i->data[0] = 0xFF;
	i->data[1] = 0x15;
	*((DWORD *)(i->data + 2)) = addr;
	i->totalSize = 6;
	SET_OFFSET_TO_OPCODE(i, 0);
	SET_OFFSET_TO_IMM(i, 2);
	SET_CONTAINS_VA(i);
	i->directVA = 2;
}

