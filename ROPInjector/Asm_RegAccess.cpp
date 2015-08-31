

#include "Asm.h"

/*
 * (once again, not dealing with mmx, vmx, sse* etc)
 *
 * assumes:
 * - OFFSET_TO_OPCODE/MODRM(i), INSTR_2B_OPCODE has been set
 */
void setRegAccessByOpcode(INSTRUCTION *i)
{
	const BYTE op1 = *(i->data + OFFSET_TO_OPCODE(i));
	const BYTE op2 = *(i->data + OFFSET_TO_OPCODE(i) + 1);
	const BYTE modRm = *(i->data + OFFSET_TO_MODRM(i));
	const BYTE *sib;
	bool readsDirectRM = false;
	bool writesDirectRM = false;
	long imm = getImm(i);


		/* set register access on stack pointer */
	if (isCall(i) || (op1 == 0xC2) || (op1 == 0xC3) || (op1 == 0xCA) || (op1 == 0xCB) || (op1 == 0xCF) // call*, (i)ret*
		|| (op1 == 0x68) || (op1 == 0x6A)										// push IMM
		|| (op1 == 0x9C) || (op1 == 0x9D)										// pushfd, popfd
		|| (op1 == 0xF1) //|| ((op1 >= 0xCC) && (op1 <= 0xCE)) 					// int(o) 3/IMM (see below)
		|| (op1 == 0x06) || (op1 == 0x07) || (op1 == 0x0E)						// push/pop ES/CS
		|| (op1 == 0x16) || (op1 == 0x17) || (op1 == 0x1E) || (op1 == 0x1F)		// push/pop SS/DS
		|| (HAS_F_2B_OPCODE(i) && ((op2 == 0xA0) || (op2 == 0xA1)				// push/pop FS
								||	(op2 == 0xA8) || (op2 == 0xA9)))			// push/pop GS
		|| (HAS_F_2B_OPCODE(i) && ((op2 == 0x34) || (op2 == 0x35)))				// sysenter/exit
		
		)
	{
		SET_READS(i,REG_ESP);
		SET_WRITES(i,REG_ESP);
	}


	/* set register reads by modr/m and SIB bytes */
	if (HAS_MODRM(i))
	{
		if (MODRM_HAS_SIB(modRm)) // MOD!=11 && RM=100 -> SIB -> indirect addressing
		{
			sib = i->data + OFFSET_TO_SIB(i);
			if (SIB_GET_INDEX(*sib) != REG_ESP)
				SET_READS(i, SIB_GET_INDEX(*sib));
			if (!((MODRM_GET_MOD(modRm) == MOD_IND) && (SIB_GET_BASE(*sib) == REG_EBP)))
				SET_READS(i, SIB_GET_BASE(*sib));
		}
		// the rest (except 32bit disp. only) -> indirect addressing
		else if ((MODRM_GET_MOD(modRm) != MOD_REG) && !MODRM_IS_DISP_ONLY(modRm))
			SET_READS(i, MODRM_GET_RM(i, modRm));
	}


	if ((op1 == 0x00) || (op1 == 0x01)				// add R/M, REG

			// special cases: and X,X;  or X,X; have no effect on X
		|| ((	(op1 == 0x08) || (op1 == 0x09)		// or R/M, REG
			||	(op1 == 0x20) || (op1 == 0x21))		// and R/M, REG
			&& !IS_MODREG_EQREGS(modRm))

		|| (op1 == 0x10) || (op1 == 0x11)			// adc R/M, REG
		|| (op1 == 0x18) || (op1 == 0x19)			// sbb R/M, REG
		|| (op1 == 0x28) || (op1 == 0x29)			// sub R/M, REG
		|| (op1 == 0x30) || (op1 == 0x31)			// xor R/M, REG
		)
	{
		// special case: xor X,X does not read X
		if (! (((op1 == 0x30) || (op1 == 0x31)) && IS_MODREG_EQREGS(modRm)) )
		{
			SET_READS(i, MODRM_GET_REG(i, modRm));
			readsDirectRM = true; // rest of the cases have been set
		}
		writesDirectRM = true;
	}
	else if ((op1 == 0x02) || (op1 == 0x03)			// add REG, R/M

		// special cases: and X,X;  or X,X; have no effect on X
		|| ((	(op1 == 0x0A) || (op1 == 0x0B)	// or REG, R/M	
			||	(op1 == 0x22) || (op1 == 0x23))	// and REG, R/M
			&& !IS_MODREG_EQREGS(modRm))

		|| (op1 == 0x12) || (op1 == 0x13)			// adc REG, R/M
		|| (op1 == 0x1A) || (op1 == 0x1B)			// sbb REG, R/M
		|| (op1 == 0x2A) || (op1 == 0x2B)			// sbb REG, R/M
		|| (op1 == 0x32) || (op1 == 0x33)			// xor REG, R/M
		|| (HAS_F_2B_OPCODE(i) && (op2 == 0xAF))	// imul REG, R/M
		)
	{
		// special case: xor X,X does not read X
		if (! (((op1 == 0x32) || (op1 == 0x33)) && IS_MODREG_EQREGS(modRm)) )
		{
			SET_READS(i, MODRM_GET_REG(i, modRm));
			readsDirectRM = true;
		}
		SET_WRITES(i, MODRM_GET_REG(i, modRm));
	}
	else if ((imm != 0 && (
		   (op1 == 0x04) || (op1 == 0x05)			// add AL/EAX, imm
		|| (op1 == 0x0C) || (op1 == 0x0D)			// or AL/EAX, imm
		|| (op1 == 0x2C) || (op1 == 0x2D)			// sub AL/EAX, imm
		|| (op1 == 0x34) || (op1 == 0x35)))			// xor AL/EAX, imm
		|| (op1 == 0x14) || (op1 == 0x15)			// adc AL/EAX, imm
		|| (op1 == 0x1C) || (op1 == 0x1D)			// sbb AL/EAX, imm
		|| (imm != -1 && (
		   (op1 == 0x24) || (op1 == 0x25)))			// and AL/EAX, imm		
		|| (op1 == 0x3F)							// aas
		|| (op1 == 0x98)							// cbde EAX, AX
		|| (op1 == 0xD4) || (op1 == 0xD5)			// amx, adx
		)
	{
		SET_READS(i, REG_EAX);
		SET_WRITES(i, REG_EAX);
	}
	else if ((op1 == 0x38) || (op1 == 0x39)			// cmp R/M, REG
		|| (op1 == 0x3A) || (op1 == 0x3B)			// cmp REG, R/M
		|| (op1 == 0x84) || (op1 == 0x85)			// test R/M, REG
		)
	{
		SET_READS(i, MODRM_GET_REG(i, modRm));
		readsDirectRM = true;
	}
	else if ((op1 == 0x3C) || (op1 == 0x3D)			// cmp AL/EAX, imm
		)
	{
		SET_READS(i, REG_EAX);
	}
	else if (((op1 >= 0x40) && (op1 <= 0x4F))		// inc/dec REG
		)
	{
		SET_READS(i, (op1 & 0x7));
		SET_WRITES(i, (op1 & 0x7));
	}
	else if (((op1 >= 0x50) && (op1 <= 0x57))		// push REG
		)
	{
		SET_READS(i, (op1 & 0x7));
		SET_READS(i, REG_ESP);
		SET_WRITES(i, REG_ESP);
	}
	else if (((op1 >= 0x58) && (op1 <= 0x5F))		// pop REG
		)
	{
		SET_WRITES(i, (op1 & 0x7));
		SET_READS(i, REG_ESP);
		SET_WRITES(i, REG_ESP);
	}
	else if ( (op1 == 0x60)							// pushad
		||	((op1 >= 0xCC) && (op1 <= 0xCE))		// int(o) 3/IMM
		)
	{
		SET_READSALL(i);
		SET_WRITES(i, REG_ESP);
	}
	else if ( (op1 == 0x61)							// popad
		)
	{
		SET_WRITESALL(i);
		SET_READS(i, REG_ESP);
	}
	else if (op1 == 0x63)							// arpl
	{
		SET_READS(i,MODRM_GET_REG(i, modRm));
		readsDirectRM = true;
	}
	else if ((op1 == 0x69) || (op1 == 0x6B))		// imul
	{
		SET_WRITES(i,MODRM_GET_REG(i, modRm));
		readsDirectRM = true;
	}
	else if ((op1 == 0x6C) || (op1 == 0x6D))		// ins
	{
		SET_READS(i,REG_EDX);
		SET_READS(i,REG_EDI);
		SET_WRITES(i,REG_EDI);
	}
	else if ((op1 == 0x6E) || (op1 == 0x6F))		// outs
	{
		SET_READS(i,REG_EDX);
		SET_READS(i,REG_ESI);
		SET_WRITES(i,REG_ESI);
	}
	else if ((op1 >= 0x80 && op1 <= 0x83)			// add/or/adc/sbb/and/sub... RM8, IMM8
		|| (op1 == 0xC0) || (op1 == 0xC1)			// rol/ror/rcl/rcr/shl/shr ... RM, IMM8
		|| (op1 == 0xD0) || (op1 == 0xD1)			// rol/ror/rcl/rcr/shl/shr ... RM, 1
		|| (((op1 == 0xF6) || (op1 == 0xF7)) && 
					((MODRM_GET_OPEXT(modRm) == 2)
				||	  MODRM_GET_OPEXT(modRm) == 3))	// not/neg RM8
		|| ( (op1 == 0xFE) ||
			((op1 == 0xFF) && 
					(MODRM_GET_OPEXT(modRm) <= 1)) ) // inc/dec RM
		|| (HAS_F_2B_OPCODE(i) && ((op2 == 0xBA)	 // bts/r/c RM, REG
			&& (MODRM_GET_OPEXT(modRm) >= 5) && (MODRM_GET_OPEXT(modRm) <= 7)))
		)
	{
		BYTE opExt = MODRM_GET_OPEXT(modRm);
		BOOL isSpecialCase = 
			(imm == 0 &&
			(((op1 >= 0x80 && op1 <= 0x83) && (opExt < 2 || opExt == 5 || opExt == 6))
				|| (op1 == 0xC0) || (op1 == 0xC1))) 
			||
			(imm == -1 &&
			((op1 >= 0x80 && op1 <= 0x83) && opExt == 4));

		readsDirectRM = !isSpecialCase;
		writesDirectRM = !isSpecialCase;
	}
	else if ((op1 == 0xD2) || (op1 == 0xD3)			// rol/ror/rcl/rcr/shl/shr ... RM, CL
		)
	{
		SET_READS(i, REG_ECX);
		readsDirectRM = true;
		writesDirectRM = true;
	}
	else if (
		// special case: xchg X,X has no effect on X
		(((op1 == 0x86) || (op1 == 0x87))			// xchg RM, REG
				&& !IS_MODREG_EQREGS(modRm))
		|| (HAS_F_2B_OPCODE(i)
			&& ((op2 == 0xC0) || (op2 == 0xC1)))	// xadd RM, REG
		)
	{
		SET_READS(i, MODRM_GET_REG(i, modRm));
		SET_WRITES(i, MODRM_GET_REG(i, modRm));
		readsDirectRM = true;
		writesDirectRM = true;
	}
	else if (((op1 == 0x88) || (op1 == 0x89)		// mov RM, REG
				&& !IS_MODREG_EQREGS(modRm))
		)
	{
		SET_READS(i,MODRM_GET_REG(i, modRm));
		writesDirectRM = true;
	}
	else if (((op1 == 0x8A) || (op1 == 0x8B)		// mov REG, RM
				&& !IS_MODREG_EQREGS(modRm))
		)
	{
		SET_WRITES(i,MODRM_GET_REG(i, modRm));
		readsDirectRM = true;
	}
	else if ((op1 == 0x8C)							// mov RM, SREG
		||	(op1 == 0xC6) || (op1 == 0xC7)			// mov RM, IMM
		||	(HAS_F_2B_OPCODE(i) && (op2 == 0x00) 
			&& (MODRM_GET_OPEXT(modRm) <= 0x1))		// sldt, str
		)
	{ // we don't care about segment registers right now
		writesDirectRM = true;
	}
	else if ((op1 == 0x8D)							// lea REG, M
		||	(op1 == 0xC4) || (op1 == 0xC5)			// les/ds REG, M
		|| (HAS_F_2B_OPCODE(i) && ((op2 == 0xB2)	// lss REG, M
								|| (op2 == 0xB4)	// lfs REG, M
								|| (op2 == 0xB5)))	// lgs REG, M
		)
	{
		SET_WRITES(i,MODRM_GET_REG(i, modRm));
	}
	else if ((op1 == 0x8E)							// mov SREG, RM
		||	(((op1 == 0xF6) || (op1 == 0xF7)) && 
					((MODRM_GET_OPEXT(modRm) == 0)
				||	  MODRM_GET_OPEXT(modRm) == 1))	// test RM8, IMM8
		||	(HAS_F_2B_OPCODE(i) && (op2 == 0x00) 
			&& (MODRM_GET_OPEXT(modRm) >= 0x2)
			&& (MODRM_GET_OPEXT(modRm) <= 0x5))		// lldt, ltr, verr, verw
		||	(HAS_F_2B_OPCODE(i) && (op2 == 0xBA)	
			&& (MODRM_GET_OPEXT(modRm) == 4))		// bt RM, IMM
		||	((op1 == 0xFF) &&						
					((MODRM_GET_OPEXT(modRm) == 2)	// call RM
				||	 (MODRM_GET_OPEXT(modRm) == 4)))// jmp RM
		)
	{
		readsDirectRM = true;
	}
	else if ((op1 == 0x8F)							// pop RM
		)
	{
		SET_READS(i,REG_ESP);
		SET_WRITES(i,REG_ESP);
		writesDirectRM = true;
	}
	else if (((op1 == 0xFF) && 
					(MODRM_GET_OPEXT(modRm) == 6))	// push RM
		)
	{
		SET_READS(i,REG_ESP);
		SET_WRITES(i,REG_ESP);
		readsDirectRM = true;
	}
	else if ((((op1 >= 0x90) &&	(op1 <= 0x97))		// xchg REG, EAX
				&& ((op1 & 0x7) != REG_EAX))
		)
	{
		SET_READS(i,REG_EAX);
		SET_WRITES(i,REG_EAX);
		SET_READS(i, (op1 & 0x7));
		SET_WRITES(i, (op1 & 0x7));
	}
	else if ((op1 == 0x99)							// cdq EDX, EAX	
		)
	{
		SET_READS(i,REG_EAX);
		SET_WRITES(i,REG_EDX);
	}
	else if ((op1 == 0x9E)							// sahf
		||	(op1 == 0xA2) || (op1 == 0xA3)			// mov moffs, EAX
		||	(op1 == 0xA8) || (op1 == 0xA9)			// mov moffs, EAX
		||	(op1 == 0xE6) || (op1 == 0xE7)			// out
		)
	{
		SET_READS(i,REG_EAX);
	}
	else if ((op1 == 0x9E)							// lahf
		||	(op1 == 0xA0) || (op1 == 0xA1)			// mov EAX, moffs
		||	(op1 == 0xD6)							// setalc
		||	(op1 == 0xE4) || (op1 == 0xE5)			// in
		)
	{
		SET_WRITES(i,REG_EAX);
	}
	else if ((op1 == 0xA4)	|| (op1 == 0xA5)		// movsb, movsd 
		||	(op1 == 0xA6) || (op1 == 0xA7)			// cmpsb, cmpsd
		)
	{
		SET_READS(i,REG_ESI);
		SET_READS(i,REG_EDI);
		SET_WRITES(i,REG_ESI);
		SET_WRITES(i,REG_EDI);
	}
	else if ((op1 == 0xAA)	|| (op1 == 0xAB)		// stos* 
		||	(op1 == 0xAE)	|| (op1 == 0xAF)		// scas* 
		)
	{
		SET_READS(i,REG_EAX);
		SET_READS(i,REG_EDI);
		SET_WRITES(i,REG_EDI);
	}
	else if ((op1 == 0xAC)	|| (op1 == 0xAD)		// lods*
		)
	{
		SET_WRITES(i,REG_EAX);
		SET_READS(i,REG_ESI);
		SET_WRITES(i,REG_ESI);
	}
	else if (((op1 >= 0xB0) && (op1 <= 0xBF))		// mov REG, IMM
		)
	{
		SET_WRITES(i,(op1 & 0x7));
	}
	else if ((op1 == 0xC8) || (op1 == 0xC9)			// enter, leave
		)
	{
		SET_READS(i,REG_EBP);
		SET_WRITES(i,REG_EBP);
		SET_READS(i,REG_ESP);
		SET_WRITES(i,REG_ESP);
	}
	else if ((op1 == 0xD7)							// xlat
		)
	{
		SET_READS(i,REG_EBX);
		SET_READS(i,REG_EAX);
		SET_WRITES(i,REG_EAX);
	}
	else if (((op1 >= 0xE0) && (op1 <= 0xE3))		// loop*
		)
	{
		SET_READS(i,REG_ECX);
	}
	else if ((op1 == 0xEC) || (op1 == 0xED)			// in ax, dx
		)
	{
		SET_READS(i,REG_EDX);
		SET_WRITES(i,REG_EAX);
	}
	else if ((op1 == 0xEE) || (op1 == 0xEF)			// out dx, ax
		)
	{
		SET_READS(i,REG_EDX);
		SET_READS(i,REG_EAX);
	}
	else if (CONTAINS_PREFIX(i,0xF2) || CONTAINS_PREFIX(i,0xF3))	// rep* prefix
	{
		SET_READS(i,REG_ECX);
		SET_WRITES(i,REG_ECX);
	}
	else if (((op1 == 0xF6) && 
					(MODRM_GET_OPEXT(modRm) >= 4))	// (i)mul, (i)div AX, A... IMM8
		)
	{
		SET_READS(i,REG_EAX);
		SET_WRITES(i,REG_EAX);
		readsDirectRM = true;
	}
	else if (((op1 == 0xF7) && 
					(MODRM_GET_OPEXT(modRm) >= 4))		// (i)mul, (i)div EDX, EAX,... IMM8
		)
	{
		SET_READS(i,REG_EAX);
		SET_READS(i,REG_EDX);
		SET_WRITES(i,REG_EAX);
		SET_WRITES(i,REG_EDX);
		readsDirectRM = true;
	}
	else if ((HAS_F_2B_OPCODE(i) && (op2 == 0x01))
		)
	{
		if (MODRM_GET_OPEXT(modRm) == 0x2)
		{
			if (modRm == 0xD0)						// xgetbv
			{
				SET_READS(i,REG_ECX);
				SET_WRITES(i,REG_EAX);
				SET_WRITES(i,REG_EDX);
			}
			else if (modRm == 0xD1)					// xsetbv
			{
				SET_READS(i,REG_ECX);
				SET_READS(i,REG_EAX);
				SET_READS(i,REG_EDX);
			}
		}
		else if (MODRM_GET_OPEXT(modRm) == 0x4)		// smsw
			writesDirectRM = true;
		else if (MODRM_GET_OPEXT(modRm) == 0x6)		// lmsw
			readsDirectRM = true;
		else if (modRm == 0xF9)						// rdtscp
		{
			SET_READS(i,REG_ECX);
			SET_WRITES(i,REG_EAX);
			SET_WRITES(i,REG_EDX);
		}
	}
	else if ((HAS_F_2B_OPCODE(i) && 
		((op2 == 0x02) || (op2 == 0x03)))			// lar/lsl
		)
	{
		SET_WRITES(i,MODRM_GET_REG(i, modRm));
		readsDirectRM = true;
	}
	else if ((HAS_F_2B_OPCODE(i) &&		
		((op2 == 0x20) || (op2 == 0x21)))			// mov from control/debug registers
		)
	{
		SET_WRITES(i,MODRM_GET_REG(i, modRm));
	}
	else if ((HAS_F_2B_OPCODE(i) &&		
		((op2 == 0x22) || (op2 == 0x23)))			// mov to control/debug registers
		)
	{
		SET_READS(i,MODRM_GET_REG(i, modRm));
	}
	else if ((HAS_F_2B_OPCODE(i) && (op2 == 0x30))	// wrmsr
		)
	{
		SET_READS(i,REG_EAX);
		SET_READS(i,REG_EDX);
		SET_READS(i,REG_ECX);
	}
	else if ((HAS_F_2B_OPCODE(i) && 
		(	(op2 == 0x31)							// rdtsc
		||	(op2 == 0x33))	)						// rdpmc
		)
	{
		SET_WRITES(i,REG_EAX);
		SET_WRITES(i,REG_EDX);
	}
	else if ((HAS_F_2B_OPCODE(i) && (op2 == 0x32))	// rdmsr
		)
	{
		SET_READS(i,REG_ECX);
		SET_WRITES(i,REG_EAX);
		SET_WRITES(i,REG_EDX);
	}
	else if ((HAS_F_2B_OPCODE(i) &&					// cmov*
		((op2 >= 0x40) && (op2 <= 0x4F)))
		)
	{
		SET_WRITES(i, MODRM_GET_REG(i, modRm));
		readsDirectRM = true;
	}
	else if ((HAS_F_2B_OPCODE(i) &&					// set*
		((op2 >= 0x90) && (op2 <= 0x9F)))
		)
	{
		writesDirectRM = true;
	}
	else if ((HAS_F_2B_OPCODE(i) && (op2 == 0xA2))	// cpuid
		)
	{
		SET_READS(i, REG_EAX);
		SET_WRITESALL(i);
	}
	else if ((HAS_F_2B_OPCODE(i) && (op2 == 0xA3))	// bt RM, REG
		)
	{
		SET_READS(i, MODRM_GET_REG(i, modRm));
		readsDirectRM = true;
	}
	else if ((HAS_F_2B_OPCODE(i) && 				
		((op2 == 0xA4) || (op2 == 0xA5)				// shld RM, REG, IMM/CL 
		|| (op2 == 0xAC) || (op2 == 0xAD)))			// shrd RM, REG, IMM/CL 
		)
	{
		if ((op2 == 0xA5) || (op2 == 0xAD))
			SET_READS(i, REG_ECX);
		SET_READS(i, MODRM_GET_REG(i, modRm));
		readsDirectRM = true;
		writesDirectRM = true;
	}
	else if ((HAS_F_2B_OPCODE(i) && ((op2 == 0xAB)	// bts RM, REG
		|| (op2 == 0xB3)							// btr RM, REG
		|| (op2 == 0xBB)))							// btc RM, REG
		)
	{
		SET_READS(i, MODRM_GET_REG(i, modRm));
		readsDirectRM = true;
		writesDirectRM = true;
	}
	else if ((HAS_F_2B_OPCODE(i) &&					// cmpxchg RM, (E)AX, REG
		((op2 == 0xB0) || (op2 == 0xB1)))
		)
	{
		SET_READS(i, MODRM_GET_REG(i, modRm));
		SET_READS(i, REG_EAX);
		SET_WRITES(i, REG_EAX);
		readsDirectRM = true;
		writesDirectRM = true;
	}
	else if ((HAS_F_2B_OPCODE(i) &&					// lss/fs/gs
		((op2 == 0xB2) || (op2 == 0xB4) || (op2 == 0xB5)))
		)
	{
		SET_WRITES(i, MODRM_GET_REG(i, modRm));
	}
	else if ((HAS_F_2B_OPCODE(i) &&					
		((op2 == 0xB6) || (op2 == 0xB7)				// movzx REG, RM
		|| (op2 == 0xBC)							// bsf REG, RM 
		|| (op2 == 0xBD)							// bsr REG, RM
		|| (op2 == 0xBE)							// movsx REG, RM 
		|| (op2 == 0xBF)							// movsx REG, RM
		|| ((op2 == 0xB8) && !CONTAINS_PREFIX(i,0xF3))	// popcnt REG, RM
		)))
	{
		SET_WRITES(i, MODRM_GET_REG(i, modRm));
		readsDirectRM = true;
	}
	else if ((HAS_F_2B_OPCODE(i) && ((op2 == 0xC7) 
				&& (MODRM_GET_OPEXT(modRm) == 1)))	// cmpxchg8b M, EAX, EDX
			)
	{
		SET_READS(i, REG_EAX);
		SET_READS(i, REG_EDX);
		SET_WRITES(i, REG_EAX);
		SET_WRITES(i, REG_EDX);
	}
	else if ((HAS_F_2B_OPCODE(i) && 
					((op2 >> 3) == 0x19))			// bswap REG 
			)
	{
		SET_READS(i,op2 & 0x7);
		SET_WRITES(i,op2 & 0x7);
	}
	


	if (HAS_MODRM(i) && MODRM_GET_MOD(modRm) == MOD_REG) 
	{
		if (readsDirectRM)
			SET_READS(i, MODRM_GET_RM(i, modRm));
		if (writesDirectRM)
			SET_WRITES(i, MODRM_GET_RM(i, modRm));
	}

//	if ((i->regReads == 0x0) && (i->regWrites == 0x0))
//	{
//#ifdef DEBUG_MODE
//		printf("[-] Assuming READSALL for instruction: ");
//		for (BYTE ib = 0; ib < i->totalSize; ib++)
//			printf("%02X", i->data[ib]);
//		printf(", index: %d\n", i->index);
//#endif
//		SET_READSALL(i); // assume this, seems safe for now
//	}
}
