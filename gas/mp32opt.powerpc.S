/*
 * mp32opt.powerpc.S
 *
 * Assembler optimized multiprecision integer routines for PowerPC
 *
 * Compile target is GNU Assembler
 *
 * Copyright (c) 2000, 2001 Virtual Unlimited B.V.
 *
 * Author: Bob Deblier <bob@virtualunlimited.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "config.gas.h"

	.file "mp32opt.powerpc.S"

	.text

#if DARWIN
# define reg0	r0
# define reg3	r3
# define reg4	r4
# define reg5	r5
# define reg6	r6
# define reg7	r7
# define reg8	r8
# define reg9	r9
#else
# define reg0	%r0
# define reg3	%r3
# define reg4	%r4
# define reg5	%r5
# define reg6	%r6
# define reg7	%r7
# define reg8	%r8
# define reg9	%r9
#endif

C_FUNCTION_BEGIN(mp32addw)
	mtctr reg3
	slwi reg0,reg3,2
	add reg4,reg4,reg0
	li reg0,0
	lwzu reg6,-4(reg4)
	addc reg6,reg6,reg5
	stw reg6,0(reg4)
	bdz .Lmp32addw_skip
.Lmp32addw_loop:
	lwzu reg6,-4(reg4)
	adde reg6,reg0,reg6
	stw reg6,0(reg4)
	bdnz .Lmp32addw_loop
.Lmp32addw_skip:
	/* return the carry */
	addze reg3,reg0
	blr
C_FUNCTION_END(mp32addw, .Lmp32addw_size)


C_FUNCTION_BEGIN(mp32subw)
	mtctr reg3
	slwi reg0,reg3,2
	add reg4,reg4,reg0
	li reg0,0
	lwz reg6,-4(reg4)
	subfc reg6,reg5,reg6
	stwu reg6,-4(reg4)
	bdz .Lmp32subw_skip
.Lmp32subw_loop:
	lwz reg6,-4(reg4)
	subfe reg6,reg0,reg6
	stwu reg6, -4(reg4)
	bdnz .Lmp32subw_loop
.Lmp32subw_skip:
	/* return the carry */
	subfe reg3,reg0,reg0
	neg reg3,reg3
	blr
C_FUNCTION_END(mp32subw, .Lmp32subw_size)


C_FUNCTION_BEGIN(mp32add)
	mtctr reg3
	slwi reg0,reg3,2
	add reg4,reg4,reg0
	add reg5,reg5,reg0
	li reg0,0
	lwz reg6,-4(reg4)
	lwzu reg7,-4(reg5)
	addc reg6,reg7,reg6
	stwu reg6,-4(reg4)
	bdz .Lmp32add_skip
.Lmp32add_loop:
	lwz reg6,-4(reg4)
	lwzu reg7,-4(reg5)
	adde reg6,reg7,reg6
	stwu reg6,-4(reg4)
	bdnz .Lmp32add_loop
.Lmp32add_skip:
	/* return the carry */
	addze reg3,reg0
	blr
C_FUNCTION_END(mp32add, .Lmp32add_size)


C_FUNCTION_BEGIN(mp32sub)
	mtctr reg3
	slwi reg0,reg3,2
	add reg4,reg4,reg0
	add reg5,reg5,reg0
	li reg0,0
	lwz reg6,-4(reg4)
	lwzu reg7,-4(reg5)
	subfc reg6,reg7,reg6
	stwu reg6,-4(reg4)
	bdz .Lmp32sub_skip
.Lmp32sub_loop:
	lwz reg6,-4(reg4)
	lwzu reg7,-4(reg5)
	subfe reg6,reg7,reg6
	stwu reg6,-4(reg4)
	bdnz .Lmp32sub_loop
.Lmp32sub_skip:
	/* return the carry */
	subfe reg3,reg0,reg0
	neg reg3,reg3
	blr
C_FUNCTION_END(mp32sub, .Lmp32sub_size)


C_FUNCTION_BEGIN(mp32setmul)
	mtctr reg3
	slwi reg0,reg3,2
	add reg4,reg4,reg0
	add reg5,reg5,reg0
	li reg3,0
.Lmp32setmul_loop:
	lwzu reg7,-4(reg5)
	mullw reg8,reg7,reg6
	addc reg8,reg8,reg3
	mulhwu reg3,reg7,reg6
	addze reg3,reg3
	stwu reg8,-4(reg4)
	bdnz .Lmp32setmul_loop
	blr
C_FUNCTION_END(mp32setmul, .Lmp32setmul_size)


C_FUNCTION_BEGIN(mp32addmul)
	mtctr reg3
	slwi reg0,reg3,2
	add reg4,reg4,reg0
	add reg5,reg5,reg0
	li reg3,0
.Lmp32addmul_loop:
	lwzu reg7,-4(reg4)
	lwzu reg8,-4(reg5)
	mullw reg9,reg8,reg6
	addc reg9,reg9,reg3
	mulhwu reg3,reg8,reg6
	addze reg3,reg3
	addc reg9,reg9,reg7
	addze reg3,reg3
	stw reg9,0(reg4)
	bdnz .Lmp32addmul_loop
	blr
C_FUNCTION_END(mp32addmul, .Lmp32addmul_size)


C_FUNCTION_BEGIN(mp32addsqrtrc)
	mtctr reg3
	slwi reg0,reg3,2
	add reg4,reg4,reg0
	add reg5,reg5,reg0
	add reg4,reg4,reg0
	li reg3,0
.Lmp32addsqrtrc_loop:
	lwzu reg0,-4(reg5)
	lwz reg6,-8(reg4)
	lwz reg7,-4(reg4)
	mullw reg9,reg0,reg0
	mulhwu reg8,reg0,reg0
	addc reg9,reg9,reg3
	addze reg8,reg8
	addc reg7,reg7,reg9
	adde reg6,reg6,reg8
	li reg3,0
	addze reg3,reg3
	stw reg7,-4(reg4)
	stwu reg6,-8(reg4)
	bdnz .Lmp32addsqrtrc_loop
	blr
C_FUNCTION_END(mp32addsqrtrc, .Lmp32addsqrtrc_size)
