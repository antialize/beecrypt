/*
 * Copyright (c) 2001, 2002 Virtual Unlimited B.V.
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
/*!\file mp32opt.arm.S
 * \brief
 * \author Bob Deblier <bob@virtualunlimited.com>
 */

#include "beecrypt.gas.h"

	.file "mp32opt.arm.S"

	.text

/* ARM uses up to four registers for parameter passing */

C_FUNCTION_BEGIN(mp32setmul)
LABEL(mp32setmul)
	stmfd sp!, {r4, r5, lr}
	/* adjust the addresses */
	add r1, r1, r0, asl #2
	add r2, r2, r0, asl #2
	/* r3 is the multiplicand; r4 load from memory, r5 is scratch, ip is carry */
	mov ip, #0
LOCAL(mp32setmul_loop):
	ldr r4, [r2, #-4]!
	mov r5, #0
	umlal ip, r5, r3, r4
	str ip, [r1, #-4]!
	mov ip, r5
	subs r0, r0, #1
	bne LOCAL(mp32setmul_loop)
	/* return carry */
	mov r0, ip
	ldmfd sp!, {r4, r5, pc}
C_FUNCTION_END(mp32setmul, LOCAL(mp32setmul_size))

	
C_FUNCTION_BEGIN(mp32addmul)
LABEL(mp32addmul)
	stmfd sp!, {r4, r5, r6, lr}
	/* adjust the addresses */
	add r1, r1, r0, asl #2
	add r2, r2, r0, asl #2
	/* r3 is the multiplicand; r4 & r5 load from memory, r6 is scratch, ip is carry */
	mov ip, #0
LOCAL(mp32addmul_loop):
	ldr r4, [r2, #-4]!
	ldr r5, [r1, #-4]
	mov r6, #0
	umlal ip, r6, r3, r4
	adds r5, r5, ip
	adc ip, r6, #0
	str r5, [r1, #-4]!
	subs r0, r0, #1
	bne LOCAL(mp32addmul_loop)
	mov r0, ip /* return carry */
	ldmfd sp!, {r4, r5, r6, pc}
C_FUNCTION_END(mp32addmul, LOCAL(mp32addmul_size))


C_FUNCTION_BEGIN(mp32addsqrtrc)
LABEL(mp32addsqrtrc)
	stmfd sp!, {r4, r5, r6, lr}
	/* adjust the addresses */
	add r1, r1, r0, asl #3
	add r2, r2, r0, asl #2
	/* r3 is a zero register, ip is the carry */
	mov r3, #0
	mov ip, #0
LOCAL(mp32addsqrtrc_loop):
	ldr r4, [r2, #-4]!
	mov r6, #0
	umlal ip, r6, r4, r4
	ldr r5, [r1, #-4] /* lo word */
	ldr r4, [r1, #-8] /* hi word */
	adds r5, r5, ip
	adcs r4, r4, r6
	str r5, [r1, #-4]
	str r4, [r1, #-8]!
	adc ip, r3, #0 /* set carry */
	subs r0, r0, #1
	bne LOCAL(mp32addsqrtrc_loop)
	mov r0, ip /* return carry */
	ldmfd sp!, {r4, r5, r6, pc}
C_FUNCTION_END(mp32addsqrtrc, LOCAL(mp32addsqrtrc_size))
