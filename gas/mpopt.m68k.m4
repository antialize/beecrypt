dnl  mpopt.m68k.m4
dnl
dnl  Copyright (c) 2003 Bob Deblier
dnl 
dnl  Author: Bob Deblier <bob.deblier@pandora.be>
dnl 
dnl  This library is free software; you can redistribute it and/or
dnl  modify it under the terms of the GNU Lesser General Public
dnl  License as published by the Free Software Foundation; either
dnl  version 2.1 of the License, or (at your option) any later version.
dnl 
dnl  This library is distributed in the hope that it will be useful,
dnl  but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
dnl  Lesser General Public License for more details.
dnl 
dnl  You should have received a copy of the GNU Lesser General Public
dnl  License along with this library; if not, write to the Free Software
dnl  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 
include(config.m4)


C_FUNCTION_BEGIN(mpsetmul)
	movem.l %d2-%d5,-(%sp)
	move.l 20(%sp),%d0
	movea.l 24(%sp),%a0
	movea.l 28(%sp),%a1
	move.l 32(%sp),%d2
	move.l %d0,%d5
	lsl.l #2,%d0
	adda.l %d0,%a0
	adda.l %d0,%a1
	clr.l %d3
	clr.l %d4

	.align 2
LOCAL(mpsetmul_loop):
	move.l -(%a1),%d1
	mulu.l %d2,%d0:%d1
	add.l %d3,%d1
	addx.l %d4,%d0
	move.l %d1,-(%a0)
	move.l %d0,%d3
	subq.l #1,%d5
	jbne LOCAL(mpsetmul_loop)

	movem.l (%sp)+,%d2-%d5
	rts
C_FUNCTION_END(mpsetmul)


C_FUNCTION_BEGIN(mpaddmul)
	movem.l %d2-%d6,-(%sp)
	move.l 24(%sp),%d0
	movea.l 28(%sp),%a1
	movea.l 32(%sp),%a2
	move.l 36(%sp),%d2
	move.l %d0,%d5
	lsl.l #2,%d0
	adda.l %d0,%a1
	adda.l %d0,%a2
	clr.l %d3
	clr.l %d4

	.align 2
LOCAL(mpaddmul_loop):
	move.l -(%a2),%d1
	move.l -(%a1),%d6
	mulu.l %d2,%d0:%d1
	add.l %d3,%d1
	addx.l %d4,%d0
	add.l %d6,%d1
	addx.l %d4,%d0
	move.l %d1,(%a1)
	move.l %d0,%d3
	subq.l #1,%d5
	jbne LOCAL(mpaddmul_loop)

	movem.l (%sp)+,%d2-%d6
	rts
C_FUNCTION_END(mpaddmul)
