#
# mp32opt.gas.ia64.s
#
# Assembler optimized multiprecision integer routines for ia64 (Intel Itanium)
#
# Compile target is GNU AS
#
# Copyright (c) 2000 Virtual Unlimited B.V.
#
# Author: Bob Deblier <bob@virtualunlimited.com>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

	.file	"mp32opt.gas.ia64.s"

	.text

	.align	16
	.global	mp32add#
	.proc	mp32add#

mp32add:
#	register use
#	r32 = size, r33 = dst, r34 = src; 3 registers
#	r35 = tmp1, r36 = tmp2, r37 = b0, r38 = ar.pfs; 4 l registers
	alloc r38 = ar.pfs, 3, 4, 0, 0
	mov r37 = b0
	# adjust size by -1
	sub r32 = r32,r0,1
	# clear carry
	mov r8 = r0
	;;
	# load addresses
	shladd r33 = r32,2,r33
	shladd r34 = r32,2,r34
	# load loop count
	mov ar.lc = r32
	;;
.L20:
	ld4 r36 = [r34],-4
	ld4 r35 = [r33]
	;;
	# use predication to add carry
	cmp.eq p1,p2 = r8,r0
	;;
	(p1) add r8 = r35,r36
	(p2) add r8 = r35,r36,1
	;;
	st4 [r33] = r8,-4
	shr.u r8 = r8,32
	br.cloop.sptk .L20
	;;
	mov ar.pfs = r38
	mov b0 = r37
	br.ret.sptk.many b0
	.endp	mp32add#


	.align	16
	.global	mp32sub#
	.proc	mp32sub#

mp32sub:
#	register use
#	r32 = size, r33 = dst, r34 = src; 3 registers
#	r35 = tmp1, r36 = tmp2, r37 = b0, r38 = ar.pfs; 4 l registers
	alloc r38 = ar.pfs, 3, 4, 0, 0
	mov r37 = b0
	# adjust size by -1
	sub r32 = r32,r0,1
	# clear carry
	mov r8 = r0
	;;
	# adjust addresses
	shladd r33 = r32,2,r33
	shladd r34 = r32,2,r34
	# load loop count
	mov ar.lc = r32
	;;
.L30:
	ld4 r36 = [r34],-4
	ld4 r35 = [r33]
	;;
	# use predication to add carry
	cmp.eq p1,p2 = r8,r0
	;;
	(p1) sub r8 = r35,r36
	(p2) sub r8 = r35,r36,1
	;;
	st4 [r33] = r8,-4
	shr.u r8 = r8,32
	br.cloop.sptk .L30
	;;
	# take the negative value of r8
	sub r8 = r0,r8
	mov ar.pfs = r38
	mov b0 = r37
	br.ret.sptk.many b0
	.endp	mp32sub#


	.align	16
	.global	mp32setmul#
	.proc	mp32setmul#

mp32setmul:
#	register use
#	r32 = size, r33 = result, r34 = data, r35 = mul; 4 i registers
#	r36 = b0, r37 = ar.pfs; 2 l registers
	alloc r37 = ar.pfs, 4, 2, 0, 0
	mov r36 = b0
	# adjust size by -1
	sub r32 = r32,r0,1
	# clear carry
	mov r8 = r0
	;;
	# adjust addresses
	shladd r33 = r32,2,r33
	shladd r34 = r32,2,r34
	# load loop count
	mov ar.lc = r32
	# load mul
	setf.sig f96 = r35
	;;
.L40:
	ld4 r35 = [r34],-4
	;;
	setf.sig f98 = r8
	setf.sig f97 = r35
	;;
#	multiplication can only be done in f registers, but we do have a multiply-add
	xma.l f98 = f96, f97, f98
	;;
	getf.sig r8 = f98
	;;
	st4 [r33] = r8,-4
	shr.u r8 = r8,32
	br.cloop.sptk .L40
	;;
	mov ar.pfs = r37
	mov b0 = r36
	br.ret.sptk.many b0
	.endp	mp32setmul#


	.align	16
	.global	mp32addmul#
	.proc	mp32addmul#

mp32addmul:
#	register use
#	r32 = size, r33 = result, r34 = data, r35 = mul; 4 i registers
#	r36 tmp, r37 = b0, r38 = ar.pfs; 2 l registers
	alloc r38 = ar.pfs, 4, 3, 0, 0
	mov r37 = b0
	# adjust size by -1
	sub r32 = r32,r0,1
	# clear carry
	mov r8 = r0
	;;
	# adjust addresses
	shladd r33 = r32,2,r33
	shladd r34 = r32,2,r34
	# load loop count
	mov ar.lc = r32
	# load mul
	setf.sig f96 = r35
	;;
.L50:
	ld4 r35 = [r34],-4
	ld4 r36 = [r33]
	;;
	setf.sig f98 = r8
	setf.sig f97 = r35
	;;
#	multiplication can only be done in f registers, but we do have a multiply-add
	xma.l f98 = f96, f97, f98
	;;
	getf.sig r8 = f98
	;;
	add r8 = r8,r36
	;;
	st4 [r33] = r8,-4
	shr.u r8 = r8,32
	br.cloop.sptk .L50
	;;
	mov ar.pfs = r38
	mov b0 = r37
	br.ret.sptk.many b0
	.endp	mp32addmul#


	.if 0
	.align	16
	.global	mp32addsqrtrc#
	.proc	mp32addsqrtrc#

mp32addsqrtrc:
	.endp	mp32addsqrtrc#
	.endif


#	ia64 has enough registers to do the full mp32mul and mp32sqr algorithms in asm
#	this should save a lot of procedure calls

	.if 0
	.align	16
	.global	mp32mul#
	.proc	mp32mul#
mp32mul:

	.endp	mp32mul#
	.endif


	.if 0
	.align	16
	.global	mp32sqr#
	.proc	mp32sqr#
mp32sqr:

	.endp	mp32sqr#
	.endif
