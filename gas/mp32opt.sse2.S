/*
 * Copyright (c) 2003 Bob Deblier
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

/*!\file mp32opt.sse2.S
 * \brief Multi-precision integer, Intel SSE2 assembler-optimized routines.
 * \author Bob Deblier <bob.deblier@pandora.be>
 * \ingroup MP32_m
 */

#include "beecrypt.gas.h"

	.file "mp32opt.sse2.S"

	.text

C_FUNCTION_BEGIN(mp32setmul)
LABEL(mp32setmul)
	pushl %edi
	pushl %esi

	movl 12(%esp),%ecx
	movl 16(%esp),%edi
	movl 20(%esp),%esi
	movd 24(%esp),%mm1

	decl %ecx
	pxor %mm0,%mm0

	.align 4
LOCAL(mp32setmul_loop):
	movd (%esi,%ecx,4),%mm2
	pmuludq %mm1,%mm2
	paddq %mm2,%mm0
	movd %mm0,(%edi,%ecx,4)
	decl %ecx
	psrlq $32,%mm0
	jns LOCAL(mp32setmul_loop)

	movd %mm0,%eax
	emms

	popl %esi
	popl %edi
	ret
C_FUNCTION_END(mp32setmul, LOCAL(mp32setmul_size))


C_FUNCTION_BEGIN(mp32addmul)
LABEL(mp32addmul)
	pushl %edi
	pushl %esi

	movl 12(%esp),%ecx
	movl 16(%esp),%edi
	movl 20(%esp),%esi
	movd 24(%esp),%mm1

	decl %ecx
	pxor %mm0,%mm0

	.align 4
LOCAL(mp32addmul_loop):
	movd (%esi,%ecx,4),%mm2
	movd (%edi,%ecx,4),%mm3
	pmuludq %mm1,%mm2
	paddq %mm2,%mm3
	paddq %mm3,%mm0
	movd %mm0,(%edi,%ecx,4)
	decl %ecx
	psrlq $32,%mm0
	jns LOCAL(mp32addmul_loop)

	movd %mm0,%eax
	emms

	popl %esi
	popl %edi
	ret
C_FUNCTION_END(mp32addmul, LOCAL(mp32addmul_size))


C_FUNCTION_BEGIN(mp32addsqrtrc)
LABEL(mp32addsqrtrc)
	pushl %edi
	pushl %esi

	movl 12(%esp),%ecx
	movl 16(%esp),%edi
	movl 20(%esp),%esi

	pxor %mm0,%mm0
	decl %ecx

	.align 4
LOCAL(mp32addsqrtrc_loop):
@mp32addsqrtrc_loop:
	movd (%esi,%ecx,4),%mm2
	pmuludq %mm2,%mm2
	movd 4(%edi,%ecx,8),%mm3
	paddq %mm2,%mm3
	movd 0(%edi,%ecx,8),%mm4
	paddq %mm3,%mm0
	movd %mm0,4(%edi,%ecx,8)
	psrlq $32,%mm0
	paddq %mm4,%mm0
	movd %mm0,0(%edi,%ecx,8)
	psrlq $32,%mm0
	decl %ecx
	jns LOCAL(mp32addsqrtrc_loop)

	movd %mm0,%eax
	emms

	popl %esi
	popl %edi
	ret
C_FUNCTION_END(mp32addsqrtrc, LOCAL(mp32addsqrtrc_size))
