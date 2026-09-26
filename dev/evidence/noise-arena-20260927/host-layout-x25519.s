	.file	"noise_layout_x25519.c"
	.text
	.section	.text$noise_curve25519_validate_public_key,"x"
	.def	noise_curve25519_validate_public_key;	.scl	3;	.type	32;	.endef
	.seh_proc	noise_curve25519_validate_public_key
noise_curve25519_validate_public_key:
	.seh_endprologue
	xorl	%eax, %eax
	ret
	.seh_endproc
	.section	.text$noise_curve25519_calculate,"x"
	.def	noise_curve25519_calculate;	.scl	3;	.type	32;	.endef
	.seh_proc	noise_curve25519_calculate
noise_curve25519_calculate:
	subq	$40, %rsp
	.seh_stackalloc	40
	.seh_endprologue
	movq	%rcx, %r9
	movq	%rdx, %rax
	movq	%r8, %rcx
	movq	24(%r9), %rdx
	movq	32(%rax), %r8
	call	crypto_scalarmult_curve25519
	testl	%eax, %eax
	je	.L2
	movl	$17675, %eax
.L2:
	addq	$40, %rsp
	ret
	.seh_endproc
	.section	.text$noise_curve25519_copy,"x"
	.def	noise_curve25519_copy;	.scl	3;	.type	32;	.endef
	.seh_proc	noise_curve25519_copy
noise_curve25519_copy:
	pushq	%rsi
	.seh_pushreg	%rsi
	pushq	%rbx
	.seh_pushreg	%rbx
	subq	$40, %rsp
	.seh_stackalloc	40
	.seh_endprologue
	movl	$32, %r8d
	movq	%rcx, %rbx
	movq	%rdx, %rsi
	leaq	104(%rcx), %rcx
	leaq	104(%rdx), %rdx
	call	memcpy
	leaq	136(%rsi), %rdx
	leaq	136(%rbx), %rcx
	movl	$32, %r8d
	call	memcpy
	xorl	%eax, %eax
	addq	$40, %rsp
	popq	%rbx
	popq	%rsi
	ret
	.seh_endproc
	.section	.text$noise_curve25519_set_keypair_private,"x"
	.def	noise_curve25519_set_keypair_private;	.scl	3;	.type	32;	.endef
	.seh_proc	noise_curve25519_set_keypair_private
noise_curve25519_set_keypair_private:
	pushq	%rsi
	.seh_pushreg	%rsi
	pushq	%rbx
	.seh_pushreg	%rbx
	subq	$40, %rsp
	.seh_stackalloc	40
	.seh_endprologue
	movl	$32, %r8d
	movq	%rcx, %rbx
	leaq	104(%rcx), %rcx
	call	memcpy
	leaq	136(%rbx), %rcx
	leaq	104(%rbx), %rdx
	call	crypto_scalarmult_curve25519_base
	xorl	%eax, %eax
	addq	$40, %rsp
	popq	%rbx
	popq	%rsi
	ret
	.seh_endproc
	.section	.text$noise_curve25519_set_keypair,"x"
	.def	noise_curve25519_set_keypair;	.scl	3;	.type	32;	.endef
	.seh_proc	noise_curve25519_set_keypair
noise_curve25519_set_keypair:
	pushq	%rbp
	.seh_pushreg	%rbp
	pushq	%rdi
	.seh_pushreg	%rdi
	pushq	%rsi
	.seh_pushreg	%rsi
	pushq	%rbx
	.seh_pushreg	%rbx
	subq	$72, %rsp
	.seh_stackalloc	72
	.seh_endprologue
	movq	%r8, %rdi
	movq	%rcx, %rbx
	leaq	32(%rsp), %rcx
	movq	%rdx, %rbp
	call	crypto_scalarmult_curve25519_base
	movq	%rdi, %rdx
	leaq	32(%rsp), %rcx
	movl	$32, %r8d
	call	noise_is_equal
	leaq	104(%rbx), %rcx
	movq	%rbp, %rdx
	movl	$32, %r8d
	movl	%eax, %esi
	call	memcpy
	leaq	136(%rbx), %rcx
	movl	$32, %r8d
	movq	%rdi, %rdx
	call	memcpy
	leal	-1(%rsi), %eax
	andl	$17679, %eax
	addq	$72, %rsp
	popq	%rbx
	popq	%rsi
	popq	%rdi
	popq	%rbp
	ret
	.seh_endproc
	.section	.text$noise_curve25519_generate_keypair,"x"
	.def	noise_curve25519_generate_keypair;	.scl	3;	.type	32;	.endef
	.seh_proc	noise_curve25519_generate_keypair
noise_curve25519_generate_keypair:
	pushq	%rsi
	.seh_pushreg	%rsi
	pushq	%rbx
	.seh_pushreg	%rbx
	subq	$40, %rsp
	.seh_stackalloc	40
	.seh_endprologue
	movl	$32, %edx
	movq	%rcx, %rbx
	leaq	104(%rcx), %rcx
	call	noise_rand_bytes_checked
	testl	%eax, %eax
	jne	.L9
	movb	135(%rbx), %al
	andb	$-8, 104(%rbx)
	leaq	136(%rbx), %rcx
	leaq	104(%rbx), %rdx
	andl	$63, %eax
	orl	$64, %eax
	movb	%al, 135(%rbx)
	call	crypto_scalarmult_curve25519_base
	testl	%eax, %eax
	je	.L9
	movl	$17678, %eax
.L9:
	addq	$40, %rsp
	popq	%rbx
	popq	%rsi
	ret
	.seh_endproc
	.section	.text$noise_curve25519_new,"x"
	.globl	noise_curve25519_new
	.def	noise_curve25519_new;	.scl	2;	.type	32;	.endef
	.seh_proc	noise_curve25519_new
noise_curve25519_new:
	subq	$40, %rsp
	.seh_stackalloc	40
	.seh_endprologue
	movl	$168, %ecx
	call	noise_new_object
	testq	%rax, %rax
	je	.L12
	leaq	104(%rax), %rdx
	leaq	noise_curve25519_generate_keypair(%rip), %rcx
	orb	$2, 13(%rax)
	movq	%rdx, 24(%rax)
	leaq	136(%rax), %rdx
	movq	%rcx, 40(%rax)
	leaq	noise_curve25519_set_keypair(%rip), %rcx
	movq	%rdx, 32(%rax)
	leaq	noise_curve25519_set_keypair_private(%rip), %rdx
	movq	%rcx, 48(%rax)
	leaq	noise_curve25519_validate_public_key(%rip), %rcx
	movq	%rdx, 56(%rax)
	leaq	noise_curve25519_copy(%rip), %rdx
	movq	%rcx, 64(%rax)
	leaq	noise_curve25519_calculate(%rip), %rcx
	movw	$17409, 8(%rax)
	movw	$32, 14(%rax)
	movl	$2097184, 16(%rax)
	movq	%rdx, 72(%rax)
	movq	%rcx, 80(%rax)
.L12:
	addq	$40, %rsp
	ret
	.seh_endproc
	.globl	dmp_layout_align_NoiseCurve25519State
	.section	.data$dmp_layout_align_NoiseCurve25519State,"w"
	.align 8
dmp_layout_align_NoiseCurve25519State:
	.space 8
	.globl	dmp_layout_size_NoiseCurve25519State
	.section	.data$dmp_layout_size_NoiseCurve25519State,"w"
	.align 32
dmp_layout_size_NoiseCurve25519State:
	.space 168
	.ident	"GCC: (GNU) 15.2.0"
	.def	crypto_scalarmult_curve25519;	.scl	2;	.type	32;	.endef
	.def	memcpy;	.scl	2;	.type	32;	.endef
	.def	crypto_scalarmult_curve25519_base;	.scl	2;	.type	32;	.endef
	.def	noise_is_equal;	.scl	2;	.type	32;	.endef
	.def	noise_rand_bytes_checked;	.scl	2;	.type	32;	.endef
	.def	noise_new_object;	.scl	2;	.type	32;	.endef
