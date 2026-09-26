	.file	"noise_layout_chachapoly.c"
	.text
	.section	.text$noise_chachapoly_new,"x"
	.globl	noise_chachapoly_new
	.def	noise_chachapoly_new;	.scl	2;	.type	32;	.endef
	.seh_proc	noise_chachapoly_new
noise_chachapoly_new:
	subq	$40, %rsp
	.seh_stackalloc	40
	.seh_endprologue
	movl	$128, %ecx
	call	noise_new_object
	testq	%rax, %rax
	je	.L1
	leaq	noise_chachapoly_new(%rip), %rdx
	leaq	noise_chachapoly_init_key(%rip), %rcx
	movl	$17153, 8(%rax)
	movq	%rdx, 24(%rax)
	leaq	noise_chachapoly_encrypt(%rip), %rdx
	movq	%rcx, 32(%rax)
	leaq	noise_chachapoly_decrypt(%rip), %rcx
	movw	$4128, 13(%rax)
	movq	%rdx, 40(%rax)
	movq	%rcx, 48(%rax)
.L1:
	addq	$40, %rsp
	ret
	.seh_endproc
	.section	.text$noise_chachapoly_encrypt,"x"
	.def	noise_chachapoly_encrypt;	.scl	3;	.type	32;	.endef
	.seh_proc	noise_chachapoly_encrypt
noise_chachapoly_encrypt:
	pushq	%r12
	.seh_pushreg	%r12
	pushq	%rbp
	.seh_pushreg	%rbp
	pushq	%rdi
	.seh_pushreg	%rdi
	pushq	%rsi
	.seh_pushreg	%rsi
	pushq	%rbx
	.seh_pushreg	%rbx
	subq	$112, %rsp
	.seh_stackalloc	112
	.seh_endprologue
	movq	192(%rsp), %r12
	movq	%rdx, %rdi
	movq	16(%rcx), %rdx
	movq	%r12, 32(%rsp)
	movq	%r8, %rbp
	leaq	48(%rsp), %rsi
	movq	%r9, %r8
	addq	$64, %rcx
	movq	%r9, %rbx
	movq	%rdx, 40(%rsp)
	movq	%rsi, %rdx
	call	crypto_stream_chacha20_ietf_session_block0_xor
	movq	%rsi, 40(%rsp)
	movq	%rbx, %r9
	movq	%rbp, %r8
	movq	%r12, 32(%rsp)
	leaq	(%rbx,%r12), %rcx
	movq	%rdi, %rdx
	call	crypto_onetimeauth_poly1305_aead_mac
	movl	$32, %edx
	movq	%rsi, %rcx
	call	sodium_memzero
	xorl	%eax, %eax
	addq	$112, %rsp
	popq	%rbx
	popq	%rsi
	popq	%rdi
	popq	%rbp
	popq	%r12
	ret
	.seh_endproc
	.section	.text$noise_chachapoly_decrypt,"x"
	.def	noise_chachapoly_decrypt;	.scl	3;	.type	32;	.endef
	.seh_proc	noise_chachapoly_decrypt
noise_chachapoly_decrypt:
	pushq	%r14
	.seh_pushreg	%r14
	pushq	%r13
	.seh_pushreg	%r13
	pushq	%r12
	.seh_pushreg	%r12
	pushq	%rbp
	.seh_pushreg	%rbp
	pushq	%rdi
	.seh_pushreg	%rdi
	pushq	%rsi
	.seh_pushreg	%rsi
	pushq	%rbx
	.seh_pushreg	%rbx
	addq	$-128, %rsp
	.seh_stackalloc	128
	.seh_endprologue
	movq	16(%rcx), %rax
	movq	224(%rsp), %rsi
	movq	%rax, 40(%rsp)
	xorl	%eax, %eax
	leaq	64(%rsp), %rbp
	leaq	64(%rcx), %r14
	movq	%rax, 32(%rsp)
	movq	%r9, %rbx
	movq	%rdx, %r12
	xorl	%r9d, %r9d
	movq	%r8, %r13
	movq	%rbp, %rdx
	xorl	%r8d, %r8d
	movq	%r14, %rcx
	call	crypto_stream_chacha20_ietf_session_block0_xor
	movq	%rbp, 40(%rsp)
	movq	%r13, %r8
	movq	%rbx, %r9
	movq	%rsi, 32(%rsp)
	movq	%r12, %rdx
	leaq	48(%rsp), %rcx
	call	crypto_onetimeauth_poly1305_aead_mac
	movl	$32, %edx
	movq	%rbp, %rcx
	call	sodium_memzero
	leaq	(%rbx,%rsi), %rdx
	movl	$16, %r8d
	leaq	48(%rsp), %rcx
	call	noise_is_equal
	testl	%eax, %eax
	jne	.L9
	movl	$16, %edx
	leaq	48(%rsp), %rcx
	call	sodium_memzero
	movl	$17668, %eax
	jmp	.L8
.L9:
	movq	%rsi, %r9
	movq	%rbx, %r8
	movq	%rbx, %rdx
	movq	%r14, %rcx
	call	crypto_stream_chacha20_ietf_session_xor
	xorl	%eax, %eax
.L8:
	subq	$-128, %rsp
	popq	%rbx
	popq	%rsi
	popq	%rdi
	popq	%rbp
	popq	%r12
	popq	%r13
	popq	%r14
	ret
	.seh_endproc
	.section	.text$noise_chachapoly_init_key,"x"
	.def	noise_chachapoly_init_key;	.scl	3;	.type	32;	.endef
	.seh_proc	noise_chachapoly_init_key
noise_chachapoly_init_key:
	.seh_endprologue
	addq	$64, %rcx
	jmp	crypto_stream_chacha20_ietf_session_init
	.seh_endproc
	.globl	dmp_layout_align_NoiseChaChaPolyState
	.section	.data$dmp_layout_align_NoiseChaChaPolyState,"w"
	.align 8
dmp_layout_align_NoiseChaChaPolyState:
	.space 8
	.globl	dmp_layout_size_NoiseChaChaPolyState
	.section	.data$dmp_layout_size_NoiseChaChaPolyState,"w"
	.align 32
dmp_layout_size_NoiseChaChaPolyState:
	.space 128
	.ident	"GCC: (GNU) 15.2.0"
	.def	noise_new_object;	.scl	2;	.type	32;	.endef
	.def	crypto_stream_chacha20_ietf_session_block0_xor;	.scl	2;	.type	32;	.endef
	.def	crypto_onetimeauth_poly1305_aead_mac;	.scl	2;	.type	32;	.endef
	.def	sodium_memzero;	.scl	2;	.type	32;	.endef
	.def	noise_is_equal;	.scl	2;	.type	32;	.endef
	.def	crypto_stream_chacha20_ietf_session_xor;	.scl	2;	.type	32;	.endef
	.def	crypto_stream_chacha20_ietf_session_init;	.scl	2;	.type	32;	.endef
