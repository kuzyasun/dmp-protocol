	.file	"noise_layout_sha256.c"
	.text
	.section	.text$noise_sha256_finalize,"x"
	.def	noise_sha256_finalize;	.scl	3;	.type	32;	.endef
	.seh_proc	noise_sha256_finalize
noise_sha256_finalize:
	.seh_endprologue
	addq	$48, %rcx
	jmp	crypto_hash_sha256_final
	.seh_endproc
	.section	.text$noise_sha256_update,"x"
	.def	noise_sha256_update;	.scl	3;	.type	32;	.endef
	.seh_proc	noise_sha256_update
noise_sha256_update:
	.seh_endprologue
	addq	$48, %rcx
	jmp	crypto_hash_sha256_update
	.seh_endproc
	.section	.text$noise_sha256_reset,"x"
	.def	noise_sha256_reset;	.scl	3;	.type	32;	.endef
	.seh_proc	noise_sha256_reset
noise_sha256_reset:
	.seh_endprologue
	addq	$48, %rcx
	jmp	crypto_hash_sha256_init
	.seh_endproc
	.section	.text$noise_sha256_new,"x"
	.globl	noise_sha256_new
	.def	noise_sha256_new;	.scl	2;	.type	32;	.endef
	.seh_proc	noise_sha256_new
noise_sha256_new:
	subq	$40, %rsp
	.seh_stackalloc	40
	.seh_endprologue
	movl	$152, %ecx
	call	noise_new_object
	testq	%rax, %rax
	je	.L4
	movabsq	$18014535948453891, %rdx
	leaq	noise_sha256_reset(%rip), %rcx
	movq	%rdx, 8(%rax)
	leaq	noise_sha256_update(%rip), %rdx
	movq	%rcx, 16(%rax)
	leaq	noise_sha256_finalize(%rip), %rcx
	movq	%rdx, 24(%rax)
	movq	%rcx, 32(%rax)
.L4:
	addq	$40, %rsp
	ret
	.seh_endproc
	.globl	dmp_layout_align_NoiseSHA256State
	.section	.data$dmp_layout_align_NoiseSHA256State,"w"
	.align 8
dmp_layout_align_NoiseSHA256State:
	.space 8
	.globl	dmp_layout_size_NoiseSHA256State
	.section	.data$dmp_layout_size_NoiseSHA256State,"w"
	.align 32
dmp_layout_size_NoiseSHA256State:
	.space 152
	.ident	"GCC: (GNU) 15.2.0"
	.def	crypto_hash_sha256_final;	.scl	2;	.type	32;	.endef
	.def	crypto_hash_sha256_update;	.scl	2;	.type	32;	.endef
	.def	crypto_hash_sha256_init;	.scl	2;	.type	32;	.endef
	.def	noise_new_object;	.scl	2;	.type	32;	.endef
