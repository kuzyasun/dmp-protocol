	.file	"noise_layout_core.c"
	.text
	.globl	dmp_layout_align_dmp_noise_test_arena
	.section	.data$dmp_layout_align_dmp_noise_test_arena,"w"
	.align 8
dmp_layout_align_dmp_noise_test_arena:
	.space 8
	.globl	dmp_layout_size_dmp_noise_test_arena
	.section	.data$dmp_layout_size_dmp_noise_test_arena,"w"
	.align 32
dmp_layout_size_dmp_noise_test_arena:
	.space 2112
	.globl	dmp_layout_align_void_pointer
	.section	.data$dmp_layout_align_void_pointer,"w"
	.align 8
dmp_layout_align_void_pointer:
	.space 8
	.globl	dmp_layout_size_void_pointer
	.section	.data$dmp_layout_size_void_pointer,"w"
	.align 8
dmp_layout_size_void_pointer:
	.space 8
	.globl	dmp_layout_align_max_align_t
	.section	.data$dmp_layout_align_max_align_t,"w"
	.align 16
dmp_layout_align_max_align_t:
	.space 16
	.globl	dmp_layout_size_max_align_t
	.section	.data$dmp_layout_size_max_align_t,"w"
	.align 32
dmp_layout_size_max_align_t:
	.space 32
	.globl	dmp_layout_align_NoiseSymmetricState
	.section	.data$dmp_layout_align_NoiseSymmetricState,"w"
	.align 8
dmp_layout_align_NoiseSymmetricState:
	.space 8
	.globl	dmp_layout_size_NoiseSymmetricState
	.section	.data$dmp_layout_size_NoiseSymmetricState,"w"
	.align 32
dmp_layout_size_NoiseSymmetricState:
	.space 256
	.globl	dmp_layout_align_NoiseHandshakeState
	.section	.data$dmp_layout_align_NoiseHandshakeState,"w"
	.align 8
dmp_layout_align_NoiseHandshakeState:
	.space 8
	.globl	dmp_layout_size_NoiseHandshakeState
	.section	.data$dmp_layout_size_NoiseHandshakeState,"w"
	.align 32
dmp_layout_size_NoiseHandshakeState:
	.space 240
	.ident	"GCC: (GNU) 15.2.0"
