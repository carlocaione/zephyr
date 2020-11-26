/*
 * Copyright (c) 2020 Carlo Caione <ccaione@baylibre.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <toolchain.h>
#include <linker/sections.h>
#include <offsets_short.h>
#include <arch/cpu.h>
#include <syscall.h>
#include "macro_priv.inc"

_ASM_FILE_PROLOGUE

GDATA(_kernel)

GTEXT(z_arm64_user_string_nlen_fault_start)
GTEXT(z_arm64_user_string_nlen_fault_end)
GTEXT(z_arm64_user_string_nlen_fixup)

/*
 * size_t arch_user_string_nlen(const char *s, size_t maxsize, int *err_arg)
 */

GTEXT(arch_user_string_nlen)
SECTION_FUNC(TEXT, arch_user_string_nlen)
	sub	sp, sp, #16
	mov	x3, #-1
	str	x3, [sp, #0]

	mov	x3, #0

strlen_loop:
z_arm64_user_string_nlen_fault_start:
	ldrb	w5, [x0, x3]
z_arm64_user_string_nlen_fault_end:
	cbz	x5, strlen_done

	cmp	x3, x1
	beq	strlen_done

	adds	x3, x3, #1
	b	strlen_loop

strlen_done:
	mov	x0, x3

	mov	w1, #0
	str	w1, [sp, #0]

z_arm64_user_string_nlen_fixup:
	ldr	w1, [sp, #0]
	add	sp, sp, #16
	str	w1, [x2]

	ret

GTEXT(z_arm64_do_syscall)
SECTION_FUNC(TEXT, z_arm64_do_syscall)
	/* Recover the syscall parameters from the ESF */
	ldp	x0, x1, [sp, ___esf_t_x0_x1_OFFSET]
	ldp	x2, x3, [sp, ___esf_t_x2_x3_OFFSET]
	ldp	x4, x5, [sp, ___esf_t_x4_x5_OFFSET]

	/* Recover the syscall ID */
	ldp	x8, xzr, [sp, ___esf_t_x8_x9_OFFSET]

	/* Check whether the ID is valid */
	ldr	x9, =K_SYSCALL_LIMIT
	cmp	x8, x9
	blo	valid_syscall_id
	ldr	x8, =K_SYSCALL_BAD

valid_syscall_id:
	ldr	x9, =_k_syscall_table
	lsl	x8, x8, #3
	add	x9, x9, x8
	ldr	x9, [x9]

	/* Recover the privileged stack */
	ldr	x10, =_kernel
	ldr	x10, [x10, #_kernel_offset_to_current]
	ldr	x11, =_thread_offset_to_priv_stack_start
	ldr     x10, [x10, x11]
	ldr	x11, =CONFIG_PRIVILEGED_STACK_SIZE
	add	x10, x10, x11

	/* Save the original SP on the privileged stack */
	mov	x11, sp
	mov	sp, x10
	stp	x11, xzr, [sp, #-16]!

	/* Jump into the syscall */
	msr	daifclr, #(DAIFSET_IRQ)
	blr	x9
	msr	daifset, #(DAIFSET_IRQ)

	/* Restore the original SP containing the ESF */
	ldp	x11, xzr, [sp], #16
	mov	sp, x11

	/* Save the return value into the ESF */
	str	x0, [sp, ___esf_t_x0_x1_OFFSET]

	/* Return faking a return from exception */
	z_arm64_exit_exc x0, x1

GTEXT(z_arm64_prepare_syscall)
SECTION_FUNC(TEXT, z_arm64_prepare_syscall)
	/* Set the landing address */
	ldr     x0, =z_arm64_do_syscall
	msr     elr_el1, x0

	/*
	 * We are overwriting the current SPSR so that we land in the syscall
	 * code in EL1 (kernel mode). The original SPSR is still saved in the
	 * ESF and it will be restored when returning from the syscall code.
	 */
	mov	x0, xzr
	orr	x0, x0, #DAIF_IRQ
	orr	x0, x0, #SPSR_MODE_EL1T
	msr	spsr_el1, x0

	eret

/*
 * Routine to jump into userspace
 *
 * We leverage z_arm64_exit_exc() to pop out the entry function and parameters
 * from ESF and fake a return from exception to move from EL1 to EL0. The fake
 * ESF is built in arch_user_mode_enter() before jumping here
 */

GTEXT(z_arm64_userspace_enter)
SECTION_FUNC(TEXT, z_arm64_userspace_enter)
	mov sp, x0
	z_arm64_exit_exc x0, x1


/*
 * Invalidate all TLB entries
 */

GTEXT(z_arm64_invalidate_tlb_all)
SECTION_FUNC(TEXT, z_arm64_invalidate_tlb_all)
	tlbi	vmalle1
	dsb	sy
	isb
	ret

/*
 * Switch TTBR0
 */

GTEXT(z_arm64_set_ttbr0)
SECTION_FUNC(TEXT, z_arm64_set_ttbr0)
	/* Disable all the caches */
	mrs	x2, sctlr_el1
	mov_imm	x1, (SCTLR_M | SCTLR_C | SCTLR_I)
	and	x1, x2, x1
	msr	sctlr_el1, x1
	isb

	/* Invalidate the TLBs */
	mov	x3, x30
	bl	z_arm64_invalidate_tlb_all

	/* Switch the TTBR0 */
	msr	ttbr0_el1, x0
	isb

	/* Restore the saved SCTLR_EL1 */
	msr	sctlr_el1, x2
	isb

	ret	x3
