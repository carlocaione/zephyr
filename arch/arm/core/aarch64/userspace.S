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
