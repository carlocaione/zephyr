/*
 * Copyright 2019 Broadcom
 * The term "Broadcom" refers to Broadcom Inc. and/or its subsidiaries.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <device.h>
#include <init.h>
#include <kernel.h>
#include <arch/arm/aarch64/cpu.h>
#include <arch/arm/aarch64/arm_mmu.h>
#include <linker/linker-defs.h>
#include <sys/util.h>
#include <sys/slist.h>
#include <kernel_arch_func.h>

#include "arm_mmu.h"

#ifdef CONFIG_USERSPACE
static sys_slist_t domain_list;
#endif

/* kernel ptables created at MMU init time */
static uint64_t kernel_xlat_tables[PTABLES_SIZE]
		__aligned(Ln_XLAT_NUM_ENTRIES * sizeof(uint64_t));

static struct arm_mmu_ptables kernel_ptables = {
	.xlat_tables = kernel_xlat_tables,
};

/* Translation table control register settings */
static uint64_t get_tcr(int el)
{
	uint64_t tcr;
	uint64_t va_bits = CONFIG_ARM64_VA_BITS;
	uint64_t tcr_ps_bits;

	tcr_ps_bits = TCR_PS_BITS;

	if (el == 1) {
		tcr = (tcr_ps_bits << TCR_EL1_IPS_SHIFT);
		/*
		 * TCR_EL1.EPD1: Disable translation table walk for addresses
		 * that are translated using TTBR1_EL1.
		 */
		tcr |= TCR_EPD1_DISABLE;
	} else
		tcr = (tcr_ps_bits << TCR_EL3_PS_SHIFT);

	tcr |= TCR_T0SZ(va_bits);
	/*
	 * Translation table walk is cacheable, inner/outer WBWA and
	 * inner shareable
	 */
	tcr |= TCR_TG0_4K | TCR_SHARED_INNER | TCR_ORGN_WBWA | TCR_IRGN_WBWA;

	return tcr;
}

static int pte_desc_type(uint64_t *pte)
{
	return *pte & PTE_DESC_TYPE_MASK;
}

static bool pte_is_page_or_block(uint64_t *pte, unsigned int level)
{
	return ((pte_desc_type(pte) == PTE_BLOCK_DESC) ||
		(pte_desc_type(pte) == PTE_PAGE_DESC &&
		   level == (XLAT_LEVEL_MAX - 1)));
}

static uint64_t *calculate_pte_index(struct arm_mmu_ptables *ptables,
				     uintptr_t addr, int level)
{
	int base_level = BASE_XLAT_LEVEL;
	uint64_t *pte;
	uint64_t idx;
	unsigned int i;

	/* Walk through all translation tables to find pte index */
	pte = (uint64_t *)ptables->xlat_tables;
	for (i = base_level; i < XLAT_LEVEL_MAX; i++) {
		idx = XLAT_TABLE_VA_IDX(addr, i);
		pte += idx;

		if (level == -1 && pte_is_page_or_block(pte, i))
			return pte;

		/* Found pte index */
		if (i == level)
			return pte;

		/* if PTE is not table desc, can't traverse */
		if (pte_desc_type(pte) != PTE_TABLE_DESC)
			return NULL;
		/* Move to the next translation table level */
		pte = (uint64_t *)(*pte & 0x0000fffffffff000ULL);
	}

	return NULL;
}

static void set_pte_table_desc(uint64_t *pte, uint64_t *table, unsigned int level)
{
#if DUMP_PTE
	MMU_DEBUG("%s", XLAT_TABLE_LEVEL_SPACE(level));
	MMU_DEBUG("%p: [Table] %p\n", pte, table);
#endif
	/* Point pte to new table */
	*pte = PTE_TABLE_DESC | (uint64_t)table;
}

static uint64_t get_region_desc(uint32_t attrs)
{
	unsigned int mem_type;
	uint64_t desc = 0;

	/* NS bit for security memory access from secure state */
	desc |= (attrs & MT_NS) ? PTE_BLOCK_DESC_NS : 0;

	/*
	 * AP bits for EL0 / ELh Data access permission
	 *
	 *   AP[2:1]   ELh  EL0
	 * +--------------------+
	 *     00      RW   NA
	 *     01      RW   RW
	 *     10      RO   NA
	 *     11      RO   RO
	 */

	/* AP bits for Data access permission */
	desc |= (attrs & MT_RW) ? PTE_BLOCK_DESC_AP_RW : PTE_BLOCK_DESC_AP_RO;

	/* Mirror permissions to EL0 */
	desc |= (attrs & MT_RW_AP_ELx) ?
		 PTE_BLOCK_DESC_AP_ELx : PTE_BLOCK_DESC_AP_EL_HIGHER;

	/* the access flag */
	desc |= PTE_BLOCK_DESC_AF;

	/* memory attribute index field */
	mem_type = MT_TYPE(attrs);
	desc |= PTE_BLOCK_DESC_MEMTYPE(mem_type);

	switch (mem_type) {
	case MT_DEVICE_nGnRnE:
	case MT_DEVICE_nGnRE:
	case MT_DEVICE_GRE:
		/* Access to Device memory and non-cacheable memory are coherent
		 * for all observers in the system and are treated as
		 * Outer shareable, so, for these 2 types of memory,
		 * it is not strictly needed to set shareability field
		 */
		desc |= PTE_BLOCK_DESC_OUTER_SHARE;
		/* Map device memory as execute-never */
		desc |= PTE_BLOCK_DESC_PXN;
		desc |= PTE_BLOCK_DESC_UXN;
		break;
	case MT_NORMAL_NC:
	case MT_NORMAL:
		/* Make Normal RW memory as execute never */
		if ((attrs & MT_RW) || (attrs & MT_P_EXECUTE_NEVER))
			desc |= PTE_BLOCK_DESC_PXN;

		if (((attrs & MT_RW) && (attrs & MT_RW_AP_ELx)) ||
		     (attrs & MT_U_EXECUTE_NEVER))
			desc |= PTE_BLOCK_DESC_UXN;

		if (mem_type == MT_NORMAL)
			desc |= PTE_BLOCK_DESC_INNER_SHARE;
		else
			desc |= PTE_BLOCK_DESC_OUTER_SHARE;
	}

	return desc;
}

static uint64_t get_region_desc_from_pte(uint64_t *pte)
{
	return ((*pte) & DESC_ATTRS_MASK);
}

static void set_pte_block_desc(uint64_t *pte, uint64_t addr_pa,
			       uint64_t desc, unsigned int level)
{
	desc |= addr_pa;
	desc |= (level == 3) ? PTE_PAGE_DESC : PTE_BLOCK_DESC;

#if DUMP_PTE
	uint8_t mem_type = (desc >> 2) & MT_TYPE_MASK;

	MMU_DEBUG("%s", XLAT_TABLE_LEVEL_SPACE(level));
	MMU_DEBUG("%p: ", pte);
	MMU_DEBUG((mem_type == MT_NORMAL) ? "MEM" :
		  ((mem_type == MT_NORMAL_NC) ? "NC" : "DEV"));
	MMU_DEBUG((desc & PTE_BLOCK_DESC_AP_RO) ? "-RO" : "-RW");
	MMU_DEBUG((desc & PTE_BLOCK_DESC_NS) ? "-NS" : "-S");
	MMU_DEBUG((desc & PTE_BLOCK_DESC_AP_ELx) ? "-ELx" : "-ELh");
	MMU_DEBUG((desc & PTE_BLOCK_DESC_PXN) ? "-PXN" : "-PX");
	MMU_DEBUG((desc & PTE_BLOCK_DESC_UXN) ? "-UXN" : "-UX");
	MMU_DEBUG("\n");
#endif

	*pte = desc;
}

/* Returns a new reallocated table */
static uint64_t *new_prealloc_table(struct arm_mmu_ptables *ptables)
{
	ptables->next_table++;

	__ASSERT(ptables->next_table < CONFIG_MAX_XLAT_TABLES,
		"Enough xlat tables not allocated");

	return (uint64_t *)(&ptables->xlat_tables[ptables->next_table *
			    Ln_XLAT_NUM_ENTRIES]);
}

/* Splits a block into table with entries spanning the old block */
static void split_pte_block_desc(struct arm_mmu_ptables *ptables, uint64_t *pte,
				 uint64_t desc, unsigned int level)
{
	uint64_t old_block_desc = *pte;
	uint64_t *new_table;
	unsigned int i = 0;
	/* get address size shift bits for next level */
	unsigned int levelshift = LEVEL_TO_VA_SIZE_SHIFT(level + 1);

	MMU_DEBUG("Splitting existing PTE %p(L%d)\n", pte, level);

	new_table = new_prealloc_table(ptables);

	for (i = 0; i < Ln_XLAT_NUM_ENTRIES; i++) {
		new_table[i] = old_block_desc | (i << levelshift);

		if ((level + 1) == 3)
			new_table[i] |= PTE_PAGE_DESC;
	}

	/* Overwrite existing PTE set the new table into effect */
	set_pte_table_desc(pte, new_table, level);
}

static void add_map_with_desc(struct arm_mmu_ptables *ptables, const char *name,
			      uintptr_t phys, uintptr_t virt, size_t size,
			      uint64_t desc)
{
	uint64_t *pte;
	uint64_t level_size;
	uint64_t *new_table;
	unsigned int level = BASE_XLAT_LEVEL;

	MMU_DEBUG("mmap [%s]: virt %lx phys %lx size %lx\n",
		   name, virt, phys, size);

	/* check minimum alignment requirement for given mmap region */
	__ASSERT(((virt & (CONFIG_MMU_PAGE_SIZE - 1)) == 0) &&
		 ((size & (CONFIG_MMU_PAGE_SIZE - 1)) == 0),
		 "address/size are not page aligned\n");

	while (size) {
		__ASSERT(level < XLAT_LEVEL_MAX,
			 "max translation table level exceeded\n");

		/* Locate PTE for given virtual address and page table level */
		pte = calculate_pte_index(ptables, virt, level);
		__ASSERT(pte != NULL, "pte not found\n");

		level_size = 1ULL << LEVEL_TO_VA_SIZE_SHIFT(level);

		if (size >= level_size && !(virt & (level_size - 1))) {
			/* Given range fits into level size,
			 * create block/page descriptor
			 */
			set_pte_block_desc(pte, phys, desc, level);
			virt += level_size;
			phys += level_size;
			size -= level_size;
			/* Range is mapped, start again for next range */
			level = BASE_XLAT_LEVEL;
		} else if (pte_desc_type(pte) == PTE_INVALID_DESC) {
			/* Range doesn't fit, create subtable */
			new_table = new_prealloc_table(ptables);
			set_pte_table_desc(pte, new_table, level);
			level++;
		} else if (pte_desc_type(pte) == PTE_BLOCK_DESC) {
			/* Check if the block is already mapped with the correct attrs */
			if (desc == get_region_desc_from_pte(pte))
				return;

			/* We need to split a new table */
			split_pte_block_desc(ptables, pte, desc, level);
			level++;
		} else if (pte_desc_type(pte) == PTE_TABLE_DESC)
			level++;
	}
}

static void add_map(struct arm_mmu_ptables *ptables, const char *name,
		    uintptr_t phys, uintptr_t virt, size_t size, uint32_t attrs)
{
	add_map_with_desc(ptables, name, phys, virt, size,
			  get_region_desc(attrs));
}

/* zephyr execution regions with appropriate attributes */
static const struct arm_mmu_region mmu_zephyr_regions[] = {

	/* Mark the whole SRAM as read-write */
	MMU_REGION_FLAT_ENTRY("SRAM",
			      (uintptr_t)CONFIG_SRAM_BASE_ADDRESS,
			      (uintptr_t)KB(CONFIG_SRAM_SIZE),
			      MT_NORMAL | MT_P_RW_U_NA | MT_DEFAULT_SECURE_STATE),

	/* Mark rest of the zephyr execution regions (data, bss, noinit, etc.)
	 * cacheable, read-write
	 * Note: read-write region is marked execute-ever internally
	 */
	MMU_REGION_FLAT_ENTRY("zephyr_data",
			      (uintptr_t)__kernel_ram_start,
			      (uintptr_t)__kernel_ram_size,
			      MT_NORMAL | MT_P_RW_U_NA | MT_DEFAULT_SECURE_STATE),

	/* Mark text segment cacheable,read only and executable */
	MMU_REGION_FLAT_ENTRY("zephyr_code",
			      (uintptr_t)_image_text_start,
			      (uintptr_t)_image_text_size,
			      MT_NORMAL | MT_P_RX_U_NA | MT_DEFAULT_SECURE_STATE),

	/* Mark rodata segment cacheable, read only and execute-never */
	MMU_REGION_FLAT_ENTRY("zephyr_rodata",
			      (uintptr_t)_image_rodata_start,
			      (uintptr_t)_image_rodata_size,
			      MT_NORMAL | MT_P_RO_U_NA | MT_DEFAULT_SECURE_STATE),
};

static inline void add_arm_mmu_region(struct arm_mmu_ptables *ptables,
				      const struct arm_mmu_region *region)
{
	add_map(ptables, region->name, region->base_pa, region->base_va,
		region->size, region->attrs);
}

static void setup_page_tables(struct arm_mmu_ptables *ptables)
{
	unsigned int index;
	const struct arm_mmu_region *region;
	uintptr_t max_va = 0, max_pa = 0;

	MMU_DEBUG("xlat tables:\n");
	for (index = 0; index < CONFIG_MAX_XLAT_TABLES; index++)
		MMU_DEBUG("%d: %p\n", index, (uint64_t *)(ptables->xlat_tables +
					(index * Ln_XLAT_NUM_ENTRIES)));

	for (index = 0; index < mmu_config.num_regions; index++) {
		region = &mmu_config.mmu_regions[index];
		max_va = MAX(max_va, region->base_va + region->size);
		max_pa = MAX(max_pa, region->base_pa + region->size);
	}

	__ASSERT(max_va <= (1ULL << CONFIG_ARM64_VA_BITS),
		 "Maximum VA not supported\n");
	__ASSERT(max_pa <= (1ULL << CONFIG_ARM64_PA_BITS),
		 "Maximum PA not supported\n");

	/* create translation tables for user provided platform regions */
	for (index = 0; index < mmu_config.num_regions; index++) {
		region = &mmu_config.mmu_regions[index];
		if (region->size || region->attrs)
			add_arm_mmu_region(ptables, region);
	}

	/* setup translation table for zephyr execution regions */
	for (index = 0; index < ARRAY_SIZE(mmu_zephyr_regions); index++) {
		region = &mmu_zephyr_regions[index];
		if (region->size || region->attrs)
			add_arm_mmu_region(ptables, region);
	}
}

static void enable_mmu_el1(struct arm_mmu_ptables *ptables, unsigned int flags)
{
	ARG_UNUSED(flags);
	uint64_t val;

	/* Set MAIR, TCR and TBBR registers */
	__asm__ volatile("msr mair_el1, %0"
			:
			: "r" (MEMORY_ATTRIBUTES)
			: "memory", "cc");
	__asm__ volatile("msr tcr_el1, %0"
			:
			: "r" (get_tcr(1))
			: "memory", "cc");
	__asm__ volatile("msr ttbr0_el1, %0"
			:
			: "r" ((uint64_t)ptables->xlat_tables)
			: "memory", "cc");

	/* Ensure these changes are seen before MMU is enabled */
	__ISB();

	/* Enable the MMU and data cache */
	__asm__ volatile("mrs %0, sctlr_el1" : "=r" (val));
	__asm__ volatile("msr sctlr_el1, %0"
			:
			: "r" (val | SCTLR_M | SCTLR_C)
			: "memory", "cc");

	/* Ensure the MMU enable takes effect immediately */
	__ISB();

	MMU_DEBUG("MMU enabled with dcache\n");
}

/* ARM MMU Driver Initial Setup */

/*
 * @brief MMU default configuration
 *
 * This function provides the default configuration mechanism for the Memory
 * Management Unit (MMU).
 */
static int arm_mmu_init(const struct device *arg)
{
	uint64_t val;
	unsigned int flags = 0;

	/* Current MMU code supports only EL1 */
	__asm__ volatile("mrs %0, CurrentEL" : "=r" (val));

	__ASSERT(CONFIG_MMU_PAGE_SIZE == KB(4),
		 "Only 4K page size is supported\n");

	__ASSERT(GET_EL(val) == MODE_EL1,
		 "Exception level not EL1, MMU not enabled!\n");

	/* Ensure that MMU is already not enabled */
	__asm__ volatile("mrs %0, sctlr_el1" : "=r" (val));
	__ASSERT((val & SCTLR_M) == 0, "MMU is already enabled\n");

	setup_page_tables(&kernel_ptables);

	/* currently only EL1 is supported */
	enable_mmu_el1(&kernel_ptables, flags);

	return 0;
}

SYS_INIT(arm_mmu_init, PRE_KERNEL_1,
#if MMU_DEBUG_PRINTS
	 MMU_DEBUG_PRIORITY
#else
	 CONFIG_KERNEL_INIT_PRIORITY_OBJECTS
#endif
);

int arch_mem_map(void *virt, uintptr_t phys, size_t size, uint32_t flags)
{
	struct arm_mmu_ptables *ptables;
	uint32_t entry_flags = MT_SECURE | MT_P_RX_U_NA;

	/* Always map in the kernel page tables */
	ptables = &kernel_ptables;

	/* Translate flags argument into HW-recognized entry flags. */
	switch (flags & K_MEM_CACHE_MASK) {
	/*
	 * K_MEM_CACHE_NONE => MT_DEVICE_nGnRnE
	 *			(Device memory nGnRnE)
	 * K_MEM_CACHE_WB   => MT_NORMAL
	 *			(Normal memory Outer WB + Inner WB)
	 * K_MEM_CACHE_WT   => MT_NORMAL_WT
	 *			(Normal memory Outer WT + Inner WT)
	 */
	case K_MEM_CACHE_NONE:
		entry_flags |= MT_DEVICE_nGnRnE;
		break;
	case K_MEM_CACHE_WT:
		entry_flags |= MT_NORMAL_WT;
		break;
	case K_MEM_CACHE_WB:
		entry_flags |= MT_NORMAL;
		break;
	default:
		return -ENOTSUP;
	}

	if ((flags & K_MEM_PERM_RW) != 0U) {
		entry_flags |= MT_RW;
	}

	if ((flags & K_MEM_PERM_EXEC) == 0U) {
		entry_flags |= MT_P_EXECUTE_NEVER;
	}

	if ((flags & K_MEM_PERM_USER) != 0U) {
		return -ENOTSUP;
	}

	add_map(ptables, "generic", phys, (uintptr_t)virt, size, entry_flags);

#ifdef CONFIG_USERSPACE
	/*
	 * All virtual-to-physical mappings are the same in all page tables in
	 * each domain
	 */
	sys_snode_t *node;

	SYS_SLIST_FOR_EACH_NODE(&domain_list, node) {
		struct arm_mmu_ptables *domain_ptables;
		struct arch_mem_domain *domain;

		domain = CONTAINER_OF(node, struct arch_mem_domain, node);
		domain_ptables = &domain->ptables;

		add_map(domain_ptables, "generic", phys, (uintptr_t)virt,
			size, entry_flags);
	}
#endif

	return 0;
}

#ifdef CONFIG_USERSPACE
static bool page_validate(struct arm_mmu_ptables *ptables, uintptr_t addr,
			  bool write)
{
	uint64_t *pte;

	pte = calculate_pte_index(ptables, addr, -1);

	if (pte == NULL)
		return false;

	if (!(*pte & PTE_BLOCK_DESC_AP_ELx))
		return false;

	if (write && ((*pte & PTE_BLOCK_DESC_AP_RO)))
		return false;

	return true;
}

int arch_buffer_validate(void *addr, size_t size, int write)
{
	struct arm_mmu_ptables *ptables;
	size_t aligned_size;
	uintptr_t virt;
	int ret = 0;

	ptables = _current->arch.ptables;

	k_mem_region_align(&virt, &aligned_size, (uintptr_t)addr,
			   size, CONFIG_MMU_PAGE_SIZE);

	for (size_t offset = 0; offset < aligned_size;
	     offset += CONFIG_MMU_PAGE_SIZE) {
		if (!page_validate(ptables, virt + offset, write)) {
			ret = -1;
			break;
		}
	}

	return ret;
}

int arch_mem_domain_max_partitions_get(void)
{
	return CONFIG_MAX_DOMAIN_PARTITIONS;
}

static void map_thread_stack(struct k_thread *thread,
			     struct arm_mmu_ptables *ptables)
{
	add_map(ptables, "thread_stack", thread->stack_info.start,
		thread->stack_info.start, thread->stack_info.size,
		MT_P_RW_U_RW | MT_NORMAL);
}

static inline uintptr_t ttbr0_get(void)
{
	return read_sysreg(ttbr0_el1);
}

/*
 * Duplicate the set of page tables
 *
 * Recursively copy the page tables starting from level. Page and block entries
 * are directly copied while the tables are copied recursively updating the
 * table pointer
 */
static void copy_page_table(struct arm_mmu_ptables *dst_pt,
			    struct arm_mmu_ptables *src_pt,
			    uint64_t *dst_xlat, uint64_t *src_xlat, int level)
{
	if (level == BASE_XLAT_LEVEL) {
		/* It's a brand new set. Reset the table counter */
		dst_pt->next_table = 0;
	}

	if (level == 3) {
		for (int i = 0; i < Ln_XLAT_NUM_ENTRIES; i++) {
			*(dst_xlat + i) = *(src_xlat + i);
		}
	} else {
		for (int i = 0; i < Ln_XLAT_NUM_ENTRIES; i++) {
			uint64_t *src_pte, *dst_pte;
			int src_pte_type;

			src_pte = src_xlat + i;
			dst_pte = dst_xlat + i;

			src_pte_type = pte_desc_type(src_pte);

			if (src_pte_type == PTE_INVALID_DESC ||
			    src_pte_type == PTE_BLOCK_DESC) {
				*dst_pte = *src_pte;
				continue;
			}

			if (src_pte_type == PTE_TABLE_DESC) {
				uint64_t *src_table, *dst_table;

				src_table = (uint64_t *)
					    (*src_pte & 0x0000fffffffff000ULL);
				dst_table = new_prealloc_table(dst_pt);

				set_pte_table_desc(dst_pte, dst_table, level);

				copy_page_table(dst_pt, src_pt, dst_table,
						src_table, level + 1);
			}
		}
	}
}

static void reset_map(struct arm_mmu_ptables *ptables, uintptr_t addr,
		      size_t size)
{
	size_t aligned_size;
	uint64_t *pte, desc;
	uintptr_t virt;

	/* There is no way (yet) to cleanly un-apply memory partitions from the
	 * domain page tables. Instead we look up the attributes of the
	 * original set of kernel page tables and we map the page with this
	 * original attributes
	 */
	k_mem_region_align(&virt, &aligned_size, addr, size,
			   CONFIG_MMU_PAGE_SIZE);

	for (size_t offset = 0; offset < aligned_size;
	     offset += CONFIG_MMU_PAGE_SIZE) {
		addr = virt + offset;

		/* Retrieve the original page attributes from the kernel
		 * ptables
		 */
		pte = calculate_pte_index(&kernel_ptables, addr, -1);

		desc = get_region_desc_from_pte(pte);

		/* Re-apply the original attributes to the page in the domain
		 * ptables
		 */
		add_map_with_desc(ptables, "partition", addr, addr,
				  CONFIG_MMU_PAGE_SIZE, desc);

	}
}

void arch_mem_domain_partition_remove(struct k_mem_domain *domain,
				      uint32_t partition_id)
{
	struct arm_mmu_ptables *domain_ptables;
	struct k_mem_partition *ptn;

	domain_ptables = &domain->arch.ptables;

	ptn = &domain->partitions[partition_id];

	reset_map(domain_ptables, ptn->start, ptn->size);
}

void arch_mem_domain_partition_add(struct k_mem_domain *domain,
				   uint32_t partition_id)
{
	struct arm_mmu_ptables *domain_ptables;
	struct k_mem_partition *ptn;

	domain_ptables = &domain->arch.ptables;

	ptn = &domain->partitions[partition_id];

	add_map(domain_ptables, "partition", ptn->start, ptn->start,
		ptn->size, ptn->attr.attrs | MT_NORMAL);

}

void arch_mem_domain_thread_add(struct k_thread *thread)
{
	struct arm_mmu_ptables *old_ptables, *domain_ptables;
	struct k_mem_domain *domain;
	bool is_user, is_migration;

	domain = thread->mem_domain_info.mem_domain;
	domain_ptables = &domain->arch.ptables;
	old_ptables = thread->arch.ptables;

	is_user = (thread->base.user_options & K_USER) != 0;
	is_migration = (old_ptables != NULL) && is_user;

	if (is_migration) {
		map_thread_stack(thread, domain_ptables);

	}

	thread->arch.ptables = domain_ptables;

	if (is_migration) {
		reset_map(old_ptables, thread->stack_info.start,
			  thread->stack_info.size);
	}

	if (thread == _current &&
	    ttbr0_get() != (uintptr_t)domain_ptables->xlat_tables) {
		z_arm64_swap_ptables(thread);
	}
}

int arch_mem_domain_init(struct k_mem_domain *domain)
{
	struct arm_mmu_ptables *domain_ptables;

	/* Initialize the domain ptables struct */
	domain_ptables = &domain->arch.ptables;
	domain_ptables->xlat_tables = domain->arch.xlat_tables;

	/* Copy the kernel page tables created at MMU init time */
	copy_page_table(domain_ptables, &kernel_ptables,
			domain_ptables->xlat_tables,
			kernel_ptables.xlat_tables, BASE_XLAT_LEVEL);

	sys_slist_append(&domain_list, &domain->arch.node);

	return 0;
}

void arch_mem_domain_thread_remove(struct k_thread *thread)
{
	struct arm_mmu_ptables *domain_ptables;
	struct k_mem_domain *domain;

	domain = thread->mem_domain_info.mem_domain;
	domain_ptables = &domain->arch.ptables;

	if ((thread->base.user_options & K_USER) == 0) {
		return;
	}

	if ((thread->base.thread_state & _THREAD_DEAD) == 0) {
		return;
	}

	reset_map(domain_ptables, thread->stack_info.start,
		  thread->stack_info.size);
}

void arch_mem_domain_destroy(struct k_mem_domain *domain)
{
	/* Empty */
}

void z_arm64_swap_ptables(struct k_thread *incoming)
{
	struct arm_mmu_ptables *ptables;
	uintptr_t pt;

	ptables = incoming->arch.ptables;
	pt = (uintptr_t)(ptables->xlat_tables);

	if (ttbr0_get() != pt) {
		z_arm64_set_ttbr0(pt);
	} else {
		z_arm64_invalidate_tlb_all();
	}
}

void z_arm64_thread_pt_init(struct k_thread *incoming)
{
	struct arm_mmu_ptables *ptables;

	if ((incoming->base.user_options & K_USER) == 0)
		return;

	ptables = incoming->arch.ptables;

	/* Map the thread stack */
	map_thread_stack(incoming, ptables);

	z_arm64_swap_ptables(incoming);
}

#endif /* CONFIG_USERSPACE */
