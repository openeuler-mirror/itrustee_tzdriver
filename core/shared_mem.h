/*
 * Copyright (c) 2012-2022 Huawei Technologies Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef SHARED_MEM_H
#define SHARED_MEM_H

#include <linux/types.h>
#include <linux/of.h>

#ifdef CONFIG_512K_LOG_PAGES_MEM
#define PAGES_LOG_MEM_LEN   (512 * SZ_1K) /* mem size: 512 k */
#else
#define PAGES_LOG_MEM_LEN   (256 * SZ_1K) /* mem size: 256 k */
#endif

#ifndef CONFIG_SHARED_MEM_RESERVED
typedef struct page mailbox_page_t;
#else
typedef uintptr_t mailbox_page_t;
#endif

struct pagelist_info {
	uint64_t page_num;
	uint64_t page_size;
	uint64_t sharedmem_offset;
	uint64_t sharedmem_size;
};

uint64_t get_reserved_cmd_vaddr_of(phys_addr_t cmd_phys, uint64_t cmd_size);
int load_tz_shared_mem(struct device_node *np);

mailbox_page_t *mailbox_alloc_pages(int order);
void mailbox_free_pages(mailbox_page_t *pages, int order);
uintptr_t mailbox_page_address(mailbox_page_t *page);
mailbox_page_t *mailbox_virt_to_page(uint64_t ptr);
uint64_t get_operation_vaddr(void);
void free_operation(uint64_t op_vaddr);
uint64_t get_mailbox_buffer_vaddr(uint32_t pool_count);
void free_mailbox_buffer(uint64_t op_vaddr);

uint64_t get_log_mem_vaddr(void);
uint64_t get_log_mem_paddr(uint64_t log_vaddr);
uint64_t get_log_mem_size(void);
void free_log_mem(uint64_t log_vaddr);

uint64_t get_cmd_mem_vaddr(void);
uint64_t get_cmd_mem_paddr(uint64_t cmd_vaddr);
void free_cmd_mem(uint64_t cmd_vaddr);

uint64_t get_spi_mem_vaddr(void);
uint64_t get_spi_mem_paddr(uintptr_t spi_vaddr);
void free_spi_mem(uint64_t spi_vaddr);
int fill_shared_mem_info(uint64_t start_vaddr, uint32_t pages_no,
	uint32_t offset, uint32_t buffer_size, uint64_t info_addr);
void release_shared_mem_page(uint64_t buf, uint32_t buf_size);

#endif
