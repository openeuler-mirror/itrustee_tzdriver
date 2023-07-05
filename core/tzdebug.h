/*
 * tzdebug.h
 *
 * function for find symbols not exported
 *
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
#ifndef TZDEBUG_H
#define TZDEBUG_H

#include <linux/types.h>
struct ta_mem {
	char ta_name[64];
	uint32_t pmem;
	uint32_t pmem_max;
	uint32_t pmem_limit;
};
#define MEMINFO_TA_MAX 100
struct tee_mem {
	uint32_t total_mem;
	uint32_t pmem;
	uint32_t free_mem;
	uint32_t free_mem_min;
	uint32_t ta_num;
	struct ta_mem ta_mem_info[MEMINFO_TA_MAX];
};

int get_tee_meminfo(struct tee_mem *meminfo);
void tee_dump_mem(void);
int tzdebug_init(void);
void free_tzdebug(void);

#endif