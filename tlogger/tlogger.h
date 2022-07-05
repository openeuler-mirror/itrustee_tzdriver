/*
 * tlogger.h
 *
 * TEE Logging Subsystem, read the tee os log from rdr memory
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
#ifndef TLOGGER_H
#define TLOGGER_H

#include <linux/types.h>

#define UINT64_MAX (uint64_t)(~((uint64_t)0))

#ifdef CONFIG_TEELOG
void tz_log_write(void);
int tlogger_store_msg(const char *file_path, uint32_t file_path_len);
int register_mem_to_teeos(uint64_t mem_addr, uint32_t mem_len, bool is_cache_mem);

#ifdef CONFIG_TZDRIVER_MODULE
int init_tlogger_service(void);
void exit_tlogger_service(void);
#endif

#else
static inline void tz_log_write(void)
{
	return;
}

static inline int tlogger_store_msg(const char *file_path, uint32_t file_path_len)
{
	(void)file_path;
	(void)file_path_len;
	return 0;
}
static inline int register_mem_to_teeos(uint64_t mem_addr, uint32_t mem_len,
	bool is_cache_mem)
{
	(void)mem_addr;
	(void)mem_len;
	return 0;
}
static inline int init_tlogger_service(void)
{
	return 0;
}
static inline int exit_tlogger_service(void)
{
}
#endif
#endif
