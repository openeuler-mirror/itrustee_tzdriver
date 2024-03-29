/*
 * tee_compat_check.h
 *
 * check compatibility between tzdriver and teeos.
 *
 * Copyright (c) 2021-2022 Huawei Technologies Co., Ltd.
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

#ifndef TEE_COMPAT_CHECK_H
#define TEE_COMPAT_CHECK_H

#include <linux/types.h>

/*
 * this version number MAJOR.MINOR is used
 * to identify the compatibility of tzdriver and teeos
 */
#define TEEOS_COMPAT_LEVEL_MAJOR 3
#define TEEOS_COMPAT_LEVEL_MINOR 0

#define TZDRIVER_LEVEL_MAJOR_SELF 3
#define TZDRIVER_LEVEL_MINOR_SELF 0

#define TEEOS_CONFIDENTIAL_OS_FLAG 1

#define VER_CHECK_MAGIC_NUM 0x5A5A5A5A
#define COMPAT_LEVEL_BUF_LEN 12

int32_t check_teeos_compat_level(const uint32_t *buffer, uint32_t size);
bool is_ccos(void);
#endif
