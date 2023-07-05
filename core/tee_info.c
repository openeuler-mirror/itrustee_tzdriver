/*
 * Copyright (c) 2023-2023 Huawei Technologies Co., Ltd.
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
#include "tee_info.h"
#include <linux/types.h>
#include <linux/err.h>
#include <linux/uaccess.h>
#include "teek_ns_client.h"
#include "tee_compat_check.h"
#include <securec.h>

int32_t tc_ns_get_tee_info(struct file *file, void __user *argp)
{
	int32_t ret;
	struct tc_ns_tee_info info;

	if (!argp) {
		tloge("error input parameter\n");
		return -EINVAL;
	}

	(void)file;
	ret = 0;
	(void)memset_s(&info, sizeof(info), 0, sizeof(info));
	info.tzdriver_version_major = TZDRIVER_LEVEL_MAJOR_SELF;
	info.tzdriver_version_minor = TZDRIVER_LEVEL_MINOR_SELF;
	if (copy_to_user(argp, &info, sizeof(info)) != 0)
		ret = -EFAULT;

	return ret;
}
