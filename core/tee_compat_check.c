/*
 * tee_compat_check.c
 *
 * check compatibility between tzdriver and tee.
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

#include "tee_compat_check.h"
#include <linux/types.h>
#include <linux/err.h>
#include <linux/delay.h>
#include "teek_ns_client.h"
#include "tc_ns_log.h"

#define RETRY_MAX_COUNT 100
#define COMPAT_LEVEL_RETRY_SLEEP 10

struct os_version {
	uint32_t magic;
	uint32_t major_version;
	uint32_t minor_version;
	uint32_t reserved[8];
	uint32_t feature_ccos : 1;
	uint32_t feature_reserved : 31;
};

static bool g_ccos_flag = false;

int32_t check_teeos_compat_level(const uint32_t *buffer, uint32_t size)
{
	const uint16_t major = TEEOS_COMPAT_LEVEL_MAJOR;
	const uint16_t minor = TEEOS_COMPAT_LEVEL_MINOR;
	struct os_version *version = NULL;
	uint32_t retry_count = 0;

	if (!buffer || size != COMPAT_LEVEL_BUF_LEN) {
		tloge("check teeos compat level failed, invalid param\n");
		return -EINVAL;
	}

	version = (struct os_version *)buffer;

	while (retry_count < RETRY_MAX_COUNT && version->magic != VER_CHECK_MAGIC_NUM) {
		tlogd("sync compat level msg, cnt: %d\n", retry_count);
		msleep(COMPAT_LEVEL_RETRY_SLEEP);
		retry_count++;
	}

	if (version->magic != VER_CHECK_MAGIC_NUM) {
		tloge("check ver magic num %u failed\n", version->magic);
		return -EPERM;
	}
	if (version->major_version != major) {
		tloge("check major ver failed, tzdriver expect teeos version=%u, actual teeos version=%u\n",
			major, version->major_version);
		return -EPERM;
	}

	if (version->minor_version < minor) {
		tloge("check minor ver failed, tzdriver expect teeos minor version=%u, actual minor teeos version=%u\n",
			minor, version->minor_version);
		return -EPERM;
	} else {
		tlogi("current tzdriver expect teeos version %u.%u, actual tee version %u.%u\n",
			major, minor, version->major_version, version->minor_version);
	}

	g_ccos_flag = (version->feature_ccos == TEEOS_CONFIDENTIAL_OS_FLAG) ? true : false;

	return 0;
}

bool is_ccos(void)
{
	return g_ccos_flag;
}
