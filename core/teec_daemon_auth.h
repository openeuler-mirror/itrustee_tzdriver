/*
 * teec_daemon_auth.h
 *
 * function definition for teecd or hidl process auth
 *
 * Copyright (c) 2012-2021 Huawei Technologies Co., Ltd.
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
#ifndef TEEC_DAEMON_AUTH_H
#define TEEC_DAEMON_AUTH_H

#ifdef CONFIG_TEECD_AUTH
#include <linux/sched.h>
#include "auth_base_impl.h"

int check_teecd_access(void);

#else

static inline int check_teecd_access(void)
{
	return 0;
}

#endif

#endif
