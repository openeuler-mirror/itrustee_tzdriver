/*
 * secs_power_ctrl.h
 *
 * function declaration for secs power ctrl
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

#ifndef SECS_POWER_CTRL_H
#define SECS_POWER_CTRL_H

#include <tc_ns_log.h>

static int power_on_cc(void)
{
    return 0;
}

static int power_down_cc(void)
{
    return 0;
}

static void secs_suspend_status(uint64_t target)
{
    (void)target;
    return;
}

#endif