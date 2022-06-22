/*
 * tz_pm.h
 *
 * suspend or freeze func declaration for tzdriver
 *
 * Copyright (c) 2020-2022 Huawei Technologies Co., Ltd.
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

#ifndef TZ_PM_H
#define TZ_PM_H
#include <linux/platform_device.h>

#define TSP_S4_SUSPEND          0xB200000C
#define TSP_S4_RESUME           0xB200000D
#define TSP_S4_ENCRYPT_AND_COPY 0xB2000010
#define TSP_S4_DECRYPT_AND_COPY 0xB2000011

int tc_s4_pm_suspend(struct device *dev);

int tc_s4_pm_resume(struct device *dev);

#endif
