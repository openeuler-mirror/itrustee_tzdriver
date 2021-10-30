/*
 * tz_spi_notify.h
 *
 * exported funcs for spi interrupt actions
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
#ifndef TZ_SPI_NOTIFY_H
#define TZ_SPI_NOTIFY_H
#include <linux/platform_device.h>
#include <linux/cdev.h>
#include "teek_ns_client.h"

int tz_spi_init(struct device *class_dev, struct device_node *np);
void tz_spi_exit(void);
int tc_ns_tst_cmd(void *argp);

#endif
