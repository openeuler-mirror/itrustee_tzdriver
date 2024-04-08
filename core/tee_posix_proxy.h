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
#ifndef TEE_POSIX_PROXY_H
#define TEE_POSIX_PROXY_H

int tee_posix_proxy_register_tasklet(void __user *arg, unsigned int nsid);
int tee_posix_proxy_unregister_all_tasklet(const void *owner);

void tee_posix_proxy_init(void);

#endif