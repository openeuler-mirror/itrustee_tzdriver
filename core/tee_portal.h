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
#ifndef TEE_PORTAL_H
#define TEE_PORTAL_H

int tee_portal_register(void *owner, void __user *arg);
int tee_portal_unregister(const void *owner);
int tee_portal_work(const void *owner);
void tee_portal_init(void);

#endif
