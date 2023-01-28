/*
 * client_hash_auth.h
 *
 * function definition for CA code hash auth
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

#ifndef CLIENT_HASH_CALC_H
#define CLIENT_HASH_CALC_H

#include "tc_ns_client.h"
#include "teek_ns_client.h"

#ifdef CONFIG_CLIENT_AUTH
#include "auth_base_impl.h"

int calc_client_auth_hash(struct tc_ns_dev_file *dev_file,
	struct tc_ns_client_context *context, struct tc_ns_session *session);

#else

static inline int calc_client_auth_hash(struct tc_ns_dev_file *dev_file,
	struct tc_ns_client_context *context, struct tc_ns_session *session)
{
	(void)dev_file;
	(void)context;
	(void)session;
	return 0;
}

#endif

#ifdef CONFIG_AUTH_SUPPORT_UNAME
#define MAX_NAME_LENGTH 256

int tc_ns_get_uname(uint32_t uid, char *username, int buffer_len, uint32_t *out_len);
#endif

#ifdef CONFIG_AUTH_HASH
int set_login_information_hash(struct tc_ns_dev_file *hash_dev_file);
#endif

#endif
