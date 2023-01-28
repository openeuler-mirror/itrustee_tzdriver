/*
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

#include <linux/module.h>

static struct smc_hooks_t {
	void (*smc_pre_hook)(void *);
	void (*smc_post_hook)(void *);
} g_smc_hooks;

/*
 * we provide a hook function here,
 * the specific implementation is implemented by the product itself
 */
void register_smc_hook(void (*pre_hook)(void *), void (*post_hook)(void *))
{
	g_smc_hooks.smc_pre_hook = pre_hook;
	g_smc_hooks.smc_post_hook = post_hook;
}
EXPORT_SYMBOL(register_smc_hook);

void call_smc_pre_hook(unsigned int cmd_id)
{
	if (g_smc_hooks.smc_pre_hook != NULL)
		g_smc_hooks.smc_pre_hook((void *)&cmd_id);
}

void call_smc_post_hook(unsigned int cmd_id)
{
	if (g_smc_hooks.smc_post_hook != NULL)
		g_smc_hooks.smc_post_hook((void *)&cmd_id);
}
