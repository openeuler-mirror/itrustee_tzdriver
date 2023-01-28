/*
 * Copyright (c) 2022-2022 Huawei Technologies Co., Ltd.
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
#ifndef INTERNAL_FUNCTIONS_H
#define INTERNAL_FUNCTIONS_H

#include <linux/device.h>
#include <securec.h>
#include "teek_ns_client.h"
#include "teek_client_constants.h"

#ifdef CONFIG_STATIC_ION
#include "static_ion_mem.h"
#else
static inline int tc_ns_register_ion_mem(void)
{
	return 0;
}
#endif

#ifndef CONFIG_HISI_VLTMM
static inline void vltmm_agent_register(void)
{
	return;
}
#endif

#ifndef CONFIG_TEE_FAULT_MANAGER
static inline void fault_monitor_start(int32_t type)
{
	(void)type;
	return;
}

static inline void fault_monitor_end(void)
{
	return;
}
#endif

#ifdef CONFIG_DYNAMIC_ION
#include "dynamic_ion_mem.h"
#else
static inline bool is_ion_param(uint32_t param_type)
{
	(void)param_type;
	return false;
}

static inline int load_image_for_ion(const struct load_img_params *params, int32_t *ret_origin)
{
	(void)params;
	(void)ret_origin;
	return 0;
}

static inline int init_dynamic_mem(void)
{
	return 0;
}

static inline int load_app_use_configid(uint32_t configid, uint32_t cafd,
	const struct tc_uuid *uuid, uint32_t size)
{
	(void)configid;
	(void)cafd;
	(void)uuid;
	(void)size;
	return 0;
}

static inline void kill_ion_by_cafd(unsigned int cafd)
{
	(void)cafd;
	return;
}

static inline void kill_ion_by_uuid(const struct tc_uuid *uuid)
{
	(void)uuid;
	return;
}
#endif

#ifndef CONFIG_ION_HISI
static inline int alloc_for_ion(const struct tc_call_params *call_params,
	struct tc_op_params *op_params, uint8_t kernel_params,
	uint32_t param_type, unsigned int index)
{
	(void)call_params;
	(void)op_params;
	(void)kernel_params;
	(void)param_type;
	(void)index;
	tloge("not support ion and related feature!\n");
	return -1;
}
#endif

#ifndef CONFIG_ION_HISI_SECSG
static inline int alloc_for_ion_sglist(const struct tc_call_params *call_params,
	struct tc_op_params *op_params, uint8_t kernel_params,
	uint32_t param_type, unsigned int index)
{
	(void)call_params;
	(void)op_params;
	(void)kernel_params;
	(void)param_type;
	(void)index;
	tloge("not support seg and related feature!\n");
	return -1;
}
#endif

#ifdef CONFIG_KTHREAD_AFFINITY
#include "tz_kthread_affinity.h"
#else
static inline void init_kthread_cpumask(void)
{
}

static inline void tz_kthread_bind_mask(struct task_struct *kthread)
{
	(void)kthread;
}

static inline void tz_workqueue_bind_mask(struct workqueue_struct *wq,
	uint32_t flag)
{
	(void)wq;
	(void)flag;
}
#endif

#ifdef CONFIG_TEE_TUI
#include "tui.h"
#else
static inline bool is_tui_agent(unsigned int agent_id)
{
	(void)agent_id;
	return false;
}

static inline int init_tui(const struct device *dev)
{
	(void)dev;
	return 0;
}

static inline void free_tui(void)
{
}

static inline void unregister_tui_driver(const char *name)
{
	(void)name;
}

static inline int send_tui_msg_config(int type, int val, const void *data)
{
	(void)type;
	(void)val;
	(void)data;
	return 0;
}

static inline void set_tui_caller_info(unsigned int devid, int pid)
{
	(void)devid;
	(void)pid;
}

static inline void free_tui_caller_info(void)
{
}

static inline unsigned int tui_attach_device(void)
{
	return 0;
}
static inline int is_tui_in_use(int pid_value)
{
	(void)pid_value;
	return 0;
}

static inline void do_ns_tui_release(void)
{
}

static inline int tc_ns_tui_event(struct tc_ns_dev_file *dev_file, const void *argp)
{
	(void)dev_file;
	(void)argp;
	return 0;
}
#endif

#ifdef CONFIG_LIVEPATCH_ENABLE
#include "livepatch_cmd.h"
#else
static inline int livepatch_init(const struct device *dev)
{
	(void)dev;
	return 0;
}
static inline void livepatch_down_read_sem(void)
{
}
static inline void livepatch_up_read_sem(void)
{
}
static inline void free_livepatch(void)
{
}
#endif

#ifdef CONFIG_TEE_TRACE
#include "tee_trace_event.h"
#include "tee_trace_interrupt.h"
#else
static inline void tee_trace_add_event(enum tee_event_id id, uint64_t add_info)
{
	(void)id;
	(void)add_info;
}
static inline void free_event_mem(void)
{
}
static inline void free_interrupt_trace(void)
{
}
#endif

#ifdef CONFIG_TEE_REBOOT
#include "reboot.h"
#else
static inline bool is_tee_rebooting(void)
{
	return false;
}
static inline int tee_init_reboot_thread(void)
{
	return 0;
}
static inline int tee_wake_up_reboot(void)
{
	return 0;
}
static inline void free_reboot_thread(void)
{
	return;
}
#endif

#endif
