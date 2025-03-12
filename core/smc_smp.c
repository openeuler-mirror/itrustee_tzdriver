/*
 * smc_smp.c
 *
 * function for sending smc cmd
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
#include "smc_smp.h"
#include <linux/of.h>
#include <linux/of_reserved_mem.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/mutex.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/semaphore.h>
#include <linux/device.h>
#include <linux/workqueue.h>
#include <linux/list.h>
#include <linux/cpu.h>
#include <linux/regulator/consumer.h>
#include <linux/spi/spi.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/rtc.h>
#include <linux/clk-provider.h>
#include <linux/clk.h>
#include <linux/string.h>
#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/bitops.h>
#include <linux/version.h>
#include <linux/cpumask.h>
#include <linux/err.h>
#include <linux/proc_ns.h>

#if (KERNEL_VERSION(4, 14, 0) <= LINUX_VERSION_CODE)
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#endif
#include <securec.h>
#include <asm/cacheflush.h>

#ifdef CONFIG_TEE_AUDIT
#include <chipset_common/security/hw_kernel_stp_interface.h>
#endif

#include "tc_ns_log.h"
#include "teek_client_constants.h"
#include "tc_ns_client.h"
#include "agent.h"
#include "teek_ns_client.h"
#include "mailbox_mempool.h"
#include "cmdmonitor.h"
#include "tlogger.h"
#include "ko_adapt.h"
#include "log_cfg_api.h"
#include "tee_compat_check.h"
#include "secs_power_ctrl.h"
#include "shared_mem.h"
#include "internal_functions.h"
#include "smc_call.h"

#define PREEMPT_COUNT            10000
#define HZ_COUNT                 10
#define IDLED_COUNT              100
/*
 * when cannot find smc entry, will sleep 1ms
 * because the task will be killed in 25s if it not return,
 * so the retry count is 25s/1ms
 */
#define FIND_SMC_ENTRY_SLEEP 1
#define FIND_SMC_ENTRY_RETRY_MAX_COUNT (CMD_MAX_EXECUTE_TIME * S_TO_MS / FIND_SMC_ENTRY_SLEEP)

#define CPU_ZERO    0
#define CPU_ONE     1
#define CPU_FOUR    4
#define CPU_FIVE    5
#define CPU_SIX     6
#define CPU_SEVEN   7
#define LOW_BYTE    0xF

#define PENDING2_RETRY      (-1)

#define RETRY_WITH_PM     1
#define CLEAN_WITHOUT_PM  2

#define MAX_CHAR 0xff

#define MAX_SIQ_NUM 4

/* Current state of the system */
static bool g_sys_crash;

struct shadow_work {
	struct kthread_work kthwork;
	struct work_struct work;
	uint64_t target;
};

unsigned long g_shadow_thread_id = 0;
static struct task_struct *g_siq_thread;
static struct task_struct *g_smc_svc_thread;
static struct task_struct *g_ipi_helper_thread;
static struct kthread_worker *g_ipi_helper_worker = NULL;

enum cmd_reuse {
	CLEAR,      /* clear this cmd index */
	RESEND,     /* use this cmd index resend */
};

struct cmd_reuse_info {
	int cmd_index;
	int saved_index;
	enum cmd_reuse cmd_usage;
};

#if (CONFIG_CPU_AFF_NR != 0)
static struct cpumask g_cpu_mask;
static int g_mask_flag = 0;
#endif

#ifdef CONFIG_DRM_ADAPT
static struct cpumask g_drm_cpu_mask;
static int g_drm_mask_flag = 0;
#endif

struct tc_ns_smc_queue *g_cmd_data;
phys_addr_t g_cmd_phys;

static struct list_head g_pending_head;
static spinlock_t g_pend_lock;

static DECLARE_WAIT_QUEUE_HEAD(siq_th_wait);
static DECLARE_WAIT_QUEUE_HEAD(ipi_th_wait);
static atomic_t g_siq_th_run;
static uint32_t g_siq_queue[MAX_SIQ_NUM];
DEFINE_MUTEX(g_siq_lock);

enum smc_ops_exit {
	SMC_OPS_NORMAL   = 0x0,
	SMC_OPS_SCHEDTO  = 0x1,
	SMC_OPS_START_SHADOW    = 0x2,
	SMC_OPS_START_FIQSHD    = 0x3,
	SMC_OPS_PROBE_ALIVE     = 0x4,
	SMC_OPS_ABORT_TASK      = 0x5,
	SMC_EXIT_NORMAL         = 0x0,
	SMC_EXIT_PREEMPTED      = 0x1,
	SMC_EXIT_SHADOW         = 0x2,
	SMC_EXIT_ABORT          = 0x3,
	SMC_EXIT_MAX            = 0x4,
};

#define SHADOW_EXIT_RUN             0x1234dead
#define SMC_EXIT_TARGET_SHADOW_EXIT 0x1

#define compile_time_assert(cond, msg) typedef char g_assert_##msg[(cond) ? 1 : -1]

#ifndef CONFIG_BIG_SESSION
compile_time_assert(sizeof(struct tc_ns_smc_queue) <= PAGE_SIZE,
	size_of_tc_ns_smc_queue_too_large);
#endif

static bool g_reserved_cmd_buffer = false;
static u64 g_cmd_size = 0;
static bool g_tz_uefi_enable = false;

#ifndef CONFIG_TZDRIVER_MODULE
static int __init tz_check_uefi_enable_func(char *str)
{
	if (str != NULL && *str == '1')
		g_tz_uefi_enable = true;

	return 0;
}
early_param("tz_uefi_enable", tz_check_uefi_enable_func);
#endif

#define MIN_CMDLINE_SIZE 0x1000
static int reserved_cmdline(struct reserved_mem *rmem)
{
	if (g_tz_uefi_enable && rmem && rmem->size >= MIN_CMDLINE_SIZE) {
		g_cmd_phys = rmem->base;
		g_cmd_size = rmem->size;
		g_reserved_cmd_buffer = true;
	} else {
		g_reserved_cmd_buffer = false;
	}

	return 0;
}
RESERVEDMEM_OF_DECLARE(g_teeos_cmdline, "teeos-cmdline", reserved_cmdline);

static void acquire_smc_buf_lock(smc_buf_lock_t *lock)
{
	int ret;

	preempt_disable();
	do
		ret = (int)cmpxchg(lock, 0, 1);
	while (ret != 0);
}

static inline void release_smc_buf_lock(smc_buf_lock_t *lock)
{
	(void)cmpxchg(lock, 1, 0);
	preempt_enable();
}

static void occupy_setbit_smc_in_doing_entry(int32_t i, int32_t *idx)
{
	g_cmd_data->in[i].event_nr = (unsigned int)i;
	isb();
	wmb();
	set_bit((unsigned int)i, (unsigned long *)g_cmd_data->in_bitmap);
	set_bit((unsigned int)i, (unsigned long *)g_cmd_data->doing_bitmap);
	*idx = i;
}

static int occupy_free_smc_in_entry(const struct tc_ns_smc_cmd *cmd)
{
	int idx = -1;
	int i;
	uint32_t retry_count = 0;

	if (!cmd) {
		tloge("bad parameters! cmd is NULL\n");
		return -1;
	}
	/*
	 * Note:
	 * acquire_smc_buf_lock will disable preempt and kernel will forbid
	 * call mutex_lock in preempt disabled scenes.
	 * To avoid such case(update_timestamp and update_chksum will call
	 * mutex_lock), only cmd copy is done when preempt is disable,
	 * then do update_timestamp and update_chksum.
	 * As soon as this idx of in_bitmap is set, gtask will see this
	 * cmd_in, but the cmd_in is not ready that lack of update_xxx,
	 * so we make a tricky here, set doing_bitmap and in_bitmap both
	 * at first, after update_xxx is done, clear doing_bitmap.
	 */
get_smc_retry:
	acquire_smc_buf_lock(&g_cmd_data->smc_lock);
	for (i = 0; i < MAX_SMC_CMD; i++) {
		if (test_bit(i, (unsigned long *)g_cmd_data->in_bitmap) != 0)
			continue;
		if (memcpy_s(&g_cmd_data->in[i], sizeof(g_cmd_data->in[i]),
			cmd, sizeof(*cmd)) != EOK) {
			tloge("memcpy failed,%s line:%d", __func__, __LINE__);
			break;
		}
		occupy_setbit_smc_in_doing_entry(i, &idx);
		break;
	}
	release_smc_buf_lock(&g_cmd_data->smc_lock);
	if (idx == -1) {
		if (retry_count <= FIND_SMC_ENTRY_RETRY_MAX_COUNT) {
			msleep(FIND_SMC_ENTRY_SLEEP);
			retry_count++;
			tlogd("can't get any free smc entry and retry:%u\n", retry_count);
			goto get_smc_retry;
		}
		tloge("can't get any free smc entry after retry:%u\n", retry_count);
		return -1;
	}

	acquire_smc_buf_lock(&g_cmd_data->smc_lock);
	isb();
	wmb();
	clear_bit((uint32_t)idx, (unsigned long *)g_cmd_data->doing_bitmap);
	release_smc_buf_lock(&g_cmd_data->smc_lock);
	return idx;
}

static int reuse_smc_in_entry(uint32_t idx)
{
	int rc = 0;

	acquire_smc_buf_lock(&g_cmd_data->smc_lock);
	if (!(test_bit((int32_t)idx, (unsigned long *)g_cmd_data->in_bitmap) != 0 &&
		test_bit((int32_t)idx, (unsigned long *)g_cmd_data->doing_bitmap) != 0)) {
		tloge("invalid cmd to reuse\n");
		rc = -1;
		goto out;
	}
	if (memcpy_s(&g_cmd_data->in[idx], sizeof(g_cmd_data->in[idx]),
		&g_cmd_data->out[idx], sizeof(g_cmd_data->out[idx])) != EOK) {
		tloge("memcpy failed,%s line:%d", __func__, __LINE__);
		rc = -1;
		goto out;
	}

	isb();
	wmb();
	clear_bit(idx, (unsigned long *)g_cmd_data->doing_bitmap);
out:
	release_smc_buf_lock(&g_cmd_data->smc_lock);
	return rc;
}

static int copy_smc_out_entry(uint32_t idx, struct tc_ns_smc_cmd *copy,
	enum cmd_reuse *usage)
{
	acquire_smc_buf_lock(&g_cmd_data->smc_lock);
	if (test_bit((int)idx, (unsigned long *)g_cmd_data->out_bitmap) == 0) {
		tloge("cmd out %u is not ready\n", idx);
		release_smc_buf_lock(&g_cmd_data->smc_lock);
		show_cmd_bitmap();
		return -ENOENT;
	}
	if (memcpy_s(copy, sizeof(*copy), &g_cmd_data->out[idx],
		sizeof(g_cmd_data->out[idx])) != EOK) {
		tloge("copy smc out failed\n");
		release_smc_buf_lock(&g_cmd_data->smc_lock);
		return -EFAULT;
	}

	isb();
	wmb();
	if (g_cmd_data->out[idx].ret_val == (int)TEEC_PENDING2 ||
		g_cmd_data->out[idx].ret_val == (int)TEEC_PENDING) {
		*usage = RESEND;
	} else {
		clear_bit(idx, (unsigned long *)g_cmd_data->in_bitmap);
		clear_bit(idx, (unsigned long *)g_cmd_data->doing_bitmap);
		*usage = CLEAR;
	}
	clear_bit(idx, (unsigned long *)g_cmd_data->out_bitmap);
	release_smc_buf_lock(&g_cmd_data->smc_lock);

	return 0;
}

static inline void clear_smc_in_entry(uint32_t idx)
{
	acquire_smc_buf_lock(&g_cmd_data->smc_lock);
	clear_bit(idx, (unsigned long *)g_cmd_data->in_bitmap);
	release_smc_buf_lock(&g_cmd_data->smc_lock);
}

static void release_smc_entry(uint32_t idx)
{
	acquire_smc_buf_lock(&g_cmd_data->smc_lock);
	clear_bit(idx, (unsigned long *)g_cmd_data->in_bitmap);
	clear_bit(idx, (unsigned long *)g_cmd_data->doing_bitmap);
	clear_bit(idx, (unsigned long *)g_cmd_data->out_bitmap);
	release_smc_buf_lock(&g_cmd_data->smc_lock);
}

static bool is_cmd_working_done(uint32_t idx)
{
	bool ret = false;

	acquire_smc_buf_lock(&g_cmd_data->smc_lock);
	if (test_bit((int)idx, (unsigned long *)g_cmd_data->out_bitmap) != 0)
		ret = true;
	release_smc_buf_lock(&g_cmd_data->smc_lock);
	return ret;
}

void occupy_clean_cmd_buf(void)
{
	acquire_smc_buf_lock(&g_cmd_data->smc_lock);
	memset_s(g_cmd_data, sizeof(struct tc_ns_smc_queue), 0, sizeof(struct tc_ns_smc_queue));
	release_smc_buf_lock(&g_cmd_data->smc_lock);
}

static void show_in_bitmap(int *cmd_in, uint32_t len)
{
	uint32_t idx;
	uint32_t in = 0;
	char bitmap[MAX_SMC_CMD + 1];

	if (len != MAX_SMC_CMD || !g_cmd_data)
		return;

	for (idx = 0; idx < MAX_SMC_CMD; idx++) {
		if (test_bit((int32_t)idx, (unsigned long *)g_cmd_data->in_bitmap) != 0) {
			bitmap[idx] = '1';
			cmd_in[in++] = (int)idx;
		} else {
			bitmap[idx] = '0';
		}
	}
	bitmap[MAX_SMC_CMD] = '\0';
	tlogi("in bitmap: %s\n", bitmap);
}

static void show_out_bitmap(int *cmd_out, uint32_t len)
{
	uint32_t idx;
	uint32_t out = 0;
	char bitmap[MAX_SMC_CMD + 1];

	if (len != MAX_SMC_CMD || !g_cmd_data)
		return;

	for (idx = 0; idx < MAX_SMC_CMD; idx++) {
		if (test_bit((int32_t)idx, (unsigned long *)g_cmd_data->out_bitmap) != 0) {
			bitmap[idx] = '1';
			cmd_out[out++] = (int)idx;
		} else {
			bitmap[idx] = '0';
		}
	}
	bitmap[MAX_SMC_CMD] = '\0';
	tlogi("out bitmap: %s\n", bitmap);
}

static void show_doing_bitmap(void)
{
	uint32_t idx;
	char bitmap[MAX_SMC_CMD + 1];

	if (!g_cmd_data)
		return;
	for (idx = 0; idx < MAX_SMC_CMD; idx++) {
		if (test_bit((int)idx, (unsigned long *)g_cmd_data->doing_bitmap) != 0)
			bitmap[idx] = '1';
		else
			bitmap[idx] = '0';
	}
	bitmap[MAX_SMC_CMD] = '\0';
	tlogi("doing bitmap: %s\n", bitmap);
}

static void show_single_cmd_info(const int *cmd, uint32_t len)
{
	uint32_t idx;

	if (len != MAX_SMC_CMD || !g_cmd_data)
		return;

	for (idx = 0; idx < MAX_SMC_CMD; idx++) {
		if (cmd[idx] == -1)
			break;
		tlogi("cmd[%d]: cmd_id=%u, ca_pid=%u, dev_id = 0x%x, "
			"event_nr=%u, ret_val=0x%x\n",
			cmd[idx],
			g_cmd_data->in[cmd[idx]].cmd_id,
			g_cmd_data->in[cmd[idx]].ca_pid,
			g_cmd_data->in[cmd[idx]].dev_file_id,
			g_cmd_data->in[cmd[idx]].event_nr,
			g_cmd_data->in[cmd[idx]].ret_val);
	}
}

void show_cmd_bitmap(void)
{
	int *cmd_in = NULL;
	int *cmd_out = NULL;

	cmd_in = kzalloc(sizeof(int) * MAX_SMC_CMD, GFP_KERNEL);
	if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)cmd_in)) {
		tloge("out of mem! cannot show in bitmap\n");
		return;
	}

	cmd_out = kzalloc(sizeof(int) * MAX_SMC_CMD, GFP_KERNEL);
	if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)cmd_out)) {
		kfree(cmd_in);
		tloge("out of mem! cannot show out bitmap\n");
		return;
	}

	if (memset_s(cmd_in, sizeof(int)* MAX_SMC_CMD, MAX_CHAR, sizeof(int)* MAX_SMC_CMD) != 0 ||
		memset_s(cmd_out, sizeof(int)* MAX_SMC_CMD, MAX_CHAR, sizeof(int)* MAX_SMC_CMD) != 0) {
		tloge("memset failed\n");
		goto error;
	}

	acquire_smc_buf_lock(&g_cmd_data->smc_lock);

	show_in_bitmap(cmd_in, MAX_SMC_CMD);
	show_doing_bitmap();
	show_out_bitmap(cmd_out, MAX_SMC_CMD);

	tlogi("cmd in value:\n");
	show_single_cmd_info(cmd_in, MAX_SMC_CMD);

	tlogi("cmd_out value:\n");
	show_single_cmd_info(cmd_out, MAX_SMC_CMD);

	release_smc_buf_lock(&g_cmd_data->smc_lock);

error:
	kfree(cmd_in);
	kfree(cmd_out);
}

static struct pending_entry *init_pending_entry(void)
{
	struct pending_entry *pe = NULL;

	pe = kzalloc(sizeof(*pe), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)pe)) {
		tloge("alloc pe failed\n");
		return NULL;
	}

	atomic_set(&pe->users, 1);
	get_task_struct(current);
	pe->task = current;

#ifdef CONFIG_TA_AFFINITY
	cpumask_copy(&pe->ca_mask, CURRENT_CPUS_ALLOWED);
	cpumask_copy(&pe->ta_mask, CURRENT_CPUS_ALLOWED);
#endif

	init_waitqueue_head(&pe->wq);
	atomic_set(&pe->run, 0);
	INIT_LIST_HEAD(&pe->list);
	spin_lock(&g_pend_lock);
	list_add_tail(&pe->list, &g_pending_head);
	spin_unlock(&g_pend_lock);

	return pe;
}

struct pending_entry *find_pending_entry(pid_t pid)
{
	struct pending_entry *pe = NULL;

	spin_lock(&g_pend_lock);
	list_for_each_entry(pe, &g_pending_head, list) {
		if (pe->task->pid == pid) {
			atomic_inc(&pe->users);
			spin_unlock(&g_pend_lock);
			return pe;
		}
	}
	spin_unlock(&g_pend_lock);
	return NULL;
}

void foreach_pending_entry(void (*func)(struct pending_entry *))
{
	struct pending_entry *pe = NULL;

	if (!func)
		return;

	spin_lock(&g_pend_lock);
	list_for_each_entry(pe, &g_pending_head, list) {
		func(pe);
	}
	spin_unlock(&g_pend_lock);
}

void put_pending_entry(struct pending_entry *pe)
{
	if (!pe)
		return;

	if (!atomic_dec_and_test(&pe->users))
		return;

	put_task_struct(pe->task);
	kfree(pe);
}

#ifdef CONFIG_TA_AFFINITY
static void restore_cpu_mask(struct pending_entry *pe)
{
	if (cpumask_equal(&pe->ca_mask, &pe->ta_mask))
		return;

	set_cpus_allowed_ptr(current, &pe->ca_mask);
}
#endif

static void release_pending_entry(struct pending_entry *pe)
{
#ifdef CONFIG_TA_AFFINITY
	restore_cpu_mask(pe);
#endif
	spin_lock(&g_pend_lock);
	list_del(&pe->list);
	spin_unlock(&g_pend_lock);
	put_pending_entry(pe);
}

static inline bool is_shadow_exit(uint64_t target)
{
	return target & SMC_EXIT_TARGET_SHADOW_EXIT;
}

/*
 * check ca and ta's affinity is match in 2 scene:
 * 1. when TA is blocked to REE
 * 2. when CA is wakeup by SPI wakeup
 * match_ta_affinity return true if affinity is changed
 */
#ifdef CONFIG_TA_AFFINITY
static bool match_ta_affinity(struct pending_entry *pe)
{
	if (!cpumask_equal(CURRENT_CPUS_ALLOWED, &pe->ta_mask)) {
		if (set_cpus_allowed_ptr(current, &pe->ta_mask)) {
			tlogw("set %s affinity failed\n", current->comm);
			return false;
		}
		return true;
	}

	return false;
}
#else
static inline bool match_ta_affinity(struct pending_entry *pe)
{
	(void)pe;
	return false;
}
#endif

struct smc_cmd_ret {
	unsigned long exit;
	unsigned long ta;
	unsigned long target;
};

bool sigkill_pending(struct task_struct *tsk)
{
	bool flag = false;

	if (!tsk) {
		tloge("tsk is null!\n");
		return false;
	}

	flag = (sigismember(&tsk->pending.signal, SIGKILL) != 0) ||
		(sigismember(&tsk->pending.signal, SIGUSR1) != 0);

	if (tsk->signal)
		return flag || sigismember(&tsk->signal->shared_pending.signal,
			SIGKILL);
	return flag;
}

#if (CONFIG_CPU_AFF_NR != 0)
static void set_cpu_strategy(struct cpumask *old_mask)
{
	unsigned int i;

	if (g_mask_flag == 0) {
		cpumask_clear(&g_cpu_mask);
		for (i = 0; i < CONFIG_CPU_AFF_NR; i++)
			cpumask_set_cpu(i, &g_cpu_mask);
		g_mask_flag = 1;
	}
	cpumask_copy(old_mask, CURRENT_CPUS_ALLOWED);
	set_cpus_allowed_ptr(current, &g_cpu_mask);
}
#endif

#if (CONFIG_CPU_AFF_NR != 0)
static void restore_cpu(struct cpumask *old_mask)
{
	/* current equal old means no set cpu affinity, no need to restore */
	if (cpumask_equal(CURRENT_CPUS_ALLOWED, old_mask))
		return;

	set_cpus_allowed_ptr(current, old_mask);
	schedule();
}
#endif

static bool is_ready_to_kill(bool need_kill, uint32_t cmd_id)
{
#ifdef CONFIG_TEE_TELEPORT_SUPPORT
	if (cmd_id == GLOBAL_CMD_ID_PORTAL_WORK) {
		return (need_kill && sigkill_pending(current));
	} else {
		return (need_kill && sigkill_pending(current) && is_thread_reported(current->pid));
	}

#else
	(void)cmd_id;
	return (need_kill && sigkill_pending(current) && is_thread_reported(current->pid));
#endif
}

static void set_smc_send_arg(struct smc_in_params *in_param,
	const struct smc_cmd_ret *secret, unsigned long ops)
{
	if (secret->exit == SMC_EXIT_PREEMPTED) {
		in_param->x1 = SMC_OPS_SCHEDTO;
		in_param->x3 = secret->ta;
		in_param->x4 = secret->target;
	}

	if (ops == SMC_OPS_SCHEDTO || ops == SMC_OPS_START_FIQSHD)
		in_param->x4 = secret->target;

	tlogd("[cpu %d]begin send x0=%lx x1=%lx x2=%lx x3=%lx x4=%lx\n",
		raw_smp_processor_id(), in_param->x0, in_param->x1,
		in_param->x2, in_param->x3, in_param->x4);
}

static void send_smc_cmd(struct smc_in_params *in_param,
	struct smc_out_params *out_param, uint8_t wait)
{
	smc_req(in_param, out_param, wait);
}

static void send_smc_cmd_with_retry(struct smc_in_params *in_param,
	struct smc_out_params *out_param)
{
#if (CONFIG_CPU_AFF_NR != 0)
	struct cpumask old_mask;
	set_cpu_strategy(&old_mask);
#endif

retry:
	send_smc_cmd(in_param, out_param, 0);

	if (out_param->exit_reason == SMC_EXIT_PREEMPTED
		&& out_param->ret == TSP_RESPONSE) {
#if (!defined(CONFIG_PREEMPT)) || defined(CONFIG_RTOS_PREEMPT_OFF)
		cond_resched();
#endif
		in_param->x1 = SMC_OPS_SCHEDTO;
		goto retry;
	}
#if (CONFIG_CPU_AFF_NR != 0)
	restore_cpu(&old_mask);
#endif
}

#ifdef CONFIG_TEE_REBOOT
int send_smc_cmd_rebooting(uint32_t cmd_id, const struct tc_ns_smc_cmd *in_cmd)
{
	struct tc_ns_smc_cmd cmd = { {0}, 0 };
	struct smc_in_params in_param = {cmd_id, 0, 0, 0, TEE_ERROR_IS_DEAD};
	struct smc_out_params out_param = {0};
	int cmd_index = 0;

	if (in_cmd != NULL) {
		if (memcpy_s(&cmd, sizeof(cmd), in_cmd, sizeof(*in_cmd)) != EOK) {
			tloge("memcpy in cmd failed\n");
			return -EFAULT;
		}
#ifdef CONFIG_CONFIDENTIAL_CONTAINER
		cmd.nsid = task_active_pid_ns(current)->ns.inum;
#else
		cmd.nsid = PROC_PID_INIT_INO;
#endif

		cmd_index = occupy_free_smc_in_entry(&cmd);
		if (cmd_index == -1) {
			tloge("there's no more smc entry\n");
			return -ENOMEM;
		}
#ifdef CONFIG_TEE_UPGRADE
		in_param.x2 = cmd_index;
#endif
	}

	send_smc_cmd_with_retry(&in_param, &out_param);

	return out_param.exit_reason;
}
#else
int send_smc_cmd_rebooting(uint32_t cmd_id, const struct tc_ns_smc_cmd *in_cmd)
{
	(void)cmd_id;
	(void)in_cmd;
	return 0;
}
#endif

struct smc_send_param {
	uint32_t cmd;
	unsigned long ops;
	unsigned long ca;
};

static noinline int smp_smc_send(struct smc_send_param param,
	struct smc_cmd_ret *secret, bool need_kill, uint32_t cmd_id)
{
	struct smc_in_params in_param = { param.cmd, param.ops, param.ca, 0, 0 };
	struct smc_out_params out_param = {0};
#if (CONFIG_CPU_AFF_NR != 0)
	struct cpumask old_mask;
#endif

#if (CONFIG_CPU_AFF_NR != 0)
	set_cpu_strategy(&old_mask);
#endif
retry:
	set_smc_send_arg(&in_param, secret, param.ops);
	tee_trace_add_event(SMC_SEND, 0);
	send_smc_cmd(&in_param, &out_param, 0);
	tee_trace_add_event(SMC_DONE, 0);
	tlogd("[cpu %d] return val %lx exit_reason %lx ta %lx targ %lx\n",
		raw_smp_processor_id(), out_param.ret, out_param.exit_reason,
		out_param.ta, out_param.target);

	secret->exit = out_param.exit_reason;
	secret->ta = out_param.ta;
	secret->target = out_param.target;

	if (out_param.exit_reason == SMC_EXIT_PREEMPTED) {
		/*
		 * There's 2 ways to send a terminate cmd to kill a running TA,
		 * in current context or another. If send terminate in another
		 * context, may encounter concurrency problem, as terminate cmd
		 * is send but not process, the original cmd has finished.
		 * So we send the terminate cmd in current context.
		 */
		if (is_ready_to_kill(need_kill, cmd_id)) {
			secret->exit = SMC_EXIT_ABORT;
			tloge("receive kill signal\n");
		} else {
#if (!defined(CONFIG_PREEMPT)) || defined(CONFIG_RTOS_PREEMPT_OFF)
			/* yield cpu to avoid soft lockup */
			cond_resched();
#endif
			goto retry;
		}
	}
#if (CONFIG_CPU_AFF_NR != 0)
	restore_cpu(&old_mask);
#endif
	return (int)out_param.ret;
}

static unsigned long raw_smc_send(uint32_t cmd, uint32_t param1,
	uint32_t param2, uint8_t wait)
{
	struct smc_in_params in_param = {cmd, param1, param2};
	struct smc_out_params out_param = {0};

#if (CONFIG_CPU_AFF_NR != 0)
	struct cpumask old_mask;
	set_cpu_strategy(&old_mask);
#endif

	send_smc_cmd(&in_param, &out_param, wait);

#if (CONFIG_CPU_AFF_NR != 0)
	restore_cpu(&old_mask);
#endif
	return out_param.ret;
}

static void siq_dump(uint32_t mode, uint32_t siq_mode)
{
	int ret = raw_smc_send(TSP_REE_SIQ, mode, 0, false);
	if (ret == TSP_CRASH) {
		tloge("TEEOS has crashed!\n");
		g_sys_crash = true;
		cmd_monitor_ta_crash(TYPE_CRASH_TEE, NULL, 0);
	}

	if (siq_mode == SIQ_DUMP_TIMEOUT) {
		tz_log_write();
	} else if (siq_mode == SIQ_DUMP_SHELL) {
#ifdef CONFIG_TEE_LOG_DUMP_PATH
		(void)tlogger_store_msg(CONFIG_TEE_LOG_DUMP_PATH,
			sizeof(CONFIG_TEE_LOG_DUMP_PATH));
#else
		tz_log_write();
#endif
	}
	do_cmd_need_archivelog();
}

static uint32_t get_free_siq_index(void)
{
	uint32_t i;

	for (i = 0; i < MAX_SIQ_NUM; i++) {
		if (g_siq_queue[i] == 0)
			return i;
	}

	return MAX_SIQ_NUM;
}

static uint32_t get_undo_siq_index(void)
{
	uint32_t i;

	for (i = 0; i < MAX_SIQ_NUM; i++) {
		if (g_siq_queue[i] != 0)
			return i;
	}

	return MAX_SIQ_NUM;
}

#define RUN_SIQ_THREAD 1
#define STOP_SIQ_THREAD 2
#define MODE_DUMP 1
static int siq_thread_fn(void *arg)
{
	int ret;
	uint32_t i;
	(void)arg;

	while (true) {
		ret = (int)wait_event_interruptible(siq_th_wait,
			atomic_read(&g_siq_th_run));
		if (ret != 0) {
			tloge("wait event interruptible failed!\n");
			return -EINTR;
		}
		if (atomic_read(&g_siq_th_run) == STOP_SIQ_THREAD)
			return 0;

		mutex_lock(&g_siq_lock);
		do {
			i = get_undo_siq_index();
			if (i >= MAX_SIQ_NUM)
				break;
			siq_dump(MODE_DUMP, g_siq_queue[i]);
			g_siq_queue[i] = 0;
		} while (true);
		atomic_set(&g_siq_th_run, 0);
		mutex_unlock(&g_siq_lock);
	}
}

#ifdef CONFIG_TEE_AUDIT
#define MAX_UPLOAD_INFO_LEN      4
#define INFO_HIGH_OFFSET         24U
#define INFO_MID_OFFSET          16U
#define INFO_LOW_OFFSET          8U

static void upload_audit_event(unsigned int eventindex)
{
#ifdef CONFIG_HW_KERNEL_STP
	struct stp_item item;
	int ret;
	char att_info[MAX_UPLOAD_INFO_LEN + 1] = {0};

	att_info[0] = (unsigned char)(eventindex >> INFO_HIGH_OFFSET);
	att_info[1] = (unsigned char)(eventindex >> INFO_MID_OFFSET);
	att_info[2] = (unsigned char)(eventindex >> INFO_LOW_OFFSET);
	att_info[3] = (unsigned char)eventindex;
	att_info[MAX_UPLOAD_INFO_LEN] = '\0';
	item.id = item_info[ITRUSTEE].id; /* 0x00000185 */
	item.status = STP_RISK;
	item.credible = STP_REFERENCE;
	item.version = 0;
	ret = strcpy_s(item.name, STP_ITEM_NAME_LEN, STP_NAME_ITRUSTEE);
	if (ret) {
		tloge("strncpy failed %x\n", ret);
		return;
	}
	tlogd("stp get size %lx succ\n", sizeof(item_info[ITRUSTEE].name));
	ret = kernel_stp_upload(item, att_info);
	if (ret)
		tloge("stp %x event upload failed\n", eventindex);
	else
		tloge("stp %x event upload succ\n", eventindex);
#else
	(void)eventindex;
#endif
}
#endif

static void cmd_result_check(const struct tc_ns_smc_cmd *cmd, int cmd_index)
{
	if (cmd->ret_val == (int)TEEC_PENDING || cmd->ret_val == (int)TEEC_PENDING2)
		tlogd("wakeup command %u\n", cmd->event_nr);

	if (cmd->ret_val == (int)TEE_ERROR_TAGET_DEAD) {
		bool ta_killed = g_cmd_data->in[cmd_index].cmd_id == GLOBAL_CMD_ID_KILL_TASK;
		tloge("error smc call: ret = %x and cmd.err_origin=%x, [ta is %s]\n",
			cmd->ret_val, cmd->err_origin, (ta_killed == true) ? "killed" : "crash");
		cmd_monitor_ta_crash((ta_killed == true) ? TYPE_KILLED_TA : TYPE_CRASH_TA,
			cmd->uuid, sizeof(struct tc_uuid));
		ta_crash_report_log();
	} else if (cmd->ret_val == (int)TEEC_ERROR_TUI_NOT_AVAILABLE) {
		do_ns_tui_release();
	} else if (cmd->ret_val == (int)TEE_ERROR_AUDIT_FAIL) {
		tloge("error smc call: ret = %x and err-origin=%x\n",
			cmd->ret_val, cmd->err_origin);
#ifdef CONFIG_TEE_AUDIT
		tloge("error smc call: status = %x and err-origin=%x\n",
			cmd->eventindex, cmd->err_origin);
		upload_audit_event(cmd->eventindex);
#endif
	}
}

static void set_shadow_smc_param(struct smc_in_params *in_params,
	const struct smc_out_params *out_params, int *n_idled)
{
	if (out_params->exit_reason == SMC_EXIT_PREEMPTED) {
		in_params->x0 = TSP_REQUEST;
		in_params->x1 = SMC_OPS_SCHEDTO;
		in_params->x2 = (unsigned long)current->pid;
		in_params->x3 = out_params->ta;
		in_params->x4 = out_params->target;
	} else if (out_params->exit_reason == SMC_EXIT_NORMAL) {
		in_params->x0 = TSP_REQUEST;
		in_params->x1 = SMC_OPS_SCHEDTO;
		in_params->x2 = (unsigned long)current->pid;
		in_params->x3 = 0;
		in_params->x4 = 0;
		if (*n_idled > IDLED_COUNT) {
			*n_idled = 0;
			in_params->x1 = SMC_OPS_PROBE_ALIVE;
		}
	}
}

static void shadow_wo_pm(const void *arg, struct smc_out_params *out_params,
	int *n_idled)
{
	struct smc_in_params in_params = {
		TSP_REQUEST, SMC_OPS_START_SHADOW, current->pid, 0, *(unsigned long *)arg
	};

	set_shadow_smc_param(&in_params, out_params, n_idled);
	tlogd("%s: [cpu %d] x0=%lx x1=%lx x2=%lx x3=%lx x4=%lx\n",
		__func__, raw_smp_processor_id(), in_params.x0, in_params.x1,
		in_params.x2, in_params.x3, in_params.x4);

	smc_req(&in_params, out_params, 0);
}

static void set_preempted_counter(int *n_preempted, int *n_idled,
	struct pending_entry *pe)
{
	*n_idled = 0;
	(*n_preempted)++;

	if (*n_preempted > PREEMPT_COUNT) {
		tlogd("counter too large: retry 10K times on CPU%d\n", smp_processor_id());
		*n_preempted = 0;
	}
#ifndef CONFIG_PREEMPT
	/* yield cpu to avoid soft lockup */
	cond_resched();
#endif
	if (match_ta_affinity(pe))
		tloge("set shadow pid %d affinity after preempted\n",
			pe->task->pid);
}

static int proc_shadow_thread_normal_exit(struct pending_entry *pe,
	int *n_preempted, int *n_idled, int *ret_val)
{
	long long timeout;
	int rc;

	if (power_down_cc() != 0) {
		tloge("power down cc failed\n");
		*ret_val = -1;
		return CLEAN_WITHOUT_PM;
	}
	*n_preempted = 0;

	timeout = HZ * (long)(HZ_COUNT + ((uint8_t)current->pid & LOW_BYTE));
	rc = (int)wait_event_freezable_timeout(pe->wq,
		atomic_read(&pe->run), (long)timeout);
	if (rc == 0)
		(*n_idled)++;
	if (atomic_read(&pe->run) == SHADOW_EXIT_RUN) {
		tlogd("shadow thread work quit, be killed\n");
		return CLEAN_WITHOUT_PM;
	} else {
		atomic_set(&pe->run, 0);
		return RETRY_WITH_PM;
	}

	return 0;
}

static bool check_shadow_crash(uint64_t crash_reason, int *ret_val)
{
	if (crash_reason != TSP_CRASH)
		return false;

	tloge("TEEOS shadow has crashed!\n");
	if (power_down_cc() != 0)
		tloge("power down cc failed\n");

	g_sys_crash = true;
	cmd_monitor_ta_crash(TYPE_CRASH_TEE, NULL, 0);
	report_log_system_error();
	*ret_val = -1;
	return true;
}

static void show_other_exit_reason(const struct smc_out_params *params)
{
	if (params->exit_reason == SMC_EXIT_SHADOW) {
		tlogd("probe shadow thread non exit, just quit\n");
		return;
	}

	tloge("exit on unknown code %ld\n", (long)params->exit_reason);
}

static int shadow_thread_fn(void *arg)
{
	int n_preempted = 0;
	int ret = 0;
	struct smc_out_params params = { 0, SMC_EXIT_MAX, 0, 0 };
	int n_idled = 0;
	struct pending_entry *pe = NULL;

	set_freezable();
	pe = init_pending_entry();
	if (!pe) {
		kfree(arg);
		tloge("init pending entry failed\n");
		return -ENOMEM;
	}
	isb();
	wmb();

retry:
	if (power_on_cc() != 0) {
		ret = -EINVAL;
		tloge("power on cc failed\n");
		goto clean_wo_pm;
	}

retry_wo_pm:
	shadow_wo_pm(arg, &params, &n_idled);
	if (check_shadow_crash(params.ret, &ret))
		goto clean_wo_pm;

	if (params.exit_reason == SMC_EXIT_PREEMPTED) {
		set_preempted_counter(&n_preempted, &n_idled, pe);
		goto retry_wo_pm;
	} else if (params.exit_reason == SMC_EXIT_NORMAL) {
		ret = proc_shadow_thread_normal_exit(pe, &n_preempted, &n_idled, &ret);
		if (ret == CLEAN_WITHOUT_PM) {
			goto clean_wo_pm;
		} else if (ret == RETRY_WITH_PM) {
			if (match_ta_affinity(pe))
				tlogd("set shadow pid %d\n", pe->task->pid);
			goto retry;
		}
	} else {
		show_other_exit_reason(&params);
	}

	if (power_down_cc() != 0) {
		tloge("power down cc failed\n");
		ret = -1;
	}
clean_wo_pm:
	kfree(arg);
	release_pending_entry(pe);
	return ret;
}

static void shadow_work_func(struct kthread_work *work)
{
	struct task_struct *shadow_thread = NULL;
	struct shadow_work *s_work =
		container_of(work, struct shadow_work, kthwork);
	uint64_t *target_arg = kzalloc(sizeof(uint64_t), GFP_KERNEL);

	if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)target_arg)) {
		tloge("%s: kmalloc failed\n", __func__);
		return;
	}

	*target_arg = s_work->target;
	shadow_thread = kthread_create(shadow_thread_fn,
		(void *)(uintptr_t)target_arg, "shadow th/%lu",
		g_shadow_thread_id++);
	if (IS_ERR_OR_NULL(shadow_thread)) {
		kfree(target_arg);
		tloge("couldn't create shadow_thread %ld\n",
			PTR_ERR(shadow_thread));
		return;
	}
	tlogd("%s: create shadow thread %lu for target %llx\n",
		__func__, g_shadow_thread_id, *target_arg);
#if CONFIG_CPU_AFF_NR
	struct cpumask shadow_mask;
	unsigned int i;

	cpumask_clear(&shadow_mask);
	for (i = 0; i < CONFIG_CPU_AFF_NR; i++)
		cpumask_set_cpu(i, &shadow_mask);

	koadpt_kthread_bind_mask(shadow_thread, &shadow_mask);
#else
	tz_kthread_bind_mask(shadow_thread);
#endif
	wake_up_process(shadow_thread);
}

static int proc_smc_wakeup_ca(pid_t ca, int which)
{
	if (ca <= 0) {
		tlogw("wakeup for ca <= 0\n");
	} else {
		struct pending_entry *pe = find_pending_entry(ca);

		if (!pe) {
			(void)raw_smc_send(TSP_REE_SIQ, (uint32_t)ca, 0, false);
			tlogd("invalid ca pid=%d for pending entry\n",
				(int)ca);
			return -1;
		}
		atomic_set(&pe->run, which);
		wake_up(&pe->wq);
		tlogd("wakeup pending thread %ld\n", (long)ca);
		put_pending_entry(pe);
	}
	return 0;
}

void wakeup_pe(struct pending_entry *pe)
{
	if (!pe)
		return;

	atomic_set(&pe->run, 1);
	wake_up(&pe->wq);
}

int smc_wakeup_broadcast(void)
{
	foreach_pending_entry(wakeup_pe);
	return 0;
}

int smc_wakeup_ca(pid_t ca)
{
	tee_trace_add_event(SPI_WAKEUP, (uint64_t)ca);
	return proc_smc_wakeup_ca(ca, 1);
}

int smc_shadow_exit(pid_t ca)
{
	return proc_smc_wakeup_ca(ca, SHADOW_EXIT_RUN);
}

void fiq_shadow_work_func(uint64_t target)
{
	struct smc_cmd_ret secret = { SMC_EXIT_MAX, 0, target };
	tee_trace_add_event(INTERRUPT_HANDLE_SPI_REE_SCHEDULED, target);
	secs_suspend_status(target);
	if (power_on_cc() != 0) {
		tloge("power on cc failed\n");
		return;
	}

	livepatch_down_read_sem();
	struct smc_send_param param = {.cmd = TSP_REQUEST, .ops = (unsigned long)SMC_OPS_START_FIQSHD,
                                    .ca = (unsigned long)(uint32_t)(current->pid)};
	smp_smc_send(param, &secret, false, 0);
	livepatch_up_read_sem();

	if (power_down_cc() != 0)
		tloge("power down cc failed\n");

	return;
}

int smc_queue_shadow_worker(uint64_t target)
{
	struct shadow_work work = {
		KTHREAD_WORK_INIT(work.kthwork, shadow_work_func),
		.target = target,
	};

#if (KERNEL_VERSION(4, 9, 0) > LINUX_VERSION_CODE)
	if (!queue_kthread_work(g_ipi_helper_worker, &work.kthwork)) {
#else
	if (!kthread_queue_work(g_ipi_helper_worker, &work.kthwork)) {
#endif
		tloge("ipi helper work fail queue, was already pending\n");
		return -1;
	}

#if (KERNEL_VERSION(4, 9, 0) > LINUX_VERSION_CODE)
	flush_kthread_work(&work.kthwork);
#else
	kthread_flush_work(&work.kthwork);
#endif
	return 0;
}

#ifdef CONFIG_DRM_ADAPT
#define DRM_USR_PRIOR (-5)
static void set_drm_strategy(void)
{
	if (!g_drm_mask_flag) {
		cpumask_clear(&g_drm_cpu_mask);
		cpumask_set_cpu(CPU_FOUR, &g_drm_cpu_mask);
		cpumask_set_cpu(CPU_FIVE, &g_drm_cpu_mask);
		cpumask_set_cpu(CPU_SIX, &g_drm_cpu_mask);
		cpumask_set_cpu(CPU_SEVEN, &g_drm_cpu_mask);
		g_drm_mask_flag = 1;
	}

	if (current->group_leader &&
		strstr(current->group_leader->comm, "drm@1.")) {
		set_cpus_allowed_ptr(current, &g_drm_cpu_mask);
		set_user_nice(current, DRM_USR_PRIOR);
	}
}
#endif

static int smc_ops_normal(struct cmd_reuse_info *info,
	const struct tc_ns_smc_cmd *cmd, u64 ops)
{
	if (ops != SMC_OPS_NORMAL)
		return 0;

	if (info->cmd_usage == RESEND) {
		if (reuse_smc_in_entry((uint32_t)info->cmd_index) != 0) {
			tloge("reuse smc entry failed\n");
			release_smc_entry((uint32_t)info->cmd_index);
			return -ENOMEM;
		}
	} else {
		info->cmd_index = occupy_free_smc_in_entry(cmd);
		if (info->cmd_index == -1) {
			tloge("there's no more smc entry\n");
			return -ENOMEM;
		}
	}

	if (info->cmd_usage != CLEAR) {
		info->cmd_index = info->saved_index;
		info->cmd_usage = CLEAR;
	} else {
		info->saved_index = info->cmd_index;
	}

	tlogd("submit new cmd: cmd.ca=%u cmd-id=%x ev-nr=%u "
		"cmd-index=%u saved-index=%d\n",
		cmd->ca_pid, cmd->cmd_id,
		g_cmd_data->in[info->cmd_index].event_nr, info->cmd_index,
		info->saved_index);
	return 0;
}

static int smp_smc_send_cmd_done(int cmd_index, struct tc_ns_smc_cmd *cmd,
	struct tc_ns_smc_cmd *in)
{
	cmd_result_check(cmd, cmd_index);
	switch (cmd->ret_val) {
	case TEEC_PENDING2: {
		unsigned int agent_id = cmd->agent_id;
		unsigned int nsid = cmd->nsid;
		/* If the agent does not exist post
		 * the answer right back to the TEE
		 */
		if (agent_process_work(cmd, agent_id, nsid) != 0)
			tloge("agent process work failed\n");
		return PENDING2_RETRY;
	}
	case TEE_ERROR_TAGET_DEAD:
	case TEEC_PENDING:
	/* just copy out, and let out to proceed */
	default:
		if (memcpy_s(in, sizeof(*in), cmd, sizeof(*cmd)) != EOK) {
			tloge("memcpy failed,%s line:%d", __func__, __LINE__);
			cmd->ret_val = -1;
		}

		break;
	}

	return 0;
}

#define KERNEL_INDEX 5
static void print_crash_msg(union crash_inf *crash_info)
{
	static const char *tee_critical_app[] = {
		"gtask",
		"teesmcmgr",
		"hmsysmgr",
		"hmfilemgr",
		"platdrv",
		"kernel", /* index must be same with KERNEL_INDEX */
		"vltmm_service",
		"tee_drv_server"
	};
	int app_num = sizeof(tee_critical_app) / sizeof(tee_critical_app[0]);
	const char *crash_app_name = "NULL";
	uint16_t off = crash_info->crash_msg.off;
	int app_index = crash_info->crash_msg.app & LOW_BYTE;
	int halt_reason = crash_info->crash_msg.halt_reason;

	crash_info->crash_msg.off = 0;

	if (app_index >= 0 && app_index < app_num)
		crash_app_name = tee_critical_app[app_index];
	else
		tloge("index error: %x\n", crash_info->crash_msg.app);

	if (app_index == KERNEL_INDEX) {
		tloge("====crash app:%s user sym:%s kernel crash off/size: "
			"<0x%x/0x%x>\n", crash_app_name,
			crash_info->crash_msg.sym_name,
			off, crash_info->crash_msg.size);
		tloge("====crash halt reason: 0x%x far:0x%x fault:0x%x "
			"elr:0x%x (ret_ip: 0x%llx)\n",
			halt_reason, crash_info->crash_msg.far,
			crash_info->crash_msg.fault, crash_info->crash_msg.elr,
			crash_info->crash_reg[2]);
	} else {
		char syms[SYM_NAME_LEN_MAX] = {0};

		if (memcpy_s(syms, SYM_NAME_LEN_MAX,
			crash_info->crash_msg.sym_name, SYM_NAME_LEN_1) != EOK)
			tloge("memcpy sym name failed!\n");

		if (memcpy_s(syms + SYM_NAME_LEN_1,
			SYM_NAME_LEN_MAX - SYM_NAME_LEN_1,
			crash_info->crash_msg.sym_name_append, SYM_NAME_LEN_2) != EOK)
			tloge("memcpy sym_name_append failed!\n");
		tloge("====crash app:%s user_sym:%s + <0x%x/0x%x>\n",
		      crash_app_name, syms, off, crash_info->crash_msg.size);
		tloge("====crash far:0x%x fault:%x\n",
		      crash_info->crash_msg.far, crash_info->crash_msg.fault);
	}
}

void clr_system_crash_flag(void)
{
	g_sys_crash = false;
}

static int smp_smc_send_process(struct tc_ns_smc_cmd *cmd, u64 ops,
	struct smc_cmd_ret *cmd_ret, int cmd_index)
{
	int ret;
	unsigned long ca;
	tlogd("smc send start cmd_id = %u, ca = %u\n",
		cmd->cmd_id, cmd->ca_pid);

	if (power_on_cc() != 0) {
		tloge("power on cc failed\n");
		cmd->ret_val = -1;
		return -1;
	}

	ca = is_ccos() ? (cmd_index) : ((unsigned long)(uint32_t)(current->pid));
	struct smc_send_param param = {.cmd = TSP_REQUEST, .ops = (unsigned long)ops, ca};
	ret = smp_smc_send(param, cmd_ret, ops != SMC_OPS_ABORT_TASK, cmd->cmd_id);

	if (power_down_cc() != 0) {
		tloge("power down cc failed\n");
		cmd->ret_val = -1;
		return -1;
	}

	tlogd("smc send ret = %x, cmd ret.exit=%ld, cmd index=%d\n",
		ret, (long)cmd_ret->exit, cmd_index);
	isb();
	wmb();
	if (ret == (int)TSP_CRASH) {
		union crash_inf crash_info;
		crash_info.crash_reg[0] = cmd_ret->exit;
		crash_info.crash_reg[1] = cmd_ret->ta;
		crash_info.crash_reg[2] = cmd_ret->target;

		tloge("TEEOS has crashed!\n");
		print_crash_msg(&crash_info);

		g_sys_crash = true;
		cmd_monitor_ta_crash(TYPE_CRASH_TEE, NULL, 0);

		tee_wake_up_reboot();
#ifndef CONFIG_TEE_REBOOT
		report_log_system_error();
#endif
		cmd->ret_val = TEE_ERROR_IS_DEAD;
		return -1;
	}

	return 0;
}

static int init_for_smc_send(struct tc_ns_smc_cmd *in,
	struct pending_entry **pe, struct tc_ns_smc_cmd *cmd,
	bool reuse)
{
#ifdef CONFIG_DRM_ADAPT
	set_drm_strategy();
#endif
	*pe = init_pending_entry();
	if (!(*pe)) {
		tloge("init pending entry failed\n");
		return -ENOMEM;
	}

	in->ca_pid = (unsigned int)current->pid;
#ifdef CONFIG_CONFIDENTIAL_CONTAINER
	if (in->nsid == 0)
		in->nsid = task_active_pid_ns(current)->ns.inum;
#else
	in->nsid = PROC_PID_INIT_INO;
#endif

	if (reuse)
		return 0;

	if (memcpy_s(cmd, sizeof(*cmd), in, sizeof(*in)) != EOK) {
		tloge("memcpy in cmd failed\n");
		release_pending_entry(*pe);
		return -EFAULT;
	}

	return 0;
}

static bool is_ca_killed(int cmd_index)
{
	(void)cmd_index;
	/* if CA has not been killed */
	if (sigkill_pending(current)) {
		/* signal pending, send abort cmd */
		tloge("wait event timeout and find pending signal\n");
		return true;
	}
	return false;
}

static void clean_smc_resrc(struct cmd_reuse_info info,
	const struct tc_ns_smc_cmd *cmd,
	struct pending_entry *pe)
{
	if (info.cmd_usage != CLEAR && cmd->ret_val != (int)TEEC_PENDING)
		release_smc_entry((uint32_t)info.cmd_index);

	release_pending_entry(pe);
}

static int set_abort_cmd(int index)
{
	acquire_smc_buf_lock(&g_cmd_data->smc_lock);
	if (test_bit(index, (unsigned long *)g_cmd_data->doing_bitmap) == 0) {
		release_smc_buf_lock(&g_cmd_data->smc_lock);
		tloge("can't abort an unprocess cmd\n");
		return -1;
	}

	g_cmd_data->in[index].cmd_id = GLOBAL_CMD_ID_KILL_TASK;
	g_cmd_data->in[index].cmd_type = CMD_TYPE_GLOBAL;
	/* these phy addrs are not necessary, clear them to avoid gtask check err */
	g_cmd_data->in[index].operation_phys = 0;
	g_cmd_data->in[index].operation_h_phys = 0;
	g_cmd_data->in[index].login_data_phy = 0;
	g_cmd_data->in[index].login_data_h_addr = 0;

	clear_bit((unsigned int)index, (unsigned long *)g_cmd_data->doing_bitmap);
	release_smc_buf_lock(&g_cmd_data->smc_lock);
	tloge("set abort cmd success\n");

	return 0;
}

static enum smc_ops_exit process_abort_cmd(int index, const struct pending_entry *pe)
{
	(void)pe;
	if (set_abort_cmd(index) == 0)
		return SMC_OPS_ABORT_TASK;

	return SMC_OPS_SCHEDTO;
}

#define TO_STEP_SIZE 5
#define INVALID_STEP_SIZE 0xFFFFFFFFU

struct timeout_step_t {
	unsigned long steps[TO_STEP_SIZE];
	uint32_t size;
	uint32_t cur;
	bool timeout_reset;
};

static void init_timeout_step(uint32_t timeout, struct timeout_step_t *step)
{
	uint32_t i = 0;

	if (timeout == 0) {
		step->steps[0] = RESLEEP_TIMEOUT * HZ;
		step->size = 1;
	} else {
		uint32_t timeout_in_jiffies;

		if (timeout > RESLEEP_TIMEOUT * MSEC_PER_SEC)
			timeout = RESLEEP_TIMEOUT * MSEC_PER_SEC;
		timeout_in_jiffies = (uint32_t)msecs_to_jiffies(timeout);

		/*
		 * [timeout_in_jiffies-1, timeout_in_jiffies+2] jiffies
		 * As REE and TEE tick have deviation, to make sure last REE timeout
		 * is after TEE timeout, we set a timeout step from
		 * 'timeout_in_jiffies -1' to 'timeout_in_jiffies + 2'
		 */
		if (timeout_in_jiffies > 1) {
			step->steps[i++] = timeout_in_jiffies - 1;
			step->steps[i++] = 1;
		} else {
			step->steps[i++] = timeout_in_jiffies;
		}
		step->steps[i++] = 1;
		step->steps[i++] = 1;

		if (RESLEEP_TIMEOUT * HZ > (timeout_in_jiffies + 2))
			step->steps[i++] = RESLEEP_TIMEOUT * HZ - 2 - timeout_in_jiffies;
		step->size = i;
	}
	step->cur = 0;
}

enum pending_t {
	PD_WAKEUP,
	PD_TIMEOUT,
	PD_DONE,
	PD_RETRY,
};

enum smc_status_t {
	ST_DONE,
	ST_RETRY,
};

static long wait_event_internal(struct pending_entry *pe, struct timeout_step_t *step)
{
	if (!current->mm) {
		return wait_event_freezable_timeout(pe->wq, atomic_read(&pe->run),
				step->steps[step->cur]);
	} else {
		return wait_event_timeout(pe->wq, atomic_read(&pe->run),
				step->steps[step->cur]);
	}
}
static enum pending_t proc_ta_pending(struct pending_entry *pe,
	struct timeout_step_t *step, uint64_t pending_args, uint32_t cmd_index,
	u64 *ops)
{
	bool kernel_call = false;
	bool woke_up = false;
	/*
	 * if ->mm is NULL, it's a kernel thread and a kthread will never
	 * receive a signal.
	 */
	uint32_t timeout = (uint32_t)pending_args;
	bool timer_no_irq = (pending_args >> 32) == 0 ? false : true;
	uint32_t cur_timeout;
	if (step->cur == INVALID_STEP_SIZE)
		init_timeout_step(timeout, step);
	if (!current->mm)
		kernel_call = true;
resleep:
	cur_timeout = jiffies_to_msecs(step->steps[step->cur]);
	tee_trace_add_event(SMC_SLEEP, 0);
	if (wait_event_internal(pe, step) == 0) {
		if (step->cur < (step->size - 1)) {
			step->cur++;
			/*
			 * As there may no timer irq in TEE, we need a chance to
			 * run timer's irq handler initiatively by SMC_OPS_SCHEDTO.
			 */
			if (timer_no_irq) {
				*ops = SMC_OPS_SCHEDTO;
				return PD_WAKEUP;
			} else {
				goto resleep;
			}
		}
		if (is_ca_killed(cmd_index)) {
			*ops = (u64)process_abort_cmd(cmd_index, pe);
			return PD_WAKEUP;
		}
	} else {
		woke_up = true;
		tlogd("%s woke up\n", __func__);
	}
	atomic_set(&pe->run, 0);
	if (!is_cmd_working_done(cmd_index)) {
		*ops = SMC_OPS_SCHEDTO;
		return PD_WAKEUP;
	} else if (!kernel_call && !woke_up) {
		tloge("cmd done, may miss a spi!\n");
		show_cmd_bitmap();
	}
	tlogd("cmd is done\n");
	return PD_DONE;
}

static void set_timeout_step(struct timeout_step_t *timeout_step)
{
	if (!timeout_step->timeout_reset)
		return;

	timeout_step->cur = INVALID_STEP_SIZE;
	timeout_step->timeout_reset = false;
}

static enum smc_status_t proc_normal_exit(struct pending_entry *pe, u64 *ops,
	struct timeout_step_t *timeout_step, struct smc_cmd_ret *cmd_ret,
	int cmd_index)
{
	enum pending_t pd_ret;

	/* notify and set affinity came first, goto retry directly */
	if (match_ta_affinity(pe)) {
		*ops = SMC_OPS_SCHEDTO;
		return ST_RETRY;
	}

	pd_ret = proc_ta_pending(pe, timeout_step,
		cmd_ret->ta, (uint32_t)cmd_index, ops);
	if (pd_ret == PD_DONE)
		return ST_DONE;

	if (pd_ret == PD_WAKEUP)
		timeout_step->timeout_reset = true;
	return ST_RETRY;
}

static enum smc_status_t handle_cmd_working_done(
	struct tc_ns_smc_cmd *cmd, u64 *ops, struct tc_ns_smc_cmd *in,
	struct cmd_reuse_info *info)
{
	if (copy_smc_out_entry((uint32_t)info->cmd_index, cmd, &info->cmd_usage) != 0) {
		cmd->ret_val = TEEC_ERROR_GENERIC;
		return ST_DONE;
	}

	if (smp_smc_send_cmd_done(info->cmd_index, cmd, in) != 0) {
		*ops = SMC_OPS_NORMAL; /* cmd will be reused */
		return ST_RETRY;
	}

	return ST_DONE;
}

static void set_cmd_reuse_info(struct cmd_reuse_info *info, struct tc_ns_smc_cmd *in)
{
	info->saved_index = (int)in->event_nr;
	info->cmd_index = (int)in->event_nr;
	info->cmd_usage = RESEND;
}

static int smp_smc_send_func(struct tc_ns_smc_cmd *in, bool reuse)
{
	struct cmd_reuse_info info = { 0, 0, CLEAR };
	struct smc_cmd_ret cmd_ret = {0};
	struct tc_ns_smc_cmd cmd = { {0}, 0 };
	struct pending_entry *pe = NULL;
	u64 ops;
	struct timeout_step_t timeout_step =
		{{0, 0, 0, 0}, TO_STEP_SIZE, -1, false};

	if (init_for_smc_send(in, &pe, &cmd, reuse) != 0)
		return TEEC_ERROR_GENERIC;

	if (reuse)
		set_cmd_reuse_info(&info, in);
	ops = SMC_OPS_NORMAL;

retry:
#ifdef CONFIG_TEE_REBOOT
	if (is_tee_rebooting() && in->cmd_id == GLOBAL_CMD_ID_SET_SERVE_CMD) {
		release_pending_entry(pe);
		return TEE_ERROR_IS_DEAD;
	}
#endif

	set_timeout_step(&timeout_step);

	if (smc_ops_normal(&info, &cmd, ops) != 0) {
		release_pending_entry(pe);
		return TEEC_ERROR_GENERIC;
	}

	if (smp_smc_send_process(&cmd, ops, &cmd_ret, info.cmd_index) == -1)
		goto clean;

	if (!is_cmd_working_done((uint32_t)info.cmd_index)) {
		if (cmd_ret.exit == SMC_EXIT_NORMAL) {
			if (proc_normal_exit(pe, &ops, &timeout_step, &cmd_ret,
				info.cmd_index) == ST_RETRY)
				goto retry;
		} else if (cmd_ret.exit == SMC_EXIT_ABORT) {
			ops = (u64)process_abort_cmd(info.cmd_index, pe);
			goto retry;
		} else {
			tloge("invalid cmd work state\n");
			cmd.ret_val = TEEC_ERROR_GENERIC;
			goto clean;
		}
	}

	if (handle_cmd_working_done(&cmd, &ops, in, &info) == ST_RETRY)
		goto retry;
clean:
	clean_smc_resrc(info, &cmd, pe);
	return cmd.ret_val;
}

static int smc_svc_thread_fn(void *arg)
{
	(void)arg;
	set_freezable();
	while (!kthread_should_stop()) {
		struct tc_ns_smc_cmd smc_cmd = { {0}, 0 };
		int ret;

		smc_cmd.cmd_type = CMD_TYPE_GLOBAL;
		smc_cmd.cmd_id = GLOBAL_CMD_ID_SET_SERVE_CMD;
		ret = smp_smc_send_func(&smc_cmd, false);
		tlogd("smc svc return 0x%x\n", ret);
		/* add schedule to avoid upgrading or rebooting soft lockup */
		cond_resched();
	}
	tloge("smc svc thread stop\n");
	return 0;
}

bool __attribute__((weak)) is_tee_hungtask(struct task_struct *task)
{
	(void)task;

	return false;
}

void wakeup_tc_siq(uint32_t siq_mode)
{
	uint32_t i;

	if (siq_mode == 0)
		return;

	mutex_lock(&g_siq_lock);
	i = get_free_siq_index();
	if (i >= MAX_SIQ_NUM) {
		tloge("dump is too frequent\n");
		mutex_unlock(&g_siq_lock);
		return;
	}
	g_siq_queue[i] = siq_mode;
	atomic_set(&g_siq_th_run, RUN_SIQ_THREAD);
	mutex_unlock(&g_siq_lock);
	wake_up_interruptible(&siq_th_wait);
}

/*
 * This function first power on crypto cell, then send smc cmd to trustedcore.
 * After finished, power off crypto cell.
 */
static int proc_tc_ns_smc(struct tc_ns_smc_cmd *cmd, bool reuse)
{
	int ret;
	struct cmd_monitor *item = NULL;

	if (g_sys_crash) {
		tloge("ERROR: sys crash happened!!!\n");
		return TEE_ERROR_IS_DEAD;
	}

#ifdef CONFIG_TEE_UPGRADE
	if (is_tee_rebooting()) {
		tloge("tee is upgrading\n");
		return TEE_ERROR_IS_DEAD;
	}
#endif

	if (!cmd) {
		tloge("invalid cmd\n");
		return TEEC_ERROR_GENERIC;
	}
	tlogd(KERN_INFO "***smc call start on cpu %d ***\n",
		raw_smp_processor_id());

	item = cmd_monitor_log(cmd);
	ret = smp_smc_send_func(cmd, reuse);
	cmd_monitor_logend(item);

	return ret;
}

int tc_ns_smc(struct tc_ns_smc_cmd *cmd)
{
	return proc_tc_ns_smc(cmd, false);
}

int tc_ns_smc_with_no_nr(struct tc_ns_smc_cmd *cmd)
{
	return proc_tc_ns_smc(cmd, true);
}

void send_smc_cmd_buffer(bool tee_is_dead)
{
	struct smc_in_params in_param = {TSP_REQUEST, g_cmd_phys, TC_NS_CMD_TYPE_SECURE_CONFIG,
		g_cmd_phys >> ADDR_TRANS_NUM};
	struct smc_out_params out_param = {0};

	if (tee_is_dead)
		in_param.x4 = TEE_ERROR_IS_DEAD;

	send_smc_cmd_with_retry(&in_param, &out_param);
}

static void smc_work_set_cmd_buffer(struct work_struct *work)
{
	(void)work;
	send_smc_cmd_buffer(false);
}

void smc_set_cmd_buffer(void)
{
	struct work_struct work;
	if (g_reserved_cmd_buffer)
		return;

	INIT_WORK_ONSTACK(&work, smc_work_set_cmd_buffer);
	/* Run work on CPU 0 */
	schedule_work_on(0, &work);
	flush_work(&work);
	tlogd("smc set cmd buffer done\n");
}

static int alloc_cmd_buffer(void)
{
	if (g_reserved_cmd_buffer) {
		tlogi("use reserved cmd buffer");
		g_cmd_data = (struct tc_ns_smc_queue *)get_reserved_cmd_vaddr_of(g_cmd_phys, (uint64_t)g_cmd_size);
		if (!g_cmd_data)
			return -ENOMEM;

		return 0;
	}
	g_cmd_data = (struct tc_ns_smc_queue *)(uintptr_t)get_cmd_mem_vaddr();
	if (!g_cmd_data)
		return -ENOMEM;

	g_cmd_phys = get_cmd_mem_paddr((uint64_t)(uintptr_t)g_cmd_data);
	return 0;
}

static int init_smc_related_rsrc(const struct device *class_dev)
{
	struct cpumask new_mask;
	int ret;

	/*
	 * TEE Dump will disable IRQ/FIQ for about 500 ms, it's not
	 * a good choice to ask CPU0/CPU1 to do the dump.
	 * So, bind this kernel thread to other CPUs rather than CPU0/CPU1.
	 */
	cpumask_setall(&new_mask);
	cpumask_clear_cpu(CPU_ZERO, &new_mask);
	cpumask_clear_cpu(CPU_ONE, &new_mask);
	koadpt_kthread_bind_mask(g_siq_thread, &new_mask);
	/* some products specify the cpu that kthread need to bind */
	tz_kthread_bind_mask(g_siq_thread);
	g_ipi_helper_worker = kthread_create_worker(0, "g_ipi_helper_worker");
	g_ipi_helper_thread = kthread_create(kthread_worker_fn,
		g_ipi_helper_worker, "ipihelper");
	if (IS_ERR_OR_NULL(g_ipi_helper_thread)) {
		dev_err(class_dev, "couldn't create ipi helper threads %ld\n",
			PTR_ERR(g_ipi_helper_thread));
		ret = (int)PTR_ERR(g_ipi_helper_thread);
		return ret;
	}

	tz_kthread_bind_mask(g_ipi_helper_thread);
	wake_up_process(g_ipi_helper_thread);
	wake_up_process(g_siq_thread);
	init_cmd_monitor();
	INIT_LIST_HEAD(&g_pending_head);
	spin_lock_init(&g_pend_lock);

	return 0;
}

int parse_params_from_tee(void)
{
	int ret;
	void *buffer = NULL;

	if (g_reserved_cmd_buffer) {
		tlogw("uefi mode, not check teeos compat level\n");
		return 0;
	}

	buffer = (void *)(g_cmd_data->in);
	ret = check_teeos_compat_level((uint32_t *)buffer,
		COMPAT_LEVEL_BUF_LEN);
	if (ret != 0) {
		tloge("check teeos compatibility failed\n");
		return ret;
	}
	if (memset_s(buffer, sizeof(g_cmd_data->in),
		0, sizeof(g_cmd_data->in)) != EOK) {
		tloge("Clean the command buffer failed\n");
		ret = -EFAULT;
		return ret;
	}
	return 0;
}

int smc_context_init(const struct device *class_dev)
{
	int ret;

	if (!class_dev || IS_ERR_OR_NULL(class_dev))
		return -ENOMEM;

	ret = alloc_cmd_buffer();
	if (ret != 0)
		return ret;

	/* Send the allocated buffer to TrustedCore for init */
	smc_set_cmd_buffer();

	ret = parse_params_from_tee();
	if (ret != 0) {
		tloge("parse params from tee failed\n");
		goto free_mem;
	}

	g_siq_thread = kthread_create(siq_thread_fn, NULL, "siqthread/%d", 0);
	if (unlikely(IS_ERR_OR_NULL(g_siq_thread))) {
		dev_err(class_dev, "couldn't create siqthread %ld\n",
			PTR_ERR(g_siq_thread));
		ret = (int)PTR_ERR(g_siq_thread);
		goto free_mem;
	}

	ret = init_smc_related_rsrc(class_dev);
	if (ret != 0)
		goto free_siq_worker;

	return 0;

free_siq_worker:
	kthread_stop(g_siq_thread);
	g_siq_thread = NULL;
free_mem:
	free_cmd_mem((uint64_t)(uintptr_t)g_cmd_data);
	g_cmd_data = NULL;
	return ret;
}

int init_smc_svc_thread(void)
{
	g_smc_svc_thread = kthread_create(smc_svc_thread_fn, NULL,
		"smc_svc_thread");
	if (unlikely(IS_ERR_OR_NULL(g_smc_svc_thread))) {
		tloge("couldn't create smc_svc_thread %ld\n",
			PTR_ERR(g_smc_svc_thread));
		return (int)PTR_ERR(g_smc_svc_thread);
	}
	tz_kthread_bind_mask(g_smc_svc_thread);
	wake_up_process(g_smc_svc_thread);
	return 0;
}

int teeos_log_exception_archive(unsigned int eventid,
	const char *exceptioninfo)
{
	(void)eventid;
	(void)exceptioninfo;
	return 0;
}

void svc_thread_release(void)
{
	if (!IS_ERR_OR_NULL(g_smc_svc_thread)) {
		kthread_stop(g_smc_svc_thread);
		g_smc_svc_thread = NULL;
	}
}

void free_smc_data(void)
{
	struct pending_entry *pe = NULL, *temp = NULL;
	if (g_reserved_cmd_buffer)
		iounmap((void __iomem *)g_cmd_data);
	else
		free_cmd_mem((uint64_t)(uintptr_t)g_cmd_data);
	smc_wakeup_broadcast();
	svc_thread_release();
	if (!IS_ERR_OR_NULL(g_siq_thread)) {
		atomic_set(&g_siq_th_run, STOP_SIQ_THREAD);
		wake_up_interruptible(&siq_th_wait);
		kthread_stop(g_siq_thread);
		g_siq_thread = NULL;
	}

#if (KERNEL_VERSION(4, 9, 0) > LINUX_VERSION_CODE)
	flush_kthread_worker(g_ipi_helper_worker);
#else
	kthread_flush_worker(g_ipi_helper_worker);
#endif
	if (!IS_ERR_OR_NULL(g_ipi_helper_thread)) {
		kthread_stop(g_ipi_helper_thread);
		g_ipi_helper_thread = NULL;
	}
    if (!IS_ERR_OR_NULL(g_ipi_helper_worker)) {
        kthread_destroy_worker(g_ipi_helper_worker);
        g_ipi_helper_worker = NULL;
    }
	free_cmd_monitor();

	spin_lock(&g_pend_lock);
	list_for_each_entry_safe(pe, temp, &g_pending_head, list) {
		list_del(&pe->list);
		put_task_struct(pe->task);
		kfree(pe);
	}
	spin_unlock(&g_pend_lock);
}
