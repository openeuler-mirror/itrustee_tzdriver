/*
 * agent.c
 *
 * agent manager function, such as register and send cmd
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
#include "agent.h"
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/atomic.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/path.h>
#include <linux/uaccess.h>
#include <linux/proc_ns.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#if (KERNEL_VERSION(4, 14, 0) <= LINUX_VERSION_CODE)
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#endif
#if (KERNEL_VERSION(5, 4, 0) <= LINUX_VERSION_CODE)
#include <linux/mman.h>
#else
#include <asm/mman.h>
#endif
#include <linux/signal.h>
#include <securec.h>
#include "teek_client_constants.h"
#include "teek_ns_client.h"
#include "smc_smp.h"
#include "mem.h"
#include "tc_ns_log.h"
#include "mailbox_mempool.h"
#include "tc_client_driver.h"
#include "cmdmonitor.h"
#include "ko_adapt.h"
#include "internal_functions.h"
#include "auth_base_impl.h"
#include "tee_compat_check.h"

#ifdef CONFIG_CMS_CAHASH_AUTH
#define HASH_FILE_MAX_SIZE         CONFIG_HASH_FILE_SIZE
#else
#define HASH_FILE_MAX_SIZE         (16 * 1024)
#endif
#define AGENT_BUFF_SIZE            (4 * 1024)
#define AGENT_MAX                  32
#define PAGE_ORDER_RATIO           2

static struct list_head g_tee_agent_list;

struct agent_control {
	spinlock_t lock;
	struct list_head agent_list;
};

struct agent_pair {
	uint32_t agent_id;
	uint32_t nsid;
};

static struct agent_control g_agent_control;

static void process_send_event_response(struct smc_event_data *event_data, bool force);
int __attribute__((weak)) is_allowed_agent_ca(const struct ca_info *ca,
	bool check_agent_id)
{
	(void)ca;
	(void)check_agent_id;

	return -EFAULT;
}

static int check_mm_struct(struct mm_struct *mm)
{
	if (!mm)
		return -EINVAL;

	if (!mm->exe_file) {
		mmput(mm);
		return -EINVAL;
	}

	return 0;
}

char *get_proc_dpath(char *path, int path_len)
{
	char *dpath = NULL;
	struct path base_path = {
		.mnt = NULL,
		.dentry = NULL
	};
	struct mm_struct *mm = NULL;
	struct file *exe_file = NULL;

	if (!path || path_len != MAX_PATH_SIZE) {
		tloge("bad params\n");
		return NULL;
	}

	if (memset_s(path, path_len, '\0', MAX_PATH_SIZE) != 0) {
		tloge("memset error\n");
		return NULL;
	}

	mm = get_task_mm(current);
	if (check_mm_struct(mm) != 0) {
		tloge("check mm_struct failed\n");
		return NULL;
	}
#if (KERNEL_VERSION(6, 1, 0) <= LINUX_VERSION_CODE)
	exe_file = mm->exe_file;
#else
	exe_file = get_mm_exe_file(mm);
#endif
	if (!exe_file) {
		mmput(mm);
		return NULL;
	}

	base_path = exe_file->f_path;
	path_get(&base_path);
	dpath = d_path(&base_path, path, MAX_PATH_SIZE);
	path_put(&base_path);
#if (KERNEL_VERSION(6, 1, 0) > LINUX_VERSION_CODE)
	fput(exe_file);
#endif
	mmput(mm);

	return dpath;
}

static int get_ca_path_and_uid(struct ca_info *ca)
{
	char *path = NULL;
	const struct cred *cred = NULL;
	int message_size;
	char *tpath = NULL;

	tpath = kmalloc(MAX_PATH_SIZE, GFP_KERNEL);
	if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)tpath)) {
		tloge("tpath kmalloc fail\n");
		return -ENOMEM;
	}

	path = get_proc_dpath(tpath, MAX_PATH_SIZE);
	if (IS_ERR_OR_NULL(path)) {
		tloge("get process path failed\n");
		kfree(tpath);
		return -ENOMEM;
	}

	message_size = snprintf_s(ca->path, MAX_PATH_SIZE,
		MAX_PATH_SIZE - 1, "%s", path);
	if (message_size <= 0) {
		tloge("pack path failed\n");
		kfree(tpath);
		return -EFAULT;
	}

	get_task_struct(current);
	cred = koadpt_get_task_cred(current);
	if (!cred) {
		tloge("cred is NULL\n");
		kfree(tpath);
		put_task_struct(current);
		return -EACCES;
	}

	ca->uid = cred->uid.val;
	tlogd("ca_task->comm is %s, path is %s, ca uid is %u\n",
	      current->comm, path, cred->uid.val);

	put_cred(cred);
	put_task_struct(current);
	kfree(tpath);
	return 0;
}

int check_ext_agent_access(uint32_t agent_id)
{
	int ret;
	struct ca_info agent_ca = { {0}, 0, 0 };

	ret = get_ca_path_and_uid(&agent_ca);
	if (ret != 0) {
		tloge("get cp path or uid failed\n");
		return ret;
	}
	agent_ca.agent_id = agent_id;

	return is_allowed_agent_ca(&agent_ca, true);
}

static int get_buf_len(const uint8_t *inbuf, uint32_t *buf_len)
{
	if (copy_from_user(buf_len, inbuf, sizeof(*buf_len))) {
		tloge("copy from user failed\n");
		return -EFAULT;
	}

	if (*buf_len > HASH_FILE_MAX_SIZE) {
		tloge("ERROR: file size[0x%x] too big\n", *buf_len);
		return -EFAULT;
	}

	return 0;
}

static int send_set_smc_cmd(struct mb_cmd_pack *mb_pack,
	struct tc_ns_smc_cmd *smc_cmd, unsigned int cmd_id,
	const uint8_t *buf_to_tee, uint32_t buf_len)
{
	int ret = 0;

	mb_pack->operation.paramtypes = TEE_PARAM_TYPE_VALUE_INPUT |
		(TEE_PARAM_TYPE_VALUE_INPUT << TEE_PARAM_NUM);
	mb_pack->operation.params[0].value.a =
		(unsigned int)mailbox_virt_to_phys((uintptr_t)buf_to_tee);
	mb_pack->operation.params[0].value.b =
		(uint64_t)mailbox_virt_to_phys((uintptr_t)buf_to_tee) >> ADDR_TRANS_NUM;
	mb_pack->operation.params[1].value.a = buf_len;
	smc_cmd->cmd_type = CMD_TYPE_GLOBAL;
	smc_cmd->cmd_id = cmd_id;
	smc_cmd->operation_phys = mailbox_virt_to_phys((uintptr_t)&mb_pack->operation);
	smc_cmd->operation_h_phys =
		(uint64_t)mailbox_virt_to_phys((uintptr_t)&mb_pack->operation) >> ADDR_TRANS_NUM;
	if (tc_ns_smc(smc_cmd) != 0) {
		ret = -EPERM;
		tloge("set native hash failed\n");
	}

	return ret;
}

int tc_ns_set_native_hash(unsigned long arg, unsigned int cmd_id)
{
	int ret;
	struct tc_ns_smc_cmd smc_cmd = { {0}, 0 };
	uint8_t *inbuf = (uint8_t *)(uintptr_t)arg;
	uint32_t buf_len = 0;
	uint8_t *buf_to_tee = NULL;
	struct mb_cmd_pack *mb_pack = NULL;

	ret = check_teecd_auth();
	if (ret != 0) {
		tloge("teecd or cadaemon auth failed, ret %d\n", ret);
		return -EACCES;
	}

	if (!inbuf)
		return -EINVAL;

	if (get_buf_len(inbuf, &buf_len) != 0)
		return -EFAULT;

	buf_to_tee = mailbox_alloc(buf_len, 0);
	if (!buf_to_tee) {
		tloge("failed to alloc memory!\n");
		return -ENOMEM;
	}

	if (copy_from_user(buf_to_tee, inbuf, buf_len)) {
		tloge("copy from user failed\n");
		mailbox_free(buf_to_tee);
		return -EFAULT;
	}

	mb_pack = mailbox_alloc_cmd_pack();
	if (!mb_pack) {
		tloge("alloc cmd pack failed\n");
		mailbox_free(buf_to_tee);
		return -ENOMEM;
	}

	ret = send_set_smc_cmd(mb_pack, &smc_cmd, cmd_id, buf_to_tee, buf_len);
	mailbox_free(buf_to_tee);
	mailbox_free(mb_pack);

	return ret;
}

int tc_ns_late_init(unsigned long arg)
{
	int ret = 0;
	struct tc_ns_smc_cmd smc_cmd = { {0}, 0 };
	uint32_t index = (uint32_t)arg; /* index is uint32, no truncate risk */
	struct mb_cmd_pack *mb_pack = NULL;

	mb_pack = mailbox_alloc_cmd_pack();
	if (!mb_pack) {
		tloge("alloc cmd pack failed\n");
		return -ENOMEM;
	}

	mb_pack->operation.paramtypes = TEE_PARAM_TYPE_VALUE_INPUT;
	mb_pack->operation.params[0].value.a = index;

	smc_cmd.cmd_type = CMD_TYPE_GLOBAL;
	smc_cmd.cmd_id = GLOBAL_CMD_ID_LATE_INIT;
	smc_cmd.operation_phys = mailbox_virt_to_phys((uintptr_t)&mb_pack->operation);
	smc_cmd.operation_h_phys =
		(uint64_t)mailbox_virt_to_phys((uintptr_t)&mb_pack->operation) >> ADDR_TRANS_NUM;

	if (tc_ns_smc(&smc_cmd)) {
		ret = -EPERM;
		tloge("late int failed\n");
	}
	mailbox_free(mb_pack);

	return ret;
}

void send_crashed_event_response_single(const struct tc_ns_dev_file *dev_file)
{
	struct smc_event_data *event_data = NULL;
	struct smc_event_data *tmp = NULL;
	unsigned long flags;
	unsigned int agent_id = 0;
	unsigned int nsid = PROC_PID_INIT_INO;
	bool need_unreg = false;

	if (!dev_file)
		return;

	spin_lock_irqsave(&g_agent_control.lock, flags);
	list_for_each_entry_safe(event_data, tmp, &g_agent_control.agent_list,
		head) {
		if (event_data->owner == dev_file) {
			agent_id = event_data->agent_id;
			nsid = event_data->nsid;
			event_data->agent_buff_user = NULL;
			need_unreg = !(atomic_read(&event_data->agent_ready) == AGENT_PENDING) &&
				!(atomic_read(&event_data->agent_ready) == AGENT_UNREGISTERED);
			break;
		}
	}
	spin_unlock_irqrestore(&g_agent_control.lock, flags);

	if (nsid != PROC_PID_INIT_INO && need_unreg)
		(void)tc_ns_unregister_agent(agent_id, nsid);

	send_event_response(agent_id, nsid);
	return;
}

struct smc_event_data *find_event_control(unsigned int agent_id, unsigned int nsid)
{
	struct smc_event_data *event_data = NULL;
	struct smc_event_data *tmp_data = NULL;
	unsigned long flags;

	spin_lock_irqsave(&g_agent_control.lock, flags);
	list_for_each_entry(event_data, &g_agent_control.agent_list, head) {
		if (event_data->agent_id == agent_id && event_data->nsid == nsid) {
			tmp_data = event_data;
			get_agent_event(event_data);
			break;
		}
	}
	spin_unlock_irqrestore(&g_agent_control.lock, flags);

	return tmp_data;
}

static void unmap_agent_buffer(struct smc_event_data *event_data)
{
	if (!event_data) {
		tloge("event data is NULL\n");
		return;
	}

	if (IS_ERR_OR_NULL(event_data->agent_buff_user))
		return;

	if (vm_munmap((unsigned long)(uintptr_t)event_data->agent_buff_user,
		event_data->agent_buff_size) != 0)
		tloge("unmap failed\n");

	event_data->agent_buff_user = NULL;
}

static void free_event_control(struct smc_event_data *event_data)
{
	unsigned long flags;
	if (event_data == NULL)
		return;

	spin_lock_irqsave(&g_agent_control.lock, flags);
	list_del(&event_data->head);
	spin_unlock_irqrestore(&g_agent_control.lock, flags);

	mailbox_free(event_data->agent_buff_kernel);
	event_data->agent_buff_kernel = NULL;
	atomic_set(&event_data->agent_ready, AGENT_UNREGISTERED);
	put_agent_event(event_data);
}

static int init_agent_context(unsigned int agent_id,
	unsigned int nsid,
	const struct tc_ns_smc_cmd *smc_cmd,
	struct smc_event_data **event_data)
{
	*event_data = find_event_control(agent_id, nsid);
	if (!(*event_data)) {
		tloge("agent 0x%x nsid 0x%x not exist\n", agent_id, nsid);
		return -EINVAL;
	}
	tlogd("agent-0x%x nsid 0x%x: returning client command", agent_id, nsid);

	if (is_tui_agent(agent_id)) {
		tloge("TEE_TUI_AGENT_ID: pid-%d", current->pid);
		set_tui_caller_info(smc_cmd->dev_file_id, current->pid);
	}

	isb();
	wmb();

	return 0;
}

static int wait_agent_response(struct smc_event_data *event_data)
{
	int ret = 0;
	/* only userspace CA need freeze */
	bool need_freeze = !(current->flags & PF_KTHREAD);
	bool sig_pending = !sigisemptyset(&current->pending.signal);
	bool answered = true;
	int rc;

	do {
		answered = true;
		/*
		 * wait_event_freezable will be interrupted by signal and
		 * freezer which is called to free a userspace task in suspend.
		 * Freezing a task means wakeup a task by fake_signal_wake_up
		 * and let it have an opportunity to enter into 'refrigerator'
		 * by try_to_freeze used in wait_event_freezable.
		 *
		 * What scenes can be freezed ?
		 * 1. CA is waiting agent -> suspend -- OK
		 * 2. suspend -> CA start agent request -- OK
		 * 3. CA is waiting agent -> CA is killed -> suspend  -- NOK
		 */
		if (need_freeze && !sig_pending) {
			rc = wait_event_freezable(event_data->ca_pending_wq,
				atomic_read(&event_data->ca_run));
			if (rc != -ERESTARTSYS)
				continue;
			if (!sigisemptyset(&current->pending.signal))
				sig_pending = true;
			tloge("agent wait event is interrupted by %s\n",
				sig_pending ? "signal" : "freezer");
			/*
			 * When freezing a userspace task, fake_signal_wake_up
			 * only set TIF_SIGPENDING but not set a real signal.
			 * After task thawed, CA need wait agent response again
			 * so TIF_SIGPENDING need to be cleared.
			 */
			if (!sig_pending)
				clear_thread_flag(TIF_SIGPENDING);
			answered = false;
		} else {
			rc = wait_event_timeout(event_data->ca_pending_wq,
				atomic_read(&event_data->ca_run),
				(long)(RESLEEP_TIMEOUT * HZ));
			if (rc)
				continue;
			tloge("agent wait event is timeout\n");
			/* if no kill signal, just resleep before agent wake */
			if (!sigkill_pending(current)) {
				answered = false;
			} else {
				tloge("CA is killed, no need to \
wait agent response\n");
				event_data->ret_flag = 0;
				ret = -EFAULT;
			}
		}
	} while (!answered);

	return ret;
}

int agent_process_work(const struct tc_ns_smc_cmd *smc_cmd,
	unsigned int agent_id, unsigned int nsid)
{
	struct smc_event_data *event_data = NULL;
	int ret;

	if (!smc_cmd) {
		tloge("smc_cmd is null\n");
		return -EINVAL;
	}

	if (init_agent_context(agent_id, nsid, smc_cmd, &event_data))
		return -EINVAL;

	if (atomic_read(&event_data->agent_ready) == AGENT_CRASHED ||
		atomic_read(&event_data->agent_ready) == AGENT_UNREGISTERED) {
		tloge("agent 0x%x nsid 0x%x is killed and restarting\n", agent_id, nsid);
		put_agent_event(event_data);
		return -EFAULT;
	}

	if (smc_cmd->cmd_type == CMD_TYPE_RELEASE_AGENT &&
		atomic_read(&event_data->agent_ready) == AGENT_PENDING) {
		tlogi("agent 0x%x nsid 0x%x is ready to release\n", agent_id, nsid);

		free_event_control(event_data);
		put_agent_event(event_data);
		ret = 0;
		goto reset_context;
	}

	event_data->ret_flag = 1;
	/* Wake up the agent that will process the command */
	tlogd("agent process work: wakeup the agent");
	wake_up(&event_data->wait_event_wq);
	tlogd("agent 0x%x nsid 0x%x request, goto sleep, pe->run=%d\n",
	      agent_id, nsid, atomic_read(&event_data->ca_run));

	ret = wait_agent_response(event_data);
	atomic_set(&event_data->ca_run, 0);
	put_agent_event(event_data);

reset_context:
	/*
	 * when agent work is done, reset cmd monitor time
	 * add agent call count, cause it's a new smc cmd.
	 */
	cmd_monitor_reset_context();
	return ret;
}

int is_agent_alive(unsigned int agent_id, unsigned int nsid)
{
	struct smc_event_data *event_data = NULL;

	event_data = find_event_control(agent_id, nsid);
	if (event_data) {
		if (atomic_read(&event_data->agent_ready) == AGENT_CRASHED ||
			atomic_read(&event_data->agent_ready) == AGENT_PENDING ||
			atomic_read(&event_data->agent_ready) == AGENT_UNREGISTERED) {
			put_agent_event(event_data);
			return AGENT_DEAD;
		}
		put_agent_event(event_data);
		return AGENT_ALIVE;
	}

	return AGENT_DEAD;
}

int tc_ns_wait_event(unsigned int agent_id, unsigned int nsid)
{
	int ret = -EINVAL;
	struct smc_event_data *event_data = NULL;

	tlogd("agent 0x%x nsid 0x%x waits for command\n", agent_id, nsid);

	event_data = find_event_control(agent_id, nsid);
	if (!event_data)
		return ret;

	if (atomic_read(&event_data->agent_ready) != AGENT_READY) {
		tlogd("agent 0x%x nsid 0x%x is not in registered status\n", agent_id, nsid);
		put_agent_event(event_data);
		return ret;
	}

	ret = wait_event_interruptible(event_data->wait_event_wq,
		event_data->ret_flag);
	put_agent_event(event_data);

	if (is_tee_rebooting())
		ret = -EINVAL;

	return ret;
}

int tc_ns_sync_sys_time(const struct tc_ns_client_time *tc_ns_time)
{
	struct tc_ns_smc_cmd smc_cmd = { {0}, 0 };
	int ret = 0;
	struct mb_cmd_pack *mb_pack = NULL;

	if (!tc_ns_time) {
		tloge("tc_ns_time is NULL input buffer\n");
		return -EINVAL;
	}

	mb_pack = mailbox_alloc_cmd_pack();
	if (!mb_pack) {
		tloge("alloc mb pack failed\n");
		return -ENOMEM;
	}

	mb_pack->operation.paramtypes = TEE_PARAM_TYPE_VALUE_INPUT;
	mb_pack->operation.params[0].value.a = tc_ns_time->seconds;
	mb_pack->operation.params[0].value.b = tc_ns_time->millis;

	smc_cmd.cmd_type = CMD_TYPE_GLOBAL;
	smc_cmd.cmd_id = GLOBAL_CMD_ID_ADJUST_TIME;
	smc_cmd.operation_phys = mailbox_virt_to_phys((uintptr_t)&mb_pack->operation);
	smc_cmd.operation_h_phys =
		(uint64_t)mailbox_virt_to_phys((uintptr_t)&mb_pack->operation) >> ADDR_TRANS_NUM;
	if (tc_ns_smc(&smc_cmd)) {
		tloge("tee adjust time failed, return error\n");
		ret = -EPERM;
	}
	mailbox_free(mb_pack);

	return ret;
}

int sync_system_time_from_user(const struct tc_ns_client_time *user_time)
{
	int ret = 0;
	struct tc_ns_client_time time = { 0 };

	if (!user_time) {
		tloge("user time is NULL input buffer\n");
		return -EINVAL;
	}

	if (copy_from_user(&time, user_time, sizeof(time))) {
		tloge("copy from user failed\n");
		return -EFAULT;
	}

	ret = tc_ns_sync_sys_time(&time);
	if (ret != 0)
		tloge("sync system time from user failed, ret = 0x%x\n", ret);

	return ret;
}

void sync_system_time_from_kernel(void)
{
	int ret = 0;
	struct tc_ns_client_time time = { 0 };

	struct time_spec kernel_time = {0};
	get_time_spec(&kernel_time);

	time.seconds = (uint32_t)kernel_time.ts.tv_sec;
	time.millis = (uint32_t)(kernel_time.ts.tv_nsec / MS_TO_NS);

	ret = tc_ns_sync_sys_time(&time);
	if (ret != 0)
		tloge("sync system time from kernel failed, ret = 0x%x\n", ret);

	return;
}

static void process_send_event_response(struct smc_event_data *event_data, bool force)
{
	if (event_data->ret_flag == 0 && !force)
		return;

	event_data->ret_flag = 0;
	/* Send the command back to the TA session waiting for it */
	tlogd("agent wakeup ca\n");
	atomic_set(&event_data->ca_run, 1);
	/* make sure reset working_ca before wakeup CA */
	asm volatile("dmb sy");
	wake_up(&event_data->ca_pending_wq);
}

int tc_ns_send_event_response(unsigned int agent_id, unsigned int nsid)
{
	struct smc_event_data *event_data = NULL;

	event_data = find_event_control(agent_id, nsid);
	if (!event_data) {
		tlogd("agent 0x%x nsid 0x%x pre-check failed\n", agent_id, nsid);
		return -EINVAL;
	}

	if (atomic_read(&event_data->agent_ready) != AGENT_READY) {
		tlogd("agent 0x%x nsid 0x%x is not in registered status\n", agent_id, nsid);
		put_agent_event(event_data);
		return -EINVAL;
	}

	tlogd("agent 0x%x nsid 0x%x sends answer back\n", agent_id, nsid);
	process_send_event_response(event_data, false);
	put_agent_event(event_data);

	return 0;
}

void send_event_response(unsigned int agent_id, unsigned int nsid)
{
	struct smc_event_data *event_data = find_event_control(agent_id, nsid);

	if (!event_data) {
		tlogd("Can't get event_data\n");
		return;
	}

	if (atomic_read(&event_data->agent_ready) == AGENT_PENDING) {
		put_agent_event(event_data);
		return;
	}

	tlogi("agent 0x%x nsid 0x%x sends answer back\n", agent_id, nsid);
	atomic_set(&event_data->agent_ready, AGENT_CRASHED);
	process_send_event_response(event_data, false);
	put_agent_event(event_data);
}

static void init_restart_agent_node(struct tc_ns_dev_file *dev_file,
	struct smc_event_data *event_data)
{
	tlogi("agent: 0x%x restarting\n", event_data->agent_id);
	event_data->ret_flag = 0;
	event_data->owner = dev_file;
	init_waitqueue_head(&(event_data->wait_event_wq));
	init_waitqueue_head(&(event_data->send_response_wq));
	init_waitqueue_head(&(event_data->ca_pending_wq));
	atomic_set(&(event_data->ca_run), 0);
}

static int create_new_agent_node(struct tc_ns_dev_file *dev_file,
	struct smc_event_data **event_data, struct agent_pair *agent_pair,
	void **agent_buff, uint32_t agent_buff_size)
{
	*agent_buff = mailbox_alloc(agent_buff_size, MB_FLAG_ZERO);
	if (!(*agent_buff)) {
		tloge("alloc agent buff failed\n");
		return -ENOMEM;
	}
	*event_data = kzalloc(sizeof(**event_data), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)(*event_data))) {
		mailbox_free(*agent_buff);
		*agent_buff = NULL;
		*event_data = NULL;
		tloge("alloc event data failed\n");
		return -ENOMEM;
	}
	(*event_data)->agent_id = agent_pair->agent_id;
	(*event_data)->nsid = agent_pair->nsid;
	(*event_data)->ret_flag = 0;
	(*event_data)->agent_buff_kernel = *agent_buff;
	(*event_data)->agent_buff_size = agent_buff_size;
	(*event_data)->owner = dev_file;
	init_waitqueue_head(&(*event_data)->wait_event_wq);
	init_waitqueue_head(&(*event_data)->send_response_wq);
	INIT_LIST_HEAD(&(*event_data)->head);
	init_waitqueue_head(&(*event_data)->ca_pending_wq);
	atomic_set(&(*event_data)->ca_run, 0);

	return 0;
}

static unsigned long agent_buffer_map(unsigned long buffer, uint32_t size)
{
	struct vm_area_struct *vma = NULL;
	unsigned long user_addr;
	int ret;

	user_addr = vm_mmap(NULL, 0, size, PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_ANONYMOUS, 0);
	if (IS_ERR_VALUE((uintptr_t)user_addr)) {
		tloge("vm mmap failed\n");
		return user_addr;
	}

	down_read(&mm_sem_lock(current->mm));
	vma = find_vma(current->mm, user_addr);
	if (!vma) {
		tloge("user_addr is not valid in vma");
		goto err_out;
	}

	ret = remap_pfn_range(vma, user_addr, buffer >> PAGE_SHIFT, size,
		vma->vm_page_prot);
	if (ret != 0) {
		tloge("remap agent buffer failed, err=%d", ret);
		goto err_out;
	}

	up_read(&mm_sem_lock(current->mm));
	return user_addr;
err_out:
	up_read(&mm_sem_lock(current->mm));
	if (vm_munmap(user_addr, size))
		tloge("munmap failed\n");
	return -EFAULT;
}

static bool is_valid_agent(unsigned int agent_id,
	unsigned int buffer_size, bool user_agent)
{
	unsigned int agent_buffer_threshold = is_ccos() ? SZ_512K : SZ_4K;
	(void)agent_id;
	if (user_agent && (buffer_size > agent_buffer_threshold)) {
		tloge("size: %u of user agent's shared mem is invalid\n",
			buffer_size);
		return false;
	}

	return true;
}

static int is_agent_already_exist(unsigned int agent_id, unsigned int nsid,
	struct smc_event_data **event_data, struct tc_ns_dev_file *dev_file, uint32_t *find_flag)
{
	unsigned long flags;
	uint32_t flag = AGENT_NO_EXIST;
	struct smc_event_data *agent_node = NULL;

	spin_lock_irqsave(&g_agent_control.lock, flags);
	list_for_each_entry(agent_node, &g_agent_control.agent_list, head) {
		if (agent_node->agent_id == agent_id && agent_node->nsid == nsid) {
			if (atomic_read(&agent_node->agent_ready) != AGENT_CRASHED &&
				atomic_read(&agent_node->agent_ready) != AGENT_PENDING) {
				tloge("no allow agent proc to reg twice\n");
				spin_unlock_irqrestore(&g_agent_control.lock, flags);
				return -EINVAL;
			}
			if (atomic_read(&agent_node->agent_ready) == AGENT_CRASHED)
				flag = AGENT_HAS_CRASHED;
			else
				flag = AGENT_READY_TO_UNREG;
			get_agent_event(agent_node);
			/*
			 * We find the agent event_data aready in agent_list, it indicate agent
			 * didn't unregister normally, so the event_data will be reused.
			*/
			init_restart_agent_node(dev_file, agent_node);
			break;
		}
	}
	spin_unlock_irqrestore(&g_agent_control.lock, flags);
	*find_flag = flag;
	if (flag != AGENT_NO_EXIST)
		*event_data = agent_node;
	return 0;
}

static void add_event_node_to_list(struct smc_event_data *event_data)
{
	unsigned long flags;

	spin_lock_irqsave(&g_agent_control.lock, flags);
	list_add_tail(&event_data->head, &g_agent_control.agent_list);
	atomic_set(&event_data->usage, 1);
	spin_unlock_irqrestore(&g_agent_control.lock, flags);
}

static int register_agent_to_tee(unsigned int agent_id, unsigned int nsid,
	const void *agent_buff, uint32_t agent_buff_size)
{
	int ret = 0;
	struct tc_ns_smc_cmd smc_cmd = { {0}, 0 };
	struct mb_cmd_pack *mb_pack = NULL;

	mb_pack = mailbox_alloc_cmd_pack();
	if (!mb_pack) {
		tloge("alloc mailbox failed\n");
		return -ENOMEM;
	}

	mb_pack->operation.paramtypes = TEE_PARAM_TYPE_VALUE_INPUT |
		(TEE_PARAM_TYPE_VALUE_INPUT << TEE_PARAM_NUM);
	mb_pack->operation.params[0].value.a =
		mailbox_virt_to_phys((uintptr_t)agent_buff);
	mb_pack->operation.params[0].value.b =
		(uint64_t)mailbox_virt_to_phys((uintptr_t)agent_buff) >> ADDR_TRANS_NUM;
	mb_pack->operation.params[1].value.a = agent_buff_size;
	smc_cmd.cmd_type = CMD_TYPE_GLOBAL;
	smc_cmd.cmd_id = GLOBAL_CMD_ID_REGISTER_AGENT;
	smc_cmd.operation_phys = mailbox_virt_to_phys((uintptr_t)&mb_pack->operation);
	smc_cmd.operation_h_phys =
		(uint64_t)mailbox_virt_to_phys((uintptr_t)&mb_pack->operation) >> ADDR_TRANS_NUM;
	smc_cmd.agent_id = agent_id;
	smc_cmd.nsid = nsid;

	if (tc_ns_smc(&smc_cmd)) {
		ret = -EPERM;
		tloge("register agent to tee failed\n");
	}
	mailbox_free(mb_pack);

	return ret;
}

static int get_agent_buffer(struct smc_event_data *event_data,
	bool user_agent, void **buffer)
{
	/* agent first start or restart, both need a remap */
	if (user_agent) {
		event_data->agent_buff_user =
			(void *)(uintptr_t)agent_buffer_map(
			mailbox_virt_to_phys((uintptr_t)event_data->agent_buff_kernel),
			event_data->agent_buff_size);
		if (IS_ERR(event_data->agent_buff_user)) {
			tloge("vm map agent buffer failed\n");
			return -EFAULT;
		}
		*buffer = event_data->agent_buff_user;
	} else {
		*buffer = event_data->agent_buff_kernel;
	}

	return 0;
}

int tc_ns_register_agent(struct tc_ns_dev_file *dev_file,
	unsigned int agent_id, unsigned int buffer_size,
	void **buffer, bool user_agent)
{
	struct smc_event_data *event_data = NULL;
	int ret = -EINVAL;
	uint32_t find_flag = AGENT_NO_EXIST;
	void *agent_buff = NULL;
	uint32_t size_align;
	uint32_t nsid = PROC_PID_INIT_INO;

	/* dev can be null */
	if (!buffer)
		return ret;

	if (!is_valid_agent(agent_id, buffer_size, user_agent))
		return ret;

	size_align = ALIGN(buffer_size, SZ_4K);
#ifdef CONFIG_CONFIDENTIAL_CONTAINER
	nsid = task_active_pid_ns(current)->ns.inum;
	if (dev_file != NULL && dev_file->nsid == 0)
		dev_file->nsid = nsid;
#endif

	if (is_agent_already_exist(agent_id, nsid, &event_data, dev_file, &find_flag))
		return ret;
	if (find_flag == AGENT_NO_EXIST) {
		struct agent_pair agent_pair = { agent_id, nsid };
		ret = create_new_agent_node(dev_file, &event_data,
			&agent_pair, &agent_buff, size_align);
		if (ret != 0)
			return ret;
	}

	if (get_agent_buffer(event_data, user_agent, buffer))
		goto release_rsrc;

	/* find_flag is false means it's a new agent register */
	if (find_flag == AGENT_NO_EXIST || find_flag == AGENT_READY_TO_UNREG) {
		/*
		 * Obtain share memory which is released
		 * in tc_ns_unregister_agent
		 */
		ret = register_agent_to_tee(agent_id, nsid, event_data->agent_buff_kernel, size_align);
		if (ret != 0) {
			unmap_agent_buffer(event_data);
			goto release_rsrc;
		}
		if (find_flag == AGENT_NO_EXIST)
			add_event_node_to_list(event_data);
	}
	atomic_set(&(event_data->agent_ready), AGENT_READY);
	if (find_flag != AGENT_NO_EXIST)
		put_agent_event(event_data); /* match get action */
	return 0;

release_rsrc:
	if (find_flag != AGENT_NO_EXIST)
		put_agent_event(event_data); /* match get action */
	else
		kfree(event_data); /* here event_data can never be NULL */

	if (agent_buff)
		mailbox_free(agent_buff);
	return ret;
}

int tc_ns_unregister_agent(unsigned int agent_id, unsigned int nsid)
{
	struct smc_event_data *event_data = NULL;
	int ret = 0;
	struct tc_ns_smc_cmd smc_cmd = { {0}, 0 };
	struct mb_cmd_pack *mb_pack = NULL;

	event_data = find_event_control(agent_id, nsid);
	if (!event_data || !event_data->agent_buff_kernel) {
		tloge("agent is not found or kaddr is not allocated\n");
		return -EINVAL;
	}

	mb_pack = mailbox_alloc_cmd_pack();
	if (!mb_pack) {
		tloge("alloc mailbox failed\n");
		put_agent_event(event_data);
		return -ENOMEM;
	}
	mb_pack->operation.paramtypes = TEE_PARAM_TYPE_VALUE_INPUT |
		(TEE_PARAM_TYPE_VALUE_INPUT << TEE_PARAM_NUM);
	mb_pack->operation.params[0].value.a =
		mailbox_virt_to_phys((uintptr_t)event_data->agent_buff_kernel);
	mb_pack->operation.params[0].value.b =
		(uint64_t)mailbox_virt_to_phys((uintptr_t)event_data->agent_buff_kernel) >> ADDR_TRANS_NUM;
	mb_pack->operation.params[1].value.a = SZ_4K;
	smc_cmd.cmd_type = CMD_TYPE_GLOBAL;
	smc_cmd.cmd_id = GLOBAL_CMD_ID_UNREGISTER_AGENT;
	smc_cmd.operation_phys = mailbox_virt_to_phys((uintptr_t)&mb_pack->operation);
	smc_cmd.operation_h_phys =
		(uint64_t)mailbox_virt_to_phys((uintptr_t)&mb_pack->operation) >> ADDR_TRANS_NUM;
	smc_cmd.agent_id = agent_id;
	smc_cmd.nsid = nsid;

	ret = tc_ns_smc(&smc_cmd);
	if (ret == 0) {
		unmap_agent_buffer(event_data);
		free_event_control(event_data);
		tlogi("unregister agent(0x%x, 0x%x) success, and agent buffer is not used in tee\n",
			agent_id, nsid);
	} else if (ret == TEEC_ERROR_BUSY) {
		ret = -EBUSY;
		atomic_set(&(event_data->agent_ready), AGENT_PENDING);
		unmap_agent_buffer(event_data);
		process_send_event_response(event_data, true);
		tlogi("unregister agent(0x%x, 0x%x) success, but agent buffer is used in tee\n",
			agent_id, nsid);
	} else {
		ret = -EPERM;
		tloge("unregister agent(0x%x, 0x%x) failed\n", agent_id, nsid);
	}
	put_agent_event(event_data);
	mailbox_free(mb_pack);
	return ret;
}

bool is_system_agent(const struct tc_ns_dev_file *dev_file)
{
	struct smc_event_data *event_data = NULL;
	struct smc_event_data *tmp = NULL;
	bool system_agent = false;
	unsigned long flags;

	if (!dev_file)
		return system_agent;

	spin_lock_irqsave(&g_agent_control.lock, flags);
	list_for_each_entry_safe(event_data, tmp, &g_agent_control.agent_list,
		head) {
		if (event_data->owner == dev_file) {
			system_agent = true;
			break;
		}
	}
	spin_unlock_irqrestore(&g_agent_control.lock, flags);

	return system_agent;
}

void send_crashed_event_response_all(const struct tc_ns_dev_file *dev_file)
{
	struct smc_event_data *event_data = NULL;
	struct smc_event_data *tmp = NULL;
	unsigned int agent_id[AGENT_MAX] = {0};
	unsigned int nsids[AGENT_MAX] = {0};
	bool need_unregs[AGENT_MAX] = {false};
	unsigned int i = 0;
	unsigned long flags;

	if (!dev_file)
		return;

	spin_lock_irqsave(&g_agent_control.lock, flags);
	list_for_each_entry_safe(event_data, tmp, &g_agent_control.agent_list,
		head) {
		if (event_data->owner == dev_file && i < AGENT_MAX) {
			nsids[i] = event_data->nsid;
			agent_id[i] = event_data->agent_id;
			event_data->agent_buff_user = NULL;
			need_unregs[i++] = !(atomic_read(&event_data->agent_ready) == AGENT_PENDING) &&
				!(atomic_read(&event_data->agent_ready) == AGENT_UNREGISTERED);
		}
	}
	spin_unlock_irqrestore(&g_agent_control.lock, flags);

	for (i = 0; i < AGENT_MAX; i++) {
		if (agent_id[i] == 0)
			continue;
		if (nsids[i] != PROC_PID_INIT_INO && need_unregs[i])
			(void)tc_ns_unregister_agent(agent_id[i], nsids[i]);
		send_event_response(agent_id[i], nsids[i]);
	}

	return;
}

void tee_agent_clear_dev_owner(const struct tc_ns_dev_file *dev_file)
{
	struct smc_event_data *event_data = NULL;
	struct smc_event_data *tmp = NULL;
	unsigned long flags;

	spin_lock_irqsave(&g_agent_control.lock, flags);
	list_for_each_entry_safe(event_data, tmp, &g_agent_control.agent_list,
		head) {
		if (event_data->owner == dev_file) {
			event_data->owner = NULL;
			break;
		}
	}
	spin_unlock_irqrestore(&g_agent_control.lock, flags);
}


static int def_tee_agent_work(void *instance)
{
	int ret = 0;
	struct tee_agent_kernel_ops *agent_instance = NULL;

	agent_instance = instance;
	while (!kthread_should_stop()) {
		tlogd("%s agent loop++++\n", agent_instance->agent_name);
		ret = tc_ns_wait_event(agent_instance->agent_id, PROC_PID_INIT_INO);
		if (ret != 0) {
			tloge("%s wait event fail\n",
				agent_instance->agent_name);
			break;
		}
		if (agent_instance->tee_agent_work) {
			ret = agent_instance->tee_agent_work(agent_instance);
			if (ret != 0)
				tloge("%s agent work fail\n",
					agent_instance->agent_name);
		}
		ret = tc_ns_send_event_response(agent_instance->agent_id, PROC_PID_INIT_INO);
		if (ret != 0) {
			tloge("%s send event response fail\n",
				agent_instance->agent_name);
			break;
		}
		tlogd("%s agent loop----\n", agent_instance->agent_name);
	}

	return ret;
}

static int def_tee_agent_run(struct tee_agent_kernel_ops *agent_instance)
{
	struct tc_ns_dev_file dev = {0};
	int ret;

	/* 1. Register agent buffer to TEE */
	ret = tc_ns_register_agent(&dev, agent_instance->agent_id,
		agent_instance->agent_buff_size, &agent_instance->agent_buff,
		false);
	if (ret != 0) {
		tloge("register agent buffer fail,ret =0x%x\n", ret);
		ret = -EINVAL;
		goto out;
	}

	/* 2. Creat thread to run agent */
	agent_instance->agent_thread =
		kthread_create(def_tee_agent_work, agent_instance,
			"agent_%s", agent_instance->agent_name);
	if (IS_ERR_OR_NULL(agent_instance->agent_thread)) {
		tloge("kthread create fail\n");
		ret = PTR_ERR(agent_instance->agent_thread);
		agent_instance->agent_thread = NULL;
		goto out;
	}
	tz_kthread_bind_mask(agent_instance->agent_thread);
	wake_up_process(agent_instance->agent_thread);
	return 0;

out:
	return ret;
}

static int def_tee_agent_stop(struct tee_agent_kernel_ops *agent_instance)
{
	int ret;

	if (tc_ns_send_event_response(agent_instance->agent_id, PROC_PID_INIT_INO) != 0)
		tloge("failed to send response for agent 0x%x nsid 0x%x\n",
			agent_instance->agent_id, PROC_PID_INIT_INO);
	ret = tc_ns_unregister_agent(agent_instance->agent_id, PROC_PID_INIT_INO);
	if (ret == -EPERM)
		tloge("failed to unregister agent 0x%x, nsid 0x%x\n",
			agent_instance->agent_id, PROC_PID_INIT_INO);
	if (!IS_ERR_OR_NULL(agent_instance->agent_thread))
		kthread_stop(agent_instance->agent_thread);

	return 0;
}

static struct tee_agent_kernel_ops g_def_tee_agent_ops = {
	.agent_name = "default",
	.agent_id = 0,
	.tee_agent_init = NULL,
	.tee_agent_run = def_tee_agent_run,
	.tee_agent_work = NULL,
	.tee_agent_exit = NULL,
	.tee_agent_stop = def_tee_agent_stop,
	.tee_agent_crash_work = NULL,
	.agent_buff_size = PAGE_SIZE,
	.list = LIST_HEAD_INIT(g_def_tee_agent_ops.list)
};

static int tee_agent_kernel_init(void)
{
	struct tee_agent_kernel_ops *agent_ops = NULL;
	int ret = 0;

	list_for_each_entry(agent_ops, &g_tee_agent_list, list) {
		/* Check the agent validity */
		if (!agent_ops->agent_id ||
			!agent_ops->agent_name ||
			!agent_ops->tee_agent_work) {
			tloge("agent is invalid\n");
			continue;
		}
		tlogd("ready to init %s agent, id=0x%x\n",
			agent_ops->agent_name, agent_ops->agent_id);

		/* Set agent buff size */
		if (!agent_ops->agent_buff_size)
			agent_ops->agent_buff_size =
				g_def_tee_agent_ops.agent_buff_size;

		/* Initialize the agent */
		if (agent_ops->tee_agent_init)
			ret = agent_ops->tee_agent_init(agent_ops);
		else if (g_def_tee_agent_ops.tee_agent_init)
			ret = g_def_tee_agent_ops.tee_agent_init(agent_ops);
		else
			tlogw("agent id %u has no init function\n",
				agent_ops->agent_id);
		if (ret != 0) {
			tloge("tee_agent_init %s failed\n",
				agent_ops->agent_name);
			continue;
		}

		/* Run the agent */
		if (agent_ops->tee_agent_run)
			ret = agent_ops->tee_agent_run(agent_ops);
		else if (g_def_tee_agent_ops.tee_agent_run)
			ret = g_def_tee_agent_ops.tee_agent_run(agent_ops);
		else
			tlogw("agent id %u has no run function\n",
				agent_ops->agent_id);

		if (ret != 0) {
			tloge("tee_agent_run %s failed\n",
				agent_ops->agent_name);
			if (agent_ops->tee_agent_exit)
				agent_ops->tee_agent_exit(agent_ops);
			continue;
		}
	}

	return 0;
}

static void tee_agent_kernel_exit(void)
{
	struct tee_agent_kernel_ops *agent_ops = NULL;

	list_for_each_entry(agent_ops, &g_tee_agent_list, list) {
		/* Stop the agent */
		if (agent_ops->tee_agent_stop)
			agent_ops->tee_agent_stop(agent_ops);
		else if (g_def_tee_agent_ops.tee_agent_stop)
			g_def_tee_agent_ops.tee_agent_stop(agent_ops);
		else
			tlogw("agent id %u has no stop function\n",
				agent_ops->agent_id);

		/* Uninitialize the agent */
		if (agent_ops->tee_agent_exit)
			agent_ops->tee_agent_exit(agent_ops);
		else if (g_def_tee_agent_ops.tee_agent_exit)
			g_def_tee_agent_ops.tee_agent_exit(agent_ops);
		else
			tlogw("agent id %u has no exit function\n",
				agent_ops->agent_id);
	}
}

int tee_agent_clear_work(struct tc_ns_client_context *context,
	unsigned int dev_file_id)
{
	struct tee_agent_kernel_ops *agent_ops = NULL;

	list_for_each_entry(agent_ops, &g_tee_agent_list, list) {
		if (agent_ops->tee_agent_crash_work)
			agent_ops->tee_agent_crash_work(agent_ops,
				context, dev_file_id);
	}
	return 0;
}

int tee_agent_kernel_register(struct tee_agent_kernel_ops *new_agent)
{
	if (!new_agent)
		return -EINVAL;

	INIT_LIST_HEAD(&new_agent->list);
	list_add_tail(&new_agent->list, &g_tee_agent_list);

	return 0;
}

void agent_init(void)
{
	spin_lock_init(&g_agent_control.lock);
	INIT_LIST_HEAD(&g_agent_control.agent_list);
	INIT_LIST_HEAD(&g_tee_agent_list);

	if (tee_agent_kernel_init() != 0)
		tloge("tee agent kernel init failed\n");
	return;
}

void free_agent(void)
{
	struct smc_event_data *event_data = NULL;
	struct smc_event_data *temp = NULL;
	unsigned long flags;

	tee_agent_kernel_exit();

	spin_lock_irqsave(&g_agent_control.lock, flags);
	list_for_each_entry_safe(event_data, temp, &g_agent_control.agent_list, head) {
		list_del(&event_data->head);
		unmap_agent_buffer(event_data);
		mailbox_free(event_data->agent_buff_kernel);
		event_data->agent_buff_kernel = NULL;
		kfree(event_data);
	}
	spin_unlock_irqrestore(&g_agent_control.lock, flags);
}

void free_agent_list(void)
{
	struct smc_event_data *event_data = NULL;
	struct smc_event_data *tmp_event = NULL;
	unsigned long flags;

	while (list_empty(&g_agent_control.agent_list) == 0) {
		event_data = NULL;
		spin_lock_irqsave(&g_agent_control.lock, flags);
		list_for_each_entry_safe(event_data, tmp_event,
			&g_agent_control.agent_list, head) {
			list_del(&event_data->head);
			break;
		}
		spin_unlock_irqrestore(&g_agent_control.lock, flags);

		if (event_data == NULL)
			return;

		event_data->ret_flag = 1;
		wake_up(&event_data->wait_event_wq);

		process_send_event_response(event_data, false);
		mailbox_free(event_data->agent_buff_kernel);
		event_data->agent_buff_kernel = NULL;
		put_agent_event(event_data);
	}
}
