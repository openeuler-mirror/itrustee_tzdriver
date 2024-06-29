/*
 * cmd_monitor.c
 *
 * cmdmonitor function, monitor every cmd which is sent to TEE.
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
#include "cmdmonitor.h"
#include <linux/workqueue.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/delay.h>
#include <linux/mutex.h>
#include <linux/timer.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <securec.h>
#if (KERNEL_VERSION(4, 14, 0) <= LINUX_VERSION_CODE)
#include <linux/sched/task.h>
#endif

#include "tc_ns_log.h"
#include "smc_smp.h"
#include "internal_functions.h"
#include "mailbox_mempool.h"
#include "tlogger.h"
#include "log_cfg_api.h"

static int g_cmd_need_archivelog;
static LIST_HEAD(g_cmd_monitor_list);
static int g_cmd_monitor_list_size;
static const long long g_memstat_report_freq = 2 * 60 * 60 * 1000;
#define MAX_CMD_MONITOR_LIST 200
#define MAX_AGENT_CALL_COUNT 250
static DEFINE_MUTEX(g_cmd_monitor_lock);

/* independent wq to avoid block system_wq */
static struct workqueue_struct *g_cmd_monitor_wq;
static struct delayed_work g_cmd_monitor_work;
static struct delayed_work g_cmd_monitor_work_archive;
static int g_tee_detect_ta_crash;
static struct tc_uuid g_crashed_ta_uuid;

void get_time_spec(struct time_spec *time)
{
	if (!time)
		return;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0))
	time->ts = current_kernel_time();
#else
	ktime_get_coarse_ts64(&time->ts);
#endif
}

static void schedule_cmd_monitor_work(struct delayed_work *work,
	unsigned long delay)
{
	if (g_cmd_monitor_wq)
		queue_delayed_work(g_cmd_monitor_wq, work, delay);
	else
		schedule_delayed_work(work, delay);
}

static void tz_archivelog(void)
{
	schedule_cmd_monitor_work(&g_cmd_monitor_work_archive,
		usecs_to_jiffies(0));
	flush_delayed_work(&g_cmd_monitor_work_archive);
}

void cmd_monitor_ta_crash(int32_t type, const uint8_t *ta_uuid, uint32_t uuid_len)
{
	g_tee_detect_ta_crash = type;
	if (g_tee_detect_ta_crash != TYPE_CRASH_TEE &&
		ta_uuid != NULL && uuid_len == sizeof(struct tc_uuid)) {
		if (memcpy_s(&g_crashed_ta_uuid, sizeof(g_crashed_ta_uuid),
			ta_uuid, uuid_len) != EOK)
			tloge("copy uuid failed when get ta crash\n");
	}
	tz_archivelog();
	fault_monitor_start(type);
	kbox_report(type, ta_uuid, uuid_len);
}

static int get_pid_name(pid_t pid, char *comm, size_t size)
{
	struct task_struct *task = NULL;
	int sret;

	if (size <= TASK_COMM_LEN - 1 || !comm)
		return -1;

	rcu_read_lock();

#ifndef CONFIG_TZDRIVER_MODULE
	task = find_task_by_pid_ns(pid, &init_pid_ns);
#else
	task = pid_task(find_pid_ns(pid, &init_pid_ns), PIDTYPE_PID);
#endif
	if (task)
		get_task_struct(task);
	rcu_read_unlock();
	if (!task) {
		tlogd("get task failed\n");
		return -1;
	}

	sret = strncpy_s(comm, size, task->comm, strlen(task->comm));
	if (sret != 0)
		tlogd("strncpy failed: errno = %d\n", sret);
	put_task_struct(task);

	return sret;
}

bool is_thread_reported(pid_t tid)
{
	bool ret = false;
	struct cmd_monitor *monitor = NULL;

	mutex_lock(&g_cmd_monitor_lock);
	list_for_each_entry(monitor, &g_cmd_monitor_list, list) {
		if (monitor->tid == tid && !is_tui_in_use(monitor->tid)) {
			ret = (monitor->is_reported ||
				monitor->agent_call_count >
				MAX_AGENT_CALL_COUNT);
			break;
		}
	}
	mutex_unlock(&g_cmd_monitor_lock);
	flush_delayed_work(&g_cmd_monitor_work);
	return ret;
}

void memstat_report(void)
{
	int ret;
	struct tee_mem *meminfo = NULL;

	meminfo = mailbox_alloc(sizeof(*meminfo), MB_FLAG_ZERO);
	if (!meminfo) {
		tloge("mailbox alloc failed\n");
		return;
	}

	ret = get_tee_meminfo(meminfo);
	if (ret != 0)
		tlogd("get meminfo failed\n");

	mailbox_free(meminfo);
}

void cmd_monitor_reset_context(void)
{
	struct cmd_monitor *monitor = NULL;
	pid_t pid = current->tgid;
	pid_t tid = current->pid;

	mutex_lock(&g_cmd_monitor_lock);
	list_for_each_entry(monitor, &g_cmd_monitor_list, list) {
		if (monitor->pid == pid && monitor->tid == tid) {
			get_time_spec(&monitor->sendtime);
			if (monitor->agent_call_count + 1 < 0)
				tloge("agent call count add overflow\n");
			else
				monitor->agent_call_count++;
			break;
		}
	}
	mutex_unlock(&g_cmd_monitor_lock);
}

/*
 * if one session timeout, monitor will print timedifs every step[n] in seconds,
 * if lasted more then 360s, monitor will print timedifs every 360s.
 */
const int32_t g_timer_step[] = {1, 1, 1, 2, 5, 10, 40, 120, 180, 360};
const int32_t g_timer_nums = sizeof(g_timer_step) / sizeof(int32_t);
static void show_timeout_cmd_info(struct cmd_monitor *monitor)
{
	long long timedif, timedif2;
	struct time_spec nowtime;
	int32_t time_in_sec;
	get_time_spec(&nowtime);

	/*
	 * 1 year means 1000 * (60*60*24*365) = 0x757B12C00
	 * only 5bytes, so timedif (timedif=nowtime-sendtime) will not overflow
	 */
	timedif = S_TO_MS * (nowtime.ts.tv_sec - monitor->sendtime.ts.tv_sec) +
		(nowtime.ts.tv_nsec - monitor->sendtime.ts.tv_nsec) / S_TO_US;

	/* timeout to 10s, we log the teeos log, and report */
	if ((timedif > CMD_MAX_EXECUTE_TIME * S_TO_MS) && (!monitor->is_reported)) {
		monitor->is_reported = true;
		tlogw("[cmd_monitor_tick] pid=%d,pname=%s,tid=%d, "
			"tname=%s, lastcmdid=%u, agent call count:%d, "
			"running with timedif=%lld ms and report\n",
			monitor->pid, monitor->pname, monitor->tid,
			monitor->tname, monitor->lastcmdid,
			monitor->agent_call_count, timedif);
		/* threads out of white table need info dump */
		tlogw("monitor: pid-%d", monitor->pid);
		if (!is_tui_in_use(monitor->tid)) {
			show_cmd_bitmap();
			g_cmd_need_archivelog = 1;
			wakeup_tc_siq(SIQ_DUMP_TIMEOUT);
		}
	}

	timedif2 = S_TO_MS * (nowtime.ts.tv_sec - monitor->lasttime.ts.tv_sec) +
		(nowtime.ts.tv_nsec - monitor->lasttime.ts.tv_nsec) / S_TO_US;
	time_in_sec = monitor->timer_index >= g_timer_nums ?
		g_timer_step[g_timer_nums - 1] : g_timer_step[monitor->timer_index];
	if (timedif2 > time_in_sec * S_TO_MS) {
		monitor->lasttime = nowtime;
		monitor->timer_index = monitor->timer_index >= (int32_t)sizeof(g_timer_step) ?
			(int32_t)sizeof(g_timer_step) : (monitor->timer_index + 1);
		tlogw("[cmd_monitor_tick] pid=%d,pname=%s,tid=%d, "
			"lastcmdid=%u,agent call count:%d,timedif=%lld ms\n",
			monitor->pid, monitor->pname, monitor->tid,
			monitor->lastcmdid, monitor->agent_call_count,
			timedif);
	}
}

static void cmd_monitor_tick(void)
{
	struct cmd_monitor *monitor = NULL;
	struct cmd_monitor *tmp = NULL;

	mutex_lock(&g_cmd_monitor_lock);
	list_for_each_entry_safe(monitor, tmp, &g_cmd_monitor_list, list) {
		if (monitor->returned) {
			g_cmd_monitor_list_size--;
			tlogd("[cmd_monitor_tick] pid=%d,pname=%s,tid=%d, "
				"tname=%s,lastcmdid=%u,count=%d,agent call count=%d, "
				"timetotal=%lld us returned, remained command(s)=%d\n",
				monitor->pid, monitor->pname, monitor->tid, monitor->tname,
				monitor->lastcmdid, monitor->count, monitor->agent_call_count,
				monitor->timetotal, g_cmd_monitor_list_size);
			list_del(&monitor->list);
			kfree(monitor);
			continue;
		}
		show_timeout_cmd_info(monitor);
	}

	/* if have cmd in monitor list, we need tick */
	if (g_cmd_monitor_list_size > 0)
		schedule_cmd_monitor_work(&g_cmd_monitor_work, usecs_to_jiffies(S_TO_US));
	mutex_unlock(&g_cmd_monitor_lock);
}

static void cmd_monitor_tickfn(struct work_struct *work)
{
	(void)(work);
	cmd_monitor_tick();
	/* check tlogcat if have new log */
	tz_log_write();
}

#define MAX_CRASH_INFO_LEN 100
static void cmd_monitor_archivefn(struct work_struct *work)
{
	(void)(work);
	if (tlogger_store_msg(CONFIG_TEE_LOG_ACHIVE_PATH,
		sizeof(CONFIG_TEE_LOG_ACHIVE_PATH)) < 0)
		tloge("[cmd_monitor_tick]tlogger store lastmsg failed\n");

	if (g_tee_detect_ta_crash == TYPE_CRASH_TEE) {
		tloge("detect teeos crash, panic\n");
		report_log_system_panic();
	} else if (g_tee_detect_ta_crash == TYPE_CRASH_TA ||
		g_tee_detect_ta_crash == TYPE_KILLED_TA) {
	}

	g_tee_detect_ta_crash = 0;
}

static struct cmd_monitor *init_monitor_locked(void)
{
	struct cmd_monitor *newitem = NULL;

	newitem = kzalloc(sizeof(*newitem), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)newitem)) {
		tloge("[cmd_monitor_tick]kzalloc failed\n");
		return NULL;
	}

	get_time_spec(&newitem->sendtime);
	newitem->lasttime = newitem->sendtime;
	newitem->timer_index = 0;
	newitem->count = 1;
	newitem->agent_call_count = 0;
	newitem->returned = false;
	newitem->is_reported = false;
	newitem->pid = current->tgid;
	newitem->tid = current->pid;
	if (get_pid_name(newitem->pid, newitem->pname,
		sizeof(newitem->pname)) != 0)
		newitem->pname[0] = '\0';
	if (get_pid_name(newitem->tid, newitem->tname,
		sizeof(newitem->tname)) != 0)
		newitem->tname[0] = '\0';
	INIT_LIST_HEAD(&newitem->list);
	list_add_tail(&newitem->list, &g_cmd_monitor_list);
	g_cmd_monitor_list_size++;
	return newitem;
}

struct cmd_monitor *cmd_monitor_log(const struct tc_ns_smc_cmd *cmd)
{
	bool found_flag = false;
	pid_t pid;
	pid_t tid;
	struct cmd_monitor *monitor = NULL;

	if (!cmd)
		return NULL;

	pid = current->tgid;
	tid = current->pid;
/* It is normal for portal applications to be stuck for a long time.
*  We do not need to add them to monitor list for checking. For example, if it starts a server,
*  it will wait for a long time until the client connects. */
#ifdef CONFIG_TEE_TELEPORT_SUPPORT
	if (cmd->cmd_id == GLOBAL_CMD_ID_PORTAL_WORK)
		return NULL;
#endif

	mutex_lock(&g_cmd_monitor_lock);
	do {
		list_for_each_entry(monitor, &g_cmd_monitor_list, list) {
			if (monitor->pid == pid && monitor->tid == tid) {
				found_flag = true;
				/* restart */
				get_time_spec(&monitor->sendtime);
				monitor->lasttime = monitor->sendtime;
				monitor->timer_index = 0;
				monitor->count++;
				monitor->returned = false;
				monitor->is_reported = false;
				monitor->lastcmdid = cmd->cmd_id;
				monitor->agent_call_count = 0;
				monitor->timetotal = 0;
				break;
			}
		}

		if (!found_flag) {
#ifndef CONFIG_BIG_SESSION
			if (g_cmd_monitor_list_size > MAX_CMD_MONITOR_LIST - 1) {
				tloge("monitor reach max node num\n");
				monitor = NULL;
				break;
			}
#endif
			monitor = init_monitor_locked();
			if (!monitor) {
				tloge("init monitor failed\n");
				break;
			}
			monitor->lastcmdid = cmd->cmd_id;
			/* the first cmd will cause timer */
			if (g_cmd_monitor_list_size == 1)
				schedule_cmd_monitor_work(&g_cmd_monitor_work, usecs_to_jiffies(S_TO_US));
		}
	} while (0);
	mutex_unlock(&g_cmd_monitor_lock);

	return monitor;
}

void cmd_monitor_logend(struct cmd_monitor *item)
{
	struct time_spec nowtime;
	long long timedif;

	if (!item)
		return;

	get_time_spec(&nowtime);
	/*
	 * get time value D (timedif=nowtime-sendtime),
	 * we do not care about overflow
	 * 1 year means 1000000 * (60*60*24*365) = 0x1CAE8C13E000
	 * only 6bytes, will not overflow
	 */
	timedif = S_TO_US * (nowtime.ts.tv_sec - item->sendtime.ts.tv_sec) +
		(nowtime.ts.tv_nsec - item->sendtime.ts.tv_nsec) / S_TO_MS;
	item->timetotal += timedif;
	item->returned = true;
}

void do_cmd_need_archivelog(void)
{
	if (g_cmd_need_archivelog == 1) {
		g_cmd_need_archivelog = 0;
		schedule_cmd_monitor_work(&g_cmd_monitor_work_archive,
			usecs_to_jiffies(S_TO_US));
	}
}

void init_cmd_monitor(void)
{
	g_cmd_monitor_wq = alloc_workqueue("tz_cmd_monitor_wq",
		WQ_UNBOUND, TZ_WQ_MAX_ACTIVE);
	if (!g_cmd_monitor_wq)
		tloge("alloc cmd monitor wq failed\n");
	else
		tz_workqueue_bind_mask(g_cmd_monitor_wq, 0);

	INIT_DEFERRABLE_WORK((struct delayed_work *)
		(uintptr_t)&g_cmd_monitor_work, cmd_monitor_tickfn);
	INIT_DEFERRABLE_WORK((struct delayed_work *)
		(uintptr_t)&g_cmd_monitor_work_archive, cmd_monitor_archivefn);
}

void free_cmd_monitor(void)
{
	struct cmd_monitor *monitor = NULL;
	struct cmd_monitor *tmp = NULL;

	mutex_lock(&g_cmd_monitor_lock);
	list_for_each_entry_safe(monitor, tmp, &g_cmd_monitor_list, list) {
		list_del(&monitor->list);
		kfree(monitor);
	}
	mutex_unlock(&g_cmd_monitor_lock);

	flush_delayed_work(&g_cmd_monitor_work);
	flush_delayed_work(&g_cmd_monitor_work_archive);
	if (g_cmd_monitor_wq) {
		flush_workqueue(g_cmd_monitor_wq);
		destroy_workqueue(g_cmd_monitor_wq);
		g_cmd_monitor_wq = NULL;
	}
}

#ifdef CONFIG_CONFIDENTIAL_TEE
#define INSMOD_THREAD "insmod"
#define TEECD_THREAD "teecd"
bool check_running_ca(void)
{
	struct cmd_monitor *monitor = NULL;
	bool has_running_ca = false;
	mutex_lock(&g_cmd_monitor_lock);
	list_for_each_entry(monitor, &g_cmd_monitor_list, list) {
		char pname[TASK_COMM_LEN] = {0};
		if (get_pid_name(monitor->pid, pname, sizeof(pname)) != 0) {
			continue;
		}
		if (strncmp(pname, INSMOD_THREAD, sizeof(INSMOD_THREAD)) != 0 &&
			strncmp(pname, TEECD_THREAD, sizeof(TEECD_THREAD)) != 0) {
			tloge("detect running thread task:%s, please stop\n", pname);
			has_running_ca = true;
		}
	}
	mutex_unlock(&g_cmd_monitor_lock);
	return has_running_ca;
}
#endif
