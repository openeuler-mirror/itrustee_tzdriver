/*
 * tz_kthread_affinity.h
 *
 * exported funcs for kthread affinity
 *
 * Copyright (c) 2021-2022 Huawei Technologies Co., Ltd.
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
#ifndef TZ_KTHREAD_AFFINITY_H
#define TZ_KTHREAD_AFFINITY_H

#include <linux/sched.h>
#include <linux/workqueue.h>

#define TZ_WQ_MAX_ACTIVE 1

#ifdef CONFIG_KTHREAD_AFFINITY
void init_kthread_cpumask(void);
void tz_kthread_bind_mask(struct task_struct *kthread);
void tz_workqueue_bind_mask(struct workqueue_struct *wq, uint32_t flag);
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
#endif
