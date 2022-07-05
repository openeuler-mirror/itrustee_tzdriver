/*
 * tee_trace_event.h
 *
 * functions declarations for tee_trace_event
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

#ifndef TEE_TRACE_EVENT_H
#define TEE_TRACE_EVENT_H

#include <linux/types.h>
#include <linux/smp.h>

/* maxium trace event per cpu stream */
#define TEE_TRACE_EVENT_NUM 20000
/* maxium trace task of 'sched_in/out' event */
#define TEE_TRACE_TASK_MAX 8

/* Add event id's name in 'view_state[]' in same order */
enum tee_event_id {
    INVOKE_CMD_START,
    INVOKE_CMD_END,
    SMC_SEND,
    SMC_DONE,
    SMC_IN,
    SMC_OUT,
    SMC_SLEEP,
    SMC_PREEMPT,
    GTASK_GET_CMD,
    GTASK_PUT_CMD,
    GTASK_REQ_TA,
    GTASK_RESP_TA,
    SPI_WAKEUP,
    SCHED_IN,
    SCHED_OUT,
    TEE_EVENT_MAX
};

#ifdef CONFIG_TEE_TRACE
void tee_trace_add_event(enum tee_event_id id, uint64_t add_info);

int tee_trace_event_enable(void);
int tee_trace_event_start(void);
int tee_trace_event_stop(void);

struct tee_trace_view_t {
    uint64_t start;
    uint32_t total;
    uint32_t end[NR_CPUS];
    uint32_t at[NR_CPUS];
};

void get_tee_trace_start(struct tee_trace_view_t *view);
int get_tee_trace_next(struct tee_trace_view_t *view, uint32_t *event_id,
    const char **event_name, uint32_t *cpu, uint32_t *ca_pid,
        uint64_t *time, uint64_t *add_info);
const char *get_tee_trace_task_name(uint32_t task_idx);
#else
static inline void tee_trace_add_event(enum tee_event_id id, uint64_t add_info)
{
    (void)id;
    (void)add_info;
}
#endif

#endif