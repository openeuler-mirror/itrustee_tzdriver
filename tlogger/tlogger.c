/*
 * tlogger.c
 *
 * TEE Logging Subsystem, read the tee os log from log memory
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
#include "tlogger.h"
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/pid_namespace.h>
#include <linux/proc_ns.h>
#include <linux/delay.h>
#include <asm/ioctls.h>
#include <linux/syscalls.h>
#include <securec.h>
#include <asm/io.h>
#include "smc_smp.h"
#include "mailbox_mempool.h"
#include "teek_client_constants.h"
#include "tc_ns_client.h"
#include "teek_ns_client.h"
#include "log_cfg_api.h"
#include "tc_ns_log.h"
#include "ko_adapt.h"
#include "internal_functions.h"
#ifdef CONFIG_TEE_REBOOT
#include "reboot.h"
#endif
#include "tee_info.h"
#include "tee_compat_check.h"

/* for log item ----------------------------------- */
#define LOG_ITEM_MAGIC          0x5A5A
#define LOG_ITEM_LEN_ALIGN      64
#define LOG_ITEM_MAX_LEN        1024
#define LOG_READ_STATUS_ERROR   0x000FFFF

/* =================================================== */
#define LOGGER_LOG_TEEOS        "teelog" /* tee os log */
#define LOGGERIOCTL             0xBE /* for ioctl */

#define DUMP_START_MAGIC "Dump SPI notification"
#define DUMP_END_MAGIC "Dump task states END"

#define GET_VERSION_BASE       5
#define SET_READERPOS_CUR_BASE 6
#define SET_TLOGCAT_STAT_BASE  7
#define GET_TLOGCAT_STAT_BASE  8
#define GET_TEE_INFO_BASE      9

/* get tee verison */
#define MAX_TEE_VERSION_LEN     256
#define TEELOGGER_GET_VERSION \
	_IOR(LOGGERIOCTL, GET_VERSION_BASE, char[MAX_TEE_VERSION_LEN])
/* set the log reader pos to current pos */
#define TEELOGGER_SET_READERPOS_CUR \
	_IO(LOGGERIOCTL, SET_READERPOS_CUR_BASE)
#define TEELOGGER_SET_TLOGCAT_STAT \
	_IO(LOGGERIOCTL, SET_TLOGCAT_STAT_BASE)
#define TEELOGGER_GET_TLOGCAT_STAT \
	_IO(LOGGERIOCTL, GET_TLOGCAT_STAT_BASE)
#define TEELOGGER_GET_TEE_INFO \
	_IOR(LOGGERIOCTL, GET_TEE_INFO_BASE, struct tc_ns_tee_info)

int g_tlogcat_f = 0;

#ifndef CONFIG_TEE_LOG_ACHIVE_PATH
#define CONFIG_TEE_LOG_ACHIVE_PATH "/data/log/tee/last_teemsg"
#endif
#define TEE_LOG_FILE_NAME_MAX 256

#ifdef CONFIG_TEE_LOG_DUMP_PATH
/* last read offset only for msg dump */
uint32_t g_last_read_offset = 0;
#endif

#define NEVER_USED_LEN 28U
#define LOG_ITEM_RESERVED_LEN 1U

/* 64 byte head + user log */
struct log_item {
	unsigned char never_used[NEVER_USED_LEN];
	unsigned int nsid;
	unsigned short magic;
	unsigned short reserved0;
	uint32_t serial_no;
	unsigned short real_len; /* log real len */
	unsigned short buffer_len; /* log buffer's len, multiple of 32 bytes */
	unsigned char uuid[UUID_LEN];
	unsigned char log_source_type;
	unsigned char reserved[LOG_ITEM_RESERVED_LEN];
	unsigned char log_level;
	unsigned char new_line; /* '\n' char, easy viewing log in bbox.bin file */
	unsigned char log_buffer[];
};

/* --- for log mem --------------------------------- */
#define TEMP_LOG_MEM_SIZE          (10 * SZ_1K)

#define LOG_BUFFER_RESERVED_LEN    11U
#define VERSION_INFO_LEN           156U

/*
 * Log's buffer flag info, size: 64 bytes head + 156 bytes's version info.
 * For filed description:
 * last_pos : current log's end position, last log's start position.
 * write_loops: Write cyclically. Init value is 0, when memory is used
 *              up, the value add 1.
 */
struct log_buffer_flag {
	uint32_t reserved0;
	uint32_t last_pos;
	uint32_t write_loops;
	uint32_t log_level;
	/* [0] is magic failed, [1] is serial_no failed, used fior log retention feature */
	uint32_t reserved[LOG_BUFFER_RESERVED_LEN];
	uint32_t max_len;
	unsigned char version_info[VERSION_INFO_LEN];
};

struct log_buffer {
	struct log_buffer_flag flag;
	unsigned char buffer_start[];
};

static struct log_buffer *g_log_buffer = NULL;

struct tlogger_log {
	unsigned char *buffer_info; /* ring buffer info */
	struct mutex mutex_info; /* this mutex protects buffer_info */
	struct list_head logs; /* log channels list */
	struct mutex mutex_log_chnl; /* this mutex protects log channels */
	struct miscdevice misc_device; /* misc device log */
	struct list_head readers; /* log's readers */
};

static LIST_HEAD(m_log_list);

struct tlogger_group {
	struct list_head node;
	uint32_t nsid;
	volatile uint32_t reader_cnt;
	volatile uint32_t tlogf_stat;
};

struct tlogger_reader {
	struct tlogger_log *log; /* tlogger_log info data */
	struct tlogger_group *group; /* tlogger_group info data */
	struct pid *pid; /* current process pid */
	struct list_head list; /* log entry in tlogger_log's list */
	wait_queue_head_t wait_queue_head; /* wait queue head for reader */
	/* Current reading position, start position of next read again */
	uint32_t r_off;
	uint32_t r_loops;
	uint32_t r_sn;
	uint32_t r_failtimes;
	uint32_t r_from_cur;
	uint32_t r_is_tlogf;
	bool r_all; /* whether this reader can read all entries */
	uint32_t r_ver;
};

static uint32_t g_log_mem_len = 0;
static uint32_t g_tlogcat_count = 0;
static struct tlogger_log *g_log;

static struct mutex g_reader_group_mutex;
static LIST_HEAD(g_reader_group_list);

static struct tlogger_log *get_reader_log(const struct file *file)
{
	struct tlogger_reader *reader = NULL;

	reader = file->private_data;
	if (!reader)
		return NULL;

	return reader->log;
}

static bool check_log_item_validite(const struct log_item *item,
	uint32_t item_max_size)
{
	bool con = (item && (item->magic == LOG_ITEM_MAGIC) &&
		(item->buffer_len > 0) &&
		(item->real_len > 0) &&
		(item->buffer_len % LOG_ITEM_LEN_ALIGN == 0) &&
		(item->real_len <= item->buffer_len) &&
		((item->buffer_len - item->real_len) < LOG_ITEM_LEN_ALIGN) &&
		(item->buffer_len + sizeof(*item) <= item_max_size));

	return con;
}

static struct log_item *get_next_log_item(const unsigned char *buffer_start,
	uint32_t max_len, uint32_t read_pos, uint32_t scope_len, uint32_t *pos)
{
	uint32_t i = 0;
	struct log_item *item = NULL;
	uint32_t max_size;

	if ((read_pos + scope_len) > max_len)
		return NULL;

	while ((i + sizeof(*item) + LOG_ITEM_LEN_ALIGN) <= scope_len) {
		*pos = read_pos + i;
		item = (struct log_item *)(uintptr_t)(buffer_start + read_pos + i);
		max_size = (((scope_len - i) > LOG_ITEM_MAX_LEN) ?
			LOG_ITEM_MAX_LEN : (scope_len - i));
		if (check_log_item_validite(item, max_size))
			break;

		i += LOG_ITEM_LEN_ALIGN;
		item = NULL;
	}

	return item;
}

static bool check_group_compat(struct tlogger_group *group, struct log_item *item)
{
	if (group->nsid == item->nsid)
		return true;

	if (group->nsid == PROC_PID_INIT_INO && item->nsid == 0)
		return true;

	return false;
}

struct reader_position {
	const unsigned char *buffer_start;
	uint32_t max_len;
	uint32_t start_pos;
	uint32_t end_pos;
};

static uint32_t parse_log_item(struct tlogger_reader *reader,
	char __user *buf, size_t count, struct reader_position *position,
	bool *user_buffer_left)
{
	struct log_item *next_item = NULL;
	size_t buf_left;
	uint32_t buf_written;
	uint32_t item_len;
	bool con = false;
	uint32_t start_pos = position->start_pos;

	buf_written = 0;
	buf_left = count;

	con = (!position->buffer_start || reader->group == NULL);
	if (con)
		return buf_written;

	*user_buffer_left = true;
	while (start_pos < position->end_pos) {
		next_item = get_next_log_item(position->buffer_start,
			position->max_len, start_pos,
			position->end_pos - start_pos, &start_pos);
		if (!next_item)
			break;

		/* copy to user */
		item_len = next_item->buffer_len + sizeof(*next_item);
		if (check_group_compat(reader->group, next_item)) {
			if (buf_left < item_len) {
				*user_buffer_left = false;
				break;
			}

			if (copy_to_user(buf + buf_written, (void *)next_item, item_len) != 0)
				tloge("copy failed, item len %u\n", item_len);

			buf_written += item_len;
			buf_left -= item_len;
		}
		start_pos += item_len;
	}

	reader->r_off = start_pos;
	return buf_written;
}

static ssize_t get_buffer_info(struct tlogger_reader *reader,
	struct log_buffer_flag *buffer_flag, struct log_buffer **log_buffer)
{
	struct tlogger_log *log = NULL;
	errno_t ret;
	struct log_buffer *buffer_tmp = NULL;

	log = reader->log;
	if (!log)
		return -EINVAL;

	buffer_tmp = (struct log_buffer*)log->buffer_info;
	if (!buffer_tmp)
		return -EINVAL;

	__asm__ volatile ("isb");
	__asm__ volatile ("dsb sy");

	mutex_lock(&log->mutex_info);
	ret = memcpy_s(buffer_flag, sizeof(*buffer_flag), &buffer_tmp->flag,
		sizeof(buffer_tmp->flag));
	mutex_unlock(&log->mutex_info);
	if (ret != 0) {
		tloge("memcpy failed %d\n", ret);
		return -EAGAIN;
	}

	*log_buffer = buffer_tmp;
	return 0;
}

#define LOG_BUFFER_MAX_LEN      0x100000

static ssize_t get_last_read_pos(struct log_buffer_flag *log_flag,
	const struct tlogger_reader *reader, uint32_t *log_last_pos, uint32_t *is_read)
{
	uint32_t buffer_max_len = g_log_mem_len - sizeof(*g_log_buffer);

	*is_read = 0;

	if (buffer_max_len > LOG_BUFFER_MAX_LEN)
		return -EINVAL;

	*log_last_pos = log_flag->last_pos;
	if (*log_last_pos == reader->r_off &&
		log_flag->write_loops == reader->r_loops)
		return 0;

	if (log_flag->max_len < *log_last_pos ||
		log_flag->max_len > buffer_max_len) {
		tloge("invalid data maxlen %x pos %x\n",
			log_flag->max_len, *log_last_pos);
		return -EFAULT;
	}

	if (reader->r_off > log_flag->max_len) {
		tloge("invalid data roff %x maxlen %x\n",
			reader->r_off, log_flag->max_len);
		return -EFAULT;
	}

	*is_read = 1;
	return 0;
}

static void set_reader_position(struct reader_position *position,
	const unsigned char *buffer_start, uint32_t max_len, uint32_t start_pos, uint32_t end_pos)
{
	position->buffer_start = buffer_start;
	position->max_len = max_len;
	position->start_pos = start_pos;
	position->end_pos = end_pos;
}

static ssize_t proc_read_ret(uint32_t buf_written,
	const struct tlogger_reader *reader)
{
	ssize_t ret = buf_written;
	(void)reader;
	tlogd("read length %u\n", buf_written);
	return ret;
}

static ssize_t check_read_params(const struct file *file,
	const char __user *buf, size_t count)
{
	if (count < LOG_ITEM_MAX_LEN)
		return -EINVAL;

	if (!file || !buf)
		return -EINVAL;

	return 0;
}

/*
 * If the sequence number of the last read position is smaller
 * than the current minimum sequence number, the last read
 * position is overwritten. And this time read data from
 * minimum number, or read data from last position.
 */
static ssize_t trigger_parse_log(char __user *buf, size_t count,
	uint32_t log_last_pos, struct log_buffer *log_buffer,
	struct tlogger_reader *reader)
{
	bool user_buffer_left = false;
	uint32_t buf_written;
	struct reader_position position = {0};
	struct log_buffer_flag *buffer_flag = &(log_buffer->flag);

	if (buffer_flag->write_loops == reader->r_loops) {
		set_reader_position(&position, log_buffer->buffer_start,
			buffer_flag->max_len, reader->r_off, log_last_pos);

		buf_written = parse_log_item(reader, buf, count, &position, &user_buffer_left);

		return proc_read_ret(buf_written, reader);
	}

	if (buffer_flag->write_loops > (reader->r_loops +1) ||
		((buffer_flag->write_loops == (reader->r_loops + 1)) &&
		(reader->r_off < log_last_pos))) {
		reader->r_off = log_last_pos;
		reader->r_loops = buffer_flag->write_loops - 1;
	}

	set_reader_position(&position, log_buffer->buffer_start,
		buffer_flag->max_len, reader->r_off, buffer_flag->max_len);

	buf_written = parse_log_item(reader, buf, count, &position, &user_buffer_left);

	if (count > buf_written && user_buffer_left) {
		set_reader_position(&position, log_buffer->buffer_start,
			buffer_flag->max_len, 0, log_last_pos);

		buf_written += parse_log_item(reader, buf + buf_written,
			count - buf_written, &position, &user_buffer_left);

		reader->r_loops = buffer_flag->write_loops;
	}

	return proc_read_ret(buf_written, reader);
}

static ssize_t process_tlogger_read(struct file *file,
	char __user *buf, size_t count, loff_t *pos)
{
	struct tlogger_reader *reader = NULL;
	struct log_buffer *log_buffer = NULL;
	ssize_t ret;
	uint32_t last_pos;
	uint32_t is_read;
	struct log_buffer_flag buffer_flag;

	(void)pos;

	ret = check_read_params(file, buf, count);
	if (ret != 0)
		return ret;

	reader = file->private_data;
	if (!reader)
		return -EINVAL;

	ret = get_buffer_info(reader, &buffer_flag, &log_buffer);
	if (ret != 0)
		return ret;

	ret = get_last_read_pos(&buffer_flag, reader, &last_pos, &is_read);
	if (is_read == 0)
		return ret;

	return trigger_parse_log(buf, count, last_pos, log_buffer, reader);
}

void tz_log_write(void)
{
	struct log_buffer *log_buffer = NULL;
	struct tlogger_reader *reader = NULL;

	if (!g_log)
		return;

	log_buffer = (struct log_buffer*)g_log->buffer_info;
	if (!log_buffer)
		return;

	mutex_lock(&g_log->mutex_log_chnl);
	list_for_each_entry(reader, &g_log->readers, list) {
		if (reader->r_off != log_buffer->flag.last_pos) {
			tlogd("wake up write tz log\n");
			wake_up_interruptible(&reader->wait_queue_head);
		}
	}
	mutex_unlock(&g_log->mutex_log_chnl);

	return;
}

#ifdef CONFIG_TEE_REBOOT
void recycle_tlogcat_processes(void)
{
	struct log_buffer *log_buffer = NULL;
	struct tlogger_reader *reader = NULL;

	if (g_log == NULL)
		return;

	log_buffer = (struct log_buffer *)g_log->buffer_info;
	if (log_buffer == NULL)
		return;

	mutex_lock(&g_log->mutex_log_chnl);
	list_for_each_entry(reader, &g_log->readers, list)
		kill_pid(reader->pid, SIGKILL, 1);
	mutex_unlock(&g_log->mutex_log_chnl);
}
#endif

static struct tlogger_group *get_tlogger_group(void)
{
	struct tlogger_group *group = NULL;
#ifdef CONFIG_CONFIDENTIAL_CONTAINER
	uint32_t nsid = task_active_pid_ns(current)->ns.inum;
#else
	uint32_t nsid = PROC_PID_INIT_INO;
#endif

	list_for_each_entry(group, &g_reader_group_list, node) {
		if (group->nsid == nsid)
			return group;
	}

	return NULL;
}

static struct tlogger_log *get_tlogger_log_by_minor(int minor)
{
	struct tlogger_log *log = NULL;

	list_for_each_entry(log, &m_log_list, logs) {
		if (log->misc_device.minor == minor)
			return log;
	}

	return NULL;
}

static void init_tlogger_reader(struct tlogger_reader *reader, struct tlogger_log *log, struct tlogger_group *group)
{
	reader->log = log;
	reader->group = group;

	get_task_struct(current);
	reader->pid = get_task_pid(current, PIDTYPE_PID);
	put_task_struct(current);

	reader->r_all = true;
	reader->r_off = 0;
	reader->r_loops = 0;
	reader->r_sn = 0;
	reader->r_failtimes = 0;
	reader->r_is_tlogf = 0;
	reader->r_from_cur = 0;

	INIT_LIST_HEAD(&reader->list);
	init_waitqueue_head(&reader->wait_queue_head);
}

static void init_tlogger_group(struct tlogger_group *group)
{
	group->reader_cnt = 1;
#ifdef CONFIG_CONFIDENTIAL_CONTAINER
	group->nsid = task_active_pid_ns(current)->ns.inum;
#else
	group->nsid = PROC_PID_INIT_INO;
#endif
	group->tlogf_stat = 0;
}

static int process_tlogger_open(struct inode *inode,
	struct file *file)
{
	struct tlogger_log *log = NULL;
	int ret;
	struct tlogger_reader *reader = NULL;
	struct tlogger_group *group = NULL;

	tlogd("open logger open ++\n");
	/* not support seek */
	ret = nonseekable_open(inode, file);
	if (ret != 0)
		return ret;

	tlogd("Before get log from minor\n");
	log = get_tlogger_log_by_minor(MINOR(inode->i_rdev));
	if (!log)
		return -ENODEV;

	mutex_lock(&g_reader_group_mutex);
	group = get_tlogger_group();
	if (group == NULL) {
		group = kzalloc(sizeof(*group), GFP_KERNEL);
		if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)group)) {
			mutex_unlock(&g_reader_group_mutex);
			return -ENOMEM;
		}
		init_tlogger_group(group);
		list_add_tail(&group->node, &g_reader_group_list);
	} else {
		group->reader_cnt++;
	}
	mutex_unlock(&g_reader_group_mutex);

	reader = kmalloc(sizeof(*reader), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)reader)) {
		mutex_lock(&g_reader_group_mutex);
		if (--group->reader_cnt == 0) {
			list_del(&group->node);
			kfree(group);
		}
		mutex_unlock(&g_reader_group_mutex);
		return -ENOMEM;
	}
	init_tlogger_reader(reader, log, group);

	mutex_lock(&log->mutex_log_chnl);
	list_add_tail(&reader->list, &log->readers);
	g_tlogcat_count++;
	mutex_unlock(&log->mutex_log_chnl);

	file->private_data = reader;
	tlogd("tlogcat count %u\n", g_tlogcat_count);
	return 0;
}

static int process_tlogger_release(struct inode *ignored,
	struct file *file)
{
	struct tlogger_reader *reader = NULL;
	struct tlogger_log *log = NULL;
	struct tlogger_group *group = NULL;

	(void)ignored;

	tlogd("logger_release ++\n");

	if (!file)
		return -1;

	reader = file->private_data;
	if (!reader) {
		tloge("reader is null\n");
		return -1;
	}

	log = reader->log;
	if (!log) {
		tloge("log is null\n");
		return -1;
	}

	mutex_lock(&log->mutex_log_chnl);
	list_del(&reader->list);
	if (g_tlogcat_count >= 1)
		g_tlogcat_count--;
	mutex_unlock(&log->mutex_log_chnl);

	group = reader->group;
	if (group != NULL) {
		mutex_lock(&g_reader_group_mutex);
		if (reader->r_is_tlogf != 0)
			group->tlogf_stat = 0;
		if (--group->reader_cnt == 0) {
			list_del(&group->node);
			kfree(group);
		}
		mutex_unlock(&g_reader_group_mutex);
	}

	kfree(reader);
	tlogd("tlogcat count %u\n", g_tlogcat_count);
	return 0;
}

static unsigned int process_tlogger_poll(struct file *file,
	poll_table *wait)
{
	struct tlogger_reader *reader = NULL;
	struct tlogger_log *log = NULL;
	struct log_buffer *buffer = NULL;
	uint32_t ret = POLLOUT | POLLWRNORM;

	tlogd("logger_poll ++\n");
	if (!file) {
		tloge("file is null\n");
		return ret;
	}

	reader = file->private_data;
	if (!reader) {
		tloge("the private data is null\n");
		return ret;
	}

	log = reader->log;
	if (!log) {
		tloge("log is null\n");
		return ret;
	}

	buffer = (struct log_buffer*)log->buffer_info;
	if (!buffer) {
		tloge("buffer is null\n");
		return ret;
	}

	poll_wait(file, &reader->wait_queue_head, wait);

	if (buffer->flag.last_pos != reader->r_off)
		ret |= POLLIN | POLLRDNORM;

	return ret;
}

#define SET_READ_POS   1U
static void set_reader_cur_pos(const struct file *file)
{
	struct tlogger_reader *reader = NULL;
	struct tlogger_log *log = NULL;
	struct log_buffer *buffer = NULL;

	reader = file->private_data;
	if (!reader)
		return;

	log = reader->log;
	if (!log)
		return;

	buffer = (struct log_buffer*)log->buffer_info;
	if (!buffer)
		return;

	reader->r_from_cur = SET_READ_POS;
	reader->r_off = buffer->flag.last_pos;
	reader->r_loops = buffer->flag.write_loops;
}

static void set_tlogcat_f_stat(const struct file *file)
{
	struct tlogger_reader *reader = NULL;

	if (file == NULL) {
		return;
	}

	reader = file->private_data;
	if (reader == NULL) {
		return;
	}

	reader->r_is_tlogf = 1;
	if (reader->group != NULL) {
		mutex_lock(&g_reader_group_mutex);
		reader->group->tlogf_stat = 1;
		mutex_unlock(&g_reader_group_mutex);
	}

	return;
}

static int get_tlogcat_f_stat(const struct file *file)
{
	struct tlogger_reader *reader = NULL;
	int tlogf_stat = 0;

	if (file == NULL) {
		return tlogf_stat;
	}

	reader = file->private_data;
	if (reader == NULL) {
		return tlogf_stat;
	}

	if (reader->group != NULL) {
		mutex_lock(&g_reader_group_mutex);
		tlogf_stat = reader->group->tlogf_stat;
		mutex_unlock(&g_reader_group_mutex);
	}

	return tlogf_stat;
}

static int get_teeos_version(uint32_t cmd, unsigned long arg)
{
	if ((_IOC_DIR(cmd) & _IOC_READ) == 0) {
		tloge("check get version cmd failed\n");
		return -1;
	}

	if (copy_to_user((void __user *)(uintptr_t)arg,
		(void *)g_log_buffer->flag.version_info,
		sizeof(g_log_buffer->flag.version_info)) != 0) {
		tloge("version info copy failed\n");
		return -1;
	}

	return 0;
}

static long process_tlogger_ioctl(struct file *file,
	unsigned int cmd, unsigned long arg)
{
	struct tlogger_log *log = NULL;
	long ret = -EINVAL;

	if (!file)
		return -1;

	log = get_reader_log(file);
	if (!log) {
		tloge("log is null\n");
		return -1;
	}

	tlogd("logger_ioctl start ++\n");
	mutex_lock(&log->mutex_info);

	switch (cmd) {
	case TEELOGGER_GET_VERSION:
		if (get_teeos_version(cmd, arg) == 0)
			ret = 0;
		break;
	case TEELOGGER_SET_READERPOS_CUR:
		set_reader_cur_pos(file);
		ret = 0;
		break;
	case TEELOGGER_SET_TLOGCAT_STAT:
		set_tlogcat_f_stat(file);
		ret = 0;
		break;
	case TEELOGGER_GET_TLOGCAT_STAT:
		ret = get_tlogcat_f_stat(file);
		break;
	case TEELOGGER_GET_TEE_INFO:
		ret = tc_ns_get_tee_info(file, (void *)(uintptr_t)arg);
		break;
	default:
		tloge("ioctl error default\n");
		break;
	}

	mutex_unlock(&log->mutex_info);
	return ret;
}

#ifdef CONFIG_COMPAT
static long process_tlogger_compat_ioctl(struct file *file,
	unsigned int cmd, unsigned long arg)
{
	tlogd("logger_compat_ioctl ++\n");
	arg = (unsigned long)(uintptr_t)compat_ptr(arg);
	return process_tlogger_ioctl(file, cmd, arg);
}
#endif

static const struct file_operations g_logger_fops = {
	.owner = THIS_MODULE,
	.read = process_tlogger_read,
	.poll = process_tlogger_poll,
	.unlocked_ioctl = process_tlogger_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = process_tlogger_compat_ioctl,
#endif
	.open = process_tlogger_open,
	.release = process_tlogger_release,
};

static int __init register_device(const char *log_name,
	uintptr_t addr, int size)
{
	int ret;
	struct tlogger_log *log = NULL;
	unsigned char *buffer = (unsigned char *)addr;
	(void)size;

	log = kzalloc(sizeof(*log), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)log)) {
		tloge("kzalloc is failed\n");
		return -ENOMEM;
	}
	log->buffer_info = buffer;
	log->misc_device.minor = MISC_DYNAMIC_MINOR;
	log->misc_device.name = kstrdup(log_name, GFP_KERNEL);
	if (!log->misc_device.name) {
		ret = -ENOMEM;
		tloge("kstrdup is failed\n");
		goto out_free_log;
	}
	log->misc_device.fops = &g_logger_fops;
	log->misc_device.parent = NULL;

	INIT_LIST_HEAD(&log->readers);
	mutex_init(&log->mutex_info);
	mutex_init(&log->mutex_log_chnl);
	INIT_LIST_HEAD(&log->logs);
	list_add_tail(&log->logs, &m_log_list);

	/* register misc device for this log */
	ret = misc_register(&log->misc_device);
	if (unlikely(ret)) {
		tloge("failed to register misc device:%s\n",
			log->misc_device.name);
		goto out_free_log;
	}
	g_log = log;
	return 0;

out_free_log:
	if (log->misc_device.name)
		kfree(log->misc_device.name);

	kfree(log);
	return ret;
}

static struct log_item *msg_get_next(unsigned char *buffer_start,
	uint32_t read_pos, uint32_t scope_len, uint32_t max_len)
{
	uint32_t i = 0;
	struct log_item *item = NULL;
	uint32_t item_max_size;
	uint32_t len;

	while (i <= scope_len &&
		((read_pos + i + sizeof(*item)) < max_len)) {
		len = (uint32_t)(scope_len - i);
		item_max_size =
			((len > LOG_ITEM_MAX_LEN) ? LOG_ITEM_MAX_LEN : len);
		item = (struct log_item *)(buffer_start + read_pos + i);

		if (check_log_item_validite(item, item_max_size)) {
			if ((read_pos + i + sizeof(*item) +
				item->buffer_len) > max_len) {
				tloge("check item len error\n");
				return NULL;
			}

			return item;
		}

		i += LOG_ITEM_LEN_ALIGN;
		item = NULL;
	}

	return NULL;
}

#ifdef CONFIG_TZDRIVER_MODULE
/* there is no way to chown in kernel-5.10 for ko */
static void tlogger_chown(const char *file_path, uint32_t file_path_len)
{
	(void)file_path;
	(void)file_path_len;
}
#else
static void tlogger_chown(const char *file_path, uint32_t file_path_len)
{
	(void)file_path_len;
	uid_t user = ROOT_UID;
	gid_t group = ROOT_GID;
	int ret;
	mm_segment_t old_fs;

	get_log_chown(&user, &group);

	/* not need modify chown attr */
	if (group == ROOT_GID && user == ROOT_UID)
		return;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
#if (KERNEL_VERSION(5, 10, 0) <= LINUX_VERSION_CODE)
	ret = (int)ksys_chown((const char __user *)file_path, user, group);
#else
	ret = (int)sys_chown((const char __user *)file_path, user, group);
#endif
	if (ret != 0)
		tloge("sys chown for last teemsg file error %d\n", ret);

	set_fs(old_fs);
}
#endif

static int write_version_to_msg(struct file *filep,
	loff_t *pos)
{
	ssize_t write_len;

	/* first write tee versino info */
	write_len = kernel_write(filep, g_log_buffer->flag.version_info,
		strlen(g_log_buffer->flag.version_info), pos);
	if (write_len < 0) {
		tloge("Failed to write to last teemsg version\n");
		return -1;
	}

	tlogd("Succeed to Write to last teemsg version, len=%zd\n", write_len);
	return 0;
}

static int write_part_log_to_msg(struct file *filep,
	unsigned char *buffer, uint32_t buffer_max_len, loff_t *pos,
	uint32_t read_off, uint32_t read_off_end)
{
	struct log_item *next_item = NULL;
	uint32_t item_len;
	uint32_t total_len = 0;
	ssize_t write_len;

	next_item = msg_get_next(buffer, read_off,
		LOG_ITEM_MAX_LEN, buffer_max_len);

	while (next_item && read_off <= read_off_end) {
		item_len = next_item->buffer_len + sizeof(*next_item);
		write_len = kernel_write(filep, next_item->log_buffer,
			next_item->real_len, pos);
		if (write_len < 0) {
			tloge("Failed to write last teemsg %zd\n", write_len);
			return -1;
		}

		tlogd("Succeed to Write last teemsg, len=%zd\n", write_len);
		total_len += item_len;
		read_off = (unsigned char *)next_item - buffer + item_len;
		if (total_len >= buffer_max_len)
			break;

		next_item = msg_get_next(buffer, read_off,
			LOG_ITEM_MAX_LEN, buffer_max_len);
	}

	return 0;
}

static int write_log_to_msg(struct file *filep,
	unsigned char *buffer, uint32_t buffer_max_len, loff_t *pos,
	uint32_t read_off, uint32_t read_off_end)
{
	if (read_off < read_off_end) {
		return write_part_log_to_msg(filep, buffer, buffer_max_len, pos,
			read_off, read_off_end);
	} else {
		if (write_part_log_to_msg(filep, buffer, buffer_max_len, pos,
			read_off, buffer_max_len) != 0)
			return -1;
		return write_part_log_to_msg(filep, buffer, buffer_max_len, pos,
			0, read_off_end);
	}
}

#ifdef CONFIG_TEE_LOG_DUMP_PATH
static void update_dumpmsg_offset(uint32_t *read_start, uint32_t *read_end,
	uint32_t read_off, uint32_t read_off_end, uint32_t *dump_start_flag, uint32_t *dump_end_flag)
{
	struct log_item *next_item = NULL;
	unsigned char *buffer = g_log_buffer->buffer_start;
	uint32_t buffer_max_len = g_log_mem_len - sizeof(*g_log_buffer);
	ssize_t item_len;
	ssize_t total_len = 0;

	next_item = msg_get_next(buffer, read_off,
		LOG_ITEM_MAX_LEN, buffer_max_len);

	while (next_item && read_off <= read_off_end) {
		item_len = next_item->buffer_len + sizeof(*next_item);
		if (strstr(next_item->log_buffer, DUMP_START_MAGIC)) {
			*read_start = read_off;
			*dump_start_flag = 1;
		} else if (strstr(next_item->log_buffer, DUMP_END_MAGIC)) {
			*read_end = read_off;
			*dump_end_flag = 1;
		}
		read_off = (unsigned char *)next_item - buffer + item_len;
		total_len += item_len;
		if (total_len >= buffer_max_len)
			break;

		next_item = msg_get_next(buffer, read_off,
			LOG_ITEM_MAX_LEN, buffer_max_len);
	}
}
#endif

#ifdef CONFIG_TEE_LOG_DUMP_PATH
static int get_dumpmsg_offset(uint32_t *read_start, uint32_t *read_end)
{
	uint32_t read_off = *read_start;
	uint32_t read_off_end = *read_end;
	uint32_t buffer_max_len = g_log_mem_len - sizeof(*g_log_buffer);
	uint32_t dump_start_flag = 0;
	uint32_t dump_end_flag = 0;

	if (read_off < read_off_end) {
		update_dumpmsg_offset(read_start, read_end, read_off, read_off_end,
			&dump_start_flag, &dump_end_flag);
	} else {
		update_dumpmsg_offset(read_start, read_end, read_off, buffer_max_len,
			&dump_start_flag, &dump_end_flag);
		update_dumpmsg_offset(read_start, read_end, 0, read_off_end,
			&dump_start_flag, &dump_end_flag);
	}

	if (dump_start_flag == 0 || dump_end_flag == 0) {
		tloge("can't find dump start or end\n");
		return -1;
	} else {
		return 0;
	}
}
#endif

static int get_msg_buffer(unsigned char **buffer, uint32_t *buffer_max_len,
	uint32_t *read_start, uint32_t *read_end,
	const char *file_path, uint32_t file_path_len)
{
	errno_t rc;
	int ret;
	unsigned char *addr = NULL;
	(void)file_path_len;

	if (!g_log_buffer)
		return -1;

	*buffer_max_len = g_log_mem_len - sizeof(*g_log_buffer);

	if (*buffer_max_len > LOG_BUFFER_MAX_LEN)
		return 0;

	*read_start = 0;
	*read_end = *buffer_max_len;
#ifdef CONFIG_TEE_LOG_DUMP_PATH
	if (strcmp(file_path, CONFIG_TEE_LOG_DUMP_PATH) == 0) {
		*read_start = g_last_read_offset;
		*read_end = ((struct log_buffer*)g_log->buffer_info)->flag.last_pos;
		if (get_dumpmsg_offset(read_start, read_end) != 0) {
			tloge("get dump offset failed\n");
			return -1;
		}
	}
#else
	(void)file_path;
#endif
	addr = kmalloc(*buffer_max_len, GFP_KERNEL);
	if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)addr)) {
		ret = -ENOMEM;
		goto free_res;
	}

	rc = memcpy_s(addr, *buffer_max_len, g_log_buffer->buffer_start,
		*buffer_max_len);
	if (rc) {
		tloge("memcpy failed %d\n", rc);
		ret = -EAGAIN;
		goto free_res;
	}

	*buffer = addr;
	return 0;

free_res:
	if (addr)
		kfree(addr);

	return ret;
}

static int open_msg_file(struct file **file,
	const char *file_path, uint32_t file_path_len)
{
	struct file *filep = NULL;
	(void)file_path_len;

	filep = filp_open(file_path, O_CREAT | O_RDWR | O_TRUNC, OPEN_FILE_MODE);
	if (!filep || IS_ERR(filep)) {
		tloge("open last teemsg file err %ld\n", PTR_ERR(filep));
		return -1;
	}

	*file = filep;
	return 0;
}

int tlogger_store_msg(const char *file_path, uint32_t file_path_len)
{
	struct file *filep = NULL;
	loff_t pos = 0;
	int ret;
	uint32_t buffer_max_len = 0;
	unsigned char *buffer = NULL;
	uint32_t read_start = 0;
	uint32_t read_end = 0;

	if (!file_path || file_path_len > TEE_LOG_FILE_NAME_MAX) {
		tloge("file path is invalid\n");
		return -1;
	}

	if (!g_tlogcat_count) {
		tlogd("tlogcat count %u\n", g_tlogcat_count);
		return 0;
	}

	/* copy logs from log memory, then parse the logs */
	ret = get_msg_buffer(&buffer, &buffer_max_len,
		&read_start, &read_end, file_path, file_path_len);
	if (ret != 0)
		return ret;

	/* exception handling, store trustedcore exception info to file */
	ret = open_msg_file(&filep, file_path, file_path_len);
	if (ret != 0)
		goto free_res;

	tlogger_chown(file_path, file_path_len);

	ret = write_version_to_msg(filep, &pos);
	if (ret != 0)
		goto free_res;

	ret = write_log_to_msg(filep, buffer, buffer_max_len,
		&pos, read_start, read_end);

#ifdef CONFIG_TEE_LOG_DUMP_PATH
	g_last_read_offset = ((struct log_buffer*)g_log->buffer_info)->flag.last_pos;
#endif

free_res:
	if (buffer) {
		kfree(buffer);
		buffer = NULL;
	}

	if (filep != NULL) {
		vfs_fsync(filep, 0);
		filp_close(filep, 0);
	}

	/* trigger write teeos log */
	tz_log_write();
	return ret;
}

int register_mem_to_teeos(uint64_t mem_addr, uint32_t mem_len, bool is_cache_mem)
{
	struct tc_ns_smc_cmd smc_cmd = { {0}, 0 };
	struct mb_cmd_pack *mb_pack = NULL;
	int ret;

	mb_pack = mailbox_alloc_cmd_pack();
	if (!mb_pack) {
		tloge("mailbox alloc failed\n");
		return -ENOMEM;
	}

	smc_cmd.cmd_type = CMD_TYPE_GLOBAL;
	smc_cmd.cmd_id = GLOBAL_CMD_ID_REGISTER_LOG_MEM;
	mb_pack->operation.paramtypes = teec_param_types(
		TEE_PARAM_TYPE_VALUE_INPUT,
		TEE_PARAM_TYPE_VALUE_INPUT,
		TEE_PARAM_TYPE_VALUE_INPUT,
		TEE_PARAM_TYPE_NONE);
	mb_pack->operation.params[0].value.a = mem_addr;
	mb_pack->operation.params[0].value.b = mem_addr >> ADDR_TRANS_NUM;
	mb_pack->operation.params[1].value.a = mem_len;
	/*
	 * is_cache_mem: true, teeos map this memory for cache
	 * style; or else map to no cache style
	 */
	mb_pack->operation.params[2].value.a = is_cache_mem;

	smc_cmd.operation_phys = mailbox_virt_to_phys((uintptr_t)&mb_pack->operation);
	smc_cmd.operation_h_phys =
		(uint64_t)mailbox_virt_to_phys((uintptr_t)&mb_pack->operation) >> ADDR_TRANS_NUM;

	if (is_tee_rebooting())
		ret = send_smc_cmd_rebooting(TSP_REQUEST, &smc_cmd);
	else
		ret = tc_ns_smc(&smc_cmd);

	mailbox_free(mb_pack);
	if (ret != 0)
		tloge("Send log mem info failed\n");

	return ret;
}

static int register_mem_cfg(uint64_t *addr, uint32_t *len)
{
	int ret;
	ret = register_log_mem(addr, len);
	if (ret != 0)
		tloge("register log mem failed %x\n", ret);

	ret = register_log_exception();
	if (ret != 0)
		tloge("teeos register exception to log module failed\n");

	return ret;
}

static int check_log_mem(uint64_t mem_addr, uint32_t mem_len)
{
	if (mem_len < TEMP_LOG_MEM_SIZE) {
		tloge("log mem init error, too small len:0x%x\n", mem_len);
		return -1;
	}
	if (!mem_addr) {
		tloge("mem init failed!!! addr is 0\n");
		return -1;
	}
	return 0;
}

int register_tloger_mem(void)
{
	int ret;
	uint64_t mem_addr = 0;

	ret = register_mem_cfg(&mem_addr, &g_log_mem_len);
	if (ret != 0)
		return ret;

	ret = check_log_mem(mem_addr, g_log_mem_len);
	if (ret != 0)
		return ret;

	g_log_buffer =
		(struct log_buffer *)map_log_mem(mem_addr, g_log_mem_len);
	if (!g_log_buffer)
		return -ENOMEM;

	g_log_buffer->flag.max_len = g_log_mem_len - sizeof(*g_log_buffer);

	return ret;
}

static int register_tloger_device(void)
{
	int ret;

	tlogi("tlogcat version %d.%d\n", TZDRIVER_LEVEL_MAJOR_SELF, TZDRIVER_LEVEL_MINOR_SELF);
	ret = register_device(LOGGER_LOG_TEEOS, (uintptr_t)g_log_buffer,
		sizeof(*g_log_buffer) + g_log_buffer->flag.max_len);
	if (ret != 0) {
		unmap_log_mem((int *)g_log_buffer);
		g_log_buffer = NULL;
		g_log_mem_len = 0;
	}

	return ret;
}

static int register_tloger(void)
{
	int ret;

	ret = register_tloger_mem();
	if (ret != 0)
		return ret;

	ret = register_tloger_device();

	return ret;
}

static void unregister_mem_cfg(void)
{
	if (g_log_buffer)
		unmap_log_mem((int *)g_log_buffer);

	unregister_log_exception();
}

static void unregister_tlogger(void)
{
	struct tlogger_log *current_log = NULL;
	struct tlogger_log *next_log = NULL;

	list_for_each_entry_safe(current_log, next_log, &m_log_list, logs) {
		/* we have to delete all the entry inside m_log_list */
		misc_deregister(&current_log->misc_device);
		kfree(current_log->misc_device.name);
		list_del(&current_log->logs);
		kfree(current_log);
	}

	unregister_mem_cfg();
	g_log_buffer = NULL;
	g_log_mem_len = 0;
}

#ifdef CONFIG_TZDRIVER_MODULE
int init_tlogger_service(void)
{
	return register_tloger();
}

void free_tlogger_service(void)
{
	unregister_tlogger();
}
#else
static int __init init_tlogger_service(void)
{
	return register_tloger();
}

static void __exit free_tlogger_service(void)
{
	unregister_tlogger();
}
#endif

#ifdef CONFIG_TZDRIVER
device_initcall(init_tlogger_service);
module_exit(free_tlogger_service);

MODULE_AUTHOR("iTrustee");
MODULE_DESCRIPTION("TrustCore Logger");
MODULE_VERSION("3.00");
#endif
