/*
 * mailbox_mempool.c
 *
 * mailbox memory managing for sharing memory with TEE.
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
#include "mailbox_mempool.h"
#include "shared_mem.h"
#include <linux/list.h>
#include <linux/sizes.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <securec.h>
#if (KERNEL_VERSION(4, 14, 0) <= LINUX_VERSION_CODE)
#include <linux/vmalloc.h>
#endif
#include "teek_client_constants.h"
#include "tc_ns_log.h"
#include "smc_smp.h"
#include "ko_adapt.h"
#include "internal_functions.h"

#define MAILBOX_PAGE_MAX (MAILBOX_POOL_SIZE >> PAGE_SHIFT)
static int g_max_oder;

#define OPT_MODE   0660U
#define STATE_MODE 0440U

#ifndef MAILBOX_POOL_COUNT
#define MAILBOX_POOL_COUNT 1
#endif
#define MAILBOX_POOL_MAX 32

struct mb_page_t {
	struct list_head node;
	mailbox_page_t *page;
	int order;
	unsigned int count; /* whether be used */
};

struct mb_free_area_t {
	struct list_head page_list;
	int order;
};

struct mb_zone_t {
	mailbox_page_t *all_pages;
	struct mb_page_t pages[MAILBOX_PAGE_MAX];
	struct mb_free_area_t free_areas[0];
};

static struct mb_zone_t **g_m_zone;
static uint32_t g_mb_count;
static struct mutex g_mb_lock;

static bool check_zone(void)
{
	uint32_t i;
	if (!g_m_zone)
		return false;

	for (i = 0; i < g_mb_count; i++) {
		if (!g_m_zone[i])
			return false;
	}
	return true;
}

static void mailbox_show_status(void)
{
	unsigned int i;
	unsigned int j;
	struct mb_page_t *pos = NULL;
	struct list_head *head = NULL;
	unsigned int used = 0;

	tloge("########################################\n");
	mutex_lock(&g_mb_lock);

	if (!check_zone()) {
		tloge("zone struct is NULL\n");
		mutex_unlock(&g_mb_lock);
		return;
	}

	for (i = 0; i < g_mb_count; i++) {
		for (j = 0; j < MAILBOX_PAGE_MAX; j++) {
			if (g_m_zone[i]->pages[j].count != 0) {
				tloge("zone[%03d], page[%02d], order=%02d, count=%d\n",
					i, j, g_m_zone[i]->pages[j].order,
					g_m_zone[i]->pages[j].count);
				used += (1 << (uint32_t)g_m_zone[i]->pages[j].order);
			}
		}
	}
	tloge("total usage:%u/%u\n", used, MAILBOX_PAGE_MAX * g_mb_count);
	tloge("----------------------------------------\n");

	for (i = 0; i < g_mb_count; i++) {
		for (j = 0; j < (unsigned int)g_max_oder; j++) {
			head = &g_m_zone[i]->free_areas[j].page_list;
			if (list_empty(head) != 0) {
				tloge("zone[%03d], order[%02d] is empty\n", i, j);
			} else {
				list_for_each_entry(pos, head, node)
					tloge("zone[%03d], order[%02d]\n", i, j);
			}
		}
	}
	mutex_unlock(&g_mb_lock);

	tloge("########################################\n");
}

#define MB_SHOW_LINE 64
#define BITS_OF_BYTE  8
static void mailbox_show_details(void)
{
	unsigned int i;
	unsigned int j;
	unsigned int used = 0;
	unsigned int left = 0;
	unsigned int order = 0;

	tloge("----- show mailbox details -----");

	mutex_lock(&g_mb_lock);
	if (!check_zone()) {
		tloge("zone struct is NULL\n");
		mutex_unlock(&g_mb_lock);
		return;
	}

	for (i = 0; i < g_mb_count; i++) {
		for (j = 0; j < MAILBOX_PAGE_MAX; j++) {
			if (j % MB_SHOW_LINE == 0) {
				tloge("\n");
				tloge("%04d-%04d:", j, j + MB_SHOW_LINE);
			}

			if (g_m_zone[i]->pages[j].count != 0) {
				left = 1 << (uint32_t)g_m_zone[i]->pages[j].order;
				order = (uint32_t)g_m_zone[i]->pages[j].order;
				used += (1 << (uint32_t)g_m_zone[i]->pages[j].order);
			}

			if (left != 0) {
				left--;
				tloge("%01d", order);
			} else {
				tloge("X");
			}

			if (j > 1 && (j + 1) % (MB_SHOW_LINE / BITS_OF_BYTE) == 0)
				tloge(" ");
		}
	}
	tloge("total usage:%u/%u\n", used, MAILBOX_PAGE_MAX * g_mb_count);
	mutex_unlock(&g_mb_lock);
}

void *mailbox_alloc(size_t size, unsigned int flag)
{
	unsigned int i;
	unsigned int j;
	unsigned int k;
	struct mb_page_t *pos = (struct mb_page_t *)NULL;
	struct list_head *head = NULL;
	int order = get_order(ALIGN(size, SZ_4K));
	void *addr = NULL;
	bool tag = false;

	if (order > g_max_oder || order < 0) {
		tloge("invalid order %d\n", order);
		return NULL;
	}
	mutex_lock(&g_mb_lock);

	if ((size == 0) || !check_zone()) {
		tlogw("alloc 0 size mailbox or zone struct is NULL\n");
		mutex_unlock(&g_mb_lock);
		return NULL;
	}

	for (k = 0; k < g_mb_count; k++) {
		if (tag == true) break;
		for (i = (unsigned int)order; i <= (unsigned int)g_max_oder; i++) {
			head = &g_m_zone[k]->free_areas[i].page_list;
			if (list_empty(head) != 0)
				continue;

			pos = list_first_entry(head, struct mb_page_t, node);

			pos->count = 1;
			pos->order = order;

			/* split and add free list */
			for (j = (unsigned int)order; j < i; j++) {
				struct mb_page_t *new_page = NULL;

				new_page = pos + (1 << j);
				new_page->count = 0;
				new_page->order = (int)j;
				list_add_tail(&new_page->node,
					&g_m_zone[k]->free_areas[j].page_list);
			}
			list_del(&pos->node);
			addr = (void *)mailbox_page_address(pos->page);
			tag = true;
			break;
		}
	}

	mutex_unlock(&g_mb_lock);
	if (addr && ((flag & MB_FLAG_ZERO) != 0)) {
		if (memset_s(addr, ALIGN(size, SZ_4K), 0, ALIGN(size, SZ_4K)) != 0) {
			tloge("clean mailbox failed\n");
			mailbox_free(addr);
			return NULL;
		}
	}
	return addr;
}

static void add_max_order_block(unsigned int order, unsigned int index)
{
	struct mb_page_t *self = NULL;

	if (order != (unsigned int)g_max_oder)
		return;

	/*
	 * when order equal max order, no one use mailbox mem,
	 * we need to hang all pages in the last free area page list
	 */
	self = &g_m_zone[index]->pages[0];
	list_add_tail(&self->node,
		&g_m_zone[index]->free_areas[g_max_oder].page_list);
}

static bool is_ptr_valid(const mailbox_page_t *page, unsigned int *index)
{
	unsigned int i;

	for (i = 0; i < g_mb_count; i++) {
		if (page >= g_m_zone[i]->all_pages &&
			page < (g_m_zone[i]->all_pages + MAILBOX_PAGE_MAX)) {
			*index = i;
			return true;
		}
	}

	tloge("invalid ptr to free in mailbox\n");
	return false;
}

void mailbox_free(const void *ptr)
{
	unsigned int i;
	mailbox_page_t *page = NULL;
	struct mb_page_t *self = NULL;
	struct mb_page_t *buddy = NULL;
	unsigned int self_idx;
	unsigned int buddy_idx;
	unsigned int index = 0;

	mutex_lock(&g_mb_lock);
	if (!ptr || !check_zone()) {
		tloge("invalid ptr or zone struct is NULL\n");
		goto end;
	}

	page = mailbox_virt_to_page((uint64_t)(uintptr_t)ptr);
	if (!is_ptr_valid(page, &index))
		goto end;

	self_idx = page - g_m_zone[index]->all_pages;
	self = &g_m_zone[index]->pages[self_idx];
	if (self->count == 0) {
		tloge("already freed in mailbox\n");
		goto end;
	}

	for (i = (unsigned int)self->order; i <
		(unsigned int)g_max_oder; i++) {
		self_idx = page - g_m_zone[index]->all_pages;
		buddy_idx = self_idx ^ (uint32_t)(1 << i);
		self = &g_m_zone[index]->pages[self_idx];
		buddy = &g_m_zone[index]->pages[buddy_idx];
		self->count = 0;
		/* is buddy free  */
		if ((unsigned int)buddy->order == i && buddy->count == 0) {
			/* release buddy */
			list_del(&buddy->node);
			/* combine self and buddy */
			if (self_idx > buddy_idx) {
				page = buddy->page;
				buddy->order = (int)i + 1;
				self->order = -1;
			} else {
				self->order = (int)i + 1;
				buddy->order = -1;
			}
		} else {
			/* release self */
			list_add_tail(&self->node,
				&g_m_zone[index]->free_areas[i].page_list);
			goto end;
		}
	}

	add_max_order_block(i, index);
end:
	mutex_unlock(&g_mb_lock);
}

struct mb_cmd_pack *mailbox_alloc_cmd_pack(void)
{
	void *pack = mailbox_alloc(SZ_4K, MB_FLAG_ZERO);

	if (!pack)
		tloge("alloc mb cmd pack failed\n");

	return (struct mb_cmd_pack *)pack;
}

void *mailbox_copy_alloc(const void *src, size_t size)
{
	void *mb_ptr = NULL;

	if (!src || !size) {
		tloge("invali src to alloc mailbox copy\n");
		return NULL;
	}

	mb_ptr = mailbox_alloc(size, 0);
	if (!mb_ptr) {
		tloge("alloc size %zu mailbox failed\n", size);
		return NULL;
	}

	if (memcpy_s(mb_ptr, size, src, size) != 0) {
		tloge("memcpy to mailbox failed\n");
		mailbox_free(mb_ptr);
		return NULL;
	}

	return mb_ptr;
}

struct mb_dbg_entry {
	struct list_head node;
	unsigned int idx;
	void *ptr;
};

static LIST_HEAD(mb_dbg_list);
static DEFINE_MUTEX(mb_dbg_lock);
static unsigned int g_mb_dbg_entry_count = 1;
static unsigned int g_mb_dbg_last_res; /* only cache 1 opt result */
static struct dentry *g_mb_dbg_dentry;

static unsigned int mb_dbg_add_entry(void *ptr)
{
	struct mb_dbg_entry *new_entry = NULL;
	unsigned int index = 0;

	new_entry = kmalloc(sizeof(*new_entry), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)new_entry)) {
		tloge("alloc entry failed\n");
		return 0;
	}

	INIT_LIST_HEAD(&new_entry->node);
	new_entry->ptr = ptr;
	mutex_lock(&mb_dbg_lock);
	new_entry->idx = g_mb_dbg_entry_count;

	if ((g_mb_dbg_entry_count++) == 0)
		g_mb_dbg_entry_count++;
	list_add_tail(&new_entry->node, &mb_dbg_list);
	index = new_entry->idx;
	mutex_unlock(&mb_dbg_lock);

	return index;
}

static void mb_dbg_remove_entry(unsigned int idx)
{
	struct mb_dbg_entry *pos = NULL;
	struct mb_dbg_entry *temp = NULL;

	mutex_lock(&mb_dbg_lock);
	list_for_each_entry_safe(pos, temp, &mb_dbg_list, node) {
		if (pos->idx == idx) {
			mailbox_free(pos->ptr);
			list_del(&pos->node);
			kfree(pos);
			mutex_unlock(&mb_dbg_lock);
			return;
		}
	}
	mutex_unlock(&mb_dbg_lock);

	tloge("entry %u invalid\n", idx);
}

static void mb_dbg_reset(void)
{
	struct mb_dbg_entry *pos = NULL;
	struct mb_dbg_entry *tmp = NULL;

	mutex_lock(&mb_dbg_lock);
	list_for_each_entry_safe(pos, tmp, &mb_dbg_list, node) {
		mailbox_free(pos->ptr);
		list_del(&pos->node);
		kfree(pos);
	}
	g_mb_dbg_entry_count = 0;
	mutex_unlock(&mb_dbg_lock);
}

#define MB_WRITE_SIZE 64

static bool is_opt_write_param_valid(const struct file *filp,
	const char __user *ubuf, size_t cnt, const loff_t *ppos)
{
	if (!filp || !ppos || !ubuf)
		return false;

	if (cnt >= MB_WRITE_SIZE || cnt == 0)
		return false;

	return true;
}

static void alloc_dbg_entry(unsigned int alloc_size)
{
	unsigned int idx;
	void *ptr = NULL;

	ptr = mailbox_alloc(alloc_size, 0);
	if (!ptr) {
		tloge("alloc order=%u in mailbox failed\n", alloc_size);
		return;
	}

	idx = mb_dbg_add_entry(ptr);
	if (idx == 0)
		mailbox_free(ptr);
	g_mb_dbg_last_res = idx;
}

static ssize_t mb_dbg_opt_write(struct file *filp,
	const char __user *ubuf, size_t cnt, loff_t *ppos)
{
	char buf[MB_WRITE_SIZE] = {0};
	char *cmd = NULL;
	char *value = NULL;
	unsigned int alloc_size;
	unsigned int free_idx;

	if (!is_opt_write_param_valid(filp, ubuf, cnt, ppos))
		return -EINVAL;

	if (copy_from_user(buf, ubuf, cnt) != 0)
		return -EFAULT;

	buf[cnt] = 0;
	value = buf;
	if (strncmp(value, "reset", strlen("reset")) == 0) {
		tlogi("mb dbg reset\n");
		mb_dbg_reset();
		return (ssize_t)cnt;
	}

	cmd = strsep(&value, ":");
	if (!cmd || !value) {
		tloge("no valid cmd or value for mb dbg\n");
		return -EFAULT;
	}

	if (strncmp(cmd, "alloc", strlen("alloc")) == 0) {
		if (kstrtou32(value, 10, &alloc_size) == 0)
			alloc_dbg_entry(alloc_size);
		else
			tloge("invalid value format for mb dbg\n");
	} else if (strncmp(cmd, "free", strlen("free")) == 0) {
		if (kstrtou32(value, 10, &free_idx) == 0)
			mb_dbg_remove_entry(free_idx);
		else
			tloge("invalid value format for mb dbg\n");
	} else {
		tloge("invalid format for mb dbg\n");
	}

	return (ssize_t)cnt;
}

static ssize_t mb_dbg_opt_read(struct file *filp, char __user *ubuf,
	size_t cnt, loff_t *ppos)
{
	char buf[16] = {0};
	ssize_t ret;

	(void)(filp);

	ret = snprintf_s(buf, sizeof(buf), 15, "%u\n", g_mb_dbg_last_res);
	if (ret < 0) {
		tloge("snprintf idx failed\n");
		return -EINVAL;
	}

	return simple_read_from_buffer(ubuf, cnt, ppos, buf, ret);
}

static const struct file_operations g_mb_dbg_opt_fops = {
	.owner = THIS_MODULE,
	.read = mb_dbg_opt_read,
	.write = mb_dbg_opt_write,
};

static ssize_t mb_dbg_state_read(struct file *filp, char __user *ubuf,
	size_t cnt, loff_t *ppos)
{
	(void)cnt;
	(void)(filp);
	(void)(ubuf);
	(void)(ppos);
	mailbox_show_status();
	mailbox_show_details();
	return 0;
}

static const struct file_operations g_mb_dbg_state_fops = {
	.owner = THIS_MODULE,
	.read = mb_dbg_state_read,
};

static int mailbox_register(const void *mb_pool, unsigned int size)
{
	struct tc_ns_operation *operation = NULL;
	struct tc_ns_smc_cmd *smc_cmd = NULL;
	int ret = 0;

	smc_cmd = kzalloc(sizeof(*smc_cmd), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)smc_cmd)) {
		tloge("alloc smc_cmd failed\n");
		return -EIO;
	}

	operation = (struct tc_ns_operation *)(uintptr_t)get_operation_vaddr();
	if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)operation)) {
		tloge("alloc operation failed\n");
		ret = -EIO;
		goto free_smc_cmd;
	}

	operation->paramtypes = TEE_PARAM_TYPE_VALUE_INPUT |
		(TEE_PARAM_TYPE_VALUE_INOUT << TEE_PARAM_NUM);
	operation->params[0].value.a = mailbox_virt_to_phys((uintptr_t)mb_pool);
	operation->params[0].value.b =
		(uint64_t)mailbox_virt_to_phys((uintptr_t)mb_pool) >> ADDR_TRANS_NUM;
	operation->params[1].value.a = size;

	smc_cmd->cmd_type = CMD_TYPE_GLOBAL;
	smc_cmd->cmd_id = GLOBAL_CMD_ID_REGISTER_MAILBOX;
	smc_cmd->operation_phys = mailbox_virt_to_phys((uintptr_t)operation);
	smc_cmd->operation_h_phys =
		(uint64_t)mailbox_virt_to_phys((uintptr_t)operation) >> ADDR_TRANS_NUM;

	if (is_tee_rebooting())
		ret = send_smc_cmd_rebooting(TSP_REQUEST, smc_cmd);
	else
		ret= tc_ns_smc(smc_cmd);

	if (ret != 0) {
		tloge("resigter mailbox failed\n");
		ret = -EIO;
	} else {
		if (operation->params[1].value.a <= g_mb_count || g_mb_count == 0)
			g_mb_count = operation->params[1].value.a;
		tlogi("wish to register %u mailbox, success %u\n", (uint32_t)MAILBOX_POOL_COUNT, g_mb_count);
	}

	free_operation((uint64_t)(uintptr_t)operation);
	operation = NULL;
free_smc_cmd:
	kfree(smc_cmd);
	smc_cmd = NULL;
	return ret;
}

static void mailbox_debug_init(void)
{
}

int re_register_mailbox(void)
{
	uint32_t i;
	int ret = 0;
	struct mailbox_buffer *buffer = NULL;

	mutex_lock(&g_mb_lock);
	if (!check_zone()) {
		mutex_unlock(&g_mb_lock);
		return -EFAULT;
	}

	buffer = (struct mailbox_buffer *)(uintptr_t)get_mailbox_buffer_vaddr(g_mb_count);
	if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)buffer)) {
		mutex_unlock(&g_mb_lock);
		return -ENOMEM;
	}
	for (i = 0; i < g_mb_count; i++) {
		(void)memset_s((void *)mailbox_page_address(g_m_zone[i]->all_pages),
			MAILBOX_POOL_SIZE, 0, MAILBOX_POOL_SIZE);
		buffer[i].buffer = mailbox_virt_to_phys(mailbox_page_address(g_m_zone[i]->all_pages));
		buffer[i].size = MAILBOX_POOL_SIZE;
	}
	mutex_unlock(&g_mb_lock);

	if (mailbox_register(buffer, sizeof(struct mailbox_buffer) * g_mb_count) != 0) {
		tloge("register mailbox failed\n");
		ret = -EIO;
	}

	free_mailbox_buffer((uint64_t)(uintptr_t)buffer);
	return ret;
}

static int init_zone(mailbox_page_t **all_pages)
{
	uint32_t i;
	uint32_t j;
	struct mb_page_t *mb_page = NULL;
	struct mb_free_area_t *area = NULL;
	size_t zone_len;

	g_m_zone = kzalloc(sizeof(struct mb_zone_t **) * g_mb_count, GFP_KERNEL);
	if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)g_m_zone)) {
		tloge("fail to alloc g_m_zone\n");
		return -ENOMEM;
	}

	zone_len = sizeof(*area) * (g_max_oder + 1) + sizeof(struct mb_zone_t);
	for (i = 0; i < g_mb_count; i++) {
		g_m_zone[i] = kzalloc(zone_len, GFP_KERNEL);
		if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)g_m_zone[i])) {
			tloge("fail to alloc zone\n");
			goto clear;
		}
		for (j = 0; j < MAILBOX_PAGE_MAX; j++) {
			g_m_zone[i]->pages[j].order = -1;
			g_m_zone[i]->pages[j].count = 0;
			g_m_zone[i]->pages[j].page = &all_pages[i][j];
		}
		g_m_zone[i]->pages[0].order = g_max_oder;

		for (j = 0; j <= g_max_oder; j++) {
			area = &g_m_zone[i]->free_areas[j];
			INIT_LIST_HEAD(&area->page_list);
			area->order = j;
		}

		mb_page = &g_m_zone[i]->pages[0];
		list_add_tail(&mb_page->node, &area->page_list);
		g_m_zone[i]->all_pages = all_pages[i];
	}
	return 0;
clear:
	for (j = 0; j < i; j++)
		kfree(g_m_zone[j]);

	kfree(g_m_zone);
	g_m_zone = NULL;
	return -ENOMEM;
}

static int mailbox_init(uint32_t pool_count, mailbox_page_t **all_pages)
{
	uint32_t i;
	int ret = 0;
	struct mailbox_buffer *buffer = NULL;

	buffer = (struct mailbox_buffer *)(uintptr_t)get_mailbox_buffer_vaddr(pool_count);
	if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)buffer))
		return -ENOMEM;
	for (i = 0; i < pool_count; i++) {
		buffer[i].buffer = mailbox_virt_to_phys(mailbox_page_address(all_pages[i]));
		buffer[i].size = MAILBOX_POOL_SIZE;
	}

	if (mailbox_register(buffer, sizeof(struct mailbox_buffer) * pool_count) != 0) {
		tloge("register mailbox failed\n");
		ret = -EIO;
		goto clear;
	}

	if (init_zone(all_pages) != 0) {
		tloge("mailbox init failed\n");
		ret = -ENOMEM;
		goto clear;
	}

	mutex_init(&g_mb_lock);
	mailbox_debug_init();
clear:
	free_mailbox_buffer((uint64_t)(uintptr_t)buffer);
	return ret;
}

int mailbox_mempool_init(void)
{
	uint32_t pool_count;
	uint32_t i;
	mailbox_page_t **all_pages = NULL;
	int ret = 0;

	if (MAILBOX_POOL_COUNT < 1 || MAILBOX_POOL_COUNT > MAILBOX_POOL_MAX) {
		tloge("mailbox pool count invalid %d %d\n", MAILBOX_POOL_COUNT, MAILBOX_POOL_MAX);
		return -EINVAL;
	}

	g_max_oder = get_order(MAILBOX_POOL_SIZE);
	tlogi("in this RE, mailbox max order is: %d\n", g_max_oder);

	all_pages = kzalloc(sizeof(mailbox_page_t **) * (uint32_t)MAILBOX_POOL_COUNT, GFP_KERNEL);
	if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)all_pages)) {
		tloge("fail to alloc mailbox mempool\n");
		return -ENOMEM;
	}

	for (pool_count = 0; pool_count < (uint32_t)MAILBOX_POOL_COUNT; pool_count++) {
		all_pages[pool_count] = mailbox_alloc_pages(g_max_oder);
		if (!all_pages[pool_count]) {
			tloge("fail to alloc pages\n");
			break;
		}
	}
	if (pool_count == 0) {
		ret = -ENOMEM;
		goto clear1;
	}

	ret = mailbox_init(pool_count, all_pages);
	if (ret != 0) {
		tloge("mailbox init failed\n");
		goto clear2;
	}

	for (i = g_mb_count; i < pool_count; i++) {
		mailbox_free_pages(all_pages[i], g_max_oder);
		all_pages[i] = NULL;
	}

	return ret;
clear2:
	for (i = 0; i < pool_count; i++) {
		mailbox_free_pages(all_pages[i], g_max_oder);
		all_pages[i] = NULL;
	}

clear1:
	kfree(all_pages);
	return ret;
}

void free_mailbox_mempool(void)
{
	unsigned int i;
	for (i = 0; i < g_mb_count; i++) {
		mailbox_free_pages(g_m_zone[i]->all_pages, g_max_oder);
		g_m_zone[i]->all_pages = NULL;
		kfree(g_m_zone[i]);
		g_m_zone[i] = NULL;
	}
	kfree(g_m_zone);
	g_m_zone = NULL;

	if (!g_mb_dbg_dentry)
		return;
	debugfs_remove_recursive(g_mb_dbg_dentry);
	g_mb_dbg_dentry = NULL;
}
