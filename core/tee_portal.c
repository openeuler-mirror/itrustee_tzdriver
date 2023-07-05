/*
 * Copyright (c) 2023-2023 Huawei Technologies Co., Ltd.
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
#include "tee_portal.h"
#include "agent.h"
#include "teek_client_constants.h"
#include "teek_client_id.h"
#include "mailbox_mempool.h"
#include "smc_smp.h"
#include "shared_mem.h"
#include <securec.h>
#include <linux/cred.h>
#include <linux/stddef.h>
#include <linux/uaccess.h>
#include <linux/errno.h>

#define TEE_PORTAL_EVENT_REGISTER_SHM 0
#define TEE_PORTAL_EVENT_UNREGISTER_SHM 1
#define TEE_PORTAL_EVENT_WORK 2

struct portal_t {
	struct list_head list;
	void *owner;
	void *buf;
	uint32_t size;
	uint32_t event;
	uint32_t mb_l_addr;
	uint32_t mb_h_addr;
};

static struct portal_t g_portal_head;
DEFINE_MUTEX(g_portal_lock);
DEFINE_MUTEX(g_portal_enable_lock);

void tee_portal_init(void)
{
	INIT_LIST_HEAD(&g_portal_head.list);
}

static int send_portal_smc(const struct portal_t *param)
{
	struct tc_ns_smc_cmd smc_cmd = {{0}, 0};
	int ret = 0;
	struct tc_uuid appmgr_uuid = TEE_SERVICE_APPMGR;
	kuid_t kuid = current_uid();

	if (param == NULL)
		return -EINVAL;

	(void)memcpy_s(&smc_cmd.uuid, sizeof(struct tc_uuid), &appmgr_uuid, sizeof(struct tc_uuid));
	smc_cmd.cmd_type = CMD_TYPE_GLOBAL;
	smc_cmd.cmd_id = GLOBAL_CMD_ID_PORTAL_WORK;
	smc_cmd.eventindex = param->event;
	smc_cmd.login_data_phy = param->mb_l_addr;
	smc_cmd.login_data_h_addr = param->mb_h_addr;
	smc_cmd.login_data_len = param->size;
	smc_cmd.uid = kuid.val;

	ret = tc_ns_smc(&smc_cmd);
	if (ret != 0) {
		tloge("smc call returns error ret 0x%x\n", smc_cmd.ret_val);
		if (smc_cmd.ret_val == TEEC_ERROR_SERVICE_NOT_EXIST)
			return -EOPNOTSUPP;
		else if (smc_cmd.ret_val == TEEC_ERROR_OUT_OF_MEMORY)
			return -ENOMEM;
	}

	return ret;
}

#ifndef CONFIG_NOCOPY_SHAREDMEM
static int fill_shared_mem_info(uint64_t start_vaddr, uint32_t pages_no,
	uint32_t offset, uint32_t buffer_size, uint64_t info_addr)
{
	(void)start_vaddr;
	(void)pages_no;
	(void)offset;
	(void)buffer_size;
	(void)info_addr;
	tloge("shared memory is unsupported\n");
	return -EINVAL;
}

static void release_shared_mem_page(uint64_t buf, uint32_t buf_size)
{
	(void)buf;
	(void)buf_size;
	tloge("shared memory is unsupported\n");
}
#endif

static int init_portal_node(struct portal_t *portal, struct agent_ioctl_args *args, void* owner)
{
	int ret = 0;
	uint64_t start_vaddr;
	uint32_t page_num;
	uint32_t mb_buff_len;
	void *mb_buff = NULL;
	start_vaddr = args->addr;
	page_num = args->buffer_size / PAGE_SIZE;
	mb_buff_len = sizeof(struct pagelist_info) + (sizeof(uint64_t) * page_num);
	mb_buff = mailbox_alloc(mb_buff_len, MB_FLAG_ZERO);
	if (mb_buff == NULL) {
		tloge("cannot alloc mailbox mem\n");
		return -ENOMEM;
	}

	if (fill_shared_mem_info(start_vaddr, page_num, 0, args->buffer_size, (uint64_t)mb_buff)) {
		tloge("cannot fill shared memory info\n");
		mailbox_free(mb_buff);
		return -EFAULT;
	}

	portal->mb_l_addr = mailbox_virt_to_phys((uintptr_t)mb_buff);
	portal->mb_h_addr = (uint64_t)mailbox_virt_to_phys((uintptr_t)mb_buff) >> ADDR_TRANS_NUM;
	portal->event = TEE_PORTAL_EVENT_REGISTER_SHM;
	portal->buf = mb_buff;
	portal->size = mb_buff_len;
	portal->owner = owner;

	return ret;
}

static bool check_portal_exist(void *owner)
{
	struct portal_t *pos = NULL;
	list_for_each_entry(pos, &g_portal_head.list, list) {
		if (pos->owner == owner)
			return true;
	}
	return false;
}

int tee_portal_register(void *owner, void __user *arg)
{
	int ret;
	struct agent_ioctl_args args;

	if (owner == NULL || arg == NULL)
		return -EFAULT;

	if (copy_from_user(&args, (void *)(uintptr_t)arg, sizeof(args))) {
		tloge("copy args failed\n");
		return -EFAULT;
	}

	if (args.addr % PAGE_SIZE != 0 || args.buffer_size % PAGE_SIZE != 0 ||
		args.buffer_size > SZ_256M || args.buffer_size == 0) {
		tloge("bad memory addr or size\n");
		return -EFAULT;
	}

	struct portal_t *portal;
	portal = (struct portal_t *)kmalloc(sizeof(struct portal_t), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)(portal))) {
		tloge("failed to alloc mem for portal node!\n");
		return -EFAULT;
	}

	mutex_lock(&g_portal_lock);
	if (check_portal_exist(owner)) {
		mutex_unlock(&g_portal_lock);
		tloge("illegal register request!\n");
		return -EFAULT;
	}

	ret = init_portal_node(portal, &args, owner);
	if (ret != 0) {
		mutex_unlock(&g_portal_lock);
		tloge("failed to init portal node!\n");
		goto clean;
	}

	list_add(&portal->list, &g_portal_head.list);
	mutex_unlock(&g_portal_lock);

	ret = send_portal_smc(portal);
	if (ret != 0) {
		release_shared_mem_page(portal->buf, portal->size);
		mailbox_free(portal->buf);
		mutex_lock(&g_portal_lock);
		list_del(&portal->list);
		mutex_unlock(&g_portal_lock);
		goto clean;
	}

	mutex_lock(&g_portal_enable_lock);
	((struct tc_ns_dev_file *)owner)->portal_enabled = true;
	mutex_unlock(&g_portal_enable_lock);
	return 0;
clean:
	kfree(portal);
	return ret;
}

int tee_portal_unregister(const void *owner)
{
	int ret;
	if (!owner)
		return -EFAULT;

	struct portal_t *pos;
	bool found = false;
	mutex_lock(&g_portal_lock);
	list_for_each_entry(pos, &g_portal_head.list, list) {
		if (pos->owner == owner) {
			found = true;
			break;
		}
	}

	if (!found) {
		tloge("failed to release portal!\n");
		mutex_unlock(&g_portal_lock);
		return -EFAULT;
	}

	pos->event = TEE_PORTAL_EVENT_UNREGISTER_SHM;
	ret = send_portal_smc(pos);

	release_shared_mem_page(pos->buf, pos->size);
	mailbox_free(pos->buf);

	list_del(&pos->list);
	kfree(pos);
	mutex_unlock(&g_portal_lock);
	return ret;
}

int tee_portal_work(const void *owner)
{
	struct portal_t *pos;
	int ret = -EFAULT;
	bool found = false;

	mutex_lock(&g_portal_lock);
	list_for_each_entry(pos, &g_portal_head.list, list) {
		if (pos->owner == owner) {
			found = true;
			pos->event = TEE_PORTAL_EVENT_WORK;
			break;
		}
	}
	mutex_unlock(&g_portal_lock);

	mutex_lock(&g_portal_enable_lock);
	found &= ((struct tc_ns_dev_file *)owner)->portal_enabled;
	mutex_unlock(&g_portal_enable_lock);

	if (!found) {
		tloge("failed to found portal!\n");
		return ret;
	}

	ret = send_portal_smc(pos);
	return ret;
}
