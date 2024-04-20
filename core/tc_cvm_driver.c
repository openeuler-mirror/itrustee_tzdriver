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
#include "tc_client_driver.h"
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/compat.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include "auth_base_impl.h"
#include "agent.h"
#ifdef CONFIG_CONFIDENTIAL_CONTAINER
#include <linux/proc_ns.h>
#include <linux/pid_namespace.h>
#endif
#ifdef CONFIG_TEE_TELEPORT_SUPPORT
#include "tee_portal.h"
#ifdef CROSS_DOMAIN_PERF
#include "tee_posix_proxy.h"
#endif
#endif

#include "tee_info.h"

#if defined(CONFIG_CONFIDENTIAL_CONTAINER) || defined(CONFIG_TEE_TELEPORT_SUPPORT)
static int tc_cvm_open(struct inode *inode, struct file *file)
{
	int ret = -1;
	struct tc_ns_dev_file *dev = NULL;
	(void)inode;

#ifdef CONFIG_TEE_TELEPORT_AUTH
	ret = check_tee_teleport_auth();
#endif
#ifdef CONFIG_TEE_AGENTD_AUTH
	if (ret != 0)
		ret = check_tee_agentd_auth();
#endif
	if (ret != 0) {
		tloge("teleport/agentd auth failed, ret %d\n", ret);
		return -EACCES;
	}

	file->private_data = NULL;
	ret = tc_ns_client_open(&dev, TEE_REQ_FROM_USER_MODE);
	if (ret == 0) {
#ifdef CONFIG_CONFIDENTIAL_CONTAINER
	dev->nsid = task_active_pid_ns(current)->ns.inum;
#endif
		file->private_data = dev;
	}
	return ret;
}

static int teleport_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = -EFAULT;
	void *argp = (void __user *)(uintptr_t)arg;
	uint32_t nsid;

#ifdef CONFIG_CONFIDENTIAL_CONTAINER
	nsid = task_active_pid_ns(current)->ns.inum;
	((struct tc_ns_dev_file *)file->private_data)->nsid = nsid;
#else
	nsid = PROC_ID_INIT_INO;
#endif

	switch(cmd) {
#ifdef CONFIG_CONFIDENTIAL_CONTAINER
	case TC_NS_CLIENT_IOCTL_PORTAL_REGISTER:
		ret = tee_portal_register(file->private_data, argp);
		break;
	case TC_NS_CLIENT_IOCTL_PORTAL_WORK:
		ret = tee_portal_work(file->private_data);
		break;
#ifdef CROSS_DOMAIN_PERF
	case TC_NS_CLIENT_IOCTL_POSIX_PROXY_REGISTER_TASKLET:
		ret = tee_posix_proxy_register_tasklet(argp, nsid);
		break;
#endif
#endif
	default:
		tloge("invalid cmd!\n");
	}
	return ret;
}

static long tc_cvm_ioctl(struct file *file, unsigned int cmd,
	unsigned long arg)
{
	int ret = -EFAULT;
	void *argp = (void __user *)(uintptr_t)arg;
	handle_cmd_prepare(cmd);

	switch (cmd) {
	case TC_NS_CLIENT_IOCTL_GET_TEE_INFO:
		ret = tc_ns_get_tee_info(file, argp);
		break;

#ifdef CONFIG_TEE_TELEPORT_SUPPORT
	case TC_NS_CLIENT_IOCTL_PORTAL_REGISTER:
	case TC_NS_CLIENT_IOCTL_PORTAL_WORK:
#ifdef CROSS_DOMAIN_PERF
	case TC_NS_CLIENT_IOCTL_POSIX_PROXY_REGISTER_TASKLET:
#endif
		if (check_tee_teleport_auth() == 0)
			ret = teleport_ioctl(file, cmd, arg);
		else
			tloge("check tee_teleport path failed\n");
		break;
#endif
	default:
		ret = public_ioctl(file, cmd, arg, false);
		break;
	}

	handle_cmd_finish(cmd);
	return ret;
}

#ifdef CONFIG_COMPAT
long tc_compat_cvm_ioctl(struct file *file, unsigned int cmd,
	unsigned long arg)
{
	long ret;

	if (!file)
		return -EINVAL;

	ret = tc_cvm_ioctl(file, cmd, (unsigned long)(uintptr_t)compat_ptr(arg));
	return ret;
}
#endif

static int tc_cvm_close(struct inode *inode, struct file *file)
{
	struct tc_ns_dev_file *dev = file->private_data;
	(void)inode;

#ifdef CONFIG_TEE_TELEPORT_SUPPORT
	if (dev->portal_enabled)
		tee_portal_unregister(file->private_data);
#endif
#ifdef CROSS_DOMAIN_PERF
	(void)tee_posix_proxy_unregister_all_tasklet(file->private_data);
#endif
	if (is_system_agent(dev)) {
		send_crashed_event_response_single(dev);
		free_dev(dev);
	} else {
		free_dev(dev);
	}
	file->private_data = NULL;

	return 0;
}

static const struct file_operations g_cvm_fops = {
	.owner = THIS_MODULE,
	.open = tc_cvm_open,
	.release = tc_cvm_close,
	.unlocked_ioctl = tc_cvm_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = tc_compat_cvm_ioctl,
#endif
};

const struct file_operations *get_cvm_fops(void)
{
	return &g_cvm_fops;
}
#endif
