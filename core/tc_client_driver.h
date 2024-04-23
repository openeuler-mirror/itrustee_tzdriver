/*
 * tc_client_driver.h
 *
 * function declaration for proc open,close session and invoke
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
#ifndef TC_CLIENT_DRIVER_H
#define TC_CLIENT_DRIVER_H

#include <linux/list.h>
#include <linux/cdev.h>
#include "teek_ns_client.h"

struct dev_node {
	struct class *driver_class;
	struct cdev char_dev;
	dev_t devt;
	struct device *class_dev;
	const struct file_operations *fops;
	const char *node_name;
};

struct dev_ops {
	bool dev_node_inited;
	bool dev_file_inited;
	int (*init_dev_node)(struct dev_node *node, const char *node_name,
		struct class *driver_class, const struct file_operations *fops);
	void (*destroy_dev_node)(struct dev_node *node, struct class *driver_class);
};

struct class *get_driver_class(void);
bool get_tz_init_flag(void);
struct tc_ns_dev_list *get_dev_list(void);
struct tc_ns_dev_file *tc_find_dev_file(unsigned int dev_file_id);
int tc_ns_client_open(struct tc_ns_dev_file **dev_file, uint8_t kernel_api);
int tc_ns_client_close(struct tc_ns_dev_file *dev);
int is_agent_alive(unsigned int agent_id, unsigned int nsid);
int tc_ns_register_host_nsid(void);
int init_dev_node(struct dev_node *node, const char *node_name,
		struct class *driver_class, const struct file_operations *fops);
void destory_dev_node(struct dev_node *node, struct class *driver_class);

#if defined(CONFIG_CONFIDENTIAL_CONTAINER) || defined(CONFIG_TEE_TELEPORT_SUPPORT)
int init_cvm_node(void);
int init_cvm_node_file(void);
void destroy_cvm_node_file(void);
void destroy_cvm_node(void);
#endif

void handle_cmd_prepare(unsigned int cmd);
void handle_cmd_finish(unsigned int cmd);
int public_ioctl(const struct file *file, unsigned int cmd, unsigned long arg, bool is_from_client_node);
void free_dev(struct tc_ns_dev_file *dev);

#ifdef CONFIG_ACPI
int get_acpi_tz_irq(void);
#endif

#endif
