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
 #include <tee_posix_proxy.h>
 #include <linux/mutex.h>
 #include <linux/uaccess.h>
 #include <securec.h>
 #include <teek_client_id.h>
 #include <teek_client_constants.h>
 #include <smc_smp.h>
 #include <shared_mem.h>
 #include <mailbox_mempool.h>
 #include <linux/atomic.h>

 #define TEE_POSIX_PROXY_EVENT_REGISTER_CTRL_TASKLET   4
 #define TEE_POSIX_PROXY_EVENT_REGISTER_DATA_TASKLET   5
 #define TEE_POSIX_PROXY_EVENT_UNREGISTER_ALL_TASKLET  6

 struct posix_proxy_shm {
    void *buffer;
    uint32_t size;
 };

struct posix_proxy_node {
    struct list_head head;
    unsigned int nsid; /* namesapce id */
    pid_t tp_pid; /* teleport pid, owner of posix_proxy_node with nsid */
    pid_t tp_ppid; /*teleport parent pid */
    struct posix_proxy_shm *ctrl_shm;
    struct posix_proxy_shm *data_shm;
    uint32_t event;
    atomic_t ref_cnt;
};

struct mailbox_info {
    void *buf; /* mailbox vaddr */
    uint32_t size; /* mailbox buffer size */
    uint32_t mb_l_addr; /* low of mailbox buffer pyhs addr */
    uint32_t mb_h_addr; /* low of mailbox buffer pyhs addr */
};

struct posix_proxy_control {
    struct mutex lock;
    struct list_head list;
};

static struct posix_proxy_control g_posix_proxy_control;

static pid_t get_pid_compatible_namespace(struct task_struct *task)
{
    /* Obtain tgid in namespace */
    pid_t namespace_tgid = task_tgid_vnr(task);

    return namespace_tgid;
}

static int alloc_and_fill_mailbox_info(struct posix_proxy_ioctl_args *args, struct mailbox_info *mb_info)
{
    uint32_t len;
    uint32_t page_num;
    int ret = 0;
    void *mb_buff = NULL;

    page_num = args->buffer_size / PAGE_SIZE;
    len = sizeof(struct pagelist_info) + (sizeof(uint64_t) * page_num);
    mb_buff = mailbox_alloc(len, MB_FLAG_ZERO);
    if (mb_buff == NULL) {
        tloge("alloc mailbox mem failed\n");
        return -ENOMEM;
    }

    mb_info->mb_l_addr = mailbox_virt_to_phys((uintptr_t)mb_buff);
    mb_info->mb_h_addr = (uint64_t)mailbox_virt_to_phys((uintptr_t)mb_buff) >> ADDR_TRANS_NUM;
    mb_info->buf = mb_buff;
    mb_info->size = len;

    if (fill_shared_mem_info(args->addr, page_num, 0, args->buffer_size, (uint64_t)(uintptr_t)mb_info->buf) != 0) {
        tloge("fill shared mem info failed\n");
        mailbox_free(mb_buff);
        ret = -EFAULT;
    }

    return ret;
}

static void release_mailbox_info(const struct mailbox_info *mb_info)
{
    if (mb_info->buf != NULL)
        mailbox_free(mb_info->buf);
}

static void destroy_posix_proxy_shm(struct posix_proxy_shm *shm)
{
    if (shm == NULL)
        return;

    if(shm->buffer != NULL) {
        release_shared_mem_page((uint64_t)(uintptr_t)shm->buffer, shm->size);
        kfree(shm->buffer);
    }
    kfree(shm);
}

#ifdef DEF_ENG
static void __attribute__((unused)) dump_posix_proxy_list(void)
{
    tloge("==== dump posix_proxy_list start ====\n");
    struct posix_proxy_node *posix_proxy = NULL;
    uint32_t i = 0;
    list_for_each_entry(posix_proxy, &g_posix_proxy_control.list, head) {
        tloge("posix_proxy_node[%d] nsid %d, tp_pid %d\n", i, posix_proxy->nsid, posix_proxy->tp_pid);
        i++;
    }
    tloge("==== dump posix_proxy_list end ====\n");
}
#endif

/* Important: must in lock protect */
static int ref_posix_proxy(struct posix_proxy_node *posix_proxy)
{
    if (posix_proxy == NULL)
        return -EINVAL;

    if (atomic_read(&posix_proxy->ref_cnt) == INT_MAX) {
        tloge("posix proxy ref_cnt is out of limit\n");
        return -EBADFD;
    }

    (void)atomic_inc(&posix_proxy->ref_cnt);
    return 0;
}

static void deref_posix_proxy(struct posix_proxy_node *posix_proxy)
{
    if (posix_proxy == NULL)
        return;

    mutex_lock(&g_posix_proxy_control.lock);
    /* unreachable branch */
    if (atomic_read(&posix_proxy->ref_cnt) == 0) {
        tloge("deref failed due to posix proxy's ref_cnt is zero\n");
        mutex_unlock(&g_posix_proxy_control.lock);
        return;
    }

    if (atomic_dec_and_test(&posix_proxy->ref_cnt)) {
        if (list_empty(&posix_proxy->head) == 0)
            list_del(&posix_proxy->head);
        if(posix_proxy->ctrl_shm != NULL)
            destroy_posix_proxy_shm(posix_proxy->ctrl_shm);
        if(posix_proxy->data_shm != NULL)
            destroy_posix_proxy_shm(posix_proxy->data_shm);

        kfree(posix_proxy);
    }

    mutex_unlock(&g_posix_proxy_control.lock);
}

static int send_posix_proxy_smc(const struct posix_proxy_node *posix_proxy, const struct mailbox_info *mb_info)
{
    struct tc_ns_smc_cmd smc_cmd = { { 0 }, 0 };
    int ret = 0;
    struct tc_uuid appmgr_uuid = TEE_SERVICE_APPMGR;

    if (posix_proxy == NULL || posix_proxy->event < TEE_POSIX_PROXY_EVENT_REGISTER_CTRL_TASKLET ||
        posix_proxy->event > TEE_POSIX_PROXY_EVENT_UNREGISTER_ALL_TASKLET) {
        tloge("bad params for posix proxy\n");
        return -EINVAL;
    }

    (void)memcpy_s(&smc_cmd.uuid, sizeof(struct tc_uuid), &appmgr_uuid, sizeof(struct tc_uuid));
    smc_cmd.cmd_type   = CMD_TYPE_GLOBAL;
    smc_cmd.cmd_id     = GLOBAL_CMD_ID_PORTAL_WORK;
    smc_cmd.eventindex = posix_proxy->event;
    smc_cmd.pid        = posix_proxy->tp_pid;
    /* temporilay use agent_id store teleport's parent pid */
    smc_cmd.agent_id   = posix_proxy->tp_ppid;

    if (posix_proxy->event == TEE_POSIX_PROXY_EVENT_REGISTER_CTRL_TASKLET ||
        posix_proxy->event == TEE_POSIX_PROXY_EVENT_REGISTER_DATA_TASKLET) {
        smc_cmd.login_data_phy = mb_info->mb_l_addr;
        smc_cmd.login_data_h_addr = mb_info->mb_h_addr;
        smc_cmd.login_data_len = mb_info->size;
    }
    /* smc_cmd.ca_pid and smc_cmd.nsid will set in tc_ns_smc() */

    ret = tc_ns_smc(&smc_cmd);

    if (ret != 0) {
        tloge("smc calll return error, ret 0x%x\n", smc_cmd.ret_val);
        if (smc_cmd.ret_val == TEEC_ERROR_SERVICE_NOT_EXIST)
            return -EOPNOTSUPP;
        else if (smc_cmd.ret_val == TEEC_ERROR_OUT_OF_MEMORY)
            return -ENOMEM;
    }

    return ret;
}

/* find_posix_proxy_node_by_tgid will add ref_cnt */
static struct posix_proxy_node *find_posix_proxy_node_by_tgid(unsigned int nsid, pid_t tgid)
{
    struct posix_proxy_node *posix_proxy = NULL;
    mutex_lock(&g_posix_proxy_control.lock);
    list_for_each_entry(posix_proxy, &g_posix_proxy_control.list, head) {
        if (posix_proxy->nsid == nsid && posix_proxy->tp_pid == tgid) {
            if (ref_posix_proxy(posix_proxy) != 0)
                break;
            mutex_unlock(&g_posix_proxy_control.lock);
            return posix_proxy;
        }
    }
    mutex_unlock(&g_posix_proxy_control.lock);
    return NULL;
}

static void add_posix_proxy_node_to_list(struct posix_proxy_node *posix_proxy)
{
    mutex_lock(&g_posix_proxy_control.lock);
    list_add_tail(&posix_proxy->head, &g_posix_proxy_control.list);
    mutex_unlock(&g_posix_proxy_control.lock);
}

static int alloc_posix_proxy_node(unsigned int nsid, struct posix_proxy_node **posix_proxy)
{
    *posix_proxy = (struct posix_proxy_node *)kzalloc(sizeof(struct posix_proxy_node), GFP_KERNEL);
    if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)(*posix_proxy))) {
        tloge("alloc mem for posix proxy node failed\n");
        return -ENOMEM;
    }

    INIT_LIST_HEAD(&(*posix_proxy)->head);
    (*posix_proxy)->nsid = nsid;
    (*posix_proxy)->tp_pid = get_pid_compatible_namespace(current);
    (*posix_proxy)->tp_ppid = get_pid_compatible_namespace(current->parent);
    (*posix_proxy)->event = -1;
    (*posix_proxy)->ctrl_shm = NULL;
    (*posix_proxy)->data_shm = NULL;
    atomic_set(&(*posix_proxy)->ref_cnt, 1);
    return 0;
}

static int add_shm_to_posix_proxy(struct posix_proxy_node *posix_proxy, struct mailbox_info *mb_info,
                                enum posix_proxy_shm_type shm_type)
{
    struct posix_proxy_shm *shm = NULL;
    int ret = 0;

    shm = kzalloc(sizeof(struct posix_proxy_shm), GFP_KERNEL);
    if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)shm)) {
        tloge("alloc shm buff failed\n");
        return -ENOMEM;
    }

    shm->buffer = kzalloc(mb_info->size, GFP_KERNEL);
    if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)shm->buffer)) {
        tloge("kzalloc failed\n");
        ret = -ENOMEM;
        goto clear;
    }

    (void)memcpy_s(shm->buffer, mb_info->size, mb_info->buf, mb_info->size);
    shm->size = mb_info->size;

    if (shm_type == CTRL_TASKLET_BUFF)
        posix_proxy->ctrl_shm = shm;
    else
        posix_proxy->data_shm = shm;
    goto end;

clear:
    kfree(shm);
end:
    return ret;
}

static int send_ctrl_tasklet_register(unsigned int nsid, struct posix_proxy_ioctl_args *args)
{
    int ret = 0;
    struct mailbox_info mb_info = { 0 };
    struct posix_proxy_node *posix_proxy = NULL;

    posix_proxy = find_posix_proxy_node_by_tgid(nsid, get_pid_compatible_namespace(current));
    if (posix_proxy != NULL) {
        tloge("find a duplicate node with the same teleport pid when register ctrl tasklet\n");
        deref_posix_proxy(posix_proxy);
        return -EEXIST;
    }

    ret = alloc_and_fill_mailbox_info(args, &mb_info);
    if (ret != 0) {
        tloge("cannot fill ctrl tasklet info to mailbox\n");
        return ret;
    }

    ret = alloc_posix_proxy_node(nsid, &posix_proxy);
    if (ret != 0) {
        tloge("alloc posix_proxy node for ctrl tasklet failed\n");
        release_shared_mem_page((uint64_t)(uintptr_t)mb_info.buf, mb_info.size);
        goto end;
    }

    ret = add_shm_to_posix_proxy(posix_proxy, &mb_info, CTRL_TASKLET_BUFF);
    if (ret != 0) {
        tloge("add shm buff info to posix_proxy failed\n");
        release_shared_mem_page((uint64_t)(uintptr_t)mb_info.buf, mb_info.size);
        goto destroy_posix_proxy;
    }

    posix_proxy->event = TEE_POSIX_PROXY_EVENT_REGISTER_CTRL_TASKLET;

    ret = send_posix_proxy_smc(posix_proxy, &mb_info);
    if (ret != 0) {
        tloge("send register tasklet request to gtask failed, shm_type %d, ret = %d\n", args->shm_type, ret);
        goto destroy_posix_proxy;
    } else {
        add_posix_proxy_node_to_list(posix_proxy);
    }

    goto end;

destroy_posix_proxy:
    /* destroy_posix_proxy_shm func will release shm buf page */
    destroy_posix_proxy_shm(posix_proxy->ctrl_shm);
    kfree(posix_proxy);
end:
    release_mailbox_info(&mb_info);
    return ret;
}

static int send_data_tasklet_register(unsigned int nsid, struct posix_proxy_ioctl_args *args)
{
    int ret = 0;
    struct mailbox_info mb_info = { 0 };
    struct posix_proxy_node *posix_proxy = NULL;

    posix_proxy = find_posix_proxy_node_by_tgid(nsid, get_pid_compatible_namespace(current));
    if (posix_proxy == NULL) {
        tloge("expected posix proxy node is NULL when register data tasklet\n");
        return -ENOENT;
    }

    ret = alloc_and_fill_mailbox_info(args, &mb_info);
    if (ret != 0) {
        tloge("cannot fill ctrl tasklet info to mailbox\n");
        goto end;
    }
    struct posix_proxy_shm *old_shm = posix_proxy->data_shm;

    ret = add_shm_to_posix_proxy(posix_proxy, &mb_info, DATA_TASKLET_BUFF);
    if (ret != 0) {
        tloge("add shm buffer info to posix proxy failed\n");
        release_shared_mem_page((uint64_t)(uintptr_t)mb_info.buf, mb_info.size);
        goto end;
    }

    posix_proxy->event = TEE_POSIX_PROXY_EVENT_REGISTER_DATA_TASKLET;

    ret = send_posix_proxy_smc(posix_proxy, &mb_info);
    if (ret != 0) {
        tloge("send register tasklet request to gtask failed, shm_type %d, ret = %d\n", args->shm_type, ret);
        goto free_data_shm;
    }
    destroy_posix_proxy_shm(old_shm);
    goto end;

free_data_shm:
    /* destroy_posix_proxy_shm func will release shm buff page */
    destroy_posix_proxy_shm(posix_proxy->data_shm);
    /* restore old data shm */
    posix_proxy->data_shm = old_shm;
end:
    deref_posix_proxy(posix_proxy);
    release_mailbox_info(&mb_info);
    return ret;
}

/* 256MB, the configuration is the same as that in teleport */
#define MAX_TASKLET_BUFF_SIZE   (256 * 1024 * 1024)

static bool posix_proxy_user_args_check(struct posix_proxy_ioctl_args *args)
{
    bool invalid = true;
    if (args->shm_type == CTRL_TASKLET_BUFF)
        invalid = args->addr == 0 || args->addr % PAGE_SIZE != 0 || args->buffer_size != PAGE_SIZE;
    else if (args->shm_type == DATA_TASKLET_BUFF)
        invalid = args->addr == 0 || args->addr % PAGE_SIZE != 0 || args->buffer_size % PAGE_SIZE != 0 ||
            args->buffer_size > MAX_TASKLET_BUFF_SIZE || args->buffer_size == 0;
    else
        tloge("bad type for shm\n");

    return invalid;
}

/* send create crtl or data tasklet request to gtask */
int tee_posix_proxy_register_tasklet(void __user *arg, unsigned int nsid)
{
    int ret = 0;
    struct posix_proxy_ioctl_args args = { 0 };
    if (arg == NULL || copy_from_user(&args, (void *)(uintptr_t)arg, sizeof(args)) != 0) {
        tloge("arg is NULL or copy posix proxy args failed\n");
        return -EINVAL;
    }

    if (posix_proxy_user_args_check(&args)) {
        tloge("bad memory addr or size or shm_type\n");
        return -EINVAL;
    }

    if (args.shm_type == CTRL_TASKLET_BUFF) {
        ret = send_ctrl_tasklet_register(nsid, &args);
    } else if (args.shm_type == DATA_TASKLET_BUFF) {
        ret = send_data_tasklet_register(nsid, &args);
    } else {
        tloge("invalid register cmd\n");
        ret = -EINVAL;
    }
    
    return ret;
}

/* send destroy all tasket request to gtask */
int tee_posix_proxy_unregister_all_tasklet(const void *owner)
{
    if (owner == NULL) {
        tloge("bad param\n");
        return -EINVAL;
    }

    int ret = 0;
    uint32_t nsid;
#ifdef CONFIG_CONFIDENTIAL_CONTAINER
    struct tc_ns_dev_file *dev = (struct tc_ns_dev_file *)owner;
    nsid = dev->nsid;
#else
    nsid = PROC_ID_INIT_INO;
#endif
    pid_t tp_pid = get_pid_compatible_namespace(current);
    struct posix_proxy_node *posix_proxy = find_posix_proxy_node_by_tgid(nsid, tp_pid);
    if (posix_proxy == NULL) {
        tlogd("cannot find posix proxy node, unregister failed\n");
        return -ENOENT;
    }

    posix_proxy->event = TEE_POSIX_PROXY_EVENT_UNREGISTER_ALL_TASKLET;

    ret = send_posix_proxy_smc(posix_proxy, NULL);
    if (ret < 0) {
        tloge("send unregister all tasklet request to gtask failed, ret = %d\n", ret);
        deref_posix_proxy(posix_proxy);
        return ret;
    }

    tlogd("destroy_posix_proxy node nsid %u, tp_pid %d, host tp_pid %d\n", nsid, tp_pid, current->tgid);
    /* sub ref_cnt for previous find_posix_proxy_node_by_tgid */
    deref_posix_proxy(posix_proxy);
    /* sub to zero to destroy posix proxy */
    deref_posix_proxy(posix_proxy);
    return ret;
}

void tee_posix_proxy_init(void)
{
    mutex_init(&g_posix_proxy_control.lock);
    INIT_LIST_HEAD(&g_posix_proxy_control.list);
}
