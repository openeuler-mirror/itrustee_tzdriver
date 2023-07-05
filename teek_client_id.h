/*
 * teek_client_id.h
 *
 * define exported data for secboot CA
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
#ifndef TEE_CLIENT_ID_H
#define TEE_CLIENT_ID_H

#define TEE_SERVICE_SECBOOT \
{ \
	0x08080808, \
	0x0808, \
	0x0808, \
	{ \
		0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08 \
	} \
}

/* e7ed1f64-4687-41da-96dc-cbe4f27c838f */
#define TEE_SERVICE_ANTIROOT \
{ \
	0xE7ED1F64, \
	0x4687, \
	0x41DA, \
	{ \
		0x96, 0xDC, 0xCB, 0xE4, 0xF2, 0x7C, 0x83, 0x8F \
	} \
}
/* dca5ae8a-769e-4e24-896b-7d06442c1c0e */
#define TEE_SERVICE_SECISP \
{ \
	0xDCA5AE8A, \
	0x769E, \
	0x4E24, \
	{ \
		0x89, 0x6B, 0x7D, 0x06, 0x44, 0x2C, 0x1C, 0x0E \
	} \
}
/* 5700f837-8b8e-4661-800b-42bb3fc3141f */
#define TEE_SERVICE_DRM_GRALLOC \
{ \
	0x5700F837, \
	0x8B8E, \
	0x4661, \
	{ \
		0x80, 0x0B, 0x42, 0xBB, 0x3F, 0xC3, 0x14, 0x1F \
	} \
}
/* d2807abe-9242-54a9-d323-90a49ee291e3 */
#define TEE_SERVICE_APPMGR \
{ \
	0xD2807ABE, \
	0x9242, \
	0x54A9, \
	{ \
		0xD3, 0x23, 0x90, 0xA4, 0x9E, 0xE2, 0x91, 0xE3 \
	} \
}
enum SVC_SECBOOT_CMD_ID {
	SECBOOT_CMD_ID_INVALID = 0x0,
	SECBOOT_CMD_ID_COPY_VRL,
	SECBOOT_CMD_ID_COPY_DATA,
	SECBOOT_CMD_ID_VERIFY_DATA,
	SECBOOT_CMD_ID_RESET_IMAGE,
	SECBOOT_CMD_ID_COPY_VRL_TYPE,
	SECBOOT_CMD_ID_COPY_DATA_TYPE,
	SECBOOT_CMD_ID_VERIFY_DATA_TYPE,
	SECBOOT_CMD_ID_VERIFY_DATA_TYPE_LOCAL,
	SECBOOT_CMD_ID_COPY_IMG_TYPE,
	SECBOOT_CMD_ID_BSP_MODEM_CALL,
	SECBOOT_CMD_ID_BSP_MODULE_VERIFY,
	SECBOOT_CMD_ID_BSP_MODEM_CALL_EXT = SECBOOT_CMD_ID_BSP_MODULE_VERIFY,
	SECBOOT_CMD_ID_GET_RNG_NUM,
	SECBOOT_CMD_ID_BSP_LOAD_MODEM_TEEOS,
	SECBOOT_CMD_ID_BSP_UNLOAD_MODEM_TEEOS,
	SECBOOT_CMD_VERIFY_BYPASS_NET_CERT,
	SECBOOT_CMD_ID_GET_SOCID,
};

enum SVC_SECBOOT_IMG_TYPE {
	MODEM,
	HIFI,
	DSP,
	XDSP,
	TAS,
	WAS,
	CAS,
	MODEM_DTB,
	ISP,

#ifdef CONFIG_COLD_PATCH
	MODEM_COLD_PATCH,
	DSP_COLD_PATCH,
#endif
	SOC_MAX
};
#endif

