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
#ifndef SMC_ABI_H
#define SMC_ABI_H

#include "smc_call.h"
#define TEE_EXIT_REASON_CRASH 0x4
void do_smc_transport(struct smc_in_params *in, struct smc_out_params *out, uint8_t wait);
#endif
