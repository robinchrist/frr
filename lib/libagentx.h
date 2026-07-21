// SPDX-License-Identifier: GPL-2.0-or-later
/* SNMP cli support
 * Copyright (C) 2024 Donald Sharp <sharpd@nvidia.com> NVIDIA Corporation
 */
#ifndef __LIBAGENTX_H__
#define __LIBAGENTX_H__

#include "lib/hook.h"

extern void libagentx_init(void);
extern bool agentx_enabled;

/* Bodies of the 'agentx' / 'no agentx' commands, shared with northbound
 * callbacks of daemons whose config is loaded through mgmtd. */
extern void libagentx_cli_enable(void);
extern bool libagentx_cli_disable(void);

DECLARE_HOOK(agentx_cli_enabled, (), ());
DECLARE_HOOK(agentx_cli_disabled, (), ());

#endif
