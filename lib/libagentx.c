// SPDX-License-Identifier: GPL-2.0-or-later
/* SNMP cli support
 * Copyright (C) 2024 Donald Sharp <sharpd@nvidia.com> NVIDIA Corporation
 */
#include <zebra.h>

#include "lib/hook.h"
#include "lib/libagentx.h"
#include "command.h"

DEFINE_HOOK(agentx_cli_enabled, (), ());
DEFINE_HOOK(agentx_cli_disabled, (), ());

bool agentx_enabled;

/* AgentX node. */
static int config_write_agentx(struct vty *vty)
{
	if (agentx_enabled)
		vty_out(vty, "agentx\n");
	return 1;
}

static struct cmd_node agentx_node = {
	.name = "smux",
	.node = SMUX_NODE,
	.prompt = "",
	.config_write = config_write_agentx,
};

void libagentx_cli_enable(void)
{
	if (!hook_have_hooks(agentx_cli_enabled)) {
		zlog_info(
			"agentx specified but the agentx Module is not loaded, is this intentional?");

		return;
	}

	hook_call(agentx_cli_enabled);
}

bool libagentx_cli_disable(void)
{
	return hook_call(agentx_cli_disabled) != 0;
}

DEFUN(agentx_enable, agentx_enable_cmd, "agentx",
      "SNMP AgentX protocol settings\n")
{
	libagentx_cli_enable();

	return CMD_SUCCESS;
}

DEFUN(no_agentx, no_agentx_cmd, "no agentx",
      NO_STR "SNMP AgentX protocol settings\n")
{
	vty_out(vty, "SNMP AgentX support cannot be disabled once enabled\n");
	if (!libagentx_cli_disable())
		return CMD_WARNING_CONFIG_FAILED;

	return CMD_SUCCESS;
}

void libagentx_init(void)
{
	agentx_enabled = false;

	install_node(&agentx_node);
	install_element(CONFIG_NODE, &agentx_enable_cmd);
	install_element(CONFIG_NODE, &no_agentx_cmd);
}
