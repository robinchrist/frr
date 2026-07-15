// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * bgpd CLI compiled into mgmtd (zebra_cli.c / staticd pattern): the
 * milestone 1 proteus-bgp conversion slice ('router bgp', 'bgp router-id',
 * '[no] bgp log-neighbor-changes').
 */
#include <zebra.h>
#include "command.h"
#include "northbound.h"
#include "northbound_cli.h"
#include "vty.h"
#include "vrf.h"
#include "asn.h"

#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_cli.h"

#include "bgpd/bgp_cli_clippy.c"

static struct cmd_node bgp_node = {
	.name = "bgp",
	.node = BGP_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-router)# ",
	.config_write = NULL,
};

DEFPY_YANG_NOSH(
	router_bgp, router_bgp_cli_cmd,
	"router bgp [ASNUM$instasn [<view|vrf>$view_vrf VIEWVRFNAME] [as-notation <dot|dot+|plain>$notation]]",
	ROUTER_STR BGP_STR AS_STR BGP_INSTANCE_HELP_STR
	"Force the AS notation output\n"
	"use 'AA.BB' format for AS 4 byte values\n"
	"use 'AA.BB' format for all AS values\n"
	"use plain format for all AS values\n")
{
	const char *vrf = viewvrfname ? viewvrfname : VRF_DEFAULT_NAME;
	char *xpath, *xpath_child;
	char highbuf[8], lowbuf[8];
	int ret;

	xpath = asprintfrr(MTYPE_TMP, "/proteus-bgp:instance[vrf='%s']", vrf);

	if (!instasn_str) {
		/* bare 'router bgp': node entry into the existing default
		 * instance (legacy semantics), nothing to commit */
		if (!yang_dnode_exists(vty->candidate_config->dnode, xpath)) {
			vty_out(vty, "%% No BGP process is configured\n");
			XFREE(MTYPE_TMP, xpath);
			return CMD_WARNING_CONFIG_FAILED;
		}
		VTY_PUSH_XPATH(BGP_NODE, xpath);
		XFREE(MTYPE_TMP, xpath);
		return CMD_SUCCESS;
	}

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	if (view_vrf && strmatch(view_vrf, "view")) {
		xpath_child = asprintfrr(MTYPE_TMP, "%s/instance-type", xpath);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "view");
		XFREE(MTYPE_TMP, xpath_child);
	}

	if (strchr(instasn_str, '.')) {
		as_t high = instasn >> 16, low = instasn & 0xffff;

		snprintf(highbuf, sizeof(highbuf), "%u", high);
		snprintf(lowbuf, sizeof(lowbuf), "%u", low);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/autonomous-system/asdot/high", xpath);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, highbuf);
		XFREE(MTYPE_TMP, xpath_child);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/autonomous-system/asdot/low", xpath);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, lowbuf);
		XFREE(MTYPE_TMP, xpath_child);
	} else {
		xpath_child = asprintfrr(MTYPE_TMP, "%s/autonomous-system/plain", xpath);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, instasn_str);
		XFREE(MTYPE_TMP, xpath_child);
	}

	if (notation) {
		xpath_child = asprintfrr(MTYPE_TMP, "%s/as-notation", xpath);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, notation);
		XFREE(MTYPE_TMP, xpath_child);
	}

	ret = nb_cli_apply_changes(vty, NULL);
	if (ret == CMD_SUCCESS)
		VTY_PUSH_XPATH(BGP_NODE, xpath);
	XFREE(MTYPE_TMP, xpath);
	return ret;
}

DEFPY_YANG(
	no_router_bgp, no_router_bgp_cli_cmd,
	"no router bgp [ASNUM$instasn [<view|vrf> VIEWVRFNAME] [as-notation <dot|dot+|plain>]]",
	NO_STR ROUTER_STR BGP_STR AS_STR BGP_INSTANCE_HELP_STR
	"Force the AS notation output\n"
	"use 'AA.BB' format for AS 4 byte values\n"
	"use 'AA.BB' format for all AS values\n"
	"use plain format for all AS values\n")
{
	const char *vrf = viewvrfname ? viewvrfname : VRF_DEFAULT_NAME;
	char *xpath;
	int ret;

	xpath = asprintfrr(MTYPE_TMP, "/proteus-bgp:instance[vrf='%s']", vrf);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	ret = nb_cli_apply_changes_clear_pending(vty, NULL);
	XFREE(MTYPE_TMP, xpath);
	return ret;
}

DEFPY_YANG(
	bgp_router_id, bgp_router_id_cli_cmd,
	"bgp router-id A.B.C.D$router_id",
	BGP_STR
	"Override configured router identifier\n"
	"Manually configured router identifier\n")
{
	nb_cli_enqueue_change(vty, "./router-id", NB_OP_MODIFY, router_id_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_router_id, no_bgp_router_id_cli_cmd,
	"no bgp router-id [A.B.C.D]",
	NO_STR BGP_STR
	"Override configured router identifier\n"
	"Manually configured router identifier\n")
{
	nb_cli_enqueue_change(vty, "./router-id", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_log_neighbor_changes, bgp_log_neighbor_changes_cli_cmd,
	"bgp log-neighbor-changes <enabled|disabled>$mode",
	BGP_STR
	"Log neighbor up/down and reset reason\n"
	"Enable neighbor up/down and reset reason logging\n"
	"Disable neighbor up/down and reset reason logging\n")
{
	nb_cli_enqueue_change(vty, "./log-neighbor-changes", NB_OP_MODIFY,
			      strmatch(mode, "enabled") ? "true" : "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_log_neighbor_changes, no_bgp_log_neighbor_changes_cli_cmd,
	"no bgp log-neighbor-changes <enabled|disabled>$mode",
	NO_STR BGP_STR
	"Log neighbor up/down and reset reason\n"
	"Enable neighbor up/down and reset reason logging\n"
	"Disable neighbor up/down and reset reason logging\n")
{
	nb_cli_enqueue_change(vty, "./log-neighbor-changes", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/* Deprecated bare aliases: kept so configs persisted before this leaf grew
 * the enabled|disabled grammar keep loading with their original meaning.
 * Bare 'bgp log-neighbor-changes' meant "on"; bare 'no bgp
 * log-neighbor-changes' persisted an explicit "off" (it only ever appeared
 * in saved config when it differed from the compile-profile default, per
 * legacy SAVE_BGP_LOG_NEIGHBOR_CHANGES), so the negative alias enqueues an
 * explicit false rather than deleting.
 */
DEFPY_ATTR(
	bgp_log_neighbor_changes_deprecated, bgp_log_neighbor_changes_deprecated_cli_cmd,
	"bgp log-neighbor-changes",
	BGP_STR
	"Log neighbor up/down and reset reason\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	nb_cli_enqueue_change(vty, "./log-neighbor-changes", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_ATTR(
	no_bgp_log_neighbor_changes_deprecated, no_bgp_log_neighbor_changes_deprecated_cli_cmd,
	"no bgp log-neighbor-changes",
	NO_STR
	BGP_STR
	"Log neighbor up/down and reset reason\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	nb_cli_enqueue_change(vty, "./log-neighbor-changes", NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

/*
 * XPath: /proteus-bgp:instance
 *
 * Must reproduce bgp_config_write()'s "router bgp ..." header byte-for-byte
 * (bgp_vty.c router bgp/asn_mode2str) so vtysh's exact-text block merge
 * (vtysh_config.c) folds this with bgpd's remaining legacy lines into one
 * "router bgp" block instead of splitting it into two.
 */
static void instance_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const char *vrf = yang_dnode_get_string(dnode, "vrf");

	vty_out(vty, "router bgp ");

	if (yang_dnode_exists(dnode, "autonomous-system/plain"))
		vty_out(vty, "%u", yang_dnode_get_uint32(dnode, "autonomous-system/plain"));
	else
		vty_out(vty, "%u.%u", yang_dnode_get_uint16(dnode, "autonomous-system/asdot/high"),
			yang_dnode_get_uint16(dnode, "autonomous-system/asdot/low"));

	if (!strmatch(vrf, VRF_DEFAULT_NAME))
		vty_out(vty, " %s %s",
			strmatch(yang_dnode_get_string(dnode, "instance-type"), "view") ? "view"
											: "vrf",
			vrf);

	if (yang_dnode_exists(dnode, "as-notation"))
		vty_out(vty, " as-notation %s", yang_dnode_get_string(dnode, "as-notation"));

	vty_out(vty, "\n");
}

static void instance_cli_write_end(struct vty *vty, const struct lyd_node *dnode)
{
	vty_out(vty, "exit\n");
	vty_out(vty, "!\n");
}

static void instance_router_id_cli_write(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	vty_out(vty, " bgp router-id %s\n", yang_dnode_get_string(dnode, NULL));
}

static void instance_log_neighbor_changes_cli_write(struct vty *vty, const struct lyd_node *dnode,
						    bool show_defaults)
{
	vty_out(vty, " bgp log-neighbor-changes %s\n",
		yang_dnode_get_bool(dnode, NULL) ? "enabled" : "disabled");
}

const struct frr_yang_module_info proteus_bgp_cli_info = {
	.name = "proteus-bgp",
	.ignore_cfg_cbs = true,
	.nodes = {
		{
			.xpath = "/proteus-bgp:instance",
			.cbs = {
				.cli_show = instance_cli_write,
				.cli_show_end = instance_cli_write_end,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/router-id",
			.cbs = {
				.cli_show = instance_router_id_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/log-neighbor-changes",
			.cbs = {
				.cli_show = instance_log_neighbor_changes_cli_write,
			}
		},
		{
			.xpath = NULL,
		},
	}
};

void bgp_cli_init(void)
{
	install_node(&bgp_node);
	install_default(BGP_NODE);

	install_element(CONFIG_NODE, &router_bgp_cli_cmd);
	install_element(CONFIG_NODE, &no_router_bgp_cli_cmd);

	install_element(BGP_NODE, &bgp_router_id_cli_cmd);
	install_element(BGP_NODE, &no_bgp_router_id_cli_cmd);
	install_element(BGP_NODE, &bgp_log_neighbor_changes_cli_cmd);
	install_element(BGP_NODE, &no_bgp_log_neighbor_changes_cli_cmd);
	install_element(BGP_NODE, &bgp_log_neighbor_changes_deprecated_cli_cmd);
	install_element(BGP_NODE, &no_bgp_log_neighbor_changes_deprecated_cli_cmd);
}
