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
 * Milestone 2 batch B1: process-wide independent scalars
 * ('/proteus-bgp:process/route-map-delay-timer', 'session-dscp',
 * 'input-queue-limit', 'output-queue-limit', 'no-rib',
 * 'send-extra-data-zebra', 'ipv6-auto-ra'). All installed at CONFIG_NODE,
 * fully qualified xpath (no BGP_NODE context to relativize against).
 */

DEFPY_YANG(
	bgp_route_map_delay_timer, bgp_route_map_delay_timer_cli_cmd,
	"bgp route-map delay-timer (0-600)$rmap_delay_timer",
	SET_STR
	"BGP route-map delay timer\n"
	"Time in secs to wait before processing route-map changes\n"
	"0 disables the timer, no route updates happen when route-maps change\n")
{
	nb_cli_enqueue_change(vty, "/proteus-bgp:process/route-map-delay-timer", NB_OP_MODIFY,
			      rmap_delay_timer_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_route_map_delay_timer, no_bgp_route_map_delay_timer_cli_cmd,
	"no bgp route-map delay-timer [(0-600)]",
	NO_STR
	BGP_STR
	"Default BGP route-map delay timer\n"
	"Reset to default time to wait for processing route-map changes\n"
	"0 disables the timer, no route updates happen when route-maps change\n")
{
	nb_cli_enqueue_change(vty, "/proteus-bgp:process/route-map-delay-timer", NB_OP_DESTROY,
			      NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_session_dscp, bgp_session_dscp_cli_cmd,
	"bgp session-dscp (0-63)$dscp",
	BGP_STR
	"Override default (CS6) DSCP for BGP connections\n"
	"Manually configured DSCP value\n")
{
	nb_cli_enqueue_change(vty, "/proteus-bgp:process/session-dscp", NB_OP_MODIFY, dscp_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_session_dscp, no_bgp_session_dscp_cli_cmd,
	"no bgp session-dscp [(0-63)]",
	NO_STR
	BGP_STR
	"Override default (CS6) DSCP for BGP connections\n"
	"Manually configured DSCP value\n")
{
	nb_cli_enqueue_change(vty, "/proteus-bgp:process/session-dscp", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_inq_limit, bgp_inq_limit_cli_cmd,
	"bgp input-queue-limit (1-4294967295)$limit",
	BGP_STR
	"Set the BGP Input Queue limit for all peers when message parsing\n"
	"Input-Queue limit\n")
{
	nb_cli_enqueue_change(vty, "/proteus-bgp:process/input-queue-limit", NB_OP_MODIFY,
			      limit_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_inq_limit, no_bgp_inq_limit_cli_cmd,
	"no bgp input-queue-limit [(1-4294967295)$limit]",
	NO_STR
	BGP_STR
	"Set the BGP Input Queue limit for all peers when message parsing\n"
	"Input-Queue limit\n")
{
	nb_cli_enqueue_change(vty, "/proteus-bgp:process/input-queue-limit", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_outq_limit, bgp_outq_limit_cli_cmd,
	"bgp output-queue-limit (1-4294967295)$limit",
	BGP_STR
	"Set the BGP Output Queue limit for all peers when message parsing\n"
	"Output-Queue limit\n")
{
	nb_cli_enqueue_change(vty, "/proteus-bgp:process/output-queue-limit", NB_OP_MODIFY,
			      limit_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_outq_limit, no_bgp_outq_limit_cli_cmd,
	"no bgp output-queue-limit [(1-4294967295)$limit]",
	NO_STR
	BGP_STR
	"Set the BGP Output Queue limit for all peers when message parsing\n"
	"Output-Queue limit\n")
{
	nb_cli_enqueue_change(vty, "/proteus-bgp:process/output-queue-limit", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_norib, bgp_norib_cli_cmd,
	"bgp no-rib",
	BGP_STR
	"Disable BGP route installation to RIB (Zebra)\n")
{
	nb_cli_enqueue_change(vty, "/proteus-bgp:process/no-rib", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_norib, no_bgp_norib_cli_cmd,
	"no bgp no-rib",
	NO_STR
	BGP_STR
	"Disable BGP route installation to RIB (Zebra)\n")
{
	nb_cli_enqueue_change(vty, "/proteus-bgp:process/no-rib", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_send_extra_data, bgp_send_extra_data_cli_cmd,
	"bgp send-extra-data zebra",
	BGP_STR
	"Extra data to Zebra for display/use\n"
	"To zebra\n")
{
	nb_cli_enqueue_change(vty, "/proteus-bgp:process/send-extra-data-zebra", NB_OP_MODIFY,
			      "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_send_extra_data, no_bgp_send_extra_data_cli_cmd,
	"no bgp send-extra-data zebra",
	NO_STR
	BGP_STR
	"Extra data to Zebra for display/use\n"
	"To zebra\n")
{
	nb_cli_enqueue_change(vty, "/proteus-bgp:process/send-extra-data-zebra", NB_OP_DESTROY,
			      NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/*
 * 'bgp ipv6-auto-ra' has both a PROCESS scope (CONFIG_NODE, this block)
 * and an INSTANCE scope (BGP_NODE per-VRF override, further below in the
 * B3 section): both are northbound now, the legacy per-VRF DEFPY
 * (bgp_ipv6_auto_ra_cmd in bgp_vty.c) is fully retired. The process leaf is
 * the chain root: a static default-on boolean, no inheritance, legacy
 * grammar (positive form destroys back to the true default, "no" form
 * modifies an explicit false). The instance leaf overrides it per VRF and
 * stays tri-state (no YANG default, absence = inherit the process leaf),
 * keeping the enabled|disabled scheme with deprecated bare aliases.
 */
DEFPY_YANG(
	bgp_process_ipv6_auto_ra, bgp_process_ipv6_auto_ra_cli_cmd,
	"bgp ipv6-auto-ra",
	BGP_STR
	"Allow enabling IPv6 ND RA sending\n")
{
	nb_cli_enqueue_change(vty, "/proteus-bgp:process/ipv6-auto-ra", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_process_ipv6_auto_ra, no_bgp_process_ipv6_auto_ra_cli_cmd,
	"no bgp ipv6-auto-ra",
	NO_STR
	BGP_STR
	"Allow enabling IPv6 ND RA sending\n")
{
	nb_cli_enqueue_change(vty, "/proteus-bgp:process/ipv6-auto-ra", NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

/* Instance (BGP_NODE) scope: per-VRF override of the process-wide leaf
 * above. Retires the legacy bgp_ipv6_auto_ra_cmd DEFPY entirely (it used
 * to serve this scope only; see bgp_vty.c history).
 */
DEFPY_YANG(
	bgp_instance_ipv6_auto_ra, bgp_instance_ipv6_auto_ra_cli_cmd,
	"bgp ipv6-auto-ra <enabled|disabled>$mode",
	BGP_STR
	"Allow enabling IPv6 ND RA sending\n"
	"Enable automatic IPv6 ND RA sending for this instance\n"
	"Disable automatic IPv6 ND RA sending for this instance\n")
{
	nb_cli_enqueue_change(vty, "./ipv6-auto-ra", NB_OP_MODIFY,
			      strmatch(mode, "enabled") ? "true" : "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_instance_ipv6_auto_ra, no_bgp_instance_ipv6_auto_ra_cli_cmd,
	"no bgp ipv6-auto-ra <enabled|disabled>$mode",
	NO_STR
	BGP_STR
	"Allow enabling IPv6 ND RA sending\n"
	"Enable automatic IPv6 ND RA sending for this instance\n"
	"Disable automatic IPv6 ND RA sending for this instance\n")
{
	nb_cli_enqueue_change(vty, "./ipv6-auto-ra", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_ATTR(
	bgp_instance_ipv6_auto_ra_deprecated, bgp_instance_ipv6_auto_ra_deprecated_cli_cmd,
	"bgp ipv6-auto-ra",
	BGP_STR
	"Allow enabling IPv6 ND RA sending\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	nb_cli_enqueue_change(vty, "./ipv6-auto-ra", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_ATTR(
	no_bgp_instance_ipv6_auto_ra_deprecated, no_bgp_instance_ipv6_auto_ra_deprecated_cli_cmd,
	"no bgp ipv6-auto-ra",
	NO_STR
	BGP_STR
	"Allow enabling IPv6 ND RA sending\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	nb_cli_enqueue_change(vty, "./ipv6-auto-ra", NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

/*
 * Milestone 2 batch B2: instance-scoped independent tuning scalars
 * ('write-quanta', 'read-quanta', 'coalesce-time', 'timers bgp'
 * keepalive/holdtime, 'bgp minimum-holdtime', 'bgp
 * conditional-advertisement timer', 'bgp default-originate timer'). All
 * installed at BGP_NODE, relative "./..." xpaths against the pushed
 * instance xpath.
 */

DEFPY_YANG(
	bgp_wpkt_quanta, bgp_wpkt_quanta_cli_cmd,
	"[no] write-quanta (1-64)$quanta",
	NO_STR
	"How many packets to write to peer socket per run\n"
	"Number of packets\n")
{
	if (no)
		nb_cli_enqueue_change(vty, "./write-quanta", NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, "./write-quanta", NB_OP_MODIFY, quanta_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_rpkt_quanta, bgp_rpkt_quanta_cli_cmd,
	"[no] read-quanta (1-10)$quanta",
	NO_STR
	"How many packets to read from peer socket per I/O cycle\n"
	"Number of packets\n")
{
	if (no)
		nb_cli_enqueue_change(vty, "./read-quanta", NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, "./read-quanta", NB_OP_MODIFY, quanta_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_coalesce_time, bgp_coalesce_time_cli_cmd,
	"coalesce-time (0-4294967295)$time",
	"Subgroup coalesce timer\n"
	"Subgroup coalesce timer value (in ms)\n")
{
	nb_cli_enqueue_change(vty, "./coalesce-time", NB_OP_MODIFY, time_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_coalesce_time, no_bgp_coalesce_time_cli_cmd,
	"no coalesce-time (0-4294967295)",
	NO_STR
	"Subgroup coalesce timer\n"
	"Subgroup coalesce timer value (in ms)\n")
{
	nb_cli_enqueue_change(vty, "./coalesce-time", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_timers, bgp_timers_cli_cmd,
	"timers bgp (0-65535)$keepalive (0-65535)$holdtime",
	"Adjust routing timers\n"
	"BGP timers\n"
	"Keepalive interval\n"
	"Holdtime\n")
{
	nb_cli_enqueue_change(vty, "./timers/keepalive", NB_OP_MODIFY, keepalive_str);
	nb_cli_enqueue_change(vty, "./timers/holdtime", NB_OP_MODIFY, holdtime_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_timers, no_bgp_timers_cli_cmd,
	"no timers bgp [(0-65535) (0-65535)]",
	NO_STR
	"Adjust routing timers\n"
	"BGP timers\n"
	"Keepalive interval\n"
	"Holdtime\n")
{
	nb_cli_enqueue_change(vty, "./timers/keepalive", NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./timers/holdtime", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_minimum_holdtime, bgp_minimum_holdtime_cli_cmd,
	"bgp minimum-holdtime (1-65535)$min_holdtime",
	BGP_STR
	"BGP minimum holdtime\n"
	"Seconds\n")
{
	nb_cli_enqueue_change(vty, "./timers/minimum-holdtime", NB_OP_MODIFY, min_holdtime_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_minimum_holdtime, no_bgp_minimum_holdtime_cli_cmd,
	"no bgp minimum-holdtime [(1-65535)]",
	NO_STR
	BGP_STR
	"BGP minimum holdtime\n"
	"Seconds\n")
{
	nb_cli_enqueue_change(vty, "./timers/minimum-holdtime", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_condadv_period, bgp_condadv_period_cli_cmd,
	"[no$no] bgp conditional-advertisement timer (5-240)$period",
	NO_STR
	BGP_STR
	"Conditional advertisement settings\n"
	"Set period to rescan BGP table to check if condition is met\n"
	"Period between BGP table scans, in seconds; default 60\n")
{
	if (no)
		nb_cli_enqueue_change(vty, "./timers/conditional-advertisement", NB_OP_DESTROY,
				      NULL);
	else
		nb_cli_enqueue_change(vty, "./timers/conditional-advertisement", NB_OP_MODIFY,
				      period_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_def_originate_eval, bgp_def_originate_eval_cli_cmd,
	"[no$no] bgp default-originate timer (0-65535)$timer",
	NO_STR
	BGP_STR
	"Control default-originate\n"
	"Set period to rescan BGP table to check if default-originate condition is met\n"
	"Period between BGP table scans, in seconds; default 5\n")
{
	if (no)
		nb_cli_enqueue_change(vty, "./timers/default-originate", NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, "./timers/default-originate", NB_OP_MODIFY, timer_str);
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

static void instance_ipv6_auto_ra_cli_write(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults)
{
	vty_out(vty, " bgp ipv6-auto-ra %s\n",
		yang_dnode_get_bool(dnode, NULL) ? "enabled" : "disabled");
}

static void instance_write_quanta_cli_write(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults)
{
	vty_out(vty, " write-quanta %u\n", yang_dnode_get_uint8(dnode, NULL));
}

static void instance_read_quanta_cli_write(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	vty_out(vty, " read-quanta %u\n", yang_dnode_get_uint8(dnode, NULL));
}

static void instance_coalesce_time_cli_write(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults)
{
	vty_out(vty, " coalesce-time %u\n", yang_dnode_get_uint32(dnode, NULL));
}

/* Joint emission of 'timers bgp <keepalive> <holdtime>': registered on the
 * shared "timers" container rather than either leaf's own xpath, because
 * the legacy config_write emits both values on a single line. A container-
 * level cli_show fires once whenever any descendant leaf is configured
 * (libyang implicitly materializes non-presence containers with data
 * underneath), so the other timers-container leaves (minimum-holdtime,
 * conditional-advertisement, default-originate) can trigger it too; guard
 * on keepalive/holdtime actually being present before emitting.
 */
static void instance_timers_cli_write(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	bool has_keepalive = yang_dnode_exists(dnode, "keepalive");
	bool has_holdtime = yang_dnode_exists(dnode, "holdtime");
	uint16_t keepalive = has_keepalive ? yang_dnode_get_uint16(dnode, "keepalive")
					   : (uint16_t)DFLT_BGP_KEEPALIVE;
	uint16_t holdtime = has_holdtime ? yang_dnode_get_uint16(dnode, "holdtime")
					 : (uint16_t)DFLT_BGP_HOLDTIME;

	if (!has_keepalive && !has_holdtime)
		return;

	vty_out(vty, " timers bgp %u %u\n", keepalive, holdtime);
}

static void instance_timers_minimum_holdtime_cli_write(struct vty *vty,
						       const struct lyd_node *dnode,
						       bool show_defaults)
{
	vty_out(vty, " bgp minimum-holdtime %u\n", yang_dnode_get_uint16(dnode, NULL));
}

static void instance_timers_conditional_advertisement_cli_write(struct vty *vty,
								const struct lyd_node *dnode,
								bool show_defaults)
{
	vty_out(vty, " bgp conditional-advertisement timer %u\n",
		yang_dnode_get_uint8(dnode, NULL));
}

static void instance_timers_default_originate_cli_write(struct vty *vty,
							const struct lyd_node *dnode,
							bool show_defaults)
{
	vty_out(vty, " bgp default-originate timer %u\n", yang_dnode_get_uint16(dnode, NULL));
}

static void process_route_map_delay_timer_cli_write(struct vty *vty, const struct lyd_node *dnode,
						    bool show_defaults)
{
	vty_out(vty, "bgp route-map delay-timer %u\n", yang_dnode_get_uint16(dnode, NULL));
}

static void process_session_dscp_cli_write(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	vty_out(vty, "bgp session-dscp %u\n", yang_dnode_get_uint8(dnode, NULL));
}

static void process_input_queue_limit_cli_write(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults)
{
	vty_out(vty, "bgp input-queue-limit %u\n", yang_dnode_get_uint32(dnode, NULL));
}

static void process_output_queue_limit_cli_write(struct vty *vty, const struct lyd_node *dnode,
						 bool show_defaults)
{
	vty_out(vty, "bgp output-queue-limit %u\n", yang_dnode_get_uint32(dnode, NULL));
}

static void process_no_rib_cli_write(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults)
{
	vty_out(vty, "bgp no-rib\n");
}

static void process_send_extra_data_zebra_cli_write(struct vty *vty, const struct lyd_node *dnode,
						    bool show_defaults)
{
	vty_out(vty, "bgp send-extra-data zebra\n");
}

static void process_ipv6_auto_ra_cli_write(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "no bgp ipv6-auto-ra\n");
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
			.xpath = "/proteus-bgp:instance/write-quanta",
			.cbs = {
				.cli_show = instance_write_quanta_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/read-quanta",
			.cbs = {
				.cli_show = instance_read_quanta_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/coalesce-time",
			.cbs = {
				.cli_show = instance_coalesce_time_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/timers",
			.cbs = {
				.cli_show = instance_timers_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/timers/minimum-holdtime",
			.cbs = {
				.cli_show = instance_timers_minimum_holdtime_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/timers/conditional-advertisement",
			.cbs = {
				.cli_show = instance_timers_conditional_advertisement_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/timers/default-originate",
			.cbs = {
				.cli_show = instance_timers_default_originate_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/ipv6-auto-ra",
			.cbs = {
				.cli_show = instance_ipv6_auto_ra_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:process/route-map-delay-timer",
			.cbs = {
				.cli_show = process_route_map_delay_timer_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:process/session-dscp",
			.cbs = {
				.cli_show = process_session_dscp_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:process/input-queue-limit",
			.cbs = {
				.cli_show = process_input_queue_limit_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:process/output-queue-limit",
			.cbs = {
				.cli_show = process_output_queue_limit_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:process/no-rib",
			.cbs = {
				.cli_show = process_no_rib_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:process/send-extra-data-zebra",
			.cbs = {
				.cli_show = process_send_extra_data_zebra_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:process/ipv6-auto-ra",
			.cbs = {
				.cli_show = process_ipv6_auto_ra_cli_write,
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

	install_element(BGP_NODE, &bgp_instance_ipv6_auto_ra_cli_cmd);
	install_element(BGP_NODE, &no_bgp_instance_ipv6_auto_ra_cli_cmd);
	install_element(BGP_NODE, &bgp_instance_ipv6_auto_ra_deprecated_cli_cmd);
	install_element(BGP_NODE, &no_bgp_instance_ipv6_auto_ra_deprecated_cli_cmd);

	install_element(BGP_NODE, &bgp_wpkt_quanta_cli_cmd);
	install_element(BGP_NODE, &bgp_rpkt_quanta_cli_cmd);
	install_element(BGP_NODE, &bgp_coalesce_time_cli_cmd);
	install_element(BGP_NODE, &no_bgp_coalesce_time_cli_cmd);
	install_element(BGP_NODE, &bgp_timers_cli_cmd);
	install_element(BGP_NODE, &no_bgp_timers_cli_cmd);
	install_element(BGP_NODE, &bgp_minimum_holdtime_cli_cmd);
	install_element(BGP_NODE, &no_bgp_minimum_holdtime_cli_cmd);
	install_element(BGP_NODE, &bgp_condadv_period_cli_cmd);
	install_element(BGP_NODE, &bgp_def_originate_eval_cli_cmd);

	install_element(CONFIG_NODE, &bgp_route_map_delay_timer_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_route_map_delay_timer_cli_cmd);
	install_element(CONFIG_NODE, &bgp_session_dscp_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_session_dscp_cli_cmd);
	install_element(CONFIG_NODE, &bgp_inq_limit_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_inq_limit_cli_cmd);
	install_element(CONFIG_NODE, &bgp_outq_limit_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_outq_limit_cli_cmd);
	install_element(CONFIG_NODE, &bgp_norib_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_norib_cli_cmd);
	install_element(CONFIG_NODE, &bgp_send_extra_data_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_send_extra_data_cli_cmd);
	install_element(CONFIG_NODE, &bgp_process_ipv6_auto_ra_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_process_ipv6_auto_ra_cli_cmd);
}
