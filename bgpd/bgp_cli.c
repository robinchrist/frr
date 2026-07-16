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
 * Milestone 2 batch B3: instance-scoped simple independent flags ('bgp
 * cluster-id', 'bgp fast-external-failover', 'bgp always-compare-med',
 * 'bgp disable-ebgp-connected-route-check', 'bgp client-to-client
 * reflection', 'bgp labeled-unicast <...>', 'bgp reject-as-sets'). All
 * installed at BGP_NODE, relative "./..." xpaths against the pushed
 * instance xpath.
 */

DEFPY_YANG(
	bgp_cluster_id, bgp_cluster_id_cli_cmd,
	"bgp cluster-id <A.B.C.D|(1-4294967295)>$cluster_id",
	BGP_STR
	"Configure Route-Reflector Cluster-id\n"
	"Route-Reflector Cluster-id in IP address format\n"
	"Route-Reflector Cluster-id as 32 bit quantity\n")
{
	nb_cli_enqueue_change(vty, "./cluster-id", NB_OP_MODIFY, cluster_id);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_cluster_id, no_bgp_cluster_id_cli_cmd,
	"no bgp cluster-id [<A.B.C.D|(1-4294967295)>]",
	NO_STR
	BGP_STR
	"Configure Route-Reflector Cluster-id\n"
	"Route-Reflector Cluster-id in IP address format\n"
	"Route-Reflector Cluster-id as 32 bit quantity\n")
{
	nb_cli_enqueue_change(vty, "./cluster-id", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/* Static default-on boolean, no inheritance: legacy grammar, positive form
 * destroys back to the true default, "no" form modifies an explicit false.
 */
DEFPY_YANG(
	bgp_fast_external_failover, bgp_fast_external_failover_cli_cmd,
	"bgp fast-external-failover",
	BGP_STR
	"Immediately reset session if a link to a directly connected external peer goes down\n")
{
	nb_cli_enqueue_change(vty, "./fast-external-failover", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_fast_external_failover, no_bgp_fast_external_failover_cli_cmd,
	"no bgp fast-external-failover",
	NO_STR
	BGP_STR
	"Immediately reset session if a link to a directly connected external peer goes down\n")
{
	nb_cli_enqueue_change(vty, "./fast-external-failover", NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_always_compare_med, bgp_always_compare_med_cli_cmd,
	"bgp always-compare-med",
	BGP_STR
	"Allow comparing MED from different neighbors\n")
{
	nb_cli_enqueue_change(vty, "./always-compare-med", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_always_compare_med, no_bgp_always_compare_med_cli_cmd,
	"no bgp always-compare-med",
	NO_STR
	BGP_STR
	"Allow comparing MED from different neighbors\n")
{
	nb_cli_enqueue_change(vty, "./always-compare-med", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_lu_uses_explicit_null, bgp_lu_uses_explicit_null_cli_cmd,
	"[no] bgp labeled-unicast <explicit-null|ipv4-explicit-null|ipv6-explicit-null>$value",
	NO_STR BGP_STR
	"BGP Labeled-unicast options\n"
	"Use explicit-null label values for all local prefixes\n"
	"Use the IPv4 explicit-null label value for IPv4 local prefixes\n"
	"Use the IPv6 explicit-null label value for IPv6 local prefixes\n")
{
	if (no) {
		nb_cli_enqueue_change(vty, "./labeled-unicast-explicit-null", NB_OP_DESTROY, NULL);
	} else {
		const char *enum_value;

		if (strmatch(value, "ipv4-explicit-null"))
			enum_value = "ipv4";
		else if (strmatch(value, "ipv6-explicit-null"))
			enum_value = "ipv6";
		else
			enum_value = "both";

		nb_cli_enqueue_change(vty, "./labeled-unicast-explicit-null", NB_OP_MODIFY,
				      enum_value);
	}
	return nb_cli_apply_changes(vty, NULL);
}

/* Static default-on boolean, no inheritance: legacy grammar, positive form
 * destroys back to the true default, "no" form modifies an explicit false.
 */
DEFPY_YANG(
	bgp_reject_as_sets, bgp_reject_as_sets_cli_cmd,
	"bgp reject-as-sets",
	BGP_STR
	"Reject routes with AS_SET or AS_CONFED_SET flag\n")
{
	nb_cli_enqueue_change(vty, "./reject-as-sets", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_reject_as_sets, no_bgp_reject_as_sets_cli_cmd,
	"no bgp reject-as-sets",
	NO_STR
	BGP_STR
	"Reject routes with AS_SET or AS_CONFED_SET flag\n")
{
	nb_cli_enqueue_change(vty, "./reject-as-sets", NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

/* Static default-on boolean, no inheritance: legacy grammar, positive form
 * destroys back to the true default, "no" form modifies an explicit false.
 */
DEFPY_YANG(
	bgp_client_to_client_reflection, bgp_client_to_client_reflection_cli_cmd,
	"bgp client-to-client reflection",
	BGP_STR
	"Configure client to client route reflection\n"
	"reflection of routes allowed\n")
{
	nb_cli_enqueue_change(vty, "./client-to-client-reflection", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_client_to_client_reflection, no_bgp_client_to_client_reflection_cli_cmd,
	"no bgp client-to-client reflection",
	NO_STR
	BGP_STR
	"Configure client to client route reflection\n"
	"reflection of routes allowed\n")
{
	nb_cli_enqueue_change(vty, "./client-to-client-reflection", NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_disable_connected_route_check, bgp_disable_connected_route_check_cli_cmd,
	"bgp disable-ebgp-connected-route-check",
	BGP_STR
	"Disable checking if nexthop is connected on ebgp sessions\n")
{
	nb_cli_enqueue_change(vty, "./disable-ebgp-connected-route-check", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_disable_connected_route_check, no_bgp_disable_connected_route_check_cli_cmd,
	"no bgp disable-ebgp-connected-route-check",
	NO_STR
	BGP_STR
	"Disable checking if nexthop is connected on ebgp sessions\n")
{
	nb_cli_enqueue_change(vty, "./disable-ebgp-connected-route-check", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_bestpath_aspath_ignore, bgp_bestpath_aspath_ignore_cli_cmd,
	"bgp bestpath as-path ignore",
	BGP_STR
	"Change the default bestpath selection\n"
	"AS-path attribute\n"
	"Ignore as-path length in selecting a route\n")
{
	nb_cli_enqueue_change(vty, "./bestpath/as-path-ignore", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_bestpath_aspath_ignore, no_bgp_bestpath_aspath_ignore_cli_cmd,
	"no bgp bestpath as-path ignore",
	NO_STR
	BGP_STR
	"Change the default bestpath selection\n"
	"AS-path attribute\n"
	"Ignore as-path length in selecting a route\n")
{
	nb_cli_enqueue_change(vty, "./bestpath/as-path-ignore", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_bestpath_aspath_confed, bgp_bestpath_aspath_confed_cli_cmd,
	"bgp bestpath as-path confed",
	BGP_STR
	"Change the default bestpath selection\n"
	"AS-path attribute\n"
	"Compare path lengths including confederation sets & sequences in selecting a route\n")
{
	nb_cli_enqueue_change(vty, "./bestpath/as-path-confed", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_bestpath_aspath_confed, no_bgp_bestpath_aspath_confed_cli_cmd,
	"no bgp bestpath as-path confed",
	NO_STR
	BGP_STR
	"Change the default bestpath selection\n"
	"AS-path attribute\n"
	"Compare path lengths including confederation sets & sequences in selecting a route\n")
{
	nb_cli_enqueue_change(vty, "./bestpath/as-path-confed", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_bestpath_aspath_multipath_relax, bgp_bestpath_aspath_multipath_relax_cli_cmd,
	"bgp bestpath as-path multipath-relax [<as-set$as_set|no-as-set$no_as_set>]",
	BGP_STR
	"Change the default bestpath selection\n"
	"AS-path attribute\n"
	"Allow load sharing across routes that have different AS paths (but same length)\n"
	"Generate an AS_SET\n"
	"Do not generate an AS_SET\n")
{
	nb_cli_enqueue_change(vty, "./bestpath/as-path-multipath-relax/enabled", NB_OP_MODIFY,
			      "true");
	nb_cli_enqueue_change(vty, "./bestpath/as-path-multipath-relax/as-set", NB_OP_MODIFY,
			      as_set ? "true" : "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_bestpath_aspath_multipath_relax, no_bgp_bestpath_aspath_multipath_relax_cli_cmd,
	"no bgp bestpath as-path multipath-relax [<as-set|no-as-set>]",
	NO_STR
	BGP_STR
	"Change the default bestpath selection\n"
	"AS-path attribute\n"
	"Allow load sharing across routes that have different AS paths (but same length)\n"
	"Generate an AS_SET\n"
	"Do not generate an AS_SET\n")
{
	nb_cli_enqueue_change(vty, "./bestpath/as-path-multipath-relax/enabled", NB_OP_DESTROY,
			      NULL);
	nb_cli_enqueue_change(vty, "./bestpath/as-path-multipath-relax/as-set", NB_OP_DESTROY,
			      NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_bestpath_compare_router_id, bgp_bestpath_compare_router_id_cli_cmd,
	"bgp bestpath compare-routerid",
	BGP_STR
	"Change the default bestpath selection\n"
	"Compare router-id for identical EBGP paths\n")
{
	nb_cli_enqueue_change(vty, "./bestpath/compare-routerid", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_bestpath_compare_router_id, no_bgp_bestpath_compare_router_id_cli_cmd,
	"no bgp bestpath compare-routerid",
	NO_STR
	BGP_STR
	"Change the default bestpath selection\n"
	"Compare router-id for identical EBGP paths\n")
{
	nb_cli_enqueue_change(vty, "./bestpath/compare-routerid", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_bestpath_use_imported_attrs, bgp_bestpath_use_imported_attrs_cli_cmd,
	"[no$no] bgp bestpath use-imported-attributes",
	NO_STR
	BGP_STR
	"Change the default bestpath selection\n"
	"Use imported path's attributes for bestpath comparison\n")
{
	if (no)
		nb_cli_enqueue_change(vty, "./bestpath/use-imported-attributes", NB_OP_DESTROY,
				      NULL);
	else
		nb_cli_enqueue_change(vty, "./bestpath/use-imported-attributes", NB_OP_MODIFY,
				      "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_bestpath_med, bgp_bestpath_med_cli_cmd,
	"bgp bestpath med <confed$confed [missing-as-worst$missing_as_worst]|missing-as-worst$missing_as_worst [confed$confed]>",
	BGP_STR
	"Change the default bestpath selection\n"
	"MED attribute\n"
	"Compare MED among confederation paths\n"
	"Treat missing MED as the least preferred one\n"
	"Treat missing MED as the least preferred one\n"
	"Compare MED among confederation paths\n")
{
	if (confed)
		nb_cli_enqueue_change(vty, "./bestpath/med/confed", NB_OP_MODIFY, "true");
	if (missing_as_worst)
		nb_cli_enqueue_change(vty, "./bestpath/med/missing-as-worst", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_bestpath_med, no_bgp_bestpath_med_cli_cmd,
	"no bgp bestpath med <confed$confed [missing-as-worst$missing_as_worst]|missing-as-worst$missing_as_worst [confed$confed]>",
	NO_STR
	BGP_STR
	"Change the default bestpath selection\n"
	"MED attribute\n"
	"Compare MED among confederation paths\n"
	"Treat missing MED as the least preferred one\n"
	"Treat missing MED as the least preferred one\n"
	"Compare MED among confederation paths\n")
{
	if (confed)
		nb_cli_enqueue_change(vty, "./bestpath/med/confed", NB_OP_DESTROY, NULL);
	if (missing_as_worst)
		nb_cli_enqueue_change(vty, "./bestpath/med/missing-as-worst", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_bestpath_peer_type_multipath_relax, bgp_bestpath_peer_type_multipath_relax_cli_cmd,
	"bgp bestpath peer-type multipath-relax",
	BGP_STR
	"Change the default bestpath selection\n"
	"Peer type\n"
	"Allow load sharing across routes learned from different peer types\n")
{
	nb_cli_enqueue_change(vty, "./bestpath/peer-type-multipath-relax", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_bestpath_peer_type_multipath_relax, no_bgp_bestpath_peer_type_multipath_relax_cli_cmd,
	"no bgp bestpath peer-type multipath-relax",
	NO_STR
	BGP_STR
	"Change the default bestpath selection\n"
	"Peer type\n"
	"Allow load sharing across routes learned from different peer types\n")
{
	nb_cli_enqueue_change(vty, "./bestpath/peer-type-multipath-relax", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_bestpath_bw, bgp_bestpath_bw_cli_cmd,
	"bgp bestpath bandwidth <ignore|skip-missing|default-weight-for-missing>$bw_cfg",
	BGP_STR
	"Change the default bestpath selection\n"
	"Link Bandwidth attribute\n"
	"Ignore link bandwidth (i.e., do regular ECMP, not weighted)\n"
	"Ignore paths without link bandwidth for ECMP (if other paths have it)\n"
	"Assign a low default weight (value 1) to paths not having link bandwidth\n")
{
	nb_cli_enqueue_change(vty, "./bestpath/bandwidth", NB_OP_MODIFY, bw_cfg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_bestpath_bw, no_bgp_bestpath_bw_cli_cmd,
	"no bgp bestpath bandwidth [<ignore|skip-missing|default-weight-for-missing>]",
	NO_STR
	BGP_STR
	"Change the default bestpath selection\n"
	"Link Bandwidth attribute\n"
	"Ignore link bandwidth (i.e., do regular ECMP, not weighted)\n"
	"Ignore paths without link bandwidth for ECMP (if other paths have it)\n"
	"Assign a low default weight (value 1) to paths not having link bandwidth\n")
{
	nb_cli_enqueue_change(vty, "./bestpath/bandwidth", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/*
 * Milestone 2 batch B5: instance 'default' container, AFI-activation group
 * ('bgp default <afi-safi>'). All eleven tokens share one legacy grammar
 * and one legacy DEFPY (bgp_default_afi_safi_cmd, bgp_vty.c). ipv4-unicast
 * is the sole static default-on/no-inheritance leaf in this family (the
 * only default/<afi-safi> leaf that is on by default): its negative form is
 * a real "false" modify rather than a delete, and its positive form
 * destroys back to the true default, matching the
 * fast-external-failover/reject-as-sets/client-to-client-reflection shape.
 * Every other token here defaults false in YANG and is positive-only, so
 * its negative form deletes back to that default. Every token string is
 * identical to its YANG leaf name, so the xpath is built directly from the
 * matched token, no translation table needed (unlike the legacy DEFPY's
 * strtok_r() afi/safi decomposition).
 */
DEFPY_YANG(
	bgp_default_afi_safi, bgp_default_afi_safi_cli_cmd,
	"[no] bgp default <ipv4-unicast|"
	"ipv4-multicast|"
	"ipv4-vpn|"
	"ipv4-labeled-unicast|"
	"ipv4-flowspec|"
	"ipv6-unicast|"
	"ipv6-multicast|"
	"ipv6-vpn|"
	"ipv6-labeled-unicast|"
	"ipv6-flowspec|"
	"l2vpn-evpn>$afi_safi",
	NO_STR
	BGP_STR
	"Configure BGP defaults\n"
	"Activate ipv4-unicast for a peer by default\n"
	"Activate ipv4-multicast for a peer by default\n"
	"Activate ipv4-vpn for a peer by default\n"
	"Activate ipv4-labeled-unicast for a peer by default\n"
	"Activate ipv4-flowspec for a peer by default\n"
	"Activate ipv6-unicast for a peer by default\n"
	"Activate ipv6-multicast for a peer by default\n"
	"Activate ipv6-vpn for a peer by default\n"
	"Activate ipv6-labeled-unicast for a peer by default\n"
	"Activate ipv6-flowspec for a peer by default\n"
	"Activate l2vpn-evpn for a peer by default\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "./default/%s", afi_safi);

	if (strmatch(afi_safi, "ipv4-unicast")) {
		if (no)
			nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, "false");
		else
			nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	} else if (no)
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, "true");

	return nb_cli_apply_changes(vty, NULL);
}

/*
 * Milestone 2 batch B6: 'bgp default local-preference (0-4294967295)'.
 * Static default-on scalar, no inheritance (YANG default 100): the "no"
 * form (value token optional and ignored, matching the legacy DEFUN)
 * destroys back to that default; the positive form always carries an
 * explicit value.
 */
DEFPY_YANG(
	bgp_default_local_preference, bgp_default_local_preference_cli_cmd,
	"bgp default local-preference (0-4294967295)$local_pref",
	BGP_STR
	"Configure BGP defaults\n"
	"local preference (higher=more preferred)\n"
	"Configure default local preference value\n")
{
	nb_cli_enqueue_change(vty, "./default/local-preference", NB_OP_MODIFY, local_pref_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_default_local_preference, no_bgp_default_local_preference_cli_cmd,
	"no bgp default local-preference [(0-4294967295)]",
	NO_STR
	BGP_STR
	"Configure BGP defaults\n"
	"local preference (higher=more preferred)\n"
	"Configure default local preference value\n")
{
	nb_cli_enqueue_change(vty, "./default/local-preference", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/*
 * 'bgp default subgroup-pkt-queue-max (20-100)'. Static default-on scalar,
 * no inheritance (YANG default 40), same shape as local-preference above.
 */
DEFPY_YANG(
	bgp_default_subgroup_pkt_queue_max, bgp_default_subgroup_pkt_queue_max_cli_cmd,
	"bgp default subgroup-pkt-queue-max (20-100)$max_size",
	BGP_STR
	"Configure BGP defaults\n"
	"subgroup-pkt-queue-max\n"
	"Configure subgroup packet queue max\n")
{
	nb_cli_enqueue_change(vty, "./default/subgroup-pkt-queue-max", NB_OP_MODIFY, max_size_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_default_subgroup_pkt_queue_max, no_bgp_default_subgroup_pkt_queue_max_cli_cmd,
	"no bgp default subgroup-pkt-queue-max [(20-100)]",
	NO_STR
	BGP_STR
	"Configure BGP defaults\n"
	"subgroup-pkt-queue-max\n"
	"Configure subgroup packet queue max\n")
{
	nb_cli_enqueue_change(vty, "./default/subgroup-pkt-queue-max", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/*
 * Milestone 2 batch B7: max-med, confederation, tcp-keepalive. All
 * installed at BGP_NODE, relative "./..." xpaths against the pushed
 * instance xpath.
 */

DEFPY_YANG(
	bgp_maxmed_onstartup, bgp_maxmed_onstartup_cli_cmd,
	"bgp max-med on-startup (5-86400)$period [(0-4294967295)$med]",
	BGP_STR
	"Advertise routes with max-med\n"
	"Effective on a startup\n"
	"Time (seconds) period for max-med\n"
	"Max MED value to be used\n")
{
	nb_cli_enqueue_change(vty, "./max-med/on-startup/period", NB_OP_MODIFY, period_str);
	if (med_str)
		nb_cli_enqueue_change(vty, "./max-med/on-startup/med", NB_OP_MODIFY, med_str);
	else
		nb_cli_enqueue_change(vty, "./max-med/on-startup/med", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_maxmed_onstartup, no_bgp_maxmed_onstartup_cli_cmd,
	"no bgp max-med on-startup [(5-86400) [(0-4294967295)]]",
	NO_STR
	BGP_STR
	"Advertise routes with max-med\n"
	"Effective on a startup\n"
	"Time (seconds) period for max-med\n"
	"Max MED value to be used\n")
{
	nb_cli_enqueue_change(vty, "./max-med/on-startup/period", NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./max-med/on-startup/med", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_maxmed_admin, bgp_maxmed_admin_cli_cmd,
	"bgp max-med administrative [(0-4294967295)$med]",
	BGP_STR
	"Advertise routes with max-med\n"
	"Administratively applied, for an indefinite period\n"
	"Max MED value to be used\n")
{
	nb_cli_enqueue_change(vty, "./max-med/administrative/enabled", NB_OP_MODIFY, "true");
	if (med_str)
		nb_cli_enqueue_change(vty, "./max-med/administrative/med", NB_OP_MODIFY, med_str);
	else
		nb_cli_enqueue_change(vty, "./max-med/administrative/med", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_maxmed_admin, no_bgp_maxmed_admin_cli_cmd,
	"no bgp max-med administrative [(0-4294967295)]",
	NO_STR
	BGP_STR
	"Advertise routes with max-med\n"
	"Administratively applied, for an indefinite period\n"
	"Max MED value to be used\n")
{
	nb_cli_enqueue_change(vty, "./max-med/administrative/enabled", NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./max-med/administrative/med", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_confederation_identifier, bgp_confederation_identifier_cli_cmd,
	"bgp confederation identifier ASNUM$asnum",
	BGP_STR
	"AS confederation parameters\n"
	"Set routing domain confederation AS\n"
	AS_STR)
{
	char highbuf[8], lowbuf[8];

	if (strchr(asnum_str, '.')) {
		as_t asn = 0;
		as_t high, low;

		if (!asn_str2asn(asnum_str, &asn)) {
			vty_out(vty, "%% BGP: No such AS %s\n", asnum_str);
			return CMD_WARNING_CONFIG_FAILED;
		}
		high = asn >> 16;
		low = asn & 0xffff;
		snprintf(highbuf, sizeof(highbuf), "%u", high);
		snprintf(lowbuf, sizeof(lowbuf), "%u", low);

		nb_cli_enqueue_change(vty, "./confederation/identifier/asdot/high", NB_OP_MODIFY,
				      highbuf);
		nb_cli_enqueue_change(vty, "./confederation/identifier/asdot/low", NB_OP_MODIFY,
				      lowbuf);
	} else {
		as_t asn = 0;

		if (!asn_str2asn(asnum_str, &asn)) {
			vty_out(vty, "%% BGP: No such AS %s\n", asnum_str);
			return CMD_WARNING_CONFIG_FAILED;
		}

		nb_cli_enqueue_change(vty, "./confederation/identifier/plain", NB_OP_MODIFY,
				      asnum_str);
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_confederation_identifier, no_bgp_confederation_identifier_cli_cmd,
	"no bgp confederation identifier [ASNUM]",
	NO_STR
	BGP_STR
	"AS confederation parameters\n"
	"Set routing domain confederation AS\n"
	AS_STR)
{
	nb_cli_enqueue_change(vty, "./confederation/identifier/plain", NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./confederation/identifier/asdot", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_confederation_peers, bgp_confederation_peers_cli_cmd,
	"bgp confederation peers ASNUM...",
	BGP_STR
	"AS confederation parameters\n"
	"Peer ASs in BGP confederation\n"
	AS_STR)
{
	int i;

	for (i = 3; i < argc; i++) {
		const char *as_str = argv[i]->arg;
		char xpath[XPATH_MAXLEN];
		as_t as = 0;

		if (!asn_str2asn(as_str, &as)) {
			vty_out(vty, "%% Invalid confed peer AS value: %s\n", as_str);
			continue;
		}

		if (strchr(as_str, '.')) {
			as_t high = as >> 16, low = as & 0xffff;

			snprintf(xpath, sizeof(xpath),
				 "./confederation/peers/asdot[high='%u'][low='%u']", high, low);
		} else {
			snprintf(xpath, sizeof(xpath), "./confederation/peers/plain[.='%s']",
				 as_str);
		}
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_confederation_peers, no_bgp_confederation_peers_cli_cmd,
	"no bgp confederation peers ASNUM...",
	NO_STR
	BGP_STR
	"AS confederation parameters\n"
	"Peer ASs in BGP confederation\n"
	AS_STR)
{
	int i;

	for (i = 4; i < argc; i++) {
		const char *as_str = argv[i]->arg;
		char xpath[XPATH_MAXLEN];
		as_t as = 0;

		if (!asn_str2asn(as_str, &as)) {
			vty_out(vty, "%% Invalid confed peer AS value: %s\n", as_str);
			continue;
		}

		if (strchr(as_str, '.')) {
			as_t high = as >> 16, low = as & 0xffff;

			snprintf(xpath, sizeof(xpath),
				 "./confederation/peers/asdot[high='%u'][low='%u']", high, low);
		} else {
			snprintf(xpath, sizeof(xpath), "./confederation/peers/plain[.='%s']",
				 as_str);
		}
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_tcp_keepalive, bgp_tcp_keepalive_cli_cmd,
	"bgp tcp-keepalive (1-65535)$idle (1-65535)$intvl (1-30)$probes",
	BGP_STR
	"TCP keepalive parameters\n"
	"TCP keepalive idle time (seconds)\n"
	"TCP keepalive interval (seconds)\n"
	"TCP keepalive maximum probes\n")
{
	nb_cli_enqueue_change(vty, "./tcp-keepalive/idle", NB_OP_MODIFY, idle_str);
	nb_cli_enqueue_change(vty, "./tcp-keepalive/interval", NB_OP_MODIFY, intvl_str);
	nb_cli_enqueue_change(vty, "./tcp-keepalive/probes", NB_OP_MODIFY, probes_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_tcp_keepalive, no_bgp_tcp_keepalive_cli_cmd,
	"no bgp tcp-keepalive [(1-65535) (1-65535) (1-30)]",
	NO_STR
	BGP_STR
	"TCP keepalive parameters\n"
	"TCP keepalive idle time (seconds)\n"
	"TCP keepalive interval (seconds)\n"
	"TCP keepalive maximum probes\n")
{
	nb_cli_enqueue_change(vty, "./tcp-keepalive/idle", NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./tcp-keepalive/interval", NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./tcp-keepalive/probes", NB_OP_DESTROY, NULL);
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

static void instance_cluster_id_cli_write(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	struct in_addr cluster;

	/* inet_aton(), not inet_pton(): the union type also accepts a plain
	 * decimal 32-bit value, and inet_aton() is what the legacy DEFUN
	 * used to accept both forms. Always rendered dotted-quad on output,
	 * matching bgp_config_write()'s "%pI4" regardless of input notation.
	 */
	inet_aton(yang_dnode_get_string(dnode, NULL), &cluster);
	vty_out(vty, " bgp cluster-id %pI4\n", &cluster);
}

static void instance_fast_external_failover_cli_write(struct vty *vty, const struct lyd_node *dnode,
						      bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no bgp fast-external-failover\n");
}

static void instance_ipv6_auto_ra_cli_write(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults)
{
	vty_out(vty, " bgp ipv6-auto-ra %s\n",
		yang_dnode_get_bool(dnode, NULL) ? "enabled" : "disabled");
}

static void instance_always_compare_med_cli_write(struct vty *vty, const struct lyd_node *dnode,
						  bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp always-compare-med\n");
}

static void instance_labeled_unicast_explicit_null_cli_write(struct vty *vty,
							     const struct lyd_node *dnode,
							     bool show_defaults)
{
	const char *value = yang_dnode_get_string(dnode, NULL);

	if (strmatch(value, "both"))
		vty_out(vty, " bgp labeled-unicast explicit-null\n");
	else if (strmatch(value, "ipv4"))
		vty_out(vty, " bgp labeled-unicast ipv4-explicit-null\n");
	else if (strmatch(value, "ipv6"))
		vty_out(vty, " bgp labeled-unicast ipv6-explicit-null\n");
}

static void instance_reject_as_sets_cli_write(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no bgp reject-as-sets\n");
}

static void instance_client_to_client_reflection_cli_write(struct vty *vty,
							   const struct lyd_node *dnode,
							   bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no bgp client-to-client reflection\n");
}

static void instance_disable_ebgp_connected_route_check_cli_write(struct vty *vty,
								  const struct lyd_node *dnode,
								  bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp disable-ebgp-connected-route-check\n");
}

static void instance_bestpath_as_path_ignore_cli_write(struct vty *vty,
						       const struct lyd_node *dnode,
						       bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp bestpath as-path ignore\n");
}

static void instance_bestpath_as_path_confed_cli_write(struct vty *vty,
						       const struct lyd_node *dnode,
						       bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp bestpath as-path confed\n");
}

/* Joint emission of 'bgp bestpath as-path multipath-relax [as-set]':
 * registered on the shared "as-path-multipath-relax" container rather than
 * either leaf's own xpath, matching bgp_config_write()'s single-line
 * emission (bgp_vty.c:21698-21707).
 */
static void instance_bestpath_as_path_multipath_relax_cli_write(struct vty *vty,
								const struct lyd_node *dnode,
								bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, "enabled"))
		return;

	if (yang_dnode_get_bool(dnode, "as-set"))
		vty_out(vty, " bgp bestpath as-path multipath-relax as-set\n");
	else
		vty_out(vty, " bgp bestpath as-path multipath-relax\n");
}

static void instance_bestpath_compare_routerid_cli_write(struct vty *vty,
							 const struct lyd_node *dnode,
							 bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp bestpath compare-routerid\n");
}

static void instance_bestpath_use_imported_attributes_cli_write(struct vty *vty,
								const struct lyd_node *dnode,
								bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp bestpath use-imported-attributes\n");
}

/* Joint emission of 'bgp bestpath med [confed] [missing-as-worst]':
 * registered on the shared "med" container, matching bgp_config_write()'s
 * single-line emission (bgp_vty.c:21724-21733).
 */
static void instance_bestpath_med_cli_write(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults)
{
	bool confed = yang_dnode_get_bool(dnode, "confed");
	bool missing_as_worst = yang_dnode_get_bool(dnode, "missing-as-worst");

	if (!confed && !missing_as_worst)
		return;

	vty_out(vty, " bgp bestpath med");
	if (confed)
		vty_out(vty, " confed");
	if (missing_as_worst)
		vty_out(vty, " missing-as-worst");
	vty_out(vty, "\n");
}

static void instance_bestpath_peer_type_multipath_relax_cli_write(struct vty *vty,
								  const struct lyd_node *dnode,
								  bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp bestpath peer-type multipath-relax\n");
}

static void instance_bestpath_bandwidth_cli_write(struct vty *vty, const struct lyd_node *dnode,
						  bool show_defaults)
{
	vty_out(vty, " bgp bestpath bandwidth %s\n", yang_dnode_get_string(dnode, NULL));
}

/* 'bgp default <afi-safi>' (batch B5): ipv4-unicast is the sole static
 * default-on/no-inheritance leaf (bgp_vty.c's FOREACH_AFI_SAFI
 * special-cases AFI_IP/SAFI_UNICAST), so it renders the legacy negative
 * line iff explicitly false. Every other leaf here is positive-only,
 * matching bgp_config_write()'s "if (bgp->default_af[...])" arm for all
 * other AFI/SAFI pairs.
 */
static void instance_default_ipv4_unicast_cli_write(struct vty *vty, const struct lyd_node *dnode,
						    bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no bgp default ipv4-unicast\n");
}

static void instance_default_ipv4_multicast_cli_write(struct vty *vty, const struct lyd_node *dnode,
						      bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp default ipv4-multicast\n");
}

static void instance_default_ipv4_labeled_unicast_cli_write(struct vty *vty,
							    const struct lyd_node *dnode,
							    bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp default ipv4-labeled-unicast\n");
}

static void instance_default_ipv4_vpn_cli_write(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp default ipv4-vpn\n");
}

static void instance_default_ipv4_flowspec_cli_write(struct vty *vty, const struct lyd_node *dnode,
						     bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp default ipv4-flowspec\n");
}

static void instance_default_ipv6_unicast_cli_write(struct vty *vty, const struct lyd_node *dnode,
						    bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp default ipv6-unicast\n");
}

static void instance_default_ipv6_multicast_cli_write(struct vty *vty, const struct lyd_node *dnode,
						      bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp default ipv6-multicast\n");
}

static void instance_default_ipv6_labeled_unicast_cli_write(struct vty *vty,
							    const struct lyd_node *dnode,
							    bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp default ipv6-labeled-unicast\n");
}

static void instance_default_ipv6_vpn_cli_write(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp default ipv6-vpn\n");
}

static void instance_default_ipv6_flowspec_cli_write(struct vty *vty, const struct lyd_node *dnode,
						     bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp default ipv6-flowspec\n");
}

static void instance_default_l2vpn_evpn_cli_write(struct vty *vty, const struct lyd_node *dnode,
						  bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp default l2vpn-evpn\n");
}

/* Static default-on scalars (batch B6): value-checked against the YANG
 * default, matching bgp_config_write()'s "if (bgp->default_local_pref !=
 * BGP_DEFAULT_LOCAL_PREF)" / subgroup-pkt-queue-max arms exactly.
 */
static void instance_default_local_preference_cli_write(struct vty *vty,
							const struct lyd_node *dnode,
							bool show_defaults)
{
	if (yang_dnode_get_uint32(dnode, NULL) != 100)
		vty_out(vty, " bgp default local-preference %u\n",
			yang_dnode_get_uint32(dnode, NULL));
}

static void instance_default_subgroup_pkt_queue_max_cli_write(struct vty *vty,
							      const struct lyd_node *dnode,
							      bool show_defaults)
{
	if (yang_dnode_get_uint8(dnode, NULL) != 40)
		vty_out(vty, " bgp default subgroup-pkt-queue-max %u\n",
			yang_dnode_get_uint8(dnode, NULL));
}

/* Joint emission of 'bgp max-med on-startup <period> [<med>]': registered
 * on the "on-startup" container, guarded on 'period' being present (the
 * CLI always sets/destroys 'period' and 'med' together, mirroring the
 * legacy DEFUN). 'med' is a no-default leaf, so its presence alone gates
 * whether the value suffix is printed - an intentional presence-based
 * divergence from the legacy value-comparison gating, same rationale as
 * batch B2's default-less leaves.
 */
static void instance_max_med_on_startup_cli_write(struct vty *vty, const struct lyd_node *dnode,
						  bool show_defaults)
{
	if (!yang_dnode_exists(dnode, "period"))
		return;

	vty_out(vty, " bgp max-med on-startup %u", yang_dnode_get_uint32(dnode, "period"));
	if (yang_dnode_exists(dnode, "med"))
		vty_out(vty, " %u", yang_dnode_get_uint32(dnode, "med"));
	vty_out(vty, "\n");
}

/* Joint emission of 'bgp max-med administrative [<med>]': registered on
 * the "administrative" container. 'enabled' has a YANG default (false),
 * so it must be value-checked rather than merely presence-checked (it can
 * be materialized with show_defaults); 'med' is presence-based like
 * on-startup's.
 */
static void instance_max_med_administrative_cli_write(struct vty *vty, const struct lyd_node *dnode,
						      bool show_defaults)
{
	if (!yang_dnode_exists(dnode, "enabled") || !yang_dnode_get_bool(dnode, "enabled"))
		return;

	vty_out(vty, " bgp max-med administrative");
	if (yang_dnode_exists(dnode, "med"))
		vty_out(vty, " %u", yang_dnode_get_uint32(dnode, "med"));
	vty_out(vty, "\n");
}

static void instance_confederation_identifier_cli_write(struct vty *vty,
							const struct lyd_node *dnode,
							bool show_defaults)
{
	if (yang_dnode_exists(dnode, "plain"))
		vty_out(vty, " bgp confederation identifier %u\n",
			yang_dnode_get_uint32(dnode, "plain"));
	else if (yang_dnode_exists(dnode, "asdot"))
		vty_out(vty, " bgp confederation identifier %u.%u\n",
			yang_dnode_get_uint16(dnode, "asdot/high"),
			yang_dnode_get_uint16(dnode, "asdot/low"));
}

static int instance_confederation_peers_plain_iter_cb(const struct lyd_node *dnode, void *arg)
{
	struct vty *vty = arg;

	vty_out(vty, " %s", yang_dnode_get_string(dnode, "."));
	return YANG_ITER_CONTINUE;
}

static int instance_confederation_peers_asdot_iter_cb(const struct lyd_node *dnode, void *arg)
{
	struct vty *vty = arg;

	vty_out(vty, " %u.%u", yang_dnode_get_uint16(dnode, "high"),
		yang_dnode_get_uint16(dnode, "low"));
	return YANG_ITER_CONTINUE;
}

/* Joint emission of 'bgp confederation peers ASN...': registered on the
 * "peers" container so both collections land on one line. Emits the
 * plain leaf-list first, then the asdot list, per the YANG description's
 * documented order - legacy's single flat confed_peers[] array is
 * insertion-ordered instead, but that's display-only (show running-config
 * presentation), not a wire/semantic difference.
 */
static void instance_confederation_peers_cli_write(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults)
{
	bool has_plain = yang_dnode_exists(dnode, "plain");
	bool has_asdot = yang_dnode_exists(dnode, "asdot");

	if (!has_plain && !has_asdot)
		return;

	vty_out(vty, " bgp confederation peers");
	if (has_plain)
		yang_dnode_iterate(instance_confederation_peers_plain_iter_cb, vty, dnode,
				   "./plain");
	if (has_asdot)
		yang_dnode_iterate(instance_confederation_peers_asdot_iter_cb, vty, dnode,
				   "./asdot");
	vty_out(vty, "\n");
}

/* Joint emission of 'bgp tcp-keepalive <idle> <interval> <probes>':
 * registered on the "tcp-keepalive" container (B2 instance_timers_cli_write
 * pattern), guarded on 'idle' since the YANG 'must' guarantees all three or
 * none.
 */
static void instance_tcp_keepalive_cli_write(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults)
{
	if (!yang_dnode_exists(dnode, "idle"))
		return;

	vty_out(vty, " bgp tcp-keepalive %u %u %u\n", yang_dnode_get_uint16(dnode, "idle"),
		yang_dnode_get_uint16(dnode, "interval"), yang_dnode_get_uint8(dnode, "probes"));
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
			.xpath = "/proteus-bgp:instance/cluster-id",
			.cbs = {
				.cli_show = instance_cluster_id_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/fast-external-failover",
			.cbs = {
				.cli_show = instance_fast_external_failover_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/ipv6-auto-ra",
			.cbs = {
				.cli_show = instance_ipv6_auto_ra_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/always-compare-med",
			.cbs = {
				.cli_show = instance_always_compare_med_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/labeled-unicast-explicit-null",
			.cbs = {
				.cli_show = instance_labeled_unicast_explicit_null_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/reject-as-sets",
			.cbs = {
				.cli_show = instance_reject_as_sets_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/client-to-client-reflection",
			.cbs = {
				.cli_show = instance_client_to_client_reflection_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/disable-ebgp-connected-route-check",
			.cbs = {
				.cli_show = instance_disable_ebgp_connected_route_check_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/bestpath/as-path-ignore",
			.cbs = {
				.cli_show = instance_bestpath_as_path_ignore_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/bestpath/as-path-confed",
			.cbs = {
				.cli_show = instance_bestpath_as_path_confed_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/bestpath/as-path-multipath-relax",
			.cbs = {
				.cli_show = instance_bestpath_as_path_multipath_relax_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/bestpath/compare-routerid",
			.cbs = {
				.cli_show = instance_bestpath_compare_routerid_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/bestpath/use-imported-attributes",
			.cbs = {
				.cli_show = instance_bestpath_use_imported_attributes_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/bestpath/med",
			.cbs = {
				.cli_show = instance_bestpath_med_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/bestpath/peer-type-multipath-relax",
			.cbs = {
				.cli_show = instance_bestpath_peer_type_multipath_relax_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/bestpath/bandwidth",
			.cbs = {
				.cli_show = instance_bestpath_bandwidth_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/ipv4-unicast",
			.cbs = {
				.cli_show = instance_default_ipv4_unicast_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/ipv4-multicast",
			.cbs = {
				.cli_show = instance_default_ipv4_multicast_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/ipv4-labeled-unicast",
			.cbs = {
				.cli_show = instance_default_ipv4_labeled_unicast_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/ipv4-vpn",
			.cbs = {
				.cli_show = instance_default_ipv4_vpn_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/ipv4-flowspec",
			.cbs = {
				.cli_show = instance_default_ipv4_flowspec_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/ipv6-unicast",
			.cbs = {
				.cli_show = instance_default_ipv6_unicast_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/ipv6-multicast",
			.cbs = {
				.cli_show = instance_default_ipv6_multicast_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/ipv6-labeled-unicast",
			.cbs = {
				.cli_show = instance_default_ipv6_labeled_unicast_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/ipv6-vpn",
			.cbs = {
				.cli_show = instance_default_ipv6_vpn_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/ipv6-flowspec",
			.cbs = {
				.cli_show = instance_default_ipv6_flowspec_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/l2vpn-evpn",
			.cbs = {
				.cli_show = instance_default_l2vpn_evpn_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/local-preference",
			.cbs = {
				.cli_show = instance_default_local_preference_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/subgroup-pkt-queue-max",
			.cbs = {
				.cli_show = instance_default_subgroup_pkt_queue_max_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/max-med/on-startup",
			.cbs = {
				.cli_show = instance_max_med_on_startup_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/max-med/administrative",
			.cbs = {
				.cli_show = instance_max_med_administrative_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/confederation/identifier",
			.cbs = {
				.cli_show = instance_confederation_identifier_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/confederation/peers",
			.cbs = {
				.cli_show = instance_confederation_peers_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/tcp-keepalive",
			.cbs = {
				.cli_show = instance_tcp_keepalive_cli_write,
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

	install_element(BGP_NODE, &bgp_cluster_id_cli_cmd);
	install_element(BGP_NODE, &no_bgp_cluster_id_cli_cmd);
	install_element(BGP_NODE, &bgp_fast_external_failover_cli_cmd);
	install_element(BGP_NODE, &no_bgp_fast_external_failover_cli_cmd);
	install_element(BGP_NODE, &bgp_always_compare_med_cli_cmd);
	install_element(BGP_NODE, &no_bgp_always_compare_med_cli_cmd);
	install_element(BGP_NODE, &bgp_lu_uses_explicit_null_cli_cmd);
	install_element(BGP_NODE, &bgp_reject_as_sets_cli_cmd);
	install_element(BGP_NODE, &no_bgp_reject_as_sets_cli_cmd);
	install_element(BGP_NODE, &bgp_client_to_client_reflection_cli_cmd);
	install_element(BGP_NODE, &no_bgp_client_to_client_reflection_cli_cmd);
	install_element(BGP_NODE, &bgp_disable_connected_route_check_cli_cmd);
	install_element(BGP_NODE, &no_bgp_disable_connected_route_check_cli_cmd);

	install_element(BGP_NODE, &bgp_bestpath_aspath_ignore_cli_cmd);
	install_element(BGP_NODE, &no_bgp_bestpath_aspath_ignore_cli_cmd);
	install_element(BGP_NODE, &bgp_bestpath_aspath_confed_cli_cmd);
	install_element(BGP_NODE, &no_bgp_bestpath_aspath_confed_cli_cmd);
	install_element(BGP_NODE, &bgp_bestpath_aspath_multipath_relax_cli_cmd);
	install_element(BGP_NODE, &no_bgp_bestpath_aspath_multipath_relax_cli_cmd);
	install_element(BGP_NODE, &bgp_bestpath_compare_router_id_cli_cmd);
	install_element(BGP_NODE, &no_bgp_bestpath_compare_router_id_cli_cmd);
	install_element(BGP_NODE, &bgp_bestpath_use_imported_attrs_cli_cmd);
	install_element(BGP_NODE, &bgp_bestpath_med_cli_cmd);
	install_element(BGP_NODE, &no_bgp_bestpath_med_cli_cmd);
	install_element(BGP_NODE, &bgp_bestpath_peer_type_multipath_relax_cli_cmd);
	install_element(BGP_NODE, &no_bgp_bestpath_peer_type_multipath_relax_cli_cmd);
	install_element(BGP_NODE, &bgp_bestpath_bw_cli_cmd);
	install_element(BGP_NODE, &no_bgp_bestpath_bw_cli_cmd);

	install_element(BGP_NODE, &bgp_default_afi_safi_cli_cmd);

	install_element(BGP_NODE, &bgp_default_local_preference_cli_cmd);
	install_element(BGP_NODE, &no_bgp_default_local_preference_cli_cmd);
	install_element(BGP_NODE, &bgp_default_subgroup_pkt_queue_max_cli_cmd);
	install_element(BGP_NODE, &no_bgp_default_subgroup_pkt_queue_max_cli_cmd);

	install_element(BGP_NODE, &bgp_maxmed_onstartup_cli_cmd);
	install_element(BGP_NODE, &no_bgp_maxmed_onstartup_cli_cmd);
	install_element(BGP_NODE, &bgp_maxmed_admin_cli_cmd);
	install_element(BGP_NODE, &no_bgp_maxmed_admin_cli_cmd);
	install_element(BGP_NODE, &bgp_confederation_identifier_cli_cmd);
	install_element(BGP_NODE, &no_bgp_confederation_identifier_cli_cmd);
	install_element(BGP_NODE, &bgp_confederation_peers_cli_cmd);
	install_element(BGP_NODE, &no_bgp_confederation_peers_cli_cmd);
	install_element(BGP_NODE, &bgp_tcp_keepalive_cli_cmd);
	install_element(BGP_NODE, &no_bgp_tcp_keepalive_cli_cmd);

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
