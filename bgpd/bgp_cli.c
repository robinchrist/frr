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
 * Milestone 2 batch B10: 'bgp suppress-fib-pending' (process + instance
 * pair). Fresh grep of bgp_vty.c/bgpd.c confirms no mutual-exclusion guard
 * exists between the two scopes: bm_wait_for_fib_set() (process,
 * bm->wait_for_fib) and bgp_suppress_fib_pending_set() (instance,
 * BGP_FLAG_SUPPRESS_FIB_PENDING) are independent setters with no
 * cross-check against each other's state in either direction, and
 * BGP_SUPPRESS_FIB_ENABLED(bgp) (bgpd.h) simply ORs the two together at
 * every use site -- both can be configured simultaneously today with no
 * error and no precedence rule beyond that OR. Converted as-is: no new
 * guard is introduced.
 *
 * 'enabled' is a static default-off boolean with a legacy positive-only
 * emission (no <cmd> deletes back to the false default, same shape as
 * 'bgp always-compare-med'); 'advertisement-delay' is a static
 * default-on scalar (YANG default 1000 == BGP_DEFAULT_SUPPRESS_FIB_ADV_DELAY,
 * same shape as 'bgp default local-preference'). Both leaves are set/reset
 * together off the single legacy "[no] bgp suppress-fib-pending
 * [(0-10000)$delay]" grammar, same shape as 'bgp max-med administrative'.
 */
DEFPY_YANG(
	bgp_global_suppress_fib_pending, bgp_global_suppress_fib_pending_cli_cmd,
	"bgp suppress-fib-pending [(0-10000)$delay]",
	BGP_STR
	"Advertise only routes that are programmed in kernel to peers globally\n"
	"Advertisement delay in milliseconds after FIB installation (default 1000)\n")
{
	nb_cli_enqueue_change(vty, "/proteus-bgp:process/suppress-fib-pending/enabled",
			      NB_OP_MODIFY, "true");
	if (delay_str)
		nb_cli_enqueue_change(vty,
				      "/proteus-bgp:process/suppress-fib-pending/advertisement-delay",
				      NB_OP_MODIFY, delay_str);
	else
		nb_cli_enqueue_change(vty,
				      "/proteus-bgp:process/suppress-fib-pending/advertisement-delay",
				      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_global_suppress_fib_pending, no_bgp_global_suppress_fib_pending_cli_cmd,
	"no bgp suppress-fib-pending [(0-10000)]",
	NO_STR
	BGP_STR
	"Advertise only routes that are programmed in kernel to peers globally\n"
	"Advertisement delay in milliseconds after FIB installation (default 1000)\n")
{
	nb_cli_enqueue_change(vty, "/proteus-bgp:process/suppress-fib-pending/enabled",
			      NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "/proteus-bgp:process/suppress-fib-pending/advertisement-delay",
			      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_suppress_fib_pending, bgp_suppress_fib_pending_cli_cmd,
	"bgp suppress-fib-pending [(0-10000)$delay]",
	BGP_STR
	"Advertise only routes that are programmed in kernel to peers\n"
	"Advertisement delay in milliseconds after FIB installation (default 1000)\n")
{
	nb_cli_enqueue_change(vty, "./suppress-fib-pending/enabled", NB_OP_MODIFY, "true");
	if (delay_str)
		nb_cli_enqueue_change(vty, "./suppress-fib-pending/advertisement-delay",
				      NB_OP_MODIFY, delay_str);
	else
		nb_cli_enqueue_change(vty, "./suppress-fib-pending/advertisement-delay",
				      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_suppress_fib_pending, no_bgp_suppress_fib_pending_cli_cmd,
	"no bgp suppress-fib-pending [(0-10000)]",
	NO_STR
	BGP_STR
	"Advertise only routes that are programmed in kernel to peers\n"
	"Advertisement delay in milliseconds after FIB installation (default 1000)\n")
{
	nb_cli_enqueue_change(vty, "./suppress-fib-pending/enabled", NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./suppress-fib-pending/advertisement-delay", NB_OP_DESTROY,
			      NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/*
 * Milestone 2 batch B11: 'bgp update-delay'/'update-delay' and 'bgp
 * advertisement-delay'/'advertisement-delay' (process + instance pairs).
 *
 * update-delay has a strict bidirectional hard-error mutual exclusion
 * between the two scopes (bgp_global_update_delay_config_vty()/
 * bgp_update_delay_config_vty(), bgpd/bgp_vty.c): the process setter
 * refuses if any VRF has a non-default per-instance value, and the
 * instance setter refuses outright whenever the process-wide value is
 * non-default. Both directions are enforced in NB_EV_VALIDATE against the
 * live bm-> / bgp-> runtime state (bgp_nb_config.c), mirroring the legacy
 * checks exactly, not against the northbound candidate tree.
 *
 * advertisement-delay has NO such guard in legacy code -- deliberately
 * asymmetric vs. update-delay, not an oversight. This conversion does not
 * add one. Both leaves are enqueued together off a single legacy grammar,
 * same shape as the suppress-fib-pending pair above: the establish-wait
 * token is only ever a MODIFY when supplied, else DESTROY (absence means
 * "inherit the delay value", matching legacy's "!establish_wait" branch).
 */
DEFPY_YANG(
	bgp_global_update_delay, bgp_global_update_delay_cli_cmd,
	"bgp update-delay (0-3600)$delay [(1-3600)$wait]",
	BGP_STR
	"Force initial delay for best-path and updates for all bgp instances\n"
	"Max delay in seconds\n"
	"Establish wait in seconds\n")
{
	nb_cli_enqueue_change(vty, "/proteus-bgp:process/update-delay/delay", NB_OP_MODIFY,
			      delay_str);
	if (wait_str)
		nb_cli_enqueue_change(vty, "/proteus-bgp:process/update-delay/establish-wait",
				      NB_OP_MODIFY, wait_str);
	else
		nb_cli_enqueue_change(vty, "/proteus-bgp:process/update-delay/establish-wait",
				      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_global_update_delay, no_bgp_global_update_delay_cli_cmd,
	"no bgp update-delay [(0-3600) [(1-3600)]]",
	NO_STR
	BGP_STR
	"Force initial delay for best-path and updates\n"
	"Max delay in seconds\n"
	"Establish wait in seconds\n")
{
	nb_cli_enqueue_change(vty, "/proteus-bgp:process/update-delay/delay", NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "/proteus-bgp:process/update-delay/establish-wait",
			      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_update_delay, bgp_update_delay_cli_cmd,
	"update-delay (0-3600)$delay [(1-3600)$wait]",
	"Force initial delay for best-path and updates\n"
	"Max delay in seconds\n"
	"Establish wait in seconds\n")
{
	nb_cli_enqueue_change(vty, "./update-delay/delay", NB_OP_MODIFY, delay_str);
	if (wait_str)
		nb_cli_enqueue_change(vty, "./update-delay/establish-wait", NB_OP_MODIFY, wait_str);
	else
		nb_cli_enqueue_change(vty, "./update-delay/establish-wait", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_update_delay, no_bgp_update_delay_cli_cmd,
	"no update-delay [(0-3600) [(1-3600)]]",
	NO_STR
	"Force initial delay for best-path and updates\n"
	"Max delay in seconds\n"
	"Establish wait in seconds\n")
{
	nb_cli_enqueue_change(vty, "./update-delay/delay", NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./update-delay/establish-wait", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_global_advertisement_delay, bgp_global_advertisement_delay_cli_cmd,
	"bgp advertisement-delay (1-3600)$delay",
	BGP_STR
	"Hold route advertisements to peers for configured seconds after first peer establishes\n"
	"Delay in seconds\n")
{
	nb_cli_enqueue_change(vty, "/proteus-bgp:process/advertisement-delay", NB_OP_MODIFY,
			      delay_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_global_advertisement_delay, no_bgp_global_advertisement_delay_cli_cmd,
	"no bgp advertisement-delay [(1-3600)]",
	NO_STR
	BGP_STR
	"Hold route advertisements to peers for configured seconds after first peer establishes\n"
	"Delay in seconds\n")
{
	nb_cli_enqueue_change(vty, "/proteus-bgp:process/advertisement-delay", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_advertisement_delay, bgp_advertisement_delay_cli_cmd,
	"advertisement-delay (1-3600)$delay",
	"Hold route advertisements to peers for configured seconds after first peer establishes\n"
	"Delay in seconds\n")
{
	nb_cli_enqueue_change(vty, "./advertisement-delay", NB_OP_MODIFY, delay_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_advertisement_delay, no_bgp_advertisement_delay_cli_cmd,
	"no advertisement-delay [(1-3600)]",
	NO_STR
	"Hold route advertisements to peers for configured seconds after first peer establishes\n"
	"Delay in seconds\n")
{
	nb_cli_enqueue_change(vty, "./advertisement-delay", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/*
 * Milestone 2 batch B12: 'bgp graceful-shutdown' (process + instance
 * pair). Legacy is a single dual-purpose DEFUN (bgp_graceful_shutdown_cmd /
 * no_bgp_graceful_shutdown_cmd, bgpd/bgp_vty.c) installed identically at
 * both CONFIG_NODE and BGP_NODE and branching on vty->node -- split here
 * into two independent DEFPY_YANG pairs (same "bgp graceful-shutdown"
 * grammar at both nodes, same as legacy), one per scope, each with its own
 * fixed target xpath. The strict bidirectional mutual-exclusion guard is
 * enforced in NB_EV_VALIDATE in bgp_nb_config.c, reading the live bm-> /
 * bgp-> runtime state. Both leaves carry a YANG default (false), so the
 * no-form maps to NB_OP_DESTROY same as suppress-fib-pending's 'enabled'
 * (B10) -- there is no separate no-form callback since DESTROY is
 * schema-invalid for a default-bearing leaf; northbound instead redelivers
 * it as a MODIFY of the default value to the single .modify callback.
 */
DEFPY_YANG(
	bgp_global_graceful_shutdown, bgp_global_graceful_shutdown_cli_cmd,
	"bgp graceful-shutdown",
	BGP_STR
	"Graceful shutdown parameters\n")
{
	nb_cli_enqueue_change(vty, "/proteus-bgp:process/graceful-shutdown", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_global_graceful_shutdown, no_bgp_global_graceful_shutdown_cli_cmd,
	"no bgp graceful-shutdown",
	NO_STR
	BGP_STR
	"Graceful shutdown parameters\n")
{
	nb_cli_enqueue_change(vty, "/proteus-bgp:process/graceful-shutdown", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_graceful_shutdown, bgp_graceful_shutdown_cli_cmd,
	"bgp graceful-shutdown",
	BGP_STR
	"Graceful shutdown parameters\n")
{
	nb_cli_enqueue_change(vty, "./graceful-shutdown", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_graceful_shutdown, no_bgp_graceful_shutdown_cli_cmd,
	"no bgp graceful-shutdown",
	NO_STR
	BGP_STR
	"Graceful shutdown parameters\n")
{
	nb_cli_enqueue_change(vty, "./graceful-shutdown", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/*
 * Milestone 2 batch B13: 'bgp graceful-restart'/'bgp graceful-restart-disable'
 * mode (process + instance pair) and 'bgp graceful-restart preserve-fw-state'
 * (process + instance pair). Legacy is two dual-purpose DEFUN pairs
 * (bgp_graceful_restart_cmd/no_bgp_graceful_restart_cmd,
 * bgp_graceful_restart_disable_cmd/no_bgp_graceful_restart_disable_cmd) plus
 * a third (bgp_graceful_restart_preserve_fw_cmd/no_...), each installed
 * identically at both CONFIG_NODE and BGP_NODE and branching on vty->node --
 * split here into independent DEFPY_YANG pairs per scope, same grammar as
 * legacy (including the GR_CMD/NO_GR_CMD/GR_DISABLE/NO_GR_DISABLE help
 * strings from lib/command.h).
 *
 * The mode leaf has no YANG default (absence == helper mode): both the
 * restarter and disable forms map their positive form to NB_OP_MODIFY of
 * the matching enum value, and their negative form to NB_OP_DESTROY --
 * which of the two legacy 'no' commands' asymmetric FSM behavior applies is
 * resolved from the *old* enum value in NB_EV_APPLY, not from which 'no'
 * command was typed (there is only one DESTROY entry point on this leaf);
 * see the mode modify/destroy callbacks in bgp_nb_config.c.
 *
 * preserve-fw-state carries a YANG default (false, Tier A), so its no-form
 * maps to NB_OP_DESTROY exactly like graceful-shutdown (B12) -- redelivered
 * as a MODIFY of the default value to the single .modify callback, no
 * separate destroy callback exists.
 */
DEFPY_YANG(
	bgp_global_graceful_restart, bgp_global_graceful_restart_cli_cmd,
	"bgp graceful-restart",
	BGP_STR
	GR_CMD)
{
	nb_cli_enqueue_change(vty, "/proteus-bgp:process/graceful-restart/mode", NB_OP_MODIFY,
			      "restarter");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_global_graceful_restart, no_bgp_global_graceful_restart_cli_cmd,
	"no bgp graceful-restart",
	NO_STR
	BGP_STR
	NO_GR_CMD)
{
	nb_cli_enqueue_change(vty, "/proteus-bgp:process/graceful-restart/mode", NB_OP_DESTROY,
			      NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_global_graceful_restart_disable, bgp_global_graceful_restart_disable_cli_cmd,
	"bgp graceful-restart-disable",
	BGP_STR
	GR_DISABLE)
{
	nb_cli_enqueue_change(vty, "/proteus-bgp:process/graceful-restart/mode", NB_OP_MODIFY,
			      "disable");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_global_graceful_restart_disable, no_bgp_global_graceful_restart_disable_cli_cmd,
	"no bgp graceful-restart-disable",
	NO_STR
	BGP_STR
	NO_GR_DISABLE)
{
	nb_cli_enqueue_change(vty, "/proteus-bgp:process/graceful-restart/mode", NB_OP_DESTROY,
			      NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_global_graceful_restart_preserve_fw, bgp_global_graceful_restart_preserve_fw_cli_cmd,
	"bgp graceful-restart preserve-fw-state",
	BGP_STR
	"Graceful restart capability parameters\n"
	"Sets F-bit indication that fib is preserved while doing Graceful Restart\n")
{
	nb_cli_enqueue_change(vty, "/proteus-bgp:process/graceful-restart/preserve-fw-state",
			      NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_global_graceful_restart_preserve_fw,
	no_bgp_global_graceful_restart_preserve_fw_cli_cmd,
	"no bgp graceful-restart preserve-fw-state",
	NO_STR
	BGP_STR
	"Graceful restart capability parameters\n"
	"Unsets F-bit indication that fib is preserved while doing Graceful Restart\n")
{
	nb_cli_enqueue_change(vty, "/proteus-bgp:process/graceful-restart/preserve-fw-state",
			      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_graceful_restart, bgp_graceful_restart_cli_cmd,
	"bgp graceful-restart",
	BGP_STR
	GR_CMD)
{
	nb_cli_enqueue_change(vty, "./graceful-restart/mode", NB_OP_MODIFY, "restarter");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_graceful_restart, no_bgp_graceful_restart_cli_cmd,
	"no bgp graceful-restart",
	NO_STR
	BGP_STR
	NO_GR_CMD)
{
	nb_cli_enqueue_change(vty, "./graceful-restart/mode", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_graceful_restart_disable, bgp_graceful_restart_disable_cli_cmd,
	"bgp graceful-restart-disable",
	BGP_STR
	GR_DISABLE)
{
	nb_cli_enqueue_change(vty, "./graceful-restart/mode", NB_OP_MODIFY, "disable");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_graceful_restart_disable, no_bgp_graceful_restart_disable_cli_cmd,
	"no bgp graceful-restart-disable",
	NO_STR
	BGP_STR
	NO_GR_DISABLE)
{
	nb_cli_enqueue_change(vty, "./graceful-restart/mode", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_graceful_restart_preserve_fw, bgp_graceful_restart_preserve_fw_cli_cmd,
	"bgp graceful-restart preserve-fw-state",
	BGP_STR
	"Graceful restart capability parameters\n"
	"Sets F-bit indication that fib is preserved while doing Graceful Restart\n")
{
	nb_cli_enqueue_change(vty, "./graceful-restart/preserve-fw-state", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_graceful_restart_preserve_fw, no_bgp_graceful_restart_preserve_fw_cli_cmd,
	"no bgp graceful-restart preserve-fw-state",
	NO_STR
	BGP_STR
	"Graceful restart capability parameters\n"
	"Unsets F-bit indication that fib is preserved while doing Graceful Restart\n")
{
	nb_cli_enqueue_change(vty, "./graceful-restart/preserve-fw-state", NB_OP_DESTROY, NULL);
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
 * Milestone 2 batch B8: graceful-restart instance-only leaves
 * ('bgp long-lived-graceful-restart stale-time', 'bgp graceful-restart
 * notification'). Both installed at BGP_NODE, relative "./..." xpaths.
 */

DEFPY_YANG(
	bgp_llgr_stalepath_time, bgp_llgr_stalepath_time_cli_cmd,
	"bgp long-lived-graceful-restart stale-time (1-16777215)$stale_time",
	BGP_STR
	"Enable Long-lived Graceful Restart\n"
	"Specifies maximum time to wait before purging long-lived stale routes\n"
	"Stale time value (seconds)\n")
{
	nb_cli_enqueue_change(vty, "./long-lived-graceful-restart-stale-time", NB_OP_MODIFY,
			      stale_time_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_llgr_stalepath_time, no_bgp_llgr_stalepath_time_cli_cmd,
	"no bgp long-lived-graceful-restart stale-time [(1-16777215)]",
	NO_STR BGP_STR
	"Enable Long-lived Graceful Restart\n"
	"Specifies maximum time to wait before purging long-lived stale routes\n"
	"Stale time value (seconds)\n")
{
	nb_cli_enqueue_change(vty, "./long-lived-graceful-restart-stale-time", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/* Tri-state (profile-dependent FRR_CFG_DEFAULT_BOOL(BGP_GRACEFUL_NOTIFICATION)):
 * legacy bgp_config_write() diffs against SAVE_BGP_GRACEFUL_NOTIFICATION to
 * decide whether to emit the bare '[no] bgp graceful-restart notification'
 * line, so this leaf has no YANG default and follows the tri-state
 * enabled|disabled scheme (see instance_log_neighbor_changes above): the
 * canonical form is presence-based (cli_show always emits an explicit
 * value), and the pre-existing bare grammar is kept as deprecated aliases
 * so configs saved before this leaf grew the enabled|disabled grammar keep
 * loading with their original meaning.
 */
DEFPY_YANG(
	bgp_graceful_restart_notification, bgp_graceful_restart_notification_cli_cmd,
	"bgp graceful-restart notification <enabled|disabled>$mode",
	BGP_STR
	"Graceful restart capability parameters\n"
	"Indicate Graceful Restart support for BGP NOTIFICATION messages\n"
	"Enable Graceful Restart Notification support\n"
	"Disable Graceful Restart Notification support\n")
{
	nb_cli_enqueue_change(vty, "./graceful-restart/notification", NB_OP_MODIFY,
			      strmatch(mode, "enabled") ? "true" : "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_graceful_restart_notification, no_bgp_graceful_restart_notification_cli_cmd,
	"no bgp graceful-restart notification <enabled|disabled>$mode",
	NO_STR BGP_STR
	"Graceful restart capability parameters\n"
	"Indicate Graceful Restart support for BGP NOTIFICATION messages\n"
	"Enable Graceful Restart Notification support\n"
	"Disable Graceful Restart Notification support\n")
{
	nb_cli_enqueue_change(vty, "./graceful-restart/notification", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_ATTR(
	bgp_graceful_restart_notification_deprecated,
	bgp_graceful_restart_notification_deprecated_cli_cmd,
	"bgp graceful-restart notification",
	BGP_STR
	"Graceful restart capability parameters\n"
	"Indicate Graceful Restart support for BGP NOTIFICATION messages\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	nb_cli_enqueue_change(vty, "./graceful-restart/notification", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_ATTR(
	no_bgp_graceful_restart_notification_deprecated,
	no_bgp_graceful_restart_notification_deprecated_cli_cmd,
	"no bgp graceful-restart notification",
	NO_STR
	BGP_STR
	"Graceful restart capability parameters\n"
	"Indicate Graceful Restart support for BGP NOTIFICATION messages\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	nb_cli_enqueue_change(vty, "./graceful-restart/notification", NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

/*
 * Milestone 2 batch B9: the 13 (14-xpath, software-version-capability
 * splits into two leaves) profile-dependent tri-state booleans.
 *
 * Every one of these leaves is tri-state for the same reason as
 * log-neighbor-changes/graceful-restart-notification above: the legacy
 * bgp_config_write() diffs the flag against a SAVE_BGP_* macro
 * (FRR_CFG_DEFAULT_BOOL profile/version table, see bgp_vty.c) and emits
 * either the bare command or its 'no' form whenever the live value differs
 * from what the *current* FRR build would pick by default, so there is no
 * single static YANG default that could replace that logic. Each leaf
 * therefore has no YANG default, follows the canonical
 * '<cmd> <enabled|disabled>' / 'no <cmd> <enabled|disabled>' scheme
 * (MODIFY true/false, DESTROY restores the DFLT_BGP_* profile default via a
 * bgp_<leaf>_default() wrapper in bgp_vty.c/bgp_vty.h), and keeps the old
 * bare grammar as deprecated aliases (bare positive -> MODIFY "true", bare
 * 'no' -> MODIFY "false", not DESTROY, since that is what the legacy
 * negative form actually persisted).
 *
 * route-reflector-allow-outbound-policy is folded into this scheme even
 * though its FRR_CFG_DEFAULT_BOOL table entry never varies by
 * profile/version (always {false}): bgp_config_write() still diffs it
 * against SAVE_BGP_RR_ALLOW_OUTBOUND_POLICY using the exact same idiom as
 * the profile-dependent leaves, so it is classified as tri-state on the
 * emission-idiom evidence, not on whether the default happens to vary
 * today.
 *
 * deterministic-med additionally carries the legacy addpath-dmed
 * NB_EV_VALIDATE rejection; see instance_deterministic_med_validate_disable()
 * in bgp_nb_config.c for the design note on why that check is safe to run
 * at VALIDATE despite VALIDATE having no guaranteed bgp struct.
 */

DEFPY_YANG(
	bgp_ebgp_requires_policy, bgp_ebgp_requires_policy_cli_cmd,
	"bgp ebgp-requires-policy <enabled|disabled>$mode",
	BGP_STR
	"Require in and out policy for eBGP peers (RFC8212)\n"
	"Enable required in/out policy for eBGP peers\n"
	"Disable required in/out policy for eBGP peers\n")
{
	nb_cli_enqueue_change(vty, "./ebgp-requires-policy", NB_OP_MODIFY,
			      strmatch(mode, "enabled") ? "true" : "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_ebgp_requires_policy, no_bgp_ebgp_requires_policy_cli_cmd,
	"no bgp ebgp-requires-policy <enabled|disabled>$mode",
	NO_STR BGP_STR
	"Require in and out policy for eBGP peers (RFC8212)\n"
	"Enable required in/out policy for eBGP peers\n"
	"Disable required in/out policy for eBGP peers\n")
{
	nb_cli_enqueue_change(vty, "./ebgp-requires-policy", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_ATTR(
	bgp_ebgp_requires_policy_deprecated, bgp_ebgp_requires_policy_deprecated_cli_cmd,
	"bgp ebgp-requires-policy",
	BGP_STR
	"Require in and out policy for eBGP peers (RFC8212)\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	nb_cli_enqueue_change(vty, "./ebgp-requires-policy", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_ATTR(
	no_bgp_ebgp_requires_policy_deprecated, no_bgp_ebgp_requires_policy_deprecated_cli_cmd,
	"no bgp ebgp-requires-policy",
	NO_STR
	BGP_STR
	"Require in and out policy for eBGP peers (RFC8212)\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	nb_cli_enqueue_change(vty, "./ebgp-requires-policy", NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_enforce_first_as, bgp_enforce_first_as_cli_cmd,
	"bgp enforce-first-as <enabled|disabled>$mode",
	BGP_STR
	"Enforce the first AS for EBGP routes\n"
	"Enable enforcing the first AS for EBGP routes\n"
	"Disable enforcing the first AS for EBGP routes\n")
{
	nb_cli_enqueue_change(vty, "./enforce-first-as", NB_OP_MODIFY,
			      strmatch(mode, "enabled") ? "true" : "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_enforce_first_as, no_bgp_enforce_first_as_cli_cmd,
	"no bgp enforce-first-as <enabled|disabled>$mode",
	NO_STR BGP_STR
	"Enforce the first AS for EBGP routes\n"
	"Enable enforcing the first AS for EBGP routes\n"
	"Disable enforcing the first AS for EBGP routes\n")
{
	nb_cli_enqueue_change(vty, "./enforce-first-as", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_ATTR(
	bgp_enforce_first_as_deprecated, bgp_enforce_first_as_deprecated_cli_cmd,
	"bgp enforce-first-as",
	BGP_STR
	"Enforce the first AS for EBGP routes\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	nb_cli_enqueue_change(vty, "./enforce-first-as", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_ATTR(
	no_bgp_enforce_first_as_deprecated, no_bgp_enforce_first_as_deprecated_cli_cmd,
	"no bgp enforce-first-as",
	NO_STR
	BGP_STR
	"Enforce the first AS for EBGP routes\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	nb_cli_enqueue_change(vty, "./enforce-first-as", NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_suppress_duplicates, bgp_suppress_duplicates_cli_cmd,
	"bgp suppress-duplicates <enabled|disabled>$mode",
	BGP_STR
	"Suppress duplicate updates if the route actually not changed\n"
	"Enable suppressing duplicate updates\n"
	"Disable suppressing duplicate updates\n")
{
	nb_cli_enqueue_change(vty, "./suppress-duplicates", NB_OP_MODIFY,
			      strmatch(mode, "enabled") ? "true" : "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_suppress_duplicates, no_bgp_suppress_duplicates_cli_cmd,
	"no bgp suppress-duplicates <enabled|disabled>$mode",
	NO_STR BGP_STR
	"Suppress duplicate updates if the route actually not changed\n"
	"Enable suppressing duplicate updates\n"
	"Disable suppressing duplicate updates\n")
{
	nb_cli_enqueue_change(vty, "./suppress-duplicates", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_ATTR(
	bgp_suppress_duplicates_deprecated, bgp_suppress_duplicates_deprecated_cli_cmd,
	"bgp suppress-duplicates",
	BGP_STR
	"Suppress duplicate updates if the route actually not changed\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	nb_cli_enqueue_change(vty, "./suppress-duplicates", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_ATTR(
	no_bgp_suppress_duplicates_deprecated, no_bgp_suppress_duplicates_deprecated_cli_cmd,
	"no bgp suppress-duplicates",
	NO_STR
	BGP_STR
	"Suppress duplicate updates if the route actually not changed\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	nb_cli_enqueue_change(vty, "./suppress-duplicates", NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_administrative_reset, bgp_administrative_reset_cli_cmd,
	"bgp hard-administrative-reset <enabled|disabled>$mode",
	BGP_STR
	"Send Hard Reset CEASE Notification for 'Administrative Reset'\n"
	"Enable Hard Reset CEASE Notification\n"
	"Disable Hard Reset CEASE Notification\n")
{
	nb_cli_enqueue_change(vty, "./hard-administrative-reset", NB_OP_MODIFY,
			      strmatch(mode, "enabled") ? "true" : "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_administrative_reset, no_bgp_administrative_reset_cli_cmd,
	"no bgp hard-administrative-reset <enabled|disabled>$mode",
	NO_STR BGP_STR
	"Send Hard Reset CEASE Notification for 'Administrative Reset'\n"
	"Enable Hard Reset CEASE Notification\n"
	"Disable Hard Reset CEASE Notification\n")
{
	nb_cli_enqueue_change(vty, "./hard-administrative-reset", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_ATTR(
	bgp_administrative_reset_deprecated, bgp_administrative_reset_deprecated_cli_cmd,
	"bgp hard-administrative-reset",
	BGP_STR
	"Send Hard Reset CEASE Notification for 'Administrative Reset'\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	nb_cli_enqueue_change(vty, "./hard-administrative-reset", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_ATTR(
	no_bgp_administrative_reset_deprecated, no_bgp_administrative_reset_deprecated_cli_cmd,
	"no bgp hard-administrative-reset",
	NO_STR
	BGP_STR
	"Send Hard Reset CEASE Notification for 'Administrative Reset'\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	nb_cli_enqueue_change(vty, "./hard-administrative-reset", NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_deterministic_med, bgp_deterministic_med_cli_cmd,
	"bgp deterministic-med <enabled|disabled>$mode",
	BGP_STR
	"Pick the best-MED path among paths advertised from the neighboring AS\n"
	"Enable deterministic-MED\n"
	"Disable deterministic-MED\n")
{
	nb_cli_enqueue_change(vty, "./deterministic-med", NB_OP_MODIFY,
			      strmatch(mode, "enabled") ? "true" : "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_deterministic_med, no_bgp_deterministic_med_cli_cmd,
	"no bgp deterministic-med <enabled|disabled>$mode",
	NO_STR BGP_STR
	"Pick the best-MED path among paths advertised from the neighboring AS\n"
	"Enable deterministic-MED\n"
	"Disable deterministic-MED\n")
{
	nb_cli_enqueue_change(vty, "./deterministic-med", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_ATTR(
	bgp_deterministic_med_deprecated, bgp_deterministic_med_deprecated_cli_cmd,
	"bgp deterministic-med",
	BGP_STR
	"Pick the best-MED path among paths advertised from the neighboring AS\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	nb_cli_enqueue_change(vty, "./deterministic-med", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_ATTR(
	no_bgp_deterministic_med_deprecated, no_bgp_deterministic_med_deprecated_cli_cmd,
	"no bgp deterministic-med",
	NO_STR
	BGP_STR
	"Pick the best-MED path among paths advertised from the neighboring AS\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	nb_cli_enqueue_change(vty, "./deterministic-med", NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_network_import_check, bgp_network_import_check_cli_cmd,
	"bgp network import-check <enabled|disabled>$mode",
	BGP_STR
	"BGP network command\n"
	"Check BGP network route exists in IGP\n"
	"Enable checking BGP network route exists in IGP\n"
	"Disable checking BGP network route exists in IGP\n")
{
	nb_cli_enqueue_change(vty, "./network-import-check", NB_OP_MODIFY,
			      strmatch(mode, "enabled") ? "true" : "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_network_import_check, no_bgp_network_import_check_cli_cmd,
	"no bgp network import-check <enabled|disabled>$mode",
	NO_STR BGP_STR
	"BGP network command\n"
	"Check BGP network route exists in IGP\n"
	"Enable checking BGP network route exists in IGP\n"
	"Disable checking BGP network route exists in IGP\n")
{
	nb_cli_enqueue_change(vty, "./network-import-check", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_ATTR(
	bgp_network_import_check_deprecated, bgp_network_import_check_deprecated_cli_cmd,
	"bgp network import-check",
	BGP_STR
	"BGP network command\n"
	"Check BGP network route exists in IGP\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	nb_cli_enqueue_change(vty, "./network-import-check", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_ATTR(
	no_bgp_network_import_check_deprecated, no_bgp_network_import_check_deprecated_cli_cmd,
	"no bgp network import-check",
	NO_STR
	BGP_STR
	"BGP network command\n"
	"Check BGP network route exists in IGP\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	nb_cli_enqueue_change(vty, "./network-import-check", NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_bestpath_aigp, bgp_bestpath_aigp_cli_cmd,
	"bgp bestpath aigp <enabled|disabled>$mode",
	BGP_STR
	"Change the default bestpath selection\n"
	"Evaluate the AIGP attribute during the best path selection process\n"
	"Enable evaluating the AIGP attribute\n"
	"Disable evaluating the AIGP attribute\n")
{
	nb_cli_enqueue_change(vty, "./bestpath/aigp", NB_OP_MODIFY,
			      strmatch(mode, "enabled") ? "true" : "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_bestpath_aigp, no_bgp_bestpath_aigp_cli_cmd,
	"no bgp bestpath aigp <enabled|disabled>$mode",
	NO_STR BGP_STR
	"Change the default bestpath selection\n"
	"Evaluate the AIGP attribute during the best path selection process\n"
	"Enable evaluating the AIGP attribute\n"
	"Disable evaluating the AIGP attribute\n")
{
	nb_cli_enqueue_change(vty, "./bestpath/aigp", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_ATTR(
	bgp_bestpath_aigp_deprecated, bgp_bestpath_aigp_deprecated_cli_cmd,
	"bgp bestpath aigp",
	BGP_STR
	"Change the default bestpath selection\n"
	"Evaluate the AIGP attribute during the best path selection process\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	nb_cli_enqueue_change(vty, "./bestpath/aigp", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_ATTR(
	no_bgp_bestpath_aigp_deprecated, no_bgp_bestpath_aigp_deprecated_cli_cmd,
	"no bgp bestpath aigp",
	NO_STR
	BGP_STR
	"Change the default bestpath selection\n"
	"Evaluate the AIGP attribute during the best path selection process\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	nb_cli_enqueue_change(vty, "./bestpath/aigp", NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_default_show_hostname, bgp_default_show_hostname_cli_cmd,
	"bgp default show-hostname <enabled|disabled>$mode",
	BGP_STR
	"Configure BGP defaults\n"
	"Show hostname in certain command outputs\n"
	"Enable showing hostname\n"
	"Disable showing hostname\n")
{
	nb_cli_enqueue_change(vty, "./default/show-hostname", NB_OP_MODIFY,
			      strmatch(mode, "enabled") ? "true" : "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_default_show_hostname, no_bgp_default_show_hostname_cli_cmd,
	"no bgp default show-hostname <enabled|disabled>$mode",
	NO_STR BGP_STR
	"Configure BGP defaults\n"
	"Show hostname in certain command outputs\n"
	"Enable showing hostname\n"
	"Disable showing hostname\n")
{
	nb_cli_enqueue_change(vty, "./default/show-hostname", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_ATTR(
	bgp_default_show_hostname_deprecated, bgp_default_show_hostname_deprecated_cli_cmd,
	"bgp default show-hostname",
	BGP_STR
	"Configure BGP defaults\n"
	"Show hostname in certain command outputs\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	nb_cli_enqueue_change(vty, "./default/show-hostname", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_ATTR(
	no_bgp_default_show_hostname_deprecated, no_bgp_default_show_hostname_deprecated_cli_cmd,
	"no bgp default show-hostname",
	NO_STR
	BGP_STR
	"Configure BGP defaults\n"
	"Show hostname in certain command outputs\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	nb_cli_enqueue_change(vty, "./default/show-hostname", NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_default_show_nexthop_hostname, bgp_default_show_nexthop_hostname_cli_cmd,
	"bgp default show-nexthop-hostname <enabled|disabled>$mode",
	BGP_STR
	"Configure BGP defaults\n"
	"Show hostname for nexthop in certain command outputs\n"
	"Enable showing nexthop hostname\n"
	"Disable showing nexthop hostname\n")
{
	nb_cli_enqueue_change(vty, "./default/show-nexthop-hostname", NB_OP_MODIFY,
			      strmatch(mode, "enabled") ? "true" : "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_default_show_nexthop_hostname, no_bgp_default_show_nexthop_hostname_cli_cmd,
	"no bgp default show-nexthop-hostname <enabled|disabled>$mode",
	NO_STR BGP_STR
	"Configure BGP defaults\n"
	"Show hostname for nexthop in certain command outputs\n"
	"Enable showing nexthop hostname\n"
	"Disable showing nexthop hostname\n")
{
	nb_cli_enqueue_change(vty, "./default/show-nexthop-hostname", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_ATTR(
	bgp_default_show_nexthop_hostname_deprecated,
	bgp_default_show_nexthop_hostname_deprecated_cli_cmd,
	"bgp default show-nexthop-hostname",
	BGP_STR
	"Configure BGP defaults\n"
	"Show hostname for nexthop in certain command outputs\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	nb_cli_enqueue_change(vty, "./default/show-nexthop-hostname", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_ATTR(
	no_bgp_default_show_nexthop_hostname_deprecated,
	no_bgp_default_show_nexthop_hostname_deprecated_cli_cmd,
	"no bgp default show-nexthop-hostname",
	NO_STR
	BGP_STR
	"Configure BGP defaults\n"
	"Show hostname for nexthop in certain command outputs\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	nb_cli_enqueue_change(vty, "./default/show-nexthop-hostname", NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

/* software-version-capability carries two independent flag bits
 * (BGP_FLAG_SOFT_VERSION_CAPABILITY_OLD/_NEW) selected by the legacy
 * grammar's optional 'latest-encoding' token; the YANG model keeps that
 * distinction as two separate leaves rather than collapsing it, so the
 * canonical/deprecated commands below come in two families, one per leaf.
 */
DEFPY_YANG(
	bgp_default_software_version_capability, bgp_default_software_version_capability_cli_cmd,
	"bgp default software-version-capability <enabled|disabled>$mode",
	BGP_STR
	"Configure BGP defaults\n"
	"Advertise software version capability for all neighbors\n"
	"Enable advertising software version capability\n"
	"Disable advertising software version capability\n")
{
	nb_cli_enqueue_change(vty, "./default/software-version-capability", NB_OP_MODIFY,
			      strmatch(mode, "enabled") ? "true" : "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_default_software_version_capability,
	no_bgp_default_software_version_capability_cli_cmd,
	"no bgp default software-version-capability <enabled|disabled>$mode",
	NO_STR BGP_STR
	"Configure BGP defaults\n"
	"Advertise software version capability for all neighbors\n"
	"Enable advertising software version capability\n"
	"Disable advertising software version capability\n")
{
	nb_cli_enqueue_change(vty, "./default/software-version-capability", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_default_software_version_capability_latest_encoding,
	bgp_default_software_version_capability_latest_encoding_cli_cmd,
	"bgp default software-version-capability latest-encoding <enabled|disabled>$mode",
	BGP_STR
	"Configure BGP defaults\n"
	"Advertise software version capability for all neighbors\n"
	"Use the latest-encoding defined in draft-abraitis-bgp-version-capability-15\n"
	"Enable the latest-encoding software version capability\n"
	"Disable the latest-encoding software version capability\n")
{
	nb_cli_enqueue_change(vty, "./default/software-version-capability-latest-encoding",
			      NB_OP_MODIFY, strmatch(mode, "enabled") ? "true" : "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_default_software_version_capability_latest_encoding,
	no_bgp_default_software_version_capability_latest_encoding_cli_cmd,
	"no bgp default software-version-capability latest-encoding <enabled|disabled>$mode",
	NO_STR BGP_STR
	"Configure BGP defaults\n"
	"Advertise software version capability for all neighbors\n"
	"Use the latest-encoding defined in draft-abraitis-bgp-version-capability-15\n"
	"Enable the latest-encoding software version capability\n"
	"Disable the latest-encoding software version capability\n")
{
	nb_cli_enqueue_change(vty, "./default/software-version-capability-latest-encoding",
			      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/* Deprecated bare alias: replicates the legacy single-DEFPY grammar
 * '[no] bgp default software-version-capability [latest-encoding]' exactly,
 * routing to whichever of the two leaves the optional token selects.
 */
DEFPY_ATTR(
	bgp_default_software_version_capability_deprecated,
	bgp_default_software_version_capability_deprecated_cli_cmd,
	"bgp default software-version-capability [latest-encoding$latest_encoding]",
	BGP_STR
	"Configure BGP defaults\n"
	"Advertise software version capability for all neighbors\n"
	"Use the latest-encoding defined in draft-abraitis-bgp-version-capability-15\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	nb_cli_enqueue_change(vty,
			      latest_encoding
				      ? "./default/software-version-capability-latest-encoding"
				      : "./default/software-version-capability",
			      NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_ATTR(
	no_bgp_default_software_version_capability_deprecated,
	no_bgp_default_software_version_capability_deprecated_cli_cmd,
	"no bgp default software-version-capability [latest-encoding$latest_encoding]",
	NO_STR
	BGP_STR
	"Configure BGP defaults\n"
	"Advertise software version capability for all neighbors\n"
	"Use the latest-encoding defined in draft-abraitis-bgp-version-capability-15\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	nb_cli_enqueue_change(vty,
			      latest_encoding
				      ? "./default/software-version-capability-latest-encoding"
				      : "./default/software-version-capability",
			      NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_default_link_local_capability, bgp_default_link_local_capability_cli_cmd,
	"bgp default link-local-capability <enabled|disabled>$mode",
	BGP_STR
	"Configure BGP defaults\n"
	"Advertise Link-Local Next Hop capability for all neighbors\n"
	"Enable advertising Link-Local Next Hop capability\n"
	"Disable advertising Link-Local Next Hop capability\n")
{
	nb_cli_enqueue_change(vty, "./default/link-local-capability", NB_OP_MODIFY,
			      strmatch(mode, "enabled") ? "true" : "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_default_link_local_capability, no_bgp_default_link_local_capability_cli_cmd,
	"no bgp default link-local-capability <enabled|disabled>$mode",
	NO_STR BGP_STR
	"Configure BGP defaults\n"
	"Advertise Link-Local Next Hop capability for all neighbors\n"
	"Enable advertising Link-Local Next Hop capability\n"
	"Disable advertising Link-Local Next Hop capability\n")
{
	nb_cli_enqueue_change(vty, "./default/link-local-capability", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_ATTR(
	bgp_default_link_local_capability_deprecated,
	bgp_default_link_local_capability_deprecated_cli_cmd,
	"bgp default link-local-capability",
	BGP_STR
	"Configure BGP defaults\n"
	"Advertise Link-Local Next Hop capability for all neighbors\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	nb_cli_enqueue_change(vty, "./default/link-local-capability", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_ATTR(
	no_bgp_default_link_local_capability_deprecated,
	no_bgp_default_link_local_capability_deprecated_cli_cmd,
	"no bgp default link-local-capability",
	NO_STR
	BGP_STR
	"Configure BGP defaults\n"
	"Advertise Link-Local Next Hop capability for all neighbors\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	nb_cli_enqueue_change(vty, "./default/link-local-capability", NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_default_dynamic_capability, bgp_default_dynamic_capability_cli_cmd,
	"bgp default dynamic-capability <enabled|disabled>$mode",
	BGP_STR
	"Configure BGP defaults\n"
	"Advertise dynamic capability for all neighbors\n"
	"Enable advertising dynamic capability\n"
	"Disable advertising dynamic capability\n")
{
	nb_cli_enqueue_change(vty, "./default/dynamic-capability", NB_OP_MODIFY,
			      strmatch(mode, "enabled") ? "true" : "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_default_dynamic_capability, no_bgp_default_dynamic_capability_cli_cmd,
	"no bgp default dynamic-capability <enabled|disabled>$mode",
	NO_STR BGP_STR
	"Configure BGP defaults\n"
	"Advertise dynamic capability for all neighbors\n"
	"Enable advertising dynamic capability\n"
	"Disable advertising dynamic capability\n")
{
	nb_cli_enqueue_change(vty, "./default/dynamic-capability", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_ATTR(
	bgp_default_dynamic_capability_deprecated, bgp_default_dynamic_capability_deprecated_cli_cmd,
	"bgp default dynamic-capability",
	BGP_STR
	"Configure BGP defaults\n"
	"Advertise dynamic capability for all neighbors\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	nb_cli_enqueue_change(vty, "./default/dynamic-capability", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_ATTR(
	no_bgp_default_dynamic_capability_deprecated,
	no_bgp_default_dynamic_capability_deprecated_cli_cmd,
	"no bgp default dynamic-capability",
	NO_STR
	BGP_STR
	"Configure BGP defaults\n"
	"Advertise dynamic capability for all neighbors\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	nb_cli_enqueue_change(vty, "./default/dynamic-capability", NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_rr_allow_outbound_policy, bgp_rr_allow_outbound_policy_cli_cmd,
	"bgp route-reflector allow-outbound-policy <enabled|disabled>$mode",
	BGP_STR
	"Allow modifications made by out route-map\n"
	"on ibgp neighbors\n"
	"Enable allowing out route-map modifications on ibgp neighbors\n"
	"Disable allowing out route-map modifications on ibgp neighbors\n")
{
	nb_cli_enqueue_change(vty, "./route-reflector-allow-outbound-policy", NB_OP_MODIFY,
			      strmatch(mode, "enabled") ? "true" : "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_rr_allow_outbound_policy, no_bgp_rr_allow_outbound_policy_cli_cmd,
	"no bgp route-reflector allow-outbound-policy <enabled|disabled>$mode",
	NO_STR BGP_STR
	"Allow modifications made by out route-map\n"
	"on ibgp neighbors\n"
	"Enable allowing out route-map modifications on ibgp neighbors\n"
	"Disable allowing out route-map modifications on ibgp neighbors\n")
{
	nb_cli_enqueue_change(vty, "./route-reflector-allow-outbound-policy", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_ATTR(
	bgp_rr_allow_outbound_policy_deprecated, bgp_rr_allow_outbound_policy_deprecated_cli_cmd,
	"bgp route-reflector allow-outbound-policy",
	BGP_STR
	"Allow modifications made by out route-map\n"
	"on ibgp neighbors\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	nb_cli_enqueue_change(vty, "./route-reflector-allow-outbound-policy", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_ATTR(
	no_bgp_rr_allow_outbound_policy_deprecated,
	no_bgp_rr_allow_outbound_policy_deprecated_cli_cmd,
	"no bgp route-reflector allow-outbound-policy",
	NO_STR
	BGP_STR
	"Allow modifications made by out route-map\n"
	"on ibgp neighbors\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	nb_cli_enqueue_change(vty, "./route-reflector-allow-outbound-policy", NB_OP_MODIFY,
			      "false");
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

/* Joint emission of 'bgp suppress-fib-pending [(0-10000)]', per-instance
 * form (batch B10): same guarded-container shape as
 * process_suppress_fib_pending_cli_write above, one leading space since
 * it's nested inside the 'router bgp' block.
 */
static void instance_suppress_fib_pending_cli_write(struct vty *vty, const struct lyd_node *dnode,
						    bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, "enabled"))
		return;

	if (yang_dnode_get_uint16(dnode, "advertisement-delay") != 1000)
		vty_out(vty, " bgp suppress-fib-pending %u\n",
			yang_dnode_get_uint16(dnode, "advertisement-delay"));
	else
		vty_out(vty, " bgp suppress-fib-pending\n");
}

/* Joint emission of 'update-delay (0-3600) [(1-3600)]', per-instance form
 * (batch B11), mirroring bgp_config_write_update_delay() (bgpd/bgp_vty.c)
 * exactly: presence-based (the leaf only exists when this scope was
 * explicitly configured -- the bidirectional VALIDATE guard makes that
 * mutually exclusive with the process-wide leaf ever being set at the same
 * time, so unlike legacy's "!= bm->v_update_delay" runtime comparison, a
 * plain presence check is sufficient and exact here), establish-wait only
 * printed when it differs from delay (absence means "inherits delay").
 */
static void instance_update_delay_cli_write(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults)
{
	uint16_t delay;

	if (!yang_dnode_exists(dnode, "delay"))
		return;

	delay = yang_dnode_get_uint16(dnode, "delay");
	vty_out(vty, " update-delay %u", delay);
	if (yang_dnode_exists(dnode, "establish-wait") &&
	    yang_dnode_get_uint16(dnode, "establish-wait") != delay)
		vty_out(vty, " %u", yang_dnode_get_uint16(dnode, "establish-wait"));
	vty_out(vty, "\n");
}

/* Emission of 'advertisement-delay (1-3600)', per-instance form (batch
 * B11). Legacy's bgp_config_write_advertisement_delay() additionally
 * suppresses the line when the (mirrored) value equals the process-wide
 * one -- a workaround for bgp->v_advertisement_delay being a single field
 * shared between explicit per-instance config and process-wide mirroring.
 * The northbound datastore tracks the two scopes as genuinely separate
 * leaves, so presence here is unambiguous; the one behavioral difference
 * from legacy is that an instance leaf explicitly set equal to the
 * process-wide value is printed here where legacy would suppress it (a
 * cosmetic difference only -- reloading either form yields the same
 * runtime state, and there is no guard against this combination in either
 * old or new code, see the no-mutual-exclusion note above).
 */
static void instance_advertisement_delay_cli_write(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults)
{
	if (yang_dnode_exists(dnode, NULL))
		vty_out(vty, " advertisement-delay %u\n", yang_dnode_get_uint16(dnode, NULL));
}

/* Batch B12: 'bgp graceful-shutdown', per-instance form. Static
 * default-off boolean, legacy positive-only emission (matches
 * bgp_config_write()'s "if (!CHECK_FLAG(bm->flags, BM_FLAG_GRACEFUL_
 * SHUTDOWN)) if (CHECK_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_SHUTDOWN)) ...";
 * the guard against the process-wide flag being set is a no-op here since
 * NB_EV_VALIDATE already refuses to let both be true at once, so a plain
 * value check reproduces the same emitted output).
 */
static void instance_graceful_shutdown_cli_write(struct vty *vty, const struct lyd_node *dnode,
						 bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp graceful-shutdown\n");
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

static void instance_long_lived_graceful_restart_stale_time_cli_write(struct vty *vty,
								      const struct lyd_node *dnode,
								      bool show_defaults)
{
	vty_out(vty, " bgp long-lived-graceful-restart stale-time %u\n",
		yang_dnode_get_uint32(dnode, NULL));
}

/* Tri-state, presence-based (see B8 DEFPY comment above): always emits an
 * explicit enabled|disabled value, never the legacy bare/negative form.
 */
static void instance_graceful_restart_notification_cli_write(struct vty *vty,
							     const struct lyd_node *dnode,
							     bool show_defaults)
{
	vty_out(vty, " bgp graceful-restart notification %s\n",
		yang_dnode_get_bool(dnode, NULL) ? "enabled" : "disabled");
}

/* Batch B13: 'bgp graceful-restart'/'bgp graceful-restart-disable' mode,
 * per-instance form. No YANG default (absence == helper mode, nothing
 * emitted -- matches legacy's config_write, which prints neither line when
 * bgp_global_gr_mode_get(bgp) == GLOBAL_HELPER); presence-based otherwise.
 * The leaf is only ever present in the datastore when a user configured
 * this exact per-instance command (process-wide mode changes mirror onto
 * bgp->global_gr_present_state directly, bypassing the northbound
 * datastore, so they never create this leaf) -- which is also why no extra
 * gating against the process-wide flags is needed here, unlike legacy's
 * config_write which explicitly gates on '!BM_FLAG_GR_CONFIGURED' for the
 * same reason expressed at the C-struct level instead.
 */
static void instance_graceful_restart_mode_cli_write(struct vty *vty, const struct lyd_node *dnode,
						     bool show_defaults)
{
	const char *mode = yang_dnode_get_string(dnode, NULL);

	if (strmatch(mode, "restarter"))
		vty_out(vty, " bgp graceful-restart\n");
	else if (strmatch(mode, "disable"))
		vty_out(vty, " bgp graceful-restart-disable\n");
}

/* Batch B13: 'bgp graceful-restart preserve-fw-state', per-instance form.
 * Static default-off boolean, legacy positive-only emission, same shape as
 * instance_graceful_shutdown_cli_write (B12) -- the gate against the
 * process-wide flag in legacy's config_write is likewise a no-op here for
 * the same datastore-presence reason as the mode leaf above.
 */
static void instance_graceful_restart_preserve_fw_state_cli_write(struct vty *vty,
								  const struct lyd_node *dnode,
								  bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp graceful-restart preserve-fw-state\n");
}

static void instance_ebgp_requires_policy_cli_write(struct vty *vty, const struct lyd_node *dnode,
						    bool show_defaults)
{
	vty_out(vty, " bgp ebgp-requires-policy %s\n",
		yang_dnode_get_bool(dnode, NULL) ? "enabled" : "disabled");
}

static void instance_enforce_first_as_cli_write(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults)
{
	vty_out(vty, " bgp enforce-first-as %s\n",
		yang_dnode_get_bool(dnode, NULL) ? "enabled" : "disabled");
}

static void instance_suppress_duplicates_cli_write(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults)
{
	vty_out(vty, " bgp suppress-duplicates %s\n",
		yang_dnode_get_bool(dnode, NULL) ? "enabled" : "disabled");
}

static void instance_hard_administrative_reset_cli_write(struct vty *vty,
							 const struct lyd_node *dnode,
							 bool show_defaults)
{
	vty_out(vty, " bgp hard-administrative-reset %s\n",
		yang_dnode_get_bool(dnode, NULL) ? "enabled" : "disabled");
}

static void instance_deterministic_med_cli_write(struct vty *vty, const struct lyd_node *dnode,
						 bool show_defaults)
{
	vty_out(vty, " bgp deterministic-med %s\n",
		yang_dnode_get_bool(dnode, NULL) ? "enabled" : "disabled");
}

static void instance_network_import_check_cli_write(struct vty *vty, const struct lyd_node *dnode,
						    bool show_defaults)
{
	vty_out(vty, " bgp network import-check %s\n",
		yang_dnode_get_bool(dnode, NULL) ? "enabled" : "disabled");
}

static void instance_bestpath_aigp_cli_write(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults)
{
	vty_out(vty, " bgp bestpath aigp %s\n",
		yang_dnode_get_bool(dnode, NULL) ? "enabled" : "disabled");
}

static void instance_default_show_hostname_cli_write(struct vty *vty, const struct lyd_node *dnode,
						     bool show_defaults)
{
	vty_out(vty, " bgp default show-hostname %s\n",
		yang_dnode_get_bool(dnode, NULL) ? "enabled" : "disabled");
}

static void instance_default_show_nexthop_hostname_cli_write(struct vty *vty,
							     const struct lyd_node *dnode,
							     bool show_defaults)
{
	vty_out(vty, " bgp default show-nexthop-hostname %s\n",
		yang_dnode_get_bool(dnode, NULL) ? "enabled" : "disabled");
}

static void instance_default_software_version_capability_cli_write(struct vty *vty,
								   const struct lyd_node *dnode,
								   bool show_defaults)
{
	vty_out(vty, " bgp default software-version-capability %s\n",
		yang_dnode_get_bool(dnode, NULL) ? "enabled" : "disabled");
}

static void instance_default_software_version_capability_latest_encoding_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " bgp default software-version-capability latest-encoding %s\n",
		yang_dnode_get_bool(dnode, NULL) ? "enabled" : "disabled");
}

static void instance_default_link_local_capability_cli_write(struct vty *vty,
							     const struct lyd_node *dnode,
							     bool show_defaults)
{
	vty_out(vty, " bgp default link-local-capability %s\n",
		yang_dnode_get_bool(dnode, NULL) ? "enabled" : "disabled");
}

static void instance_default_dynamic_capability_cli_write(struct vty *vty,
							  const struct lyd_node *dnode,
							  bool show_defaults)
{
	vty_out(vty, " bgp default dynamic-capability %s\n",
		yang_dnode_get_bool(dnode, NULL) ? "enabled" : "disabled");
}

static void instance_route_reflector_allow_outbound_policy_cli_write(struct vty *vty,
								     const struct lyd_node *dnode,
								     bool show_defaults)
{
	vty_out(vty, " bgp route-reflector allow-outbound-policy %s\n",
		yang_dnode_get_bool(dnode, NULL) ? "enabled" : "disabled");
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

/* Joint emission of 'bgp suppress-fib-pending [(0-10000)]', process-wide
 * form: registered on the "suppress-fib-pending" container so 'enabled'
 * and 'advertisement-delay' land on one line (batch B10), same
 * guarded-container shape as instance_max_med_administrative_cli_write.
 * 'enabled' has a YANG default (false), so it's value-checked, not merely
 * presence-checked; 'advertisement-delay' also carries a YANG default
 * (1000) and is value-checked against it, matching bgp_config_write()'s
 * "if (bm->suppress_fib_adv_delay != BGP_DEFAULT_SUPPRESS_FIB_ADV_DELAY)"
 * arm exactly.
 */
static void process_suppress_fib_pending_cli_write(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, "enabled"))
		return;

	if (yang_dnode_get_uint16(dnode, "advertisement-delay") != 1000)
		vty_out(vty, "bgp suppress-fib-pending %u\n",
			yang_dnode_get_uint16(dnode, "advertisement-delay"));
	else
		vty_out(vty, "bgp suppress-fib-pending\n");
}

/* Joint emission of 'bgp update-delay (0-3600) [(1-3600)]', process-wide
 * form (batch B11), same presence-based shape as
 * instance_update_delay_cli_write above -- no leading space, top level.
 */
static void process_update_delay_cli_write(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	uint16_t delay;

	if (!yang_dnode_exists(dnode, "delay"))
		return;

	delay = yang_dnode_get_uint16(dnode, "delay");
	vty_out(vty, "bgp update-delay %u", delay);
	if (yang_dnode_exists(dnode, "establish-wait") &&
	    yang_dnode_get_uint16(dnode, "establish-wait") != delay)
		vty_out(vty, " %u", yang_dnode_get_uint16(dnode, "establish-wait"));
	vty_out(vty, "\n");
}

/* Emission of 'bgp advertisement-delay (1-3600)', process-wide form
 * (batch B11), no leading space.
 */
static void process_advertisement_delay_cli_write(struct vty *vty, const struct lyd_node *dnode,
						  bool show_defaults)
{
	if (yang_dnode_exists(dnode, NULL))
		vty_out(vty, "bgp advertisement-delay %u\n", yang_dnode_get_uint16(dnode, NULL));
}

/* Batch B12: 'bgp graceful-shutdown', process-wide form. Same
 * value-checked shape as instance_graceful_shutdown_cli_write above, no
 * leading space (top-level, matches legacy's "if (CHECK_FLAG(bm->flags,
 * BM_FLAG_GRACEFUL_SHUTDOWN)) vty_out(vty, \"bgp graceful-shutdown\\n\")").
 */
static void process_graceful_shutdown_cli_write(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "bgp graceful-shutdown\n");
}

/* Batch B13: 'bgp graceful-restart'/'bgp graceful-restart-disable' mode,
 * process-wide form. Same presence-based shape as
 * instance_graceful_restart_mode_cli_write above, no leading space.
 */
static void process_graceful_restart_mode_cli_write(struct vty *vty, const struct lyd_node *dnode,
						    bool show_defaults)
{
	const char *mode = yang_dnode_get_string(dnode, NULL);

	if (strmatch(mode, "restarter"))
		vty_out(vty, "bgp graceful-restart\n");
	else if (strmatch(mode, "disable"))
		vty_out(vty, "bgp graceful-restart-disable\n");
}

/* Batch B13: 'bgp graceful-restart preserve-fw-state', process-wide form.
 * Same value-checked shape as process_graceful_shutdown_cli_write above.
 */
static void process_graceful_restart_preserve_fw_state_cli_write(struct vty *vty,
								 const struct lyd_node *dnode,
								 bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "bgp graceful-restart preserve-fw-state\n");
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
			.xpath = "/proteus-bgp:instance/suppress-fib-pending",
			.cbs = {
				.cli_show = instance_suppress_fib_pending_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/update-delay",
			.cbs = {
				.cli_show = instance_update_delay_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/advertisement-delay",
			.cbs = {
				.cli_show = instance_advertisement_delay_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/graceful-shutdown",
			.cbs = {
				.cli_show = instance_graceful_shutdown_cli_write,
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
			.xpath = "/proteus-bgp:instance/long-lived-graceful-restart-stale-time",
			.cbs = {
				.cli_show = instance_long_lived_graceful_restart_stale_time_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/graceful-restart/notification",
			.cbs = {
				.cli_show = instance_graceful_restart_notification_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/graceful-restart/mode",
			.cbs = {
				.cli_show = instance_graceful_restart_mode_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/graceful-restart/preserve-fw-state",
			.cbs = {
				.cli_show = instance_graceful_restart_preserve_fw_state_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/ebgp-requires-policy",
			.cbs = {
				.cli_show = instance_ebgp_requires_policy_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/enforce-first-as",
			.cbs = {
				.cli_show = instance_enforce_first_as_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/suppress-duplicates",
			.cbs = {
				.cli_show = instance_suppress_duplicates_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/hard-administrative-reset",
			.cbs = {
				.cli_show = instance_hard_administrative_reset_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/deterministic-med",
			.cbs = {
				.cli_show = instance_deterministic_med_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/network-import-check",
			.cbs = {
				.cli_show = instance_network_import_check_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/bestpath/aigp",
			.cbs = {
				.cli_show = instance_bestpath_aigp_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/show-hostname",
			.cbs = {
				.cli_show = instance_default_show_hostname_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/show-nexthop-hostname",
			.cbs = {
				.cli_show = instance_default_show_nexthop_hostname_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/software-version-capability",
			.cbs = {
				.cli_show = instance_default_software_version_capability_cli_write,
			}
		},
		{
			.xpath =
				"/proteus-bgp:instance/default/software-version-capability-latest-encoding",
			.cbs = {
				.cli_show =
					instance_default_software_version_capability_latest_encoding_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/link-local-capability",
			.cbs = {
				.cli_show = instance_default_link_local_capability_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/dynamic-capability",
			.cbs = {
				.cli_show = instance_default_dynamic_capability_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/route-reflector-allow-outbound-policy",
			.cbs = {
				.cli_show = instance_route_reflector_allow_outbound_policy_cli_write,
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
			.xpath = "/proteus-bgp:process/suppress-fib-pending",
			.cbs = {
				.cli_show = process_suppress_fib_pending_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:process/update-delay",
			.cbs = {
				.cli_show = process_update_delay_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:process/advertisement-delay",
			.cbs = {
				.cli_show = process_advertisement_delay_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:process/graceful-shutdown",
			.cbs = {
				.cli_show = process_graceful_shutdown_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:process/graceful-restart/mode",
			.cbs = {
				.cli_show = process_graceful_restart_mode_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:process/graceful-restart/preserve-fw-state",
			.cbs = {
				.cli_show = process_graceful_restart_preserve_fw_state_cli_write,
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

	install_element(BGP_NODE, &bgp_suppress_fib_pending_cli_cmd);
	install_element(BGP_NODE, &no_bgp_suppress_fib_pending_cli_cmd);

	install_element(BGP_NODE, &bgp_update_delay_cli_cmd);
	install_element(BGP_NODE, &no_bgp_update_delay_cli_cmd);
	install_element(BGP_NODE, &bgp_advertisement_delay_cli_cmd);
	install_element(BGP_NODE, &no_bgp_advertisement_delay_cli_cmd);

	install_element(BGP_NODE, &bgp_graceful_shutdown_cli_cmd);
	install_element(BGP_NODE, &no_bgp_graceful_shutdown_cli_cmd);

	install_element(BGP_NODE, &bgp_graceful_restart_cli_cmd);
	install_element(BGP_NODE, &no_bgp_graceful_restart_cli_cmd);
	install_element(BGP_NODE, &bgp_graceful_restart_disable_cli_cmd);
	install_element(BGP_NODE, &no_bgp_graceful_restart_disable_cli_cmd);
	install_element(BGP_NODE, &bgp_graceful_restart_preserve_fw_cli_cmd);
	install_element(BGP_NODE, &no_bgp_graceful_restart_preserve_fw_cli_cmd);

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

	install_element(BGP_NODE, &bgp_llgr_stalepath_time_cli_cmd);
	install_element(BGP_NODE, &no_bgp_llgr_stalepath_time_cli_cmd);
	install_element(BGP_NODE, &bgp_graceful_restart_notification_cli_cmd);
	install_element(BGP_NODE, &no_bgp_graceful_restart_notification_cli_cmd);
	install_element(BGP_NODE, &bgp_graceful_restart_notification_deprecated_cli_cmd);
	install_element(BGP_NODE, &no_bgp_graceful_restart_notification_deprecated_cli_cmd);

	install_element(BGP_NODE, &bgp_ebgp_requires_policy_cli_cmd);
	install_element(BGP_NODE, &no_bgp_ebgp_requires_policy_cli_cmd);
	install_element(BGP_NODE, &bgp_ebgp_requires_policy_deprecated_cli_cmd);
	install_element(BGP_NODE, &no_bgp_ebgp_requires_policy_deprecated_cli_cmd);

	install_element(BGP_NODE, &bgp_enforce_first_as_cli_cmd);
	install_element(BGP_NODE, &no_bgp_enforce_first_as_cli_cmd);
	install_element(BGP_NODE, &bgp_enforce_first_as_deprecated_cli_cmd);
	install_element(BGP_NODE, &no_bgp_enforce_first_as_deprecated_cli_cmd);

	install_element(BGP_NODE, &bgp_suppress_duplicates_cli_cmd);
	install_element(BGP_NODE, &no_bgp_suppress_duplicates_cli_cmd);
	install_element(BGP_NODE, &bgp_suppress_duplicates_deprecated_cli_cmd);
	install_element(BGP_NODE, &no_bgp_suppress_duplicates_deprecated_cli_cmd);

	install_element(BGP_NODE, &bgp_administrative_reset_cli_cmd);
	install_element(BGP_NODE, &no_bgp_administrative_reset_cli_cmd);
	install_element(BGP_NODE, &bgp_administrative_reset_deprecated_cli_cmd);
	install_element(BGP_NODE, &no_bgp_administrative_reset_deprecated_cli_cmd);

	install_element(BGP_NODE, &bgp_deterministic_med_cli_cmd);
	install_element(BGP_NODE, &no_bgp_deterministic_med_cli_cmd);
	install_element(BGP_NODE, &bgp_deterministic_med_deprecated_cli_cmd);
	install_element(BGP_NODE, &no_bgp_deterministic_med_deprecated_cli_cmd);

	install_element(BGP_NODE, &bgp_network_import_check_cli_cmd);
	install_element(BGP_NODE, &no_bgp_network_import_check_cli_cmd);
	install_element(BGP_NODE, &bgp_network_import_check_deprecated_cli_cmd);
	install_element(BGP_NODE, &no_bgp_network_import_check_deprecated_cli_cmd);

	install_element(BGP_NODE, &bgp_bestpath_aigp_cli_cmd);
	install_element(BGP_NODE, &no_bgp_bestpath_aigp_cli_cmd);
	install_element(BGP_NODE, &bgp_bestpath_aigp_deprecated_cli_cmd);
	install_element(BGP_NODE, &no_bgp_bestpath_aigp_deprecated_cli_cmd);

	install_element(BGP_NODE, &bgp_default_show_hostname_cli_cmd);
	install_element(BGP_NODE, &no_bgp_default_show_hostname_cli_cmd);
	install_element(BGP_NODE, &bgp_default_show_hostname_deprecated_cli_cmd);
	install_element(BGP_NODE, &no_bgp_default_show_hostname_deprecated_cli_cmd);

	install_element(BGP_NODE, &bgp_default_show_nexthop_hostname_cli_cmd);
	install_element(BGP_NODE, &no_bgp_default_show_nexthop_hostname_cli_cmd);
	install_element(BGP_NODE, &bgp_default_show_nexthop_hostname_deprecated_cli_cmd);
	install_element(BGP_NODE, &no_bgp_default_show_nexthop_hostname_deprecated_cli_cmd);

	install_element(BGP_NODE, &bgp_default_software_version_capability_cli_cmd);
	install_element(BGP_NODE, &no_bgp_default_software_version_capability_cli_cmd);
	install_element(BGP_NODE, &bgp_default_software_version_capability_latest_encoding_cli_cmd);
	install_element(BGP_NODE,
			&no_bgp_default_software_version_capability_latest_encoding_cli_cmd);
	install_element(BGP_NODE, &bgp_default_software_version_capability_deprecated_cli_cmd);
	install_element(BGP_NODE, &no_bgp_default_software_version_capability_deprecated_cli_cmd);

	install_element(BGP_NODE, &bgp_default_link_local_capability_cli_cmd);
	install_element(BGP_NODE, &no_bgp_default_link_local_capability_cli_cmd);
	install_element(BGP_NODE, &bgp_default_link_local_capability_deprecated_cli_cmd);
	install_element(BGP_NODE, &no_bgp_default_link_local_capability_deprecated_cli_cmd);

	install_element(BGP_NODE, &bgp_default_dynamic_capability_cli_cmd);
	install_element(BGP_NODE, &no_bgp_default_dynamic_capability_cli_cmd);
	install_element(BGP_NODE, &bgp_default_dynamic_capability_deprecated_cli_cmd);
	install_element(BGP_NODE, &no_bgp_default_dynamic_capability_deprecated_cli_cmd);

	install_element(BGP_NODE, &bgp_rr_allow_outbound_policy_cli_cmd);
	install_element(BGP_NODE, &no_bgp_rr_allow_outbound_policy_cli_cmd);
	install_element(BGP_NODE, &bgp_rr_allow_outbound_policy_deprecated_cli_cmd);
	install_element(BGP_NODE, &no_bgp_rr_allow_outbound_policy_deprecated_cli_cmd);

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

	install_element(CONFIG_NODE, &bgp_global_suppress_fib_pending_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_global_suppress_fib_pending_cli_cmd);

	install_element(CONFIG_NODE, &bgp_global_update_delay_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_global_update_delay_cli_cmd);
	install_element(CONFIG_NODE, &bgp_global_advertisement_delay_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_global_advertisement_delay_cli_cmd);

	install_element(CONFIG_NODE, &bgp_global_graceful_shutdown_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_global_graceful_shutdown_cli_cmd);

	install_element(CONFIG_NODE, &bgp_global_graceful_restart_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_global_graceful_restart_cli_cmd);
	install_element(CONFIG_NODE, &bgp_global_graceful_restart_disable_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_global_graceful_restart_disable_cli_cmd);
	install_element(CONFIG_NODE, &bgp_global_graceful_restart_preserve_fw_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_global_graceful_restart_preserve_fw_cli_cmd);
}
