// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Robin Christ, partimus GmbH */
/* Process-wide ('bgp ...' global-scope) CLI (DEFPYs + northbound cli_show callbacks) for the proteus-bgp conversion.
 *
 * Split out of bgpd/bgp_cli.c (bgpd-yang-conversion intermezzo): pure code
 * motion for the DEFPY/cli_show bodies below. bgp_cli_init()'s body could
 * not move verbatim -- see bgp_cli_common.c and bgp_cli_process_init()
 * in this file for why.
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
#include "bgpd/proteus/bgp_cli_local.h"
#include "bgpd/proteus/bgp_cli_process_clippy.c"

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

/*
 * Milestone 2 batch B14: 'bgp graceful-restart restart-time/stalepath-time/
 * select-defer-time/rib-stale-time' (process + instance pairs). Legacy is
 * three dual-purpose DEFUN pairs (restart-time, stalepath-time,
 * select-defer-time), same install-at-both-nodes-branch-on-vty->node shape
 * as the mode/preserve-fw-state family above, plus a fourth
 * (rib-stale-time) whose CONFIG_NODE half was dead code (see the
 * bgp_nb_config.c comment on process_graceful_restart_rib_stale_time_modify()
 * for the fresh-code note). None of the four leaves carries a YANG default,
 * so all eight DEFPY_YANG pairs below map their 'no' form to NB_OP_DESTROY
 * (no separate default-transition MODIFY needed, unlike preserve-fw-state).
 */
DEFPY_YANG(
	bgp_global_graceful_restart_restart_time, bgp_global_graceful_restart_restart_time_cli_cmd,
	"bgp graceful-restart restart-time (0-4095)$restart_time",
	BGP_STR
	"Graceful restart capability parameters\n"
	"Set the time to wait to delete stale routes before a BGP open message is received\n"
	"Delay value (seconds)\n")
{
	nb_cli_enqueue_change(vty, "/proteus-bgp:process/graceful-restart/restart-time",
			      NB_OP_MODIFY, restart_time_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_global_graceful_restart_restart_time,
	no_bgp_global_graceful_restart_restart_time_cli_cmd,
	"no bgp graceful-restart restart-time [(0-4095)]",
	NO_STR
	BGP_STR
	"Graceful restart capability parameters\n"
	"Set the time to wait to delete stale routes before a BGP open message is received\n"
	"Delay value (seconds)\n")
{
	nb_cli_enqueue_change(vty, "/proteus-bgp:process/graceful-restart/restart-time",
			      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_global_graceful_restart_stalepath_time,
	bgp_global_graceful_restart_stalepath_time_cli_cmd,
	"bgp graceful-restart stalepath-time (1-4095)$stalepath_time",
	BGP_STR
	"Graceful restart capability parameters\n"
	"Set the max time to hold onto restarting peer's stale paths\n"
	"Delay value (seconds)\n")
{
	nb_cli_enqueue_change(vty, "/proteus-bgp:process/graceful-restart/stalepath-time",
			      NB_OP_MODIFY, stalepath_time_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_global_graceful_restart_stalepath_time,
	no_bgp_global_graceful_restart_stalepath_time_cli_cmd,
	"no bgp graceful-restart stalepath-time [(1-4095)]",
	NO_STR
	BGP_STR
	"Graceful restart capability parameters\n"
	"Set the max time to hold onto restarting peer's stale paths\n"
	"Delay value (seconds)\n")
{
	nb_cli_enqueue_change(vty, "/proteus-bgp:process/graceful-restart/stalepath-time",
			      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_global_graceful_restart_select_defer_time,
	bgp_global_graceful_restart_select_defer_time_cli_cmd,
	"bgp graceful-restart select-defer-time (0-3600)$defer_time",
	BGP_STR
	"Graceful restart capability parameters\n"
	"Set the time to defer the BGP route selection after restart\n"
	"Delay value (seconds, 0 - disable)\n")
{
	nb_cli_enqueue_change(vty, "/proteus-bgp:process/graceful-restart/select-defer-time",
			      NB_OP_MODIFY, defer_time_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_global_graceful_restart_select_defer_time,
	no_bgp_global_graceful_restart_select_defer_time_cli_cmd,
	"no bgp graceful-restart select-defer-time [(0-3600)]",
	NO_STR
	BGP_STR
	"Graceful restart capability parameters\n"
	"Set the time to defer the BGP route selection after restart\n"
	"Delay value (seconds)\n")
{
	nb_cli_enqueue_change(vty, "/proteus-bgp:process/graceful-restart/select-defer-time",
			      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_global_graceful_restart_rib_stale_time,
	bgp_global_graceful_restart_rib_stale_time_cli_cmd,
	"bgp graceful-restart rib-stale-time (1-3600)$stale_time",
	BGP_STR
	"Graceful restart configuration parameters\n"
	"Specify the stale route removal timer in rib\n"
	"Delay value (seconds)\n")
{
	nb_cli_enqueue_change(vty, "/proteus-bgp:process/graceful-restart/rib-stale-time",
			      NB_OP_MODIFY, stale_time_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_global_graceful_restart_rib_stale_time,
	no_bgp_global_graceful_restart_rib_stale_time_cli_cmd,
	"no bgp graceful-restart rib-stale-time [(1-3600)]",
	NO_STR
	BGP_STR
	"Graceful restart configuration parameters\n"
	"Specify the stale route removal timer in rib\n"
	"Delay value (seconds)\n")
{
	nb_cli_enqueue_change(vty, "/proteus-bgp:process/graceful-restart/rib-stale-time",
			      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

void process_route_map_delay_timer_cli_write(struct vty *vty, const struct lyd_node *dnode,
						    bool show_defaults)
{
	vty_out(vty, "bgp route-map delay-timer %u\n", yang_dnode_get_uint16(dnode, NULL));
}

void process_session_dscp_cli_write(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	vty_out(vty, "bgp session-dscp %u\n", yang_dnode_get_uint8(dnode, NULL));
}

void process_input_queue_limit_cli_write(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults)
{
	vty_out(vty, "bgp input-queue-limit %u\n", yang_dnode_get_uint32(dnode, NULL));
}

void process_output_queue_limit_cli_write(struct vty *vty, const struct lyd_node *dnode,
						 bool show_defaults)
{
	vty_out(vty, "bgp output-queue-limit %u\n", yang_dnode_get_uint32(dnode, NULL));
}

void process_no_rib_cli_write(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults)
{
	vty_out(vty, "bgp no-rib\n");
}

void process_send_extra_data_zebra_cli_write(struct vty *vty, const struct lyd_node *dnode,
						    bool show_defaults)
{
	vty_out(vty, "bgp send-extra-data zebra\n");
}

void process_ipv6_auto_ra_cli_write(struct vty *vty, const struct lyd_node *dnode,
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
void process_suppress_fib_pending_cli_write(struct vty *vty, const struct lyd_node *dnode,
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
void process_update_delay_cli_write(struct vty *vty, const struct lyd_node *dnode,
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
void process_advertisement_delay_cli_write(struct vty *vty, const struct lyd_node *dnode,
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
void process_graceful_shutdown_cli_write(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "bgp graceful-shutdown\n");
}

/* Batch B13: 'bgp graceful-restart'/'bgp graceful-restart-disable' mode,
 * process-wide form. Same presence-based shape as
 * instance_graceful_restart_mode_cli_write above, no leading space.
 */
void process_graceful_restart_mode_cli_write(struct vty *vty, const struct lyd_node *dnode,
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
void process_graceful_restart_preserve_fw_state_cli_write(struct vty *vty,
								 const struct lyd_node *dnode,
								 bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "bgp graceful-restart preserve-fw-state\n");
}

/* Batch B14: 'bgp graceful-restart restart-time/stalepath-time/
 * select-defer-time/rib-stale-time', process-wide form. Same presence-based
 * shape as instance_graceful_restart_restart_time_cli_write etc. above, no
 * leading space.
 */
void process_graceful_restart_restart_time_cli_write(struct vty *vty,
							    const struct lyd_node *dnode,
							    bool show_defaults)
{
	vty_out(vty, "bgp graceful-restart restart-time %u\n", yang_dnode_get_uint16(dnode, NULL));
}

void process_graceful_restart_stalepath_time_cli_write(struct vty *vty,
							      const struct lyd_node *dnode,
							      bool show_defaults)
{
	vty_out(vty, "bgp graceful-restart stalepath-time %u\n",
		yang_dnode_get_uint16(dnode, NULL));
}

void process_graceful_restart_select_defer_time_cli_write(struct vty *vty,
								 const struct lyd_node *dnode,
								 bool show_defaults)
{
	vty_out(vty, "bgp graceful-restart select-defer-time %u\n",
		yang_dnode_get_uint16(dnode, NULL));
}

void process_graceful_restart_rib_stale_time_cli_write(struct vty *vty,
							      const struct lyd_node *dnode,
							      bool show_defaults)
{
	vty_out(vty, "bgp graceful-restart rib-stale-time %u\n",
		yang_dnode_get_uint16(dnode, NULL));
}

void bgp_cli_process_init(void)
{
	install_element(CONFIG_NODE, &bgp_process_ipv6_auto_ra_cli_cmd);
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
	install_element(CONFIG_NODE, &bgp_global_graceful_restart_restart_time_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_global_graceful_restart_restart_time_cli_cmd);
	install_element(CONFIG_NODE, &bgp_global_graceful_restart_stalepath_time_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_global_graceful_restart_stalepath_time_cli_cmd);
	install_element(CONFIG_NODE, &bgp_global_graceful_restart_select_defer_time_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_global_graceful_restart_select_defer_time_cli_cmd);
	install_element(CONFIG_NODE, &bgp_global_graceful_restart_rib_stale_time_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_global_graceful_restart_rib_stale_time_cli_cmd);
}
