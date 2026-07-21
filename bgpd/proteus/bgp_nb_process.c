// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Robin Christ, partimus GmbH */
/* Northbound callbacks for the /proteus-bgp:process subtree (process-wide bm-> scalars).
 *
 * Split out of bgpd/bgp_nb_config.c (bgpd-yang-conversion intermezzo):
 * pure code motion, function bodies unchanged.
 */
#include <zebra.h>

#include "lib/northbound.h"
#include "lib/vrf.h"
#include "lib/asn.h"
#include "lib/log.h"
#include "lib/yang_wrappers.h"
#include "lib/frrevent.h"
#include "lib/libagentx.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_nb.h"
#include "bgpd/bgp_io.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_updgrp.h"
#include "bgpd/bgp_conditional_adv.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_open.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_addpath.h"
#include "bgpd/proteus/bgp_nb_local.h"

int process_route_map_delay_timer_modify(struct nb_cb_modify_args *args)
{
	uint16_t rmap_delay_timer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rmap_delay_timer = yang_dnode_get_uint16(args->dnode, NULL);
	bm->rmap_update_timer = rmap_delay_timer;

	/* if the dynamic update handling is being disabled, and a timer is
	 * running, stop the timer and act as if the timer has already fired.
	 */
	if (!rmap_delay_timer && event_is_scheduled(bm->t_rmap_update)) {
		event_cancel(&bm->t_rmap_update);
		event_execute(bm->master, bgp_route_map_update_timer, NULL, 0, NULL);
	}

	return NB_OK;
}

int process_route_map_delay_timer_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bm->rmap_update_timer = RMAP_DEFAULT_UPDATE_TIMER;

	return NB_OK;
}

int process_update_delay_delay_modify(struct nb_cb_modify_args *args)
{
	uint16_t delay, establish_wait;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (bgp_nb_update_delay_process_blocked_by_instance()) {
			snprintf(args->errmsg, args->errmsg_len,
				 "global update-delay config not permitted: per-vrf update-delay configuration exists");
			return NB_ERR_VALIDATION;
		}
		delay = yang_dnode_get_uint16(args->dnode, NULL);
		establish_wait = yang_dnode_exists(args->dnode, "../establish-wait")
					 ? yang_dnode_get_uint16(args->dnode, "../establish-wait")
					 : 0;
		if (establish_wait && delay < establish_wait) {
			snprintf(args->errmsg, args->errmsg_len,
				 "update-delay less than the establish-wait");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	delay = yang_dnode_get_uint16(args->dnode, NULL);
	establish_wait = yang_dnode_exists(args->dnode, "../establish-wait")
				 ? yang_dnode_get_uint16(args->dnode, "../establish-wait")
				 : 0;
	bgp_nb_process_update_delay_apply(delay, establish_wait);

	return NB_OK;
}

/* The legacy "no bgp update-delay [...]" DEFPY (bgp_global_update_delay_
 * deconfig_vty()) unconditionally resets both fields with no guard at all,
 * regardless of any optional numeric arguments given -- replicated as-is.
 */
int process_update_delay_delay_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp_nb_process_update_delay_apply(BGP_UPDATE_DELAY_DEFAULT, 0);

	return NB_OK;
}

int process_update_delay_establish_wait_modify(struct nb_cb_modify_args *args)
{
	uint16_t delay, establish_wait;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (bgp_nb_update_delay_process_blocked_by_instance()) {
			snprintf(args->errmsg, args->errmsg_len,
				 "global update-delay config not permitted: per-vrf update-delay configuration exists");
			return NB_ERR_VALIDATION;
		}
		establish_wait = yang_dnode_get_uint16(args->dnode, NULL);
		delay = yang_dnode_exists(args->dnode, "../delay")
				? yang_dnode_get_uint16(args->dnode, "../delay")
				: bm->v_update_delay;
		if (delay < establish_wait) {
			snprintf(args->errmsg, args->errmsg_len,
				 "update-delay less than the establish-wait");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	establish_wait = yang_dnode_get_uint16(args->dnode, NULL);
	delay = yang_dnode_exists(args->dnode, "../delay")
			? yang_dnode_get_uint16(args->dnode, "../delay")
			: bm->v_update_delay;
	bgp_nb_process_update_delay_apply(delay, establish_wait);

	return NB_OK;
}

int process_update_delay_establish_wait_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp_nb_process_update_delay_apply(BGP_UPDATE_DELAY_DEFAULT, 0);

	return NB_OK;
}

/* advertisement-delay has NO mutual-exclusion guard against the
 * per-instance leaf anywhere in legacy code -- deliberately asymmetric vs.
 * update-delay above, not an oversight. Do not add one here.
 */
int process_advertisement_delay_modify(struct nb_cb_modify_args *args)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	uint16_t delay;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	delay = yang_dnode_get_uint16(args->dnode, NULL);
	bm->v_advertisement_delay = delay;

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp))
		bgp->v_advertisement_delay = bm->v_advertisement_delay;

	return NB_OK;
}

int process_advertisement_delay_destroy(struct nb_cb_destroy_args *args)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bm->v_advertisement_delay = BGP_ADVERTISEMENT_DELAY_DEFAULT;

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp))
		bgp_nb_advertisement_delay_reset(bgp);

	return NB_OK;
}

/* Both leaves below drive the same bm_wait_for_fib_set(set, adv_delay) call
 * (bgpd.c), matching bgp_global_suppress_fib_pending_cmd exactly: whichever
 * leaf's modify callback runs re-reads its sibling (both are default-bearing
 * so a plain yang_dnode_get_* always succeeds, no existence check needed)
 * and re-applies the full state. bm_wait_for_fib_set() is idempotent when
 * called twice with the same resulting (set, adv_delay) pair, which happens
 * whenever both leaves change in the same transaction (same shape as B7's
 * instance_tcp_keepalive_*_modify siblings).
 */
int process_suppress_fib_pending_enabled_modify(struct nb_cb_modify_args *args)
{
	bool enabled;
	uint16_t adv_delay;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	enabled = yang_dnode_get_bool(args->dnode, NULL);
	adv_delay = yang_dnode_get_uint16(args->dnode, "../advertisement-delay");

	bm_wait_for_fib_set(enabled, adv_delay);

	return NB_OK;
}

int process_suppress_fib_pending_advertisement_delay_modify(struct nb_cb_modify_args *args)
{
	bool enabled;
	uint16_t adv_delay;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	adv_delay = yang_dnode_get_uint16(args->dnode, NULL);
	enabled = yang_dnode_get_bool(args->dnode, "../enabled");

	bm_wait_for_fib_set(enabled, adv_delay);

	return NB_OK;
}

int process_no_rib_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL))
		bgp_option_norib_set_runtime();
	else
		bgp_option_norib_unset_runtime();

	return NB_OK;
}

int process_send_extra_data_zebra_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bm->flags, BM_FLAG_SEND_EXTRA_DATA_TO_ZEBRA);
	else
		UNSET_FLAG(bm->flags, BM_FLAG_SEND_EXTRA_DATA_TO_ZEBRA);

	return NB_OK;
}

/* Shared APPLY body for the process-wide ipv6-auto-ra leaf: mirrors the
 * legacy CONFIG_NODE branch of bgp_ipv6_auto_ra_cmd exactly, including
 * unconditionally overwriting every existing instance's per-VRF flag.
 */
static int process_ipv6_auto_ra_apply(bool auto_ra)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;

	COND_FLAG(bm->flags, BM_FLAG_IPV6_NO_AUTO_RA, !auto_ra);
	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp))
		COND_FLAG(bgp->flags, BGP_FLAG_IPV6_NO_AUTO_RA, !auto_ra);

	return NB_OK;
}

int process_ipv6_auto_ra_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	return process_ipv6_auto_ra_apply(yang_dnode_get_bool(args->dnode, NULL));
}

/* 'agentx' (TODO #31 B5): same bodies as the legacy lib DEFUN pair in
 * lib/libagentx.c, via the shared libagentx_cli_* helpers. True enables the
 * AgentX subagent connection (or logs the "module not loaded" info line when
 * the snmp module is absent). False is a no-op unless AgentX is already up,
 * in which case it cannot actually be torn down again; warn like the legacy
 * no-form did instead of failing the whole transaction, so a replayed config
 * without the line still applies. */
int process_agentx_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL))
		libagentx_cli_enable();
	else if (agentx_enabled && !libagentx_cli_disable())
		zlog_warn("SNMP AgentX support cannot be disabled once enabled");

	return NB_OK;
}

/* 'bgp snmp traps ...' (M8.5 B-snmp): bm->options flag toggles. Default
 * resolution: destroy on these default-bearing leaves redispatches as a
 * modify-with-default, so only .modify exists. */
static int process_snmp_trap_flag_modify(struct nb_cb_modify_args *args, uint32_t flag)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bm->options, flag);
	else
		UNSET_FLAG(bm->options, flag);

	return NB_OK;
}

int process_snmp_traps_rfc4273_modify(struct nb_cb_modify_args *args)
{
	return process_snmp_trap_flag_modify(args, BGP_OPT_TRAPS_RFC4273);
}

int process_snmp_traps_rfc4382_modify(struct nb_cb_modify_args *args)
{
	return process_snmp_trap_flag_modify(args, BGP_OPT_TRAPS_RFC4382);
}

int process_snmp_traps_bgp4_mibv2_modify(struct nb_cb_modify_args *args)
{
	return process_snmp_trap_flag_modify(args, BGP_OPT_TRAPS_BGP4MIBV2);
}

int process_session_dscp_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bm->ip_tos = yang_dnode_get_uint8(args->dnode, NULL) << 2;

	return NB_OK;
}

int process_session_dscp_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bm->ip_tos = IPTOS_PREC_INTERNETCONTROL;

	return NB_OK;
}

int process_input_queue_limit_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bm->inq_limit = yang_dnode_get_uint32(args->dnode, NULL);

	return NB_OK;
}

int process_input_queue_limit_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bm->inq_limit = BM_DEFAULT_Q_LIMIT;

	return NB_OK;
}

int process_output_queue_limit_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bm->outq_limit = yang_dnode_get_uint32(args->dnode, NULL);

	return NB_OK;
}

int process_output_queue_limit_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bm->outq_limit = BM_DEFAULT_Q_LIMIT;

	return NB_OK;
}
