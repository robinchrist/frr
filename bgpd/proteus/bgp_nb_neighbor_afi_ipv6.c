// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Robin Christ, partimus GmbH */
/* Northbound callbacks for neighbor per-afi-safi IPv6 settings.
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


int instance_neighbor_afi_safis_ipv6_unicast_activate_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_activate_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_activate_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_activate_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_addpath_tx_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/addpath/tx");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_addpath_tx_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/addpath/tx");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_addpath_tx_best_selected_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/addpath/tx-best-selected");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_addpath_tx_best_selected_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/addpath/tx-best-selected");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_addpath_disable_rx_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/addpath/disable-rx");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_addpath_rx_paths_limit_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/addpath/rx-paths-limit");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_addpath_rx_paths_limit_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/addpath/rx-paths-limit");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_orf_prefix_list_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/orf-prefix-list");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_orf_prefix_list_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/orf-prefix-list");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/route-reflector-client");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_next_hop_self_enabled_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/next-hop-self/enabled");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_next_hop_self_force_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/next-hop-self/force");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_remove_private_as_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/remove-private-as");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_remove_private_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/remove-private-as");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_as_override_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/as-override");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_send_community_standard_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/send-community/standard");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_send_community_standard_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/send-community/standard");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_send_community_extended_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/send-community/extended");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_send_community_extended_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/send-community/extended");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_send_community_large_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/send-community/large");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_send_community_large_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/send-community/large");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_send_community_extended_rpki_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/send-community/extended-rpki");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_default_originate_enabled_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/default-originate/enabled");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_default_originate_route_map_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/default-originate/route-map");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/default-originate/route-map");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_soft_reconfiguration_inbound_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/soft-reconfiguration-inbound");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_maximum_prefix_count_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/maximum-prefix/count");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_maximum_prefix_count_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/maximum-prefix/count");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_maximum_prefix_threshold_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/maximum-prefix/threshold");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_maximum_prefix_threshold_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/maximum-prefix/threshold");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_maximum_prefix_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/maximum-prefix/warning-only");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_maximum_prefix_restart_interval_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/maximum-prefix/restart-interval");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_maximum_prefix_restart_interval_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/maximum-prefix/restart-interval");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_maximum_prefix_force_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/maximum-prefix/force");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_maximum_prefix_out_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/maximum-prefix-out");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_maximum_prefix_out_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/maximum-prefix-out");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_route_server_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/route-server-client");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_nexthop_local_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/nexthop-local-unchanged");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_allowas_in_enabled_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/allowas-in/enabled");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_allowas_in_count_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/allowas-in/count");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_allowas_in_count_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/allowas-in/count");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_allowas_in_origin_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/allowas-in/origin");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_allowas_in_route_map_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/allowas-in/route-map");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_allowas_in_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/allowas-in/route-map");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_accept_own_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/accept-own");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_soo_create(struct nb_cb_create_args *args)
{
	return bgp_nb_neighbor_af_soo_create(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_soo_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_soo_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_soo_as2_create(struct nb_cb_create_args *args)
{
	return bgp_nb_neighbor_af_soo_case_create(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_soo_as2_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_soo_case_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_soo_as2_global_admin_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_soo_leaf_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_soo_as2_local_admin_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_soo_leaf_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_soo_as4_create(struct nb_cb_create_args *args)
{
	return bgp_nb_neighbor_af_soo_case_create(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_soo_as4_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_soo_case_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_soo_as4_global_admin_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_soo_leaf_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_soo_as4_local_admin_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_soo_leaf_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_soo_ipv4_create(struct nb_cb_create_args *args)
{
	return bgp_nb_neighbor_af_soo_case_create(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_soo_ipv4_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_soo_case_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_soo_ipv4_global_admin_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_soo_leaf_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_soo_ipv4_local_admin_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_soo_leaf_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_weight_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/weight");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_weight_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/weight");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_attribute_unchanged_as_path_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/attribute-unchanged/as-path");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_attribute_unchanged_next_hop_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/attribute-unchanged/next-hop");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_attribute_unchanged_med_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/attribute-unchanged/med");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_dampening_enabled_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/dampening/enabled");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_dampening_half_life_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/dampening/half-life");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_dampening_half_life_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/dampening/half-life");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_dampening_reuse_threshold_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/dampening/reuse-threshold");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_dampening_reuse_threshold_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/dampening/reuse-threshold");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_dampening_suppress_threshold_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/dampening/suppress-threshold");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_dampening_suppress_threshold_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/dampening/suppress-threshold");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_dampening_max_suppress_time_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/dampening/max-suppress-time");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_dampening_max_suppress_time_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/dampening/max-suppress-time");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_unicast_filters_distribute_list_in_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_distribute_list_modify(args, AFI_IP6, SAFI_UNICAST, FILTER_IN);
}

int instance_neighbor_afi_safis_ipv6_unicast_filters_distribute_list_in_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_distribute_list_destroy(args, AFI_IP6, SAFI_UNICAST, FILTER_IN);
}

int instance_neighbor_afi_safis_ipv6_unicast_filters_distribute_list_out_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_distribute_list_modify(args, AFI_IP6, SAFI_UNICAST, FILTER_OUT);
}

int instance_neighbor_afi_safis_ipv6_unicast_filters_distribute_list_out_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_distribute_list_destroy(args, AFI_IP6, SAFI_UNICAST, FILTER_OUT);
}

int instance_neighbor_afi_safis_ipv6_unicast_filters_prefix_list_in_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_prefix_list_modify(args, AFI_IP6, SAFI_UNICAST, FILTER_IN);
}

int instance_neighbor_afi_safis_ipv6_unicast_filters_prefix_list_in_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_prefix_list_destroy(args, AFI_IP6, SAFI_UNICAST, FILTER_IN);
}

int instance_neighbor_afi_safis_ipv6_unicast_filters_prefix_list_out_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_prefix_list_modify(args, AFI_IP6, SAFI_UNICAST, FILTER_OUT);
}

int instance_neighbor_afi_safis_ipv6_unicast_filters_prefix_list_out_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_prefix_list_destroy(args, AFI_IP6, SAFI_UNICAST, FILTER_OUT);
}

int instance_neighbor_afi_safis_ipv6_unicast_filters_filter_list_in_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_filter_list_modify(args, AFI_IP6, SAFI_UNICAST, FILTER_IN);
}

int instance_neighbor_afi_safis_ipv6_unicast_filters_filter_list_in_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_filter_list_destroy(args, AFI_IP6, SAFI_UNICAST, FILTER_IN);
}

int instance_neighbor_afi_safis_ipv6_unicast_filters_filter_list_out_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_filter_list_modify(args, AFI_IP6, SAFI_UNICAST, FILTER_OUT);
}

int instance_neighbor_afi_safis_ipv6_unicast_filters_filter_list_out_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_filter_list_destroy(args, AFI_IP6, SAFI_UNICAST, FILTER_OUT);
}

int instance_neighbor_afi_safis_ipv6_unicast_filters_route_map_in_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_route_map_modify(args, AFI_IP6, SAFI_UNICAST, RMAP_IN);
}

int instance_neighbor_afi_safis_ipv6_unicast_filters_route_map_in_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_route_map_destroy(args, AFI_IP6, SAFI_UNICAST, RMAP_IN);
}

int instance_neighbor_afi_safis_ipv6_unicast_filters_route_map_out_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_route_map_modify(args, AFI_IP6, SAFI_UNICAST, RMAP_OUT);
}

int instance_neighbor_afi_safis_ipv6_unicast_filters_route_map_out_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_route_map_destroy(args, AFI_IP6, SAFI_UNICAST, RMAP_OUT);
}

int instance_neighbor_afi_safis_ipv6_unicast_filters_unsuppress_map_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_unsuppress_map_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_filters_unsuppress_map_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_unsuppress_map_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_filters_conditional_advertisement_advertise_map_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_advertise_map_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_filters_conditional_advertisement_advertise_map_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_advertise_map_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_filters_conditional_advertisement_condition_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_condition_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_filters_conditional_advertisement_condition_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_condition_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_filters_conditional_advertisement_condition_map_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_condition_map_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_filters_conditional_advertisement_condition_map_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_condition_map_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_activate_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_activate_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_activate_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_activate_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_addpath_tx_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/addpath/tx");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_addpath_tx_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/addpath/tx");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_addpath_tx_best_selected_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/addpath/tx-best-selected");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_addpath_tx_best_selected_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/addpath/tx-best-selected");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_addpath_disable_rx_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/addpath/disable-rx");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_addpath_rx_paths_limit_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/addpath/rx-paths-limit");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_addpath_rx_paths_limit_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/addpath/rx-paths-limit");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_orf_prefix_list_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/orf-prefix-list");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_orf_prefix_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/orf-prefix-list");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/route-reflector-client");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_next_hop_self_enabled_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/next-hop-self/enabled");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_next_hop_self_force_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/next-hop-self/force");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_remove_private_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/remove-private-as");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_remove_private_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/remove-private-as");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_as_override_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/as-override");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_send_community_standard_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/send-community/standard");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_send_community_standard_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/send-community/standard");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_send_community_extended_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/send-community/extended");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_send_community_extended_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/send-community/extended");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_send_community_large_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/send-community/large");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_send_community_large_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/send-community/large");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_send_community_extended_rpki_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/send-community/extended-rpki");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_default_originate_enabled_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/default-originate/enabled");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_default_originate_route_map_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/default-originate/route-map");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/default-originate/route-map");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_soft_reconfiguration_inbound_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/soft-reconfiguration-inbound");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_maximum_prefix_count_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/maximum-prefix/count");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_maximum_prefix_count_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/maximum-prefix/count");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_maximum_prefix_threshold_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/maximum-prefix/threshold");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_maximum_prefix_threshold_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/maximum-prefix/threshold");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_maximum_prefix_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/maximum-prefix/warning-only");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_maximum_prefix_restart_interval_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/maximum-prefix/restart-interval");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_maximum_prefix_restart_interval_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/maximum-prefix/restart-interval");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_maximum_prefix_force_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/maximum-prefix/force");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_maximum_prefix_out_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/maximum-prefix-out");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_maximum_prefix_out_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/maximum-prefix-out");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_route_server_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/route-server-client");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_nexthop_local_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/nexthop-local-unchanged");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_allowas_in_enabled_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/allowas-in/enabled");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_allowas_in_count_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/allowas-in/count");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_allowas_in_count_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/allowas-in/count");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_allowas_in_origin_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/allowas-in/origin");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_allowas_in_route_map_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/allowas-in/route-map");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_allowas_in_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/allowas-in/route-map");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_accept_own_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/accept-own");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_soo_create(struct nb_cb_create_args *args)
{
	return bgp_nb_neighbor_af_soo_create(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_soo_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_soo_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_soo_as2_create(struct nb_cb_create_args *args)
{
	return bgp_nb_neighbor_af_soo_case_create(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_soo_as2_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_soo_case_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_soo_as2_global_admin_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_soo_leaf_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_soo_as2_local_admin_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_soo_leaf_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_soo_as4_create(struct nb_cb_create_args *args)
{
	return bgp_nb_neighbor_af_soo_case_create(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_soo_as4_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_soo_case_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_soo_as4_global_admin_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_soo_leaf_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_soo_as4_local_admin_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_soo_leaf_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_soo_ipv4_create(struct nb_cb_create_args *args)
{
	return bgp_nb_neighbor_af_soo_case_create(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_soo_ipv4_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_soo_case_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_soo_ipv4_global_admin_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_soo_leaf_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_soo_ipv4_local_admin_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_soo_leaf_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_weight_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/weight");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_weight_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/weight");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_attribute_unchanged_as_path_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/attribute-unchanged/as-path");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_attribute_unchanged_next_hop_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/attribute-unchanged/next-hop");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_attribute_unchanged_med_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/attribute-unchanged/med");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_dampening_enabled_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/dampening/enabled");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_dampening_half_life_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/dampening/half-life");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_dampening_half_life_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/dampening/half-life");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_dampening_reuse_threshold_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/dampening/reuse-threshold");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_dampening_reuse_threshold_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/dampening/reuse-threshold");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_dampening_suppress_threshold_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/dampening/suppress-threshold");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_dampening_suppress_threshold_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/dampening/suppress-threshold");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_dampening_max_suppress_time_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/dampening/max-suppress-time");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_dampening_max_suppress_time_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/dampening/max-suppress-time");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_multicast_filters_distribute_list_in_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_distribute_list_modify(args, AFI_IP6, SAFI_MULTICAST, FILTER_IN);
}

int instance_neighbor_afi_safis_ipv6_multicast_filters_distribute_list_in_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_distribute_list_destroy(args, AFI_IP6, SAFI_MULTICAST, FILTER_IN);
}

int instance_neighbor_afi_safis_ipv6_multicast_filters_distribute_list_out_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_distribute_list_modify(args, AFI_IP6, SAFI_MULTICAST, FILTER_OUT);
}

int instance_neighbor_afi_safis_ipv6_multicast_filters_distribute_list_out_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_distribute_list_destroy(args, AFI_IP6, SAFI_MULTICAST,
							  FILTER_OUT);
}

int instance_neighbor_afi_safis_ipv6_multicast_filters_prefix_list_in_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_prefix_list_modify(args, AFI_IP6, SAFI_MULTICAST, FILTER_IN);
}

int instance_neighbor_afi_safis_ipv6_multicast_filters_prefix_list_in_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_prefix_list_destroy(args, AFI_IP6, SAFI_MULTICAST, FILTER_IN);
}

int instance_neighbor_afi_safis_ipv6_multicast_filters_prefix_list_out_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_prefix_list_modify(args, AFI_IP6, SAFI_MULTICAST, FILTER_OUT);
}

int instance_neighbor_afi_safis_ipv6_multicast_filters_prefix_list_out_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_prefix_list_destroy(args, AFI_IP6, SAFI_MULTICAST, FILTER_OUT);
}

int instance_neighbor_afi_safis_ipv6_multicast_filters_filter_list_in_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_filter_list_modify(args, AFI_IP6, SAFI_MULTICAST, FILTER_IN);
}

int instance_neighbor_afi_safis_ipv6_multicast_filters_filter_list_in_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_filter_list_destroy(args, AFI_IP6, SAFI_MULTICAST, FILTER_IN);
}

int instance_neighbor_afi_safis_ipv6_multicast_filters_filter_list_out_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_filter_list_modify(args, AFI_IP6, SAFI_MULTICAST, FILTER_OUT);
}

int instance_neighbor_afi_safis_ipv6_multicast_filters_filter_list_out_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_filter_list_destroy(args, AFI_IP6, SAFI_MULTICAST, FILTER_OUT);
}

int instance_neighbor_afi_safis_ipv6_multicast_filters_route_map_in_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_route_map_modify(args, AFI_IP6, SAFI_MULTICAST, RMAP_IN);
}

int instance_neighbor_afi_safis_ipv6_multicast_filters_route_map_in_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_route_map_destroy(args, AFI_IP6, SAFI_MULTICAST, RMAP_IN);
}

int instance_neighbor_afi_safis_ipv6_multicast_filters_route_map_out_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_route_map_modify(args, AFI_IP6, SAFI_MULTICAST, RMAP_OUT);
}

int instance_neighbor_afi_safis_ipv6_multicast_filters_route_map_out_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_route_map_destroy(args, AFI_IP6, SAFI_MULTICAST, RMAP_OUT);
}

int instance_neighbor_afi_safis_ipv6_multicast_filters_unsuppress_map_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_unsuppress_map_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_filters_unsuppress_map_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_unsuppress_map_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_filters_conditional_advertisement_advertise_map_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_advertise_map_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_filters_conditional_advertisement_advertise_map_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_advertise_map_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_filters_conditional_advertisement_condition_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_condition_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_filters_conditional_advertisement_condition_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_condition_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_filters_conditional_advertisement_condition_map_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_condition_map_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_filters_conditional_advertisement_condition_map_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_condition_map_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_activate_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_activate_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_activate_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_activate_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_addpath_tx_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/addpath/tx");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_addpath_tx_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/addpath/tx");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_addpath_tx_best_selected_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/addpath/tx-best-selected");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_addpath_tx_best_selected_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/addpath/tx-best-selected");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_addpath_disable_rx_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/addpath/disable-rx");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_addpath_rx_paths_limit_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/addpath/rx-paths-limit");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_addpath_rx_paths_limit_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/addpath/rx-paths-limit");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_orf_prefix_list_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/orf-prefix-list");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_orf_prefix_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/orf-prefix-list");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/route-reflector-client");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_next_hop_self_enabled_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/next-hop-self/enabled");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_next_hop_self_force_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/next-hop-self/force");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_remove_private_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/remove-private-as");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_remove_private_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/remove-private-as");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_as_override_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/as-override");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_send_community_standard_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/send-community/standard");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_send_community_standard_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/send-community/standard");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_send_community_extended_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/send-community/extended");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_send_community_extended_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/send-community/extended");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_send_community_large_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/send-community/large");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_send_community_large_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/send-community/large");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_send_community_extended_rpki_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/send-community/extended-rpki");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_default_originate_enabled_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/default-originate/enabled");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_default_originate_route_map_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/default-originate/route-map");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/default-originate/route-map");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_soft_reconfiguration_inbound_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/soft-reconfiguration-inbound");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_maximum_prefix_count_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/maximum-prefix/count");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_maximum_prefix_count_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/maximum-prefix/count");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_maximum_prefix_threshold_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/maximum-prefix/threshold");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_maximum_prefix_threshold_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/maximum-prefix/threshold");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_maximum_prefix_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/maximum-prefix/warning-only");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_maximum_prefix_restart_interval_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/maximum-prefix/restart-interval");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_maximum_prefix_restart_interval_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/maximum-prefix/restart-interval");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_maximum_prefix_force_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/maximum-prefix/force");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_maximum_prefix_out_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/maximum-prefix-out");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_maximum_prefix_out_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/maximum-prefix-out");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_route_server_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/route-server-client");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_nexthop_local_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/nexthop-local-unchanged");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_allowas_in_enabled_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/allowas-in/enabled");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_allowas_in_count_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/allowas-in/count");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_allowas_in_count_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/allowas-in/count");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_allowas_in_origin_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/allowas-in/origin");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_allowas_in_route_map_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/allowas-in/route-map");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_allowas_in_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/allowas-in/route-map");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_accept_own_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/accept-own");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_soo_create(struct nb_cb_create_args *args)
{
	return bgp_nb_neighbor_af_soo_create(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_soo_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_soo_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_soo_as2_create(struct nb_cb_create_args *args)
{
	return bgp_nb_neighbor_af_soo_case_create(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_soo_as2_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_soo_case_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_soo_as2_global_admin_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_soo_leaf_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_soo_as2_local_admin_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_soo_leaf_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_soo_as4_create(struct nb_cb_create_args *args)
{
	return bgp_nb_neighbor_af_soo_case_create(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_soo_as4_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_soo_case_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_soo_as4_global_admin_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_soo_leaf_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_soo_as4_local_admin_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_soo_leaf_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_soo_ipv4_create(struct nb_cb_create_args *args)
{
	return bgp_nb_neighbor_af_soo_case_create(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_soo_ipv4_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_soo_case_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_soo_ipv4_global_admin_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_soo_leaf_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_soo_ipv4_local_admin_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_soo_leaf_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_weight_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/weight");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_weight_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/weight");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_attribute_unchanged_as_path_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/attribute-unchanged/as-path");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_attribute_unchanged_next_hop_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/attribute-unchanged/next-hop");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_attribute_unchanged_med_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/attribute-unchanged/med");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_dampening_enabled_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/dampening/enabled");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_dampening_half_life_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/dampening/half-life");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_dampening_half_life_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/dampening/half-life");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_dampening_reuse_threshold_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/dampening/reuse-threshold");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_dampening_reuse_threshold_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/dampening/reuse-threshold");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_dampening_suppress_threshold_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/dampening/suppress-threshold");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_dampening_suppress_threshold_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/dampening/suppress-threshold");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_dampening_max_suppress_time_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/dampening/max-suppress-time");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_dampening_max_suppress_time_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/dampening/max-suppress-time");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_distribute_list_in_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_distribute_list_modify(args, AFI_IP6, SAFI_LABELED_UNICAST,
							 FILTER_IN);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_distribute_list_in_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_distribute_list_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST,
							  FILTER_IN);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_distribute_list_out_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_distribute_list_modify(args, AFI_IP6, SAFI_LABELED_UNICAST,
							 FILTER_OUT);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_distribute_list_out_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_distribute_list_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST,
							  FILTER_OUT);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_prefix_list_in_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_prefix_list_modify(args, AFI_IP6, SAFI_LABELED_UNICAST,
						     FILTER_IN);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_prefix_list_in_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_prefix_list_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST,
						      FILTER_IN);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_prefix_list_out_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_prefix_list_modify(args, AFI_IP6, SAFI_LABELED_UNICAST,
						     FILTER_OUT);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_prefix_list_out_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_prefix_list_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST,
						      FILTER_OUT);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_filter_list_in_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_filter_list_modify(args, AFI_IP6, SAFI_LABELED_UNICAST,
						     FILTER_IN);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_filter_list_in_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_filter_list_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST,
						      FILTER_IN);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_filter_list_out_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_filter_list_modify(args, AFI_IP6, SAFI_LABELED_UNICAST,
						     FILTER_OUT);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_filter_list_out_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_filter_list_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST,
						      FILTER_OUT);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_route_map_in_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_route_map_modify(args, AFI_IP6, SAFI_LABELED_UNICAST, RMAP_IN);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_route_map_in_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_route_map_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST, RMAP_IN);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_route_map_out_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_route_map_modify(args, AFI_IP6, SAFI_LABELED_UNICAST, RMAP_OUT);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_route_map_out_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_route_map_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST, RMAP_OUT);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_unsuppress_map_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_unsuppress_map_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_unsuppress_map_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_unsuppress_map_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_conditional_advertisement_advertise_map_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_advertise_map_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_conditional_advertisement_advertise_map_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_advertise_map_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_conditional_advertisement_condition_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_condition_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_conditional_advertisement_condition_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_condition_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_conditional_advertisement_condition_map_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_condition_map_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_conditional_advertisement_condition_map_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_condition_map_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_vpn_activate_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_activate_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_activate_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_activate_destroy(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_addpath_tx_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/addpath/tx");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_addpath_tx_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/addpath/tx");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_addpath_tx_best_selected_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/addpath/tx-best-selected");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_addpath_tx_best_selected_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/addpath/tx-best-selected");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_addpath_disable_rx_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/addpath/disable-rx");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_addpath_rx_paths_limit_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/addpath/rx-paths-limit");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_addpath_rx_paths_limit_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/addpath/rx-paths-limit");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_orf_prefix_list_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/orf-prefix-list");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_orf_prefix_list_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/orf-prefix-list");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_route_reflector_client_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/route-reflector-client");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_next_hop_self_enabled_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/next-hop-self/enabled");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_next_hop_self_force_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/next-hop-self/force");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_remove_private_as_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/remove-private-as");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_remove_private_as_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/remove-private-as");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_as_override_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/as-override");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_send_community_standard_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/send-community/standard");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_send_community_standard_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/send-community/standard");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_send_community_extended_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/send-community/extended");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_send_community_extended_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/send-community/extended");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_send_community_large_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/send-community/large");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_send_community_large_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/send-community/large");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_send_community_extended_rpki_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/send-community/extended-rpki");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_default_originate_enabled_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/default-originate/enabled");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_default_originate_route_map_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/default-originate/route-map");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/default-originate/route-map");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_soft_reconfiguration_inbound_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/soft-reconfiguration-inbound");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_maximum_prefix_count_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/maximum-prefix/count");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_maximum_prefix_count_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/maximum-prefix/count");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_maximum_prefix_threshold_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/maximum-prefix/threshold");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_maximum_prefix_threshold_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/maximum-prefix/threshold");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_maximum_prefix_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/maximum-prefix/warning-only");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_maximum_prefix_restart_interval_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/maximum-prefix/restart-interval");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_maximum_prefix_restart_interval_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/maximum-prefix/restart-interval");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_maximum_prefix_force_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/maximum-prefix/force");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_maximum_prefix_out_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/maximum-prefix-out");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_maximum_prefix_out_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/maximum-prefix-out");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_route_server_client_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/route-server-client");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_nexthop_local_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/nexthop-local-unchanged");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_allowas_in_enabled_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/allowas-in/enabled");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_allowas_in_count_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/allowas-in/count");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_allowas_in_count_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/allowas-in/count");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_allowas_in_origin_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/allowas-in/origin");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_allowas_in_route_map_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/allowas-in/route-map");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_allowas_in_route_map_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/allowas-in/route-map");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_accept_own_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/accept-own");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_soo_create(struct nb_cb_create_args *args)
{
	return bgp_nb_neighbor_af_soo_create(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_soo_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_soo_destroy(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_soo_as2_create(struct nb_cb_create_args *args)
{
	return bgp_nb_neighbor_af_soo_case_create(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_soo_as2_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_soo_case_destroy(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_soo_as2_global_admin_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_soo_leaf_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_soo_as2_local_admin_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_soo_leaf_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_soo_as4_create(struct nb_cb_create_args *args)
{
	return bgp_nb_neighbor_af_soo_case_create(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_soo_as4_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_soo_case_destroy(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_soo_as4_global_admin_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_soo_leaf_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_soo_as4_local_admin_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_soo_leaf_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_soo_ipv4_create(struct nb_cb_create_args *args)
{
	return bgp_nb_neighbor_af_soo_case_create(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_soo_ipv4_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_soo_case_destroy(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_soo_ipv4_global_admin_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_soo_leaf_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_soo_ipv4_local_admin_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_soo_leaf_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_weight_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/weight");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_weight_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/weight");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_attribute_unchanged_as_path_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/attribute-unchanged/as-path");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_attribute_unchanged_next_hop_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/attribute-unchanged/next-hop");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_attribute_unchanged_med_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/attribute-unchanged/med");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_dampening_enabled_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/dampening/enabled");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_dampening_half_life_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/dampening/half-life");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_dampening_half_life_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/dampening/half-life");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_dampening_reuse_threshold_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/dampening/reuse-threshold");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_dampening_reuse_threshold_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/dampening/reuse-threshold");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_dampening_suppress_threshold_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/dampening/suppress-threshold");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_dampening_suppress_threshold_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/dampening/suppress-threshold");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_dampening_max_suppress_time_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/dampening/max-suppress-time");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_dampening_max_suppress_time_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/dampening/max-suppress-time");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_afi_safis_ipv6_vpn_filters_distribute_list_in_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_distribute_list_modify(args, AFI_IP6, SAFI_MPLS_VPN, FILTER_IN);
}

int instance_neighbor_afi_safis_ipv6_vpn_filters_distribute_list_in_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_distribute_list_destroy(args, AFI_IP6, SAFI_MPLS_VPN, FILTER_IN);
}

int instance_neighbor_afi_safis_ipv6_vpn_filters_distribute_list_out_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_distribute_list_modify(args, AFI_IP6, SAFI_MPLS_VPN, FILTER_OUT);
}

int instance_neighbor_afi_safis_ipv6_vpn_filters_distribute_list_out_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_distribute_list_destroy(args, AFI_IP6, SAFI_MPLS_VPN, FILTER_OUT);
}

int instance_neighbor_afi_safis_ipv6_vpn_filters_prefix_list_in_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_prefix_list_modify(args, AFI_IP6, SAFI_MPLS_VPN, FILTER_IN);
}

int instance_neighbor_afi_safis_ipv6_vpn_filters_prefix_list_in_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_prefix_list_destroy(args, AFI_IP6, SAFI_MPLS_VPN, FILTER_IN);
}

int instance_neighbor_afi_safis_ipv6_vpn_filters_prefix_list_out_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_prefix_list_modify(args, AFI_IP6, SAFI_MPLS_VPN, FILTER_OUT);
}

int instance_neighbor_afi_safis_ipv6_vpn_filters_prefix_list_out_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_prefix_list_destroy(args, AFI_IP6, SAFI_MPLS_VPN, FILTER_OUT);
}

int instance_neighbor_afi_safis_ipv6_vpn_filters_filter_list_in_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_filter_list_modify(args, AFI_IP6, SAFI_MPLS_VPN, FILTER_IN);
}

int instance_neighbor_afi_safis_ipv6_vpn_filters_filter_list_in_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_filter_list_destroy(args, AFI_IP6, SAFI_MPLS_VPN, FILTER_IN);
}

int instance_neighbor_afi_safis_ipv6_vpn_filters_filter_list_out_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_filter_list_modify(args, AFI_IP6, SAFI_MPLS_VPN, FILTER_OUT);
}

int instance_neighbor_afi_safis_ipv6_vpn_filters_filter_list_out_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_filter_list_destroy(args, AFI_IP6, SAFI_MPLS_VPN, FILTER_OUT);
}

int instance_neighbor_afi_safis_ipv6_vpn_filters_route_map_in_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_route_map_modify(args, AFI_IP6, SAFI_MPLS_VPN, RMAP_IN);
}

int instance_neighbor_afi_safis_ipv6_vpn_filters_route_map_in_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_route_map_destroy(args, AFI_IP6, SAFI_MPLS_VPN, RMAP_IN);
}

int instance_neighbor_afi_safis_ipv6_vpn_filters_route_map_out_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_route_map_modify(args, AFI_IP6, SAFI_MPLS_VPN, RMAP_OUT);
}

int instance_neighbor_afi_safis_ipv6_vpn_filters_route_map_out_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_route_map_destroy(args, AFI_IP6, SAFI_MPLS_VPN, RMAP_OUT);
}

int instance_neighbor_afi_safis_ipv6_vpn_filters_unsuppress_map_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_unsuppress_map_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_filters_unsuppress_map_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_unsuppress_map_destroy(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_filters_conditional_advertisement_advertise_map_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_advertise_map_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_filters_conditional_advertisement_advertise_map_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_advertise_map_destroy(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_filters_conditional_advertisement_condition_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_condition_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_filters_conditional_advertisement_condition_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_condition_destroy(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_filters_conditional_advertisement_condition_map_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_condition_map_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_filters_conditional_advertisement_condition_map_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_condition_map_destroy(args, AFI_IP6, SAFI_MPLS_VPN);
}
