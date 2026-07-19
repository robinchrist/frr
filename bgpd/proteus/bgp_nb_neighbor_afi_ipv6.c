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
	return bgp_nb_neighbor_af_addpath_tx_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_addpath_tx_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_addpath_tx_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_addpath_tx_best_selected_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_addpath_tx_best_selected_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_addpath_tx_best_selected_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_addpath_tx_best_selected_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_addpath_disable_rx_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_UNICAST, PEER_FLAG_DISABLE_ADDPATH_RX);
}

int instance_neighbor_afi_safis_ipv6_unicast_addpath_rx_paths_limit_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_addpath_rx_paths_limit_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_addpath_rx_paths_limit_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_addpath_rx_paths_limit_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_orf_prefix_list_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_orf_prefix_list_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_orf_prefix_list_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_orf_prefix_list_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_UNICAST,
					      PEER_FLAG_REFLECTOR_CLIENT);
}

int instance_neighbor_afi_safis_ipv6_unicast_next_hop_self_enabled_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_UNICAST, PEER_FLAG_NEXTHOP_SELF);
}

int instance_neighbor_afi_safis_ipv6_unicast_next_hop_self_force_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_UNICAST,
					      PEER_FLAG_FORCE_NEXTHOP_SELF);
}

int instance_neighbor_afi_safis_ipv6_unicast_remove_private_as_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_remove_private_as_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_remove_private_as_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_remove_private_as_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_as_override_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_UNICAST, PEER_FLAG_AS_OVERRIDE);
}

int instance_neighbor_afi_safis_ipv6_unicast_send_community_standard_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(
		args, AFI_IP6, SAFI_UNICAST, PEER_FLAG_SEND_COMMUNITY);
}

int instance_neighbor_afi_safis_ipv6_unicast_send_community_standard_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_flag_destroy(
		args, AFI_IP6, SAFI_UNICAST, PEER_FLAG_SEND_COMMUNITY, true);
}

int instance_neighbor_afi_safis_ipv6_unicast_send_community_extended_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(
		args, AFI_IP6, SAFI_UNICAST, PEER_FLAG_SEND_EXT_COMMUNITY);
}

int instance_neighbor_afi_safis_ipv6_unicast_send_community_extended_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_flag_destroy(
		args, AFI_IP6, SAFI_UNICAST, PEER_FLAG_SEND_EXT_COMMUNITY, true);
}

int instance_neighbor_afi_safis_ipv6_unicast_send_community_large_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(
		args, AFI_IP6, SAFI_UNICAST, PEER_FLAG_SEND_LARGE_COMMUNITY);
}

int instance_neighbor_afi_safis_ipv6_unicast_send_community_large_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_flag_destroy(
		args, AFI_IP6, SAFI_UNICAST, PEER_FLAG_SEND_LARGE_COMMUNITY, true);
}

int instance_neighbor_afi_safis_ipv6_unicast_send_community_extended_rpki_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(
		args, AFI_IP6, SAFI_UNICAST, PEER_FLAG_SEND_EXT_COMMUNITY_RPKI);
}

int instance_neighbor_afi_safis_ipv6_unicast_default_originate_enabled_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_default_originate_enabled_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_default_originate_route_map_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_default_originate_route_map_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_default_originate_route_map_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_default_originate_route_map_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_soft_reconfiguration_inbound_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_UNICAST,
					      PEER_FLAG_SOFT_RECONFIG);
}

int instance_neighbor_afi_safis_ipv6_unicast_maximum_prefix_count_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_count_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_maximum_prefix_count_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_count_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_maximum_prefix_threshold_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_threshold_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_maximum_prefix_threshold_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_threshold_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_maximum_prefix_warning_only_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_warning_only_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_maximum_prefix_restart_interval_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_restart_interval_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_maximum_prefix_restart_interval_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_restart_interval_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_maximum_prefix_force_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_force_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_maximum_prefix_out_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_out_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_maximum_prefix_out_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_out_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_route_server_client_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_UNICAST,
					      PEER_FLAG_RSERVER_CLIENT);
}

int instance_neighbor_afi_safis_ipv6_unicast_nexthop_local_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_UNICAST,
					      PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED);
}

int instance_neighbor_afi_safis_ipv6_unicast_allowas_in_enabled_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_allowas_in_enabled_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_allowas_in_count_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_allowas_in_count_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_allowas_in_count_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_allowas_in_count_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_allowas_in_origin_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_allowas_in_origin_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_allowas_in_route_map_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_allowas_in_route_map_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_allowas_in_route_map_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_allowas_in_route_map_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_accept_own_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_UNICAST, PEER_FLAG_ACCEPT_OWN);
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
	return bgp_nb_neighbor_af_weight_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_weight_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_weight_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_attribute_unchanged_as_path_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_UNICAST,
					      PEER_FLAG_AS_PATH_UNCHANGED);
}

int instance_neighbor_afi_safis_ipv6_unicast_attribute_unchanged_next_hop_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_UNICAST,
					      PEER_FLAG_NEXTHOP_UNCHANGED);
}

int instance_neighbor_afi_safis_ipv6_unicast_attribute_unchanged_med_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_UNICAST,
					      PEER_FLAG_MED_UNCHANGED);
}

int instance_neighbor_afi_safis_ipv6_unicast_dampening_enabled_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_dampening_enabled_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_dampening_half_life_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_dampening_half_life_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_dampening_half_life_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_dampening_half_life_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_dampening_reuse_threshold_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_dampening_reuse_threshold_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_dampening_reuse_threshold_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_dampening_reuse_threshold_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_dampening_suppress_threshold_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_dampening_suppress_threshold_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_dampening_suppress_threshold_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_dampening_suppress_threshold_destroy(args, AFI_IP6,
								       SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_dampening_max_suppress_time_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_dampening_max_suppress_time_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_dampening_max_suppress_time_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_dampening_max_suppress_time_destroy(args, AFI_IP6, SAFI_UNICAST);
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
	return bgp_nb_neighbor_af_addpath_tx_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_addpath_tx_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_addpath_tx_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_addpath_tx_best_selected_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_addpath_tx_best_selected_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_addpath_tx_best_selected_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_addpath_tx_best_selected_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_addpath_disable_rx_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_MULTICAST,
					      PEER_FLAG_DISABLE_ADDPATH_RX);
}

int instance_neighbor_afi_safis_ipv6_multicast_addpath_rx_paths_limit_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_addpath_rx_paths_limit_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_addpath_rx_paths_limit_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_addpath_rx_paths_limit_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_orf_prefix_list_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_orf_prefix_list_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_orf_prefix_list_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_orf_prefix_list_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_MULTICAST,
					      PEER_FLAG_REFLECTOR_CLIENT);
}

int instance_neighbor_afi_safis_ipv6_multicast_next_hop_self_enabled_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_MULTICAST,
					      PEER_FLAG_NEXTHOP_SELF);
}

int instance_neighbor_afi_safis_ipv6_multicast_next_hop_self_force_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_MULTICAST,
					      PEER_FLAG_FORCE_NEXTHOP_SELF);
}

int instance_neighbor_afi_safis_ipv6_multicast_remove_private_as_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_remove_private_as_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_remove_private_as_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_remove_private_as_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_as_override_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_MULTICAST,
					      PEER_FLAG_AS_OVERRIDE);
}

int instance_neighbor_afi_safis_ipv6_multicast_send_community_standard_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(
		args, AFI_IP6, SAFI_MULTICAST, PEER_FLAG_SEND_COMMUNITY);
}

int instance_neighbor_afi_safis_ipv6_multicast_send_community_standard_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_flag_destroy(
		args, AFI_IP6, SAFI_MULTICAST, PEER_FLAG_SEND_COMMUNITY, true);
}

int instance_neighbor_afi_safis_ipv6_multicast_send_community_extended_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(
		args, AFI_IP6, SAFI_MULTICAST, PEER_FLAG_SEND_EXT_COMMUNITY);
}

int instance_neighbor_afi_safis_ipv6_multicast_send_community_extended_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_flag_destroy(
		args, AFI_IP6, SAFI_MULTICAST, PEER_FLAG_SEND_EXT_COMMUNITY, true);
}

int instance_neighbor_afi_safis_ipv6_multicast_send_community_large_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(
		args, AFI_IP6, SAFI_MULTICAST, PEER_FLAG_SEND_LARGE_COMMUNITY);
}

int instance_neighbor_afi_safis_ipv6_multicast_send_community_large_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_flag_destroy(
		args, AFI_IP6, SAFI_MULTICAST, PEER_FLAG_SEND_LARGE_COMMUNITY, true);
}

int instance_neighbor_afi_safis_ipv6_multicast_send_community_extended_rpki_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(
		args, AFI_IP6, SAFI_MULTICAST, PEER_FLAG_SEND_EXT_COMMUNITY_RPKI);
}

int instance_neighbor_afi_safis_ipv6_multicast_default_originate_enabled_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_default_originate_enabled_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_default_originate_route_map_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_default_originate_route_map_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_default_originate_route_map_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_default_originate_route_map_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_soft_reconfiguration_inbound_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_MULTICAST,
					      PEER_FLAG_SOFT_RECONFIG);
}

int instance_neighbor_afi_safis_ipv6_multicast_maximum_prefix_count_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_count_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_maximum_prefix_count_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_count_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_maximum_prefix_threshold_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_threshold_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_maximum_prefix_threshold_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_threshold_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_maximum_prefix_warning_only_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_warning_only_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_maximum_prefix_restart_interval_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_restart_interval_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_maximum_prefix_restart_interval_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_restart_interval_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_maximum_prefix_force_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_force_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_maximum_prefix_out_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_out_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_maximum_prefix_out_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_out_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_route_server_client_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_MULTICAST,
					      PEER_FLAG_RSERVER_CLIENT);
}

int instance_neighbor_afi_safis_ipv6_multicast_nexthop_local_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_MULTICAST,
					      PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED);
}

int instance_neighbor_afi_safis_ipv6_multicast_allowas_in_enabled_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_allowas_in_enabled_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_allowas_in_count_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_allowas_in_count_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_allowas_in_count_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_allowas_in_count_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_allowas_in_origin_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_allowas_in_origin_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_allowas_in_route_map_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_allowas_in_route_map_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_allowas_in_route_map_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_allowas_in_route_map_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_accept_own_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_MULTICAST, PEER_FLAG_ACCEPT_OWN);
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
	return bgp_nb_neighbor_af_weight_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_weight_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_weight_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_attribute_unchanged_as_path_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_MULTICAST,
					      PEER_FLAG_AS_PATH_UNCHANGED);
}

int instance_neighbor_afi_safis_ipv6_multicast_attribute_unchanged_next_hop_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_MULTICAST,
					      PEER_FLAG_NEXTHOP_UNCHANGED);
}

int instance_neighbor_afi_safis_ipv6_multicast_attribute_unchanged_med_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_MULTICAST,
					      PEER_FLAG_MED_UNCHANGED);
}

int instance_neighbor_afi_safis_ipv6_multicast_dampening_enabled_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_dampening_enabled_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_dampening_half_life_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_dampening_half_life_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_dampening_half_life_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_dampening_half_life_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_dampening_reuse_threshold_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_dampening_reuse_threshold_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_dampening_reuse_threshold_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_dampening_reuse_threshold_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_dampening_suppress_threshold_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_dampening_suppress_threshold_modify(args, AFI_IP6,
								      SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_dampening_suppress_threshold_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_dampening_suppress_threshold_destroy(args, AFI_IP6,
								       SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_dampening_max_suppress_time_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_dampening_max_suppress_time_modify(args, AFI_IP6,
								     SAFI_MULTICAST);
}

int instance_neighbor_afi_safis_ipv6_multicast_dampening_max_suppress_time_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_dampening_max_suppress_time_destroy(args, AFI_IP6,
								      SAFI_MULTICAST);
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

int instance_neighbor_afi_safis_ipv6_labeled_unicast_addpath_tx_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_addpath_tx_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_addpath_tx_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_addpath_tx_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_addpath_tx_best_selected_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_addpath_tx_best_selected_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_addpath_tx_best_selected_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_addpath_tx_best_selected_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_addpath_disable_rx_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_LABELED_UNICAST,
					      PEER_FLAG_DISABLE_ADDPATH_RX);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_addpath_rx_paths_limit_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_addpath_rx_paths_limit_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_addpath_rx_paths_limit_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_addpath_rx_paths_limit_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_orf_prefix_list_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_orf_prefix_list_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_orf_prefix_list_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_orf_prefix_list_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_LABELED_UNICAST,
					      PEER_FLAG_REFLECTOR_CLIENT);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_next_hop_self_enabled_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_LABELED_UNICAST,
					      PEER_FLAG_NEXTHOP_SELF);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_next_hop_self_force_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_LABELED_UNICAST,
					      PEER_FLAG_FORCE_NEXTHOP_SELF);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_remove_private_as_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_remove_private_as_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_remove_private_as_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_remove_private_as_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_as_override_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_LABELED_UNICAST,
					      PEER_FLAG_AS_OVERRIDE);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_send_community_standard_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(
		args, AFI_IP6, SAFI_LABELED_UNICAST, PEER_FLAG_SEND_COMMUNITY);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_send_community_standard_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_flag_destroy(
		args, AFI_IP6, SAFI_LABELED_UNICAST, PEER_FLAG_SEND_COMMUNITY, true);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_send_community_extended_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(
		args, AFI_IP6, SAFI_LABELED_UNICAST, PEER_FLAG_SEND_EXT_COMMUNITY);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_send_community_extended_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_flag_destroy(
		args, AFI_IP6, SAFI_LABELED_UNICAST, PEER_FLAG_SEND_EXT_COMMUNITY, true);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_send_community_large_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(
		args, AFI_IP6, SAFI_LABELED_UNICAST, PEER_FLAG_SEND_LARGE_COMMUNITY);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_send_community_large_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_flag_destroy(
		args, AFI_IP6, SAFI_LABELED_UNICAST, PEER_FLAG_SEND_LARGE_COMMUNITY, true);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_send_community_extended_rpki_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(
		args, AFI_IP6, SAFI_LABELED_UNICAST, PEER_FLAG_SEND_EXT_COMMUNITY_RPKI);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_default_originate_enabled_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_default_originate_enabled_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_default_originate_route_map_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_default_originate_route_map_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_default_originate_route_map_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_default_originate_route_map_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_soft_reconfiguration_inbound_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_LABELED_UNICAST,
					      PEER_FLAG_SOFT_RECONFIG);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_maximum_prefix_count_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_count_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_maximum_prefix_count_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_count_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_maximum_prefix_threshold_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_threshold_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_maximum_prefix_threshold_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_threshold_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_maximum_prefix_warning_only_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_warning_only_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_maximum_prefix_restart_interval_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_restart_interval_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_maximum_prefix_restart_interval_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_restart_interval_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_maximum_prefix_force_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_force_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_maximum_prefix_out_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_out_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_maximum_prefix_out_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_out_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_route_server_client_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_LABELED_UNICAST,
					      PEER_FLAG_RSERVER_CLIENT);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_nexthop_local_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_LABELED_UNICAST,
					      PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_allowas_in_enabled_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_allowas_in_enabled_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_allowas_in_count_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_allowas_in_count_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_allowas_in_count_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_allowas_in_count_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_allowas_in_origin_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_allowas_in_origin_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_allowas_in_route_map_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_allowas_in_route_map_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_allowas_in_route_map_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_allowas_in_route_map_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_accept_own_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_LABELED_UNICAST,
					      PEER_FLAG_ACCEPT_OWN);
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
	return bgp_nb_neighbor_af_weight_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_weight_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_weight_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_attribute_unchanged_as_path_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_LABELED_UNICAST,
					      PEER_FLAG_AS_PATH_UNCHANGED);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_attribute_unchanged_next_hop_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_LABELED_UNICAST,
					      PEER_FLAG_NEXTHOP_UNCHANGED);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_attribute_unchanged_med_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_LABELED_UNICAST,
					      PEER_FLAG_MED_UNCHANGED);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_dampening_enabled_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_dampening_enabled_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_dampening_half_life_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_dampening_half_life_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_dampening_half_life_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_dampening_half_life_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_dampening_reuse_threshold_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_dampening_reuse_threshold_modify(args, AFI_IP6,
								   SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_dampening_reuse_threshold_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_dampening_reuse_threshold_destroy(args, AFI_IP6,
								    SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_dampening_suppress_threshold_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_dampening_suppress_threshold_modify(args, AFI_IP6,
								      SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_dampening_suppress_threshold_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_dampening_suppress_threshold_destroy(args, AFI_IP6,
								       SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_dampening_max_suppress_time_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_dampening_max_suppress_time_modify(args, AFI_IP6,
								     SAFI_LABELED_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_labeled_unicast_dampening_max_suppress_time_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_dampening_max_suppress_time_destroy(args, AFI_IP6,
								      SAFI_LABELED_UNICAST);
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
	return bgp_nb_neighbor_af_addpath_tx_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_addpath_tx_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_addpath_tx_destroy(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_addpath_tx_best_selected_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_addpath_tx_best_selected_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_addpath_tx_best_selected_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_addpath_tx_best_selected_destroy(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_addpath_disable_rx_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_MPLS_VPN, PEER_FLAG_DISABLE_ADDPATH_RX);
}

int instance_neighbor_afi_safis_ipv6_vpn_addpath_rx_paths_limit_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_addpath_rx_paths_limit_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_addpath_rx_paths_limit_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_addpath_rx_paths_limit_destroy(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_orf_prefix_list_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_orf_prefix_list_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_orf_prefix_list_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_orf_prefix_list_destroy(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_MPLS_VPN,
					      PEER_FLAG_REFLECTOR_CLIENT);
}

int instance_neighbor_afi_safis_ipv6_vpn_next_hop_self_enabled_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_MPLS_VPN,
					      PEER_FLAG_NEXTHOP_SELF);
}

int instance_neighbor_afi_safis_ipv6_vpn_next_hop_self_force_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_MPLS_VPN,
					      PEER_FLAG_FORCE_NEXTHOP_SELF);
}

int instance_neighbor_afi_safis_ipv6_vpn_remove_private_as_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_remove_private_as_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_remove_private_as_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_remove_private_as_destroy(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_as_override_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_MPLS_VPN, PEER_FLAG_AS_OVERRIDE);
}

int instance_neighbor_afi_safis_ipv6_vpn_send_community_standard_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(
		args, AFI_IP6, SAFI_MPLS_VPN, PEER_FLAG_SEND_COMMUNITY);
}

int instance_neighbor_afi_safis_ipv6_vpn_send_community_standard_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_flag_destroy(
		args, AFI_IP6, SAFI_MPLS_VPN, PEER_FLAG_SEND_COMMUNITY, true);
}

int instance_neighbor_afi_safis_ipv6_vpn_send_community_extended_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(
		args, AFI_IP6, SAFI_MPLS_VPN, PEER_FLAG_SEND_EXT_COMMUNITY);
}

int instance_neighbor_afi_safis_ipv6_vpn_send_community_extended_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_flag_destroy(
		args, AFI_IP6, SAFI_MPLS_VPN, PEER_FLAG_SEND_EXT_COMMUNITY, true);
}

int instance_neighbor_afi_safis_ipv6_vpn_send_community_large_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(
		args, AFI_IP6, SAFI_MPLS_VPN, PEER_FLAG_SEND_LARGE_COMMUNITY);
}

int instance_neighbor_afi_safis_ipv6_vpn_send_community_large_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_flag_destroy(
		args, AFI_IP6, SAFI_MPLS_VPN, PEER_FLAG_SEND_LARGE_COMMUNITY, true);
}

int instance_neighbor_afi_safis_ipv6_vpn_send_community_extended_rpki_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(
		args, AFI_IP6, SAFI_MPLS_VPN, PEER_FLAG_SEND_EXT_COMMUNITY_RPKI);
}

int instance_neighbor_afi_safis_ipv6_vpn_default_originate_enabled_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_default_originate_enabled_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_default_originate_route_map_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_default_originate_route_map_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_default_originate_route_map_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_default_originate_route_map_destroy(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_soft_reconfiguration_inbound_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_MPLS_VPN,
					      PEER_FLAG_SOFT_RECONFIG);
}

int instance_neighbor_afi_safis_ipv6_vpn_maximum_prefix_count_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_count_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_maximum_prefix_count_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_count_destroy(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_maximum_prefix_threshold_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_threshold_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_maximum_prefix_threshold_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_threshold_destroy(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_maximum_prefix_warning_only_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_warning_only_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_maximum_prefix_restart_interval_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_restart_interval_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_maximum_prefix_restart_interval_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_restart_interval_destroy(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_maximum_prefix_force_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_force_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_maximum_prefix_out_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_out_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_maximum_prefix_out_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_maximum_prefix_out_destroy(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_route_server_client_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_MPLS_VPN,
					      PEER_FLAG_RSERVER_CLIENT);
}

int instance_neighbor_afi_safis_ipv6_vpn_nexthop_local_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_MPLS_VPN,
					      PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED);
}

int instance_neighbor_afi_safis_ipv6_vpn_allowas_in_enabled_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_allowas_in_enabled_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_allowas_in_count_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_allowas_in_count_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_allowas_in_count_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_allowas_in_count_destroy(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_allowas_in_origin_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_allowas_in_origin_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_allowas_in_route_map_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_allowas_in_route_map_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_allowas_in_route_map_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_allowas_in_route_map_destroy(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_accept_own_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_MPLS_VPN, PEER_FLAG_ACCEPT_OWN);
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
	return bgp_nb_neighbor_af_weight_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_weight_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_weight_destroy(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_attribute_unchanged_as_path_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_MPLS_VPN,
					      PEER_FLAG_AS_PATH_UNCHANGED);
}

int instance_neighbor_afi_safis_ipv6_vpn_attribute_unchanged_next_hop_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_MPLS_VPN,
					      PEER_FLAG_NEXTHOP_UNCHANGED);
}

int instance_neighbor_afi_safis_ipv6_vpn_attribute_unchanged_med_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_MPLS_VPN,
					      PEER_FLAG_MED_UNCHANGED);
}

int instance_neighbor_afi_safis_ipv6_vpn_dampening_enabled_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_dampening_enabled_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_dampening_half_life_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_dampening_half_life_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_dampening_half_life_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_dampening_half_life_destroy(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_dampening_reuse_threshold_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_dampening_reuse_threshold_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_dampening_reuse_threshold_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_dampening_reuse_threshold_destroy(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_dampening_suppress_threshold_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_dampening_suppress_threshold_modify(args, AFI_IP6,
								      SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_dampening_suppress_threshold_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_dampening_suppress_threshold_destroy(args, AFI_IP6,
								       SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_dampening_max_suppress_time_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_dampening_max_suppress_time_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_neighbor_afi_safis_ipv6_vpn_dampening_max_suppress_time_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_dampening_max_suppress_time_destroy(args, AFI_IP6,
								      SAFI_MPLS_VPN);
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

/* M8.5 encapsulation knobs. */
int instance_neighbor_afi_safis_ipv6_unicast_encapsulation_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_encap_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_unicast_encapsulation_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_encap_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_neighbor_afi_safis_ipv6_vpn_encapsulation_srv6_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_MPLS_VPN,
					      PEER_FLAG_CONFIG_ENCAPSULATION_SRV6);
}

int instance_neighbor_afi_safis_ipv6_vpn_encapsulation_mpls_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_flag_modify(args, AFI_IP6, SAFI_MPLS_VPN,
					      PEER_FLAG_CONFIG_ENCAPSULATION_MPLS);
}
