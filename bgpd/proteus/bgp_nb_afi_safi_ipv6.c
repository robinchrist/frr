// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Robin Christ, partimus GmbH */
/* Northbound callbacks for instance-level /proteus-bgp:instance/afi-safis IPv6 address families.
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


int instance_afi_safis_ipv6_unicast_network_create(struct nb_cb_create_args *args)
{
	return bgp_nb_af_network_create(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_network_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_network_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_network_route_map_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_network_route_map_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_network_route_map_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_network_route_map_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_network_label_index_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_network_label_index_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_network_label_index_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_network_label_index_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_aggregate_address_create(struct nb_cb_create_args *args)
{
	return bgp_nb_af_aggregate_create(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_aggregate_address_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_aggregate_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_aggregate_address_as_set_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_aggregate_as_set_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_aggregate_address_summary_only_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_aggregate_summary_only_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_aggregate_address_route_map_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_aggregate_route_map_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_aggregate_address_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_aggregate_route_map_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_aggregate_address_origin_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_aggregate_origin_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_aggregate_address_origin_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_aggregate_origin_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_aggregate_address_matching_med_only_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_aggregate_matching_med_only_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_aggregate_address_suppress_map_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_aggregate_suppress_map_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_aggregate_address_suppress_map_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_aggregate_suppress_map_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_redistribute_create(struct nb_cb_create_args *args)
{
	return bgp_nb_af_redistribute_create(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_redistribute_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_redistribute_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_redistribute_metric_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_redistribute_metric_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_redistribute_metric_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_redistribute_metric_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_redistribute_route_map_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_redistribute_route_map_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_redistribute_route_map_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_redistribute_route_map_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_maximum_paths_ebgp_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_maximum_paths_ebgp_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_maximum_paths_ebgp_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_maximum_paths_ebgp_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_maximum_paths_ibgp_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_maximum_paths_ibgp_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_maximum_paths_ibgp_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_maximum_paths_ibgp_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_maximum_paths_ibgp_equal_cluster_length_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_maximum_paths_ibgp_equal_cluster_length_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_table_map_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_table_map_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_table_map_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_table_map_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_dampening_enabled_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_dampening_enabled_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_dampening_half_life_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_dampening_half_life_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_dampening_half_life_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_dampening_half_life_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_dampening_reuse_threshold_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_dampening_reuse_threshold_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_dampening_reuse_threshold_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_dampening_reuse_threshold_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_dampening_suppress_threshold_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_dampening_suppress_threshold_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_dampening_suppress_threshold_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_dampening_suppress_threshold_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_dampening_max_suppress_time_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_dampening_max_suppress_time_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_dampening_max_suppress_time_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_dampening_max_suppress_time_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_distance_ebgp_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_distance_ebgp_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_distance_ebgp_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_distance_ebgp_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_distance_ibgp_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_distance_ibgp_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_distance_ibgp_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_distance_ibgp_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_distance_local_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_distance_local_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_distance_local_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_distance_local_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_distance_prefix_create(struct nb_cb_create_args *args)
{
	return bgp_nb_af_distance_prefix_create(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_distance_prefix_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_distance_prefix_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_distance_prefix_distance_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_distance_prefix_distance_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_distance_prefix_access_list_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_distance_prefix_access_list_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_distance_prefix_access_list_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_distance_prefix_access_list_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_export_vpn_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_export_vpn_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_import_vpn_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_import_vpn_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_import_vrf_create(struct nb_cb_create_args *args)
{
	return bgp_nb_af_import_vrf_create(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_import_vrf_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_import_vrf_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_import_vrf_route_map_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_import_vrf_route_map_modify(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_import_vrf_route_map_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_import_vrf_route_map_destroy(args, AFI_IP6, SAFI_UNICAST);
}

int instance_afi_safis_ipv6_unicast_vpn_route_map_import_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/route-map-import");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_route_map_import_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/route-map-import");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_route_map_export_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/route-map-export");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_route_map_export_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/route-map-export");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_label_export_value_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/label-export/value");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_label_export_value_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/label-export/value");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_label_export_auto_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/label-export/auto");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_label_export_auto_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/label-export/auto");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_label_export_allocation_mode_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/label-export/allocation-mode");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_label_export_allocation_mode_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/label-export/allocation-mode");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_rd_export_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rd-export");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_rd_export_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rd-export");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_rd_export_as2_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rd-export/as2");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_rd_export_as2_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rd-export/as2");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_rd_export_as2_administrator_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rd-export/as2/administrator");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_rd_export_as2_assigned_number_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rd-export/as2/assigned-number");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_rd_export_ipv4_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rd-export/ipv4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_rd_export_ipv4_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rd-export/ipv4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_rd_export_ipv4_administrator_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rd-export/ipv4/administrator");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_rd_export_ipv4_assigned_number_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rd-export/ipv4/assigned-number");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_rd_export_as4_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rd-export/as4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_rd_export_as4_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rd-export/as4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_rd_export_as4_administrator_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rd-export/as4/administrator");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_rd_export_as4_assigned_number_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rd-export/as4/assigned-number");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_rd_export_mac_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rd-export/mac");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_rd_export_mac_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rd-export/mac");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_rd_export_raw_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rd-export/raw");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_rd_export_raw_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rd-export/raw");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_nexthop_export_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/nexthop-export");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_nexthop_export_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/nexthop-export");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_rt_import_as2_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rt-import/as2");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_rt_import_as2_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rt-import/as2");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_rt_import_as4_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rt-import/as4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_rt_import_as4_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rt-import/as4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_rt_import_ipv4_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rt-import/ipv4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_rt_import_ipv4_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rt-import/ipv4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_rt_export_as2_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rt-export/as2");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_rt_export_as2_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rt-export/as2");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_rt_export_as4_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rt-export/as4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_rt_export_as4_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rt-export/as4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_rt_export_ipv4_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rt-export/ipv4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_vpn_rt_export_ipv4_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rt-export/ipv4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/*
 * M5 batch B14: instance-AF 'nexthop prefer-global', ipv6-unicast only
 * (proteus-bgp.yang:3264). A no-default boolean (see the leaf's own
 * description and bgp_ipv6_nexthop_prefer_global_default(), bgp_vty.c) --
 * MODIFY sets the leaf's value via the vty-free core the legacy DEFUN was
 * split into (bgp_ipv6_nexthop_prefer_global_set()), DESTROY reverts to the
 * compile-time default (bgp_ipv6_nexthop_prefer_global_default()), the same
 * shape instance_ipv6_auto_ra_modify()/_destroy() (bgp_nb_instance.c) use
 * for the process-wide leaf's per-VRF override.
 */
int instance_afi_safis_ipv6_unicast_nexthop_prefer_global_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		bgp_ipv6_nexthop_prefer_global_set(bgp, AFI_IP6, SAFI_UNICAST,
						   yang_dnode_get_bool(args->dnode, NULL));
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_unicast_nexthop_prefer_global_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		bgp_ipv6_nexthop_prefer_global_set(bgp, AFI_IP6, SAFI_UNICAST,
						   bgp_ipv6_nexthop_prefer_global_default());
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_multicast_network_create(struct nb_cb_create_args *args)
{
	return bgp_nb_af_network_create(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_network_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_network_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_network_route_map_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_network_route_map_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_network_route_map_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_network_route_map_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_network_label_index_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_network_label_index_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_network_label_index_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_network_label_index_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_aggregate_address_create(struct nb_cb_create_args *args)
{
	return bgp_nb_af_aggregate_create(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_aggregate_address_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_aggregate_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_aggregate_address_as_set_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_aggregate_as_set_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_aggregate_address_summary_only_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_aggregate_summary_only_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_aggregate_address_route_map_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_aggregate_route_map_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_aggregate_address_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_aggregate_route_map_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_aggregate_address_origin_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_aggregate_origin_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_aggregate_address_origin_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_aggregate_origin_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_aggregate_address_matching_med_only_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_aggregate_matching_med_only_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_aggregate_address_suppress_map_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_aggregate_suppress_map_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_aggregate_address_suppress_map_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_aggregate_suppress_map_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_maximum_paths_ebgp_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_maximum_paths_ebgp_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_maximum_paths_ebgp_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_maximum_paths_ebgp_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_maximum_paths_ibgp_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_maximum_paths_ibgp_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_maximum_paths_ibgp_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_maximum_paths_ibgp_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_maximum_paths_ibgp_equal_cluster_length_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_maximum_paths_ibgp_equal_cluster_length_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_table_map_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_table_map_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_table_map_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_table_map_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_dampening_enabled_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_dampening_enabled_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_dampening_half_life_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_dampening_half_life_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_dampening_half_life_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_dampening_half_life_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_dampening_reuse_threshold_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_dampening_reuse_threshold_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_dampening_reuse_threshold_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_dampening_reuse_threshold_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_dampening_suppress_threshold_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_dampening_suppress_threshold_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_dampening_suppress_threshold_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_dampening_suppress_threshold_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_dampening_max_suppress_time_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_dampening_max_suppress_time_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_dampening_max_suppress_time_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_dampening_max_suppress_time_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_distance_ebgp_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_distance_ebgp_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_distance_ebgp_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_distance_ebgp_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_distance_ibgp_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_distance_ibgp_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_distance_ibgp_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_distance_ibgp_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_distance_local_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_distance_local_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_distance_local_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_distance_local_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_distance_prefix_create(struct nb_cb_create_args *args)
{
	return bgp_nb_af_distance_prefix_create(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_distance_prefix_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_distance_prefix_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_distance_prefix_distance_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_distance_prefix_distance_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_distance_prefix_access_list_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_distance_prefix_access_list_modify(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_multicast_distance_prefix_access_list_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_distance_prefix_access_list_destroy(args, AFI_IP6, SAFI_MULTICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_network_create(struct nb_cb_create_args *args)
{
	return bgp_nb_af_network_create(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_network_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_network_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_network_route_map_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_network_route_map_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_network_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_network_route_map_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_network_label_index_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_network_label_index_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_network_label_index_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_network_label_index_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_aggregate_address_create(
	struct nb_cb_create_args *args)
{
	return bgp_nb_af_aggregate_create(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_aggregate_address_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_aggregate_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_aggregate_address_as_set_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_aggregate_as_set_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_aggregate_address_summary_only_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_aggregate_summary_only_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_aggregate_address_route_map_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_aggregate_route_map_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_aggregate_address_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_aggregate_route_map_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_aggregate_address_origin_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_aggregate_origin_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_aggregate_address_origin_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_aggregate_origin_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_aggregate_address_matching_med_only_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_aggregate_matching_med_only_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_aggregate_address_suppress_map_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_aggregate_suppress_map_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_aggregate_address_suppress_map_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_aggregate_suppress_map_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_maximum_paths_ebgp_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_maximum_paths_ebgp_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_maximum_paths_ebgp_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_maximum_paths_ebgp_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_maximum_paths_ibgp_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_maximum_paths_ibgp_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_maximum_paths_ibgp_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_maximum_paths_ibgp_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_maximum_paths_ibgp_equal_cluster_length_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_maximum_paths_ibgp_equal_cluster_length_modify(args, AFI_IP6,
				SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_table_map_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_table_map_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_table_map_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_table_map_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_dampening_enabled_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_dampening_enabled_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_dampening_half_life_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_dampening_half_life_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_dampening_half_life_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_dampening_half_life_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_dampening_reuse_threshold_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_dampening_reuse_threshold_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_dampening_reuse_threshold_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_dampening_reuse_threshold_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_dampening_suppress_threshold_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_dampening_suppress_threshold_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_dampening_suppress_threshold_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_dampening_suppress_threshold_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_dampening_max_suppress_time_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_dampening_max_suppress_time_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_dampening_max_suppress_time_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_dampening_max_suppress_time_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_distance_ebgp_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_distance_ebgp_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_distance_ebgp_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_distance_ebgp_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_distance_ibgp_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_distance_ibgp_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_distance_ibgp_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_distance_ibgp_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_distance_local_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_distance_local_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_distance_local_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_distance_local_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_distance_prefix_create(struct nb_cb_create_args *args)
{
	return bgp_nb_af_distance_prefix_create(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_distance_prefix_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_distance_prefix_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_distance_prefix_distance_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_distance_prefix_distance_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_distance_prefix_access_list_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_distance_prefix_access_list_modify(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_labeled_unicast_distance_prefix_access_list_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_distance_prefix_access_list_destroy(args, AFI_IP6, SAFI_LABELED_UNICAST);
}

int instance_afi_safis_ipv6_vpn_network_as2_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-vpn/network/as2");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_vpn_network_as2_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-vpn/network/as2");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_vpn_network_as2_label_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-vpn/network/as2/label");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_vpn_network_as2_route_map_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-vpn/network/as2/route-map");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_vpn_network_as2_route_map_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-vpn/network/as2/route-map");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_vpn_network_ipv4_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-vpn/network/ipv4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_vpn_network_ipv4_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-vpn/network/ipv4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_vpn_network_ipv4_label_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-vpn/network/ipv4/label");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_vpn_network_ipv4_route_map_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-vpn/network/ipv4/route-map");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_vpn_network_ipv4_route_map_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-vpn/network/ipv4/route-map");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_vpn_network_as4_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-vpn/network/as4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_vpn_network_as4_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-vpn/network/as4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_vpn_network_as4_label_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-vpn/network/as4/label");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_vpn_network_as4_route_map_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-vpn/network/as4/route-map");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_vpn_network_as4_route_map_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-vpn/network/as4/route-map");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_vpn_network_raw_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-vpn/network/raw");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_vpn_network_raw_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-vpn/network/raw");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_vpn_network_raw_label_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-vpn/network/raw/label");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_vpn_network_raw_route_map_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-vpn/network/raw/route-map");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_vpn_network_raw_route_map_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-vpn/network/raw/route-map");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_vpn_maximum_paths_ebgp_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_maximum_paths_ebgp_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_afi_safis_ipv6_vpn_maximum_paths_ebgp_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_maximum_paths_ebgp_destroy(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_afi_safis_ipv6_vpn_maximum_paths_ibgp_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_maximum_paths_ibgp_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_afi_safis_ipv6_vpn_maximum_paths_ibgp_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_maximum_paths_ibgp_destroy(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_afi_safis_ipv6_vpn_maximum_paths_ibgp_equal_cluster_length_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_af_maximum_paths_ibgp_equal_cluster_length_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_afi_safis_ipv6_vpn_table_map_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_table_map_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_afi_safis_ipv6_vpn_table_map_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_table_map_destroy(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_afi_safis_ipv6_vpn_dampening_enabled_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_dampening_enabled_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_afi_safis_ipv6_vpn_dampening_half_life_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_dampening_half_life_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_afi_safis_ipv6_vpn_dampening_half_life_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_dampening_half_life_destroy(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_afi_safis_ipv6_vpn_dampening_reuse_threshold_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_dampening_reuse_threshold_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_afi_safis_ipv6_vpn_dampening_reuse_threshold_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_dampening_reuse_threshold_destroy(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_afi_safis_ipv6_vpn_dampening_suppress_threshold_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_dampening_suppress_threshold_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_afi_safis_ipv6_vpn_dampening_suppress_threshold_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_dampening_suppress_threshold_destroy(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_afi_safis_ipv6_vpn_dampening_max_suppress_time_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_dampening_max_suppress_time_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_afi_safis_ipv6_vpn_dampening_max_suppress_time_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_dampening_max_suppress_time_destroy(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_afi_safis_ipv6_vpn_distance_ebgp_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_distance_ebgp_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_afi_safis_ipv6_vpn_distance_ebgp_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_distance_ebgp_destroy(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_afi_safis_ipv6_vpn_distance_ibgp_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_distance_ibgp_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_afi_safis_ipv6_vpn_distance_ibgp_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_distance_ibgp_destroy(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_afi_safis_ipv6_vpn_distance_local_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_distance_local_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_afi_safis_ipv6_vpn_distance_local_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_distance_local_destroy(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_afi_safis_ipv6_vpn_distance_prefix_create(struct nb_cb_create_args *args)
{
	return bgp_nb_af_distance_prefix_create(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_afi_safis_ipv6_vpn_distance_prefix_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_distance_prefix_destroy(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_afi_safis_ipv6_vpn_distance_prefix_distance_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_distance_prefix_distance_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_afi_safis_ipv6_vpn_distance_prefix_access_list_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_af_distance_prefix_access_list_modify(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_afi_safis_ipv6_vpn_distance_prefix_access_list_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_af_distance_prefix_access_list_destroy(args, AFI_IP6, SAFI_MPLS_VPN);
}

int instance_afi_safis_ipv6_vpn_retain_route_target_all_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-vpn/retain-route-target-all");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_ipv6_vpn_retain_route_target_all_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/ipv6-vpn/retain-route-target-all");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}
