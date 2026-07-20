// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Robin Christ, partimus GmbH */
/* Route map CLI (northbound commands) for bgpd's frr-bgp-route-map
 * augment of frr-route-map. Copyright (C) 1998, 1999 Kunihiro
 * Ishiguro.
 *
 * Split out of bgp_routemap.c (bgpd-proteus-conversion M3, batch
 * B-RM3) so this CLI can be compiled into mgmtd, alongside
 * bgp_cli.c, the same split-CLI pattern used for zebra/staticd.
 * bgp_routemap.c keeps every route_map_rule_cmd (match/set runtime
 * compile/apply) and the frr-bgp-route-map northbound
 * .modify/.destroy callbacks (bgp_routemap_nb.c /
 * bgp_routemap_nb_config.c); only the CLI-side DEFUN_YANG/DEFPY_YANG
 * command bodies and their RMAP_NODE install_element() calls moved
 * here. cli_show for these nodes needs no relocation: frr-bgp-route-map
 * has no per-node .cli_show callbacks of its own (bgp_routemap_nb.c
 * has none) -- rendering goes through lib/routemap_cli.c's generic
 * nb_cli_show_dnode_cmds(), which is lib-owned already.
 *
 * M3 B-RM1 finished the move: bgp_routemap_cli.c compiles only into
 * mgmtd (mgmtd/subdir.am), exactly like bgp_cli.c; bgpd/subdir.am no
 * longer lists it, and bgp_route_map_init() (bgp_routemap.c) no
 * longer calls bgp_routemap_cli_init() -- bgpd stops installing any
 * route-map CLI locally, matching ripd/zebra/staticd. All 143
 * match/set commands, including the nine below that B-RM3 left
 * behind (match/no_match alias, set_aspath_prepend_asn,
 * set_aspath_exclude, set_community, set/no_set_vpn_nexthop,
 * set/no_set_ipx_vpn_nexthop), now run only in mgmtd; the CLI-side
 * bodies had their bgpd-only validation helper calls
 * (bgp_ca_alias_lookup, route_aspath_compile, community_str2com,
 * argv_find_and_parse_vpnvx/afi) dropped or inlined -- see the
 * comment immediately above match_alias_cmd below for why that is
 * not a validation regression.
 */

#include <zebra.h>

#include "prefix.h"
#include "filter.h"
#include "routemap.h"
#include "command.h"
#include "linklist.h"
#include "plist.h"
#include "memory.h"
#include "log.h"
#include "frrlua.h"
#include "frrscript.h"
#include "buffer.h"
#include "sockunion.h"
#include "hash.h"
#include "queue.h"
#include "frrstr.h"
#include "network.h"
#include "lib/northbound_cli.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_regex.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_clist.h"
#include "bgpd/bgp_filter.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/proteus/bgp_filter_value.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_lcommunity.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_evpn.h"
#include "bgpd/bgp_evpn_private.h"
#include "bgpd/bgp_evpn_vty.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_pbr.h"
#include "bgpd/bgp_flowspec_util.h"
#include "bgpd/bgp_encap_types.h"
#include "bgpd/bgp_mpath.h"
#include "bgpd/bgp_script.h"
#include "bgpd/bgp_encap_types.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_routemap_cli.h"

#include "bgpd/bgp_routemap_cli_clippy.c"

DEFUN_YANG (match_mac_address,
	    match_mac_address_cmd,
	    "match mac address ACCESSLIST_MAC_NAME",
	    MATCH_STR
	    "mac address\n"
	    "Match address of route\n"
	    "MAC Access-list name\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:mac-address-list']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:list-name", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, argv[3]->arg);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_match_mac_address,
	    no_match_mac_address_cmd,
	    "no match mac address ACCESSLIST_MAC_NAME",
	    NO_STR
	    MATCH_STR
	    "mac\n"
	    "Match address of route\n"
	    "MAC acess-list name\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:mac-address-list']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/*
 * Helper to handle the case of the user passing in a number or type string
 */
static const char *parse_evpn_rt_type(const char *num_rt_type)
{
	switch (num_rt_type[0]) {
	case '1':
		return "ead";
	case '2':
		return "macip";
	case '3':
		return "multicast";
	case '4':
		return "es";
	case '5':
		return "prefix";
	default:
		break;
	}

	/* Was already full type string */
	return num_rt_type;
}

DEFUN_YANG (match_evpn_route_type,
	    match_evpn_route_type_cmd,
	    "match evpn route-type <ead|1|macip|2|multicast|3|es|4|prefix|5>",
	    MATCH_STR
	    EVPN_HELP_STR
	    EVPN_TYPE_HELP_STR
	    EVPN_TYPE_1_HELP_STR
	    EVPN_TYPE_1_HELP_STR
	    EVPN_TYPE_2_HELP_STR
	    EVPN_TYPE_2_HELP_STR
	    EVPN_TYPE_3_HELP_STR
	    EVPN_TYPE_3_HELP_STR
	    EVPN_TYPE_4_HELP_STR
	    EVPN_TYPE_4_HELP_STR
	    EVPN_TYPE_5_HELP_STR
	    EVPN_TYPE_5_HELP_STR)
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:evpn-route-type']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:evpn-route-type",
		 xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			      parse_evpn_rt_type(argv[3]->arg));

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_match_evpn_route_type,
	    no_match_evpn_route_type_cmd,
	    "no match evpn route-type <ead|1|macip|2|multicast|3|es|4|prefix|5>",
	    NO_STR
	    MATCH_STR
	    EVPN_HELP_STR
	    EVPN_TYPE_HELP_STR
	    EVPN_TYPE_1_HELP_STR
	    EVPN_TYPE_1_HELP_STR
	    EVPN_TYPE_2_HELP_STR
	    EVPN_TYPE_2_HELP_STR
	    EVPN_TYPE_3_HELP_STR
	    EVPN_TYPE_3_HELP_STR
	    EVPN_TYPE_4_HELP_STR
	    EVPN_TYPE_4_HELP_STR
	    EVPN_TYPE_5_HELP_STR
	    EVPN_TYPE_5_HELP_STR)
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:evpn-route-type']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}


DEFUN_YANG (match_evpn_vni,
	    match_evpn_vni_cmd,
	    "match evpn vni " CMD_VNI_RANGE,
	    MATCH_STR
	    EVPN_HELP_STR
	    "Match VNI\n"
	    "VNI ID\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:evpn-vni']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:evpn-vni", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, argv[3]->arg);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_match_evpn_vni,
	    no_match_evpn_vni_cmd,
	    "no match evpn vni " CMD_VNI_RANGE,
	    NO_STR
	    MATCH_STR
	    EVPN_HELP_STR
	    "Match VNI\n"
	    "VNI ID\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:evpn-vni']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:evpn-vni", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_DESTROY, argv[3]->arg);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (match_evpn_default_route,
	    match_evpn_default_route_cmd,
	    "match evpn default-route",
	    MATCH_STR
	    EVPN_HELP_STR
	    "default EVPN type-5 route\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:evpn-default-route']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:evpn-default-route",
		 xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_match_evpn_default_route,
	    no_match_evpn_default_route_cmd,
	    "no match evpn default-route",
	    NO_STR
	    MATCH_STR
	    EVPN_HELP_STR
	    "default EVPN type-5 route\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:evpn-default-route']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

/* Parse one canonical decimal number (no sign, no leading zero) not
 * bigger than 'max'; '*str' is the field, 'end' one past its last
 * character. */
static bool match_evpn_rd_decimal(const char *str, const char *end,
				  uint64_t max, uint64_t *val)
{
	const char *p;

	if (str == end || (*str == '0' && end - str > 1))
		return false;
	*val = 0;
	for (p = str; p < end; p++) {
		if (!isdigit((unsigned char)*p))
			return false;
		*val = *val * 10 + (uint64_t)(*p - '0');
		if (*val > max)
			return false;
	}

	return true;
}

DEFUN_YANG (match_evpn_rd,
	    match_evpn_rd_cmd,
	    "match evpn rd ASN:NN_OR_IP-ADDRESS:NN",
	    MATCH_STR
	    EVPN_HELP_STR
	    "Route Distinguisher\n"
	    "ASN:XX or A.B.C.D:XX\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:evpn-rd']";
	const char *arg = argv[3]->arg;
	const char *body = arg, *colon, *colon2;
	char xpath_rd[XPATH_MAXLEN];
	char xpath_value[XPATH_MAXLEN * 2];
	char admin[INET_ADDRSTRLEN];
	char number[32];
	const char *fmt = NULL;
	struct in_addr ip;
	uint64_t aval, nval;
	int etype = -1;

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_rd, sizeof(xpath_rd),
		 "%s/rmap-match-condition/frr-bgp-route-map:route-distinguisher",
		 xpath);
	/* Replace, not merge, whatever an earlier line left. */
	nb_cli_enqueue_change(vty, xpath_rd, NB_OP_DESTROY, NULL);

	/* Classify the value the way the daemon parses it: an
	 * 'ADMIN:NN' pair whose type follows from the administrator's
	 * syntax, optionally preceded by an explicit numeric type that
	 * must agree with it. The explicit type is stripped here; any
	 * other spelling travels through the raw fallback and keeps
	 * its apply-time fate. */
	colon = strchr(body, ':');
	colon2 = colon ? strchr(colon + 1, ':') : NULL;
	if (colon2) {
		if ((arg[0] == '0' || arg[0] == '1' || arg[0] == '2') &&
		    arg[1] == ':') {
			etype = arg[0] - '0';
			body = arg + 2;
			colon = colon2;
		} else {
			colon = NULL;
		}
	}

	if (colon && (size_t)(colon - body) < sizeof(admin)) {
		memcpy(admin, body, colon - body);
		admin[colon - body] = '\0';

		/* A plain-decimal administrator is an AS number; zero
		 * is not one to the daemon (it reads a lone '0' as the
		 * IPv4 address 0.0.0.0), so it stays raw. */
		if (match_evpn_rd_decimal(body, colon, UINT32_MAX, &aval) &&
		    aval >= 1) {
			if (aval <= UINT16_MAX &&
			    match_evpn_rd_decimal(colon + 1,
						  body + strlen(body),
						  UINT32_MAX, &nval) &&
			    (etype == -1 || etype == 0))
				fmt = "as2";
			else if (aval > UINT16_MAX &&
				 match_evpn_rd_decimal(colon + 1,
						       body + strlen(body),
						       UINT16_MAX, &nval) &&
				 (etype == -1 || etype == 2))
				fmt = "as4";
		} else if (inet_pton(AF_INET, admin, &ip) == 1 &&
			   match_evpn_rd_decimal(colon + 1,
						 body + strlen(body),
						 UINT16_MAX, &nval) &&
			   (etype == -1 || etype == 1)) {
			fmt = "ipv4";
		}
	}

	if (fmt) {
		snprintf(xpath_value, sizeof(xpath_value),
			 "%s/%s/administrator", xpath_rd, fmt);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, admin);
		snprintf(number, sizeof(number), "%" PRIu64, nval);
		snprintf(xpath_value, sizeof(xpath_value),
			 "%s/%s/assigned-number", xpath_rd, fmt);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, number);
	} else {
		/* Kept verbatim; the apply-time compile keeps the old
		 * accept-or-reject behavior for it. */
		snprintf(xpath_value, sizeof(xpath_value), "%s/raw", xpath_rd);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, arg);
	}

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_match_evpn_rd,
	    no_match_evpn_rd_cmd,
	    "no match evpn rd ASN:NN_OR_IP-ADDRESS:NN",
	    NO_STR
	    MATCH_STR
	    EVPN_HELP_STR
	    "Route Distinguisher\n"
	    "ASN:XX or A.B.C.D:XX\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:evpn-rd']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (set_evpn_gw_ip_ipv4,
	    set_evpn_gw_ip_ipv4_cmd,
	    "set evpn gateway-ip ipv4 A.B.C.D",
	    SET_STR
	    EVPN_HELP_STR
	    "Set gateway IP for prefix advertisement route\n"
	    "IPv4 address\n"
	    "Gateway IP address in IPv4 format\n")
{
	int ret;
	union sockunion su;
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-evpn-gateway-ip-ipv4']";
	char xpath_value[XPATH_MAXLEN];

	ret = str2sockunion(argv[4]->arg, &su);
	if (ret < 0) {
		vty_out(vty, "%% Malformed gateway IP\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (su.sin.sin_addr.s_addr == 0 ||
	    !ipv4_unicast_valid(&su.sin.sin_addr)) {
		vty_out(vty,
			"%% Gateway IP cannot be 0.0.0.0, multicast or reserved\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:evpn-gateway-ip-ipv4",
		 xpath);

	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, argv[4]->arg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_evpn_gw_ip_ipv4,
	    no_set_evpn_gw_ip_ipv4_cmd,
	    "no set evpn gateway-ip ipv4 A.B.C.D",
	    NO_STR
	    SET_STR
	    EVPN_HELP_STR
	    "Set gateway IP for prefix advertisement route\n"
	    "IPv4 address\n"
	    "Gateway IP address in IPv4 format\n")
{
	int ret;
	union sockunion su;
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-evpn-gateway-ip-ipv4']";

	ret = str2sockunion(argv[5]->arg, &su);
	if (ret < 0) {
		vty_out(vty, "%% Malformed gateway IP\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (su.sin.sin_addr.s_addr == 0 ||
	    !ipv4_unicast_valid(&su.sin.sin_addr)) {
		vty_out(vty,
			"%% Gateway IP cannot be 0.0.0.0, multicast or reserved\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (set_evpn_gw_ip_ipv6,
	    set_evpn_gw_ip_ipv6_cmd,
	    "set evpn gateway-ip ipv6 X:X::X:X",
	    SET_STR
	    EVPN_HELP_STR
	    "Set gateway IP for prefix advertisement route\n"
	    "IPv6 address\n"
	    "Gateway IP address in IPv6 format\n")
{
	int ret;
	union sockunion su;
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-evpn-gateway-ip-ipv6']";
	char xpath_value[XPATH_MAXLEN];

	ret = str2sockunion(argv[4]->arg, &su);
	if (ret < 0) {
		vty_out(vty, "%% Malformed gateway IP\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (IN6_IS_ADDR_LINKLOCAL(&su.sin6.sin6_addr)
	    || IN6_IS_ADDR_MULTICAST(&su.sin6.sin6_addr)) {
		vty_out(vty,
			"%% Gateway IP cannot be a linklocal or multicast address\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:evpn-gateway-ip-ipv6",
		 xpath);

	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, argv[4]->arg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_evpn_gw_ip_ipv6,
	    no_set_evpn_gw_ip_ipv6_cmd,
	    "no set evpn gateway-ip ipv6 X:X::X:X",
	    NO_STR
	    SET_STR
	    EVPN_HELP_STR
	    "Set gateway IP for prefix advertisement route\n"
	    "IPv4 address\n"
	    "Gateway IP address in IPv4 format\n")
{
	int ret;
	union sockunion su;
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-evpn-gateway-ip-ipv6']";

	ret = str2sockunion(argv[5]->arg, &su);
	if (ret < 0) {
		vty_out(vty, "%% Malformed gateway IP\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (IN6_IS_ADDR_LINKLOCAL(&su.sin6.sin6_addr)
	    || IN6_IS_ADDR_MULTICAST(&su.sin6.sin6_addr)) {
		vty_out(vty,
			"%% Gateway IP cannot be a linklocal or multicast address\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (set_ecommunity_evpn_rmac,
	    set_ecommunity_evpn_rmac_cmd,
	    "set extcommunity evpn rmac X:X:X:X:X:X",
	    SET_STR
	    "BGP extended community attribute\n"
	    "EVPN extended community\n"
	    "Router MAC extended community\n"
	    "MAC address in XX:XX:XX:XX:XX:XX format\n")
{
	const char *xpath = "./set-action[action='frr-bgp-route-map:set-extcommunity-evpn-rmac']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:extcommunity-evpn-rmac", xpath);

	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, argv[4]->arg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (no_set_ecommunity_evpn_rmac,
	    no_set_ecommunity_evpn_rmac_cmd,
	    "no set extcommunity evpn rmac [X:X:X:X:X:X]",
	    NO_STR
	    SET_STR
	    "BGP extended community attribute\n"
	    "EVPN extended community\n"
	    "Router MAC extended community\n"
	    "MAC address in XX:XX:XX:XX:XX:XX format\n")
{
	const char *xpath = "./set-action[action='frr-bgp-route-map:set-extcommunity-evpn-rmac']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(match_vrl_source_vrf,
      match_vrl_source_vrf_cmd,
      "match source-vrf NAME$vrf_name",
      MATCH_STR
      "source vrf\n"
      "The VRF name\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:source-vrf']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:source-vrf", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, vrf_name);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_match_vrl_source_vrf,
      no_match_vrl_source_vrf_cmd,
      "no match source-vrf NAME$vrf_name",
      NO_STR MATCH_STR
      "source vrf\n"
      "The VRF name\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:source-vrf']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (match_peer,
       match_peer_cmd,
       "match peer <A.B.C.D$addrv4|X:X::X:X$addrv6|WORD$intf>",
       MATCH_STR
       "Match peer address\n"
       "IP address of peer\n"
       "IPv6 address of peer\n"
       "Interface name of peer or peer group name\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:peer']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:peer-ipv4-address",
		 xpath);
	nb_cli_enqueue_change(vty, xpath_value,
			      addrv4_str ? NB_OP_MODIFY : NB_OP_DESTROY,
			      addrv4_str);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:peer-ipv6-address",
		 xpath);
	nb_cli_enqueue_change(vty, xpath_value,
			      addrv6_str ? NB_OP_MODIFY : NB_OP_DESTROY,
			      addrv6_str);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:peer-interface",
		 xpath);
	nb_cli_enqueue_change(vty, xpath_value,
			      intf ? NB_OP_MODIFY : NB_OP_DESTROY, intf);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (match_peer_local,
	    match_peer_local_cmd,
	    "match peer local",
	    MATCH_STR
	    "Match peer address\n"
	    "Static or Redistributed routes\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:peer']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:peer-local", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, "true");

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_match_peer,
	    no_match_peer_cmd,
	    "no match peer [<local|A.B.C.D|X:X::X:X|WORD>]",
	    NO_STR
	    MATCH_STR
	    "Match peer address\n"
	    "Static or Redistributed routes\n"
	    "IP address of peer\n"
	    "IPv6 address of peer\n"
	    "Interface name of peer\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:peer']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (match_src_peer,
       match_src_peer_cmd,
       "match src-peer <A.B.C.D$addrv4|X:X::X:X$addrv6|WORD$intf>",
       MATCH_STR
       "Match source peer address\n"
       "IP address of peer\n"
       "IPv6 address of peer\n"
       "Interface name of peer or peer group name\n")
{
	const char *xpath = "./match-condition[condition='frr-bgp-route-map:src-peer']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:src-peer-ipv4-address", xpath);
	nb_cli_enqueue_change(vty, xpath_value, addrv4_str ? NB_OP_MODIFY : NB_OP_DESTROY,
			      addrv4_str);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:src-peer-ipv6-address", xpath);
	nb_cli_enqueue_change(vty, xpath_value, addrv6_str ? NB_OP_MODIFY : NB_OP_DESTROY,
			      addrv6_str);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:src-peer-interface", xpath);
	nb_cli_enqueue_change(vty, xpath_value, intf ? NB_OP_MODIFY : NB_OP_DESTROY, intf);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_match_src_peer,
	    no_match_src_peer_cmd,
	    "no match src-peer [<A.B.C.D|X:X::X:X|WORD>]",
	    NO_STR
	    MATCH_STR
	    "Match peer address\n"
	    "IP address of peer\n"
	    "IPv6 address of peer\n"
	    "Interface name of peer\n")
{
	const char *xpath = "./match-condition[condition='frr-bgp-route-map:src-peer']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

#ifdef HAVE_SCRIPTING
DEFUN_YANG (match_script,
	    match_script_cmd,
	    "[no] match script WORD",
	    NO_STR
	    MATCH_STR
	    "Execute script to determine match\n"
	    "The script name to run, without .lua; e.g. 'myroutemap' to run myroutemap.lua\n")
{
	bool no = strmatch(argv[0]->text, "no");
	int i = 0;
	argv_find(argv, argc, "WORD", &i);
	const char *script = argv[i]->arg;
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:match-script']";
	char xpath_value[XPATH_MAXLEN];

	if (no) {
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
		snprintf(xpath_value, sizeof(xpath_value),
			 "%s/rmap-match-condition/frr-bgp-route-map:script",
			 xpath);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_DESTROY,
				      script);

		return nb_cli_apply_changes(vty, NULL);
	}

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
			"%s/rmap-match-condition/frr-bgp-route-map:script",
			xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			script);

	return nb_cli_apply_changes(vty, NULL);
}
#endif /* HAVE_SCRIPTING */

/* match probability */
DEFUN_YANG (match_probability,
	    match_probability_cmd,
	    "match probability (0-100)",
	    MATCH_STR
	    "Match portion of routes defined by percentage value\n"
	    "Percentage of routes\n")
{
	int idx_number = 2;

	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:probability']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:probability",
		 xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			      argv[idx_number]->arg);

	return nb_cli_apply_changes(vty, NULL);
}


DEFUN_YANG (no_match_probability,
	    no_match_probability_cmd,
	    "no match probability [(0-100)]",
	    NO_STR
	    MATCH_STR
	    "Match portion of routes defined by percentage value\n"
	    "Percentage of routes\n")
{
	int idx_number = 3;
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:probability']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	if (argc <= idx_number)
		return nb_cli_apply_changes(vty, NULL);

	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:probability",
		 xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_DESTROY,
			      argv[idx_number]->arg);

	return nb_cli_apply_changes(vty, NULL);
}


DEFPY_YANG (match_ip_route_source,
       match_ip_route_source_cmd,
       "match ip route-source ACCESSLIST4_NAME",
       MATCH_STR
       IP_STR
       "Match advertising source address of route\n"
       "IP Access-list name\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:ip-route-source']";
	char xpath_value[XPATH_MAXLEN + 32];
	int idx_acl = 3;

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
			"%s/rmap-match-condition/frr-bgp-route-map:list-name",
			xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			      argv[idx_acl]->arg);

	return nb_cli_apply_changes(vty, NULL);
}


DEFUN_YANG (no_match_ip_route_source,
	    no_match_ip_route_source_cmd,
	    "no match ip route-source [ACCESSLIST4_NAME]",
	    NO_STR
	    MATCH_STR
	    IP_STR
	    "Match advertising source address of route\n"
	    "IP Access-list name\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:ip-route-source']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (match_ip_route_source_prefix_list,
	    match_ip_route_source_prefix_list_cmd,
	    "match ip route-source prefix-list PREFIXLIST_NAME",
	    MATCH_STR
	    IP_STR
	    "Match advertising source address of route\n"
	    "Match entries of prefix-lists\n"
	    "IP prefix-list name\n")
{
	int idx_word = 4;
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:ip-route-source-prefix-list']";
	char xpath_value[XPATH_MAXLEN + 32];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:list-name", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			      argv[idx_word]->arg);

	return nb_cli_apply_changes(vty, NULL);
}


DEFUN_YANG (no_match_ip_route_source_prefix_list,
	    no_match_ip_route_source_prefix_list_cmd,
	    "no match ip route-source prefix-list [PREFIXLIST_NAME]",
	    NO_STR
	    MATCH_STR
	    IP_STR
	    "Match advertising source address of route\n"
	    "Match entries of prefix-lists\n"
	    "IP prefix-list name\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:ip-route-source-prefix-list']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (match_local_pref,
	    match_local_pref_cmd,
	    "match local-preference (0-4294967295)",
	    MATCH_STR
	    "Match local-preference of route\n"
	    "Metric value\n")
{
	int idx_number = 2;

	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:match-local-preference']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:local-preference",
		 xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			      argv[idx_number]->arg);

	return nb_cli_apply_changes(vty, NULL);
}


DEFUN_YANG (no_match_local_pref,
	    no_match_local_pref_cmd,
	    "no match local-preference [(0-4294967295)]",
	    NO_STR
	    MATCH_STR
	    "Match local preference of route\n"
	    "Local preference value\n")
{
	int idx_localpref = 3;
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:match-local-preference']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	if (argc <= idx_localpref)
		return nb_cli_apply_changes(vty, NULL);

	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:local-preference",
		 xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_DESTROY,
			      argv[idx_localpref]->arg);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	match_community, match_community_cmd,
	"match community <(1-99)|(100-500)|COMMUNITY_LIST_NAME> [<exact-match$exact|any$any>]",
	MATCH_STR "Match BGP community list\n"
		  "Community-list number (standard)\n"
		  "Community-list number (expanded)\n"
		  "Community-list name\n"
		  "Do exact matching of communities\n"
		  "Do matching of any community\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:match-community']";
	char xpath_value[XPATH_MAXLEN];
	char xpath_match[XPATH_MAXLEN];
	int idx_comm_list = 2;

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(
		xpath_value, sizeof(xpath_value),
		"%s/rmap-match-condition/frr-bgp-route-map:comm-list/comm-list-name",
		xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, argv[idx_comm_list]->arg);

	snprintf(xpath_match, sizeof(xpath_match),
		 "%s/rmap-match-condition/frr-bgp-route-map:comm-list/comm-list-name-exact-match",
		 xpath);
	if (exact)
		nb_cli_enqueue_change(vty, xpath_match, NB_OP_MODIFY,
				"true");
	else
		nb_cli_enqueue_change(vty, xpath_match, NB_OP_MODIFY, "false");

	snprintf(xpath_match, sizeof(xpath_match),
		 "%s/rmap-match-condition/frr-bgp-route-map:comm-list/comm-list-name-any",
		 xpath);
	if (any)
		nb_cli_enqueue_change(vty, xpath_match, NB_OP_MODIFY, "true");
	else
		nb_cli_enqueue_change(vty, xpath_match, NB_OP_MODIFY, "false");

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	match_community_limit, match_community_limit_cmd,
	"[no$no] match community-limit ![(0-65535)$limit]",
	NO_STR
	MATCH_STR
	"Match BGP community limit\n"
	"Community limit number\n")
{
	const char *xpath = "./match-condition[condition='frr-bgp-route-map:match-community-limit']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, no ? NB_OP_DESTROY : NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:community-limit", xpath);

	nb_cli_enqueue_change(vty, xpath_value, no ? NB_OP_DESTROY : NB_OP_MODIFY, limit_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(
	no_match_community, no_match_community_cmd,
	"no match community [<(1-99)|(100-500)|COMMUNITY_LIST_NAME> [<exact-match$exact|any$any>]]",
	NO_STR MATCH_STR "Match BGP community list\n"
			 "Community-list number (standard)\n"
			 "Community-list number (expanded)\n"
			 "Community-list name\n"
			 "Do exact matching of communities\n"
			 "Do matching of any community\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:match-community']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	match_lcommunity, match_lcommunity_cmd,
	"match large-community <(1-99)|(100-500)|LCOMMUNITY_LIST_NAME> [<exact-match$exact|any$any>]",
	MATCH_STR "Match BGP large community list\n"
		  "Large Community-list number (standard)\n"
		  "Large Community-list number (expanded)\n"
		  "Large Community-list name\n"
		  "Do exact matching of communities\n"
		  "Do matching of any community\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:match-large-community']";
	char xpath_value[XPATH_MAXLEN];
	char xpath_match[XPATH_MAXLEN];
	int idx_lcomm_list = 2;

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(
		xpath_value, sizeof(xpath_value),
		"%s/rmap-match-condition/frr-bgp-route-map:comm-list/comm-list-name",
		xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, argv[idx_lcomm_list]->arg);

	snprintf(xpath_match, sizeof(xpath_match),
		 "%s/rmap-match-condition/frr-bgp-route-map:comm-list/comm-list-name-exact-match",
		 xpath);
	if (exact)
		nb_cli_enqueue_change(vty, xpath_match, NB_OP_MODIFY,
				"true");
	else
		nb_cli_enqueue_change(vty, xpath_match, NB_OP_MODIFY, "false");

	snprintf(xpath_match, sizeof(xpath_match),
		 "%s/rmap-match-condition/frr-bgp-route-map:comm-list/comm-list-name-any",
		 xpath);
	if (any)
		nb_cli_enqueue_change(vty, xpath_match, NB_OP_MODIFY, "true");
	else
		nb_cli_enqueue_change(vty, xpath_match, NB_OP_MODIFY, "false");

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(
	no_match_lcommunity, no_match_lcommunity_cmd,
	"no match large-community [<(1-99)|(100-500)|LCOMMUNITY_LIST_NAME> [<exact-match|any>]]",
	NO_STR MATCH_STR "Match BGP large community list\n"
			 "Large Community-list number (standard)\n"
			 "Large Community-list number (expanded)\n"
			 "Large Community-list name\n"
			 "Do exact matching of communities\n"
			 "Do matching of any community\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:match-large-community']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (match_ecommunity,
	    match_ecommunity_cmd,
            "match extcommunity <(1-99)|(100-500)|EXTCOMMUNITY_LIST_NAME> [<exact-match$exact|any$any>]",
	    MATCH_STR
	    "Match BGP/VPN extended community list\n"
	    "Extended community-list number (standard)\n"
	    "Extended community-list number (expanded)\n"
	    "Extended community-list name\n"
	    "Do exact matching of communities\n"
	    "Do matching of any community\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:match-extcommunity']";
	char xpath_value[XPATH_MAXLEN];
	char xpath_match[XPATH_MAXLEN];
	int idx_comm_list = 2;

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(
		xpath_value, sizeof(xpath_value),
		"%s/rmap-match-condition/frr-bgp-route-map:comm-list/comm-list-name",
		xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, argv[idx_comm_list]->arg);

	snprintf(xpath_match, sizeof(xpath_match),
		 "%s/rmap-match-condition/frr-bgp-route-map:comm-list/comm-list-name-exact-match",
		 xpath);
	if (exact)
		nb_cli_enqueue_change(vty, xpath_match, NB_OP_MODIFY, "true");
	else
		nb_cli_enqueue_change(vty, xpath_match, NB_OP_MODIFY, "false");

	snprintf(xpath_match, sizeof(xpath_match),
		 "%s/rmap-match-condition/frr-bgp-route-map:comm-list/comm-list-name-any", xpath);
	if (any)
		nb_cli_enqueue_change(vty, xpath_match, NB_OP_MODIFY, "true");
	else
		nb_cli_enqueue_change(vty, xpath_match, NB_OP_MODIFY, "false");

	return nb_cli_apply_changes(vty, NULL);
}


DEFPY_YANG(
	match_extcommunity_limit, match_extcommunity_limit_cmd,
	"[no$no] match extcommunity-limit ![(0-65535)$limit]",
	NO_STR
	MATCH_STR
	"Match BGP extended community limit\n"
	"Extended community limit number\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:match-extcommunity-limit']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, no ? NB_OP_DESTROY : NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:extcommunity-limit", xpath);

	nb_cli_enqueue_change(vty, xpath_value, no ? NB_OP_DESTROY : NB_OP_MODIFY, limit_str);
	return nb_cli_apply_changes(vty, NULL);
}


DEFUN_YANG (no_match_ecommunity,
	    no_match_ecommunity_cmd,
	    "no match extcommunity [<(1-99)|(100-500)|EXTCOMMUNITY_LIST_NAME> [<exact-match$exact|any$any>]]",
	    NO_STR
	    MATCH_STR
	    "Match BGP/VPN extended community list\n"
	    "Extended community-list number (standard)\n"
	    "Extended community-list number (expanded)\n"
	    "Extended community-list name\n"
	    "Do exact matching of communities\n"
	    "Do matching of any community\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:match-extcommunity']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

static int _set_ecommunity_delete_cmd(struct vty *vty, const char *name)
{
	const char *xpath = "./set-action[action='frr-bgp-route-map:extended-comm-list-delete']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:comm-list-name", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, name);
	return nb_cli_apply_changes(vty, NULL);
}

#if CONFDATE > 20270527
CPP_NOTICE("Remove `[no] set extended-comm-list <COMM_LIST> delete` commands")
#endif

DEFPY_YANG (set_ecommunity_delete,
	    set_ecommunity_delete_cmd,
            "set extended-comm-list " EXTCOMM_LIST_CMD_STR " delete",
	    SET_STR
	    "set BGP extended community list (for deletion)\n"
	    EXTCOMM_STD_LIST_NUM_STR
	    EXTCOMM_EXP_LIST_NUM_STR
	    EXTCOMM_LIST_NAME_STR
            "Delete matching extended communities\n")
{
	int idx_comm_list = 2;

	return _set_ecommunity_delete_cmd(vty, argv[idx_comm_list]->arg);
}

DEFPY_YANG (no_set_ecommunity_delete,
	    no_set_ecommunity_delete_cmd,
            "no set extended-comm-list [" EXTCOMM_LIST_CMD_STR "] delete",
	    NO_STR
	    SET_STR
	    "set BGP extended community list (for deletion)\n"
	    EXTCOMM_STD_LIST_NUM_STR
	    EXTCOMM_EXP_LIST_NUM_STR
	    EXTCOMM_LIST_NAME_STR
            "Delete matching extended communities\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:extended-comm-list-delete']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (set_ecommunity_delete_method2,
	    set_ecommunity_delete_method2_cmd,
            "set extended-comm-list delete " EXTCOMM_LIST_CMD_STR,
	    SET_STR
	    "set BGP extended community list\n"
            "Delete matching extended communities\n"
	    EXTCOMM_STD_LIST_NUM_STR
	    EXTCOMM_EXP_LIST_NUM_STR
	    EXTCOMM_LIST_NAME_STR)
{
	int idx_comm_list = 3;

	return _set_ecommunity_delete_cmd(vty, argv[idx_comm_list]->arg);
}

DEFPY_YANG (no_set_ecommunity_delete_method2,
	    no_set_ecommunity_delete_method2_cmd,
            "no set extended-comm-list delete [" EXTCOMM_LIST_CMD_STR "]",
	    NO_STR
	    SET_STR
	    "set BGP extended community list\n"
            "Delete matching extended communities\n"
	    EXTCOMM_STD_LIST_NUM_STR
	    EXTCOMM_EXP_LIST_NUM_STR
	    EXTCOMM_LIST_NAME_STR)
{
	const char *xpath = "./set-action[action='frr-bgp-route-map:extended-comm-list-delete']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (match_aspath,
	    match_aspath_cmd,
	    "match as-path AS_PATH_FILTER_NAME",
	    MATCH_STR
	    "Match BGP AS path list\n"
	    "AS path access-list name\n")
{
	int idx_word = 2;

	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:as-path-list']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:list-name", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			      argv[idx_word]->arg);

	return nb_cli_apply_changes(vty, NULL);
}


DEFUN_YANG (no_match_aspath,
	    no_match_aspath_cmd,
	    "no match as-path [AS_PATH_FILTER_NAME]",
	    NO_STR
	    MATCH_STR
	    "Match BGP AS path list\n"
	    "AS path access-list name\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:as-path-list']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}


DEFPY_YANG(
	match_aspath_count, match_aspath_count_cmd,
	"[no$no] match as-path-count ![(0-1028)$count]",
	NO_STR
	MATCH_STR
	"Match BGP AS path count\n"
	"AS path count number\n")
{
	const char *xpath = "./match-condition[condition='frr-bgp-route-map:match-as-path-count']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, no ? NB_OP_DESTROY : NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:as-path-count", xpath);

	nb_cli_enqueue_change(vty, xpath_value, no ? NB_OP_DESTROY : NB_OP_MODIFY, count_str);
	return nb_cli_apply_changes(vty, NULL);
}


DEFUN_YANG (match_origin,
	    match_origin_cmd,
	    "match origin <egp|igp|incomplete>",
	    MATCH_STR
	    "BGP origin code\n"
	    "remote EGP\n"
	    "local IGP\n"
	     "unknown heritage\n")
{
	int idx_origin = 2;
	const char *origin_type;
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:match-origin']";
	char xpath_value[XPATH_MAXLEN];

	if (strncmp(argv[idx_origin]->arg, "igp", 2) == 0)
		origin_type = "igp";
	else if (strncmp(argv[idx_origin]->arg, "egp", 1) == 0)
		origin_type = "egp";
	else if (strncmp(argv[idx_origin]->arg, "incomplete", 2) == 0)
		origin_type = "incomplete";
	else {
		vty_out(vty, "%% Invalid match origin type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:origin", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, origin_type);

	return nb_cli_apply_changes(vty, NULL);
}


DEFUN_YANG (no_match_origin,
	    no_match_origin_cmd,
	    "no match origin [<egp|igp|incomplete>]",
	    NO_STR
	    MATCH_STR
	    "BGP origin code\n"
	    "remote EGP\n"
	    "local IGP\n"
	    "unknown heritage\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:match-origin']";
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (set_table_id,
	    set_table_id_cmd,
	    "set table (1-4294967295)",
	    SET_STR
	    "export route to non-main kernel table\n"
	    "Kernel routing table id\n")
{
	int idx_number = 2;
	const char *xpath = "./set-action[action='frr-bgp-route-map:table']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:table", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			      argv[idx_number]->arg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_table_id,
	    no_set_table_id_cmd,
	    "no set table [(1-4294967295)]",
	    NO_STR
	    SET_STR
	    "export route to non-main kernel table\n"
	    "Kernel routing table id\n")
{
	const char *xpath = "./set-action[action='frr-bgp-route-map:table']";
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (set_ip_nexthop_peer,
	    set_ip_nexthop_peer_cmd,
	    "[no] set ip next-hop peer-address",
	    NO_STR
	    SET_STR
	    IP_STR
	    "Next hop address\n"
	    "Use peer address (for BGP only)\n")
{
	char xpath_value[XPATH_MAXLEN];
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-ipv4-nexthop']";

	if (strmatch(argv[0]->text, "no"))
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	else {
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		snprintf(xpath_value, sizeof(xpath_value),
			 "%s/rmap-set-action/frr-bgp-route-map:ipv4-nexthop",
			 xpath);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
				      "peer-address");
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (set_ip_nexthop_unchanged,
	    set_ip_nexthop_unchanged_cmd,
	    "[no] set ip next-hop unchanged",
	    NO_STR
	    SET_STR
	    IP_STR
	    "Next hop address\n"
	    "Don't modify existing Next hop address\n")
{
	char xpath_value[XPATH_MAXLEN];
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-ipv4-nexthop']";

	if (strmatch(argv[0]->text, "no"))
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	else {
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		snprintf(xpath_value, sizeof(xpath_value),
			 "%s/rmap-set-action/frr-bgp-route-map:ipv4-nexthop",
			 xpath);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
				      "unchanged");
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (set_distance,
	    set_distance_cmd,
	    "set distance (1-255)",
	    SET_STR
	    "BGP Administrative Distance to use\n"
	    "Distance value\n")
{
	int idx_number = 2;
	const char *xpath = "./set-action[action='frr-bgp-route-map:distance']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:distance", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			      argv[idx_number]->arg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_distance,
	    no_set_distance_cmd,
	    "no set distance [(1-255)]",
	    NO_STR SET_STR
	    "BGP Administrative Distance to use\n"
	    "Distance value\n")
{
	const char *xpath = "./set-action[action='frr-bgp-route-map:distance']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(set_l3vpn_nexthop_encapsulation, set_l3vpn_nexthop_encapsulation_cmd,
	   "[no] set l3vpn next-hop encapsulation <gre|gretap>$ziftype",
	   NO_STR SET_STR
	   "L3VPN operations\n"
	   "Next hop Information\n"
	   "Encapsulation options (for BGP only)\n"
	   "Accept L3VPN traffic over GRE encapsulation\n"
	   "Accept L3VPN traffic over GRETAP encapsulation\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-l3vpn-nexthop-encapsulation']";
	const char *xpath_value =
		"./set-action[action='frr-bgp-route-map:set-l3vpn-nexthop-encapsulation']/rmap-set-action/frr-bgp-route-map:l3vpn-nexthop-encapsulation";
	enum nb_operation operation;

	if (no)
		operation = NB_OP_DESTROY;
	else
		operation = NB_OP_CREATE;

	nb_cli_enqueue_change(vty, xpath, operation, NULL);
	if (operation == NB_OP_DESTROY)
		return nb_cli_apply_changes(vty, NULL);

	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, ziftype);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (set_local_pref,
	    set_local_pref_cmd,
	    "set local-preference WORD",
	    SET_STR
	    "BGP local preference path attribute\n"
	    "Preference value (0-4294967295)\n")
{
	int idx_number = 2;
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-local-preference']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:local-pref", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			      argv[idx_number]->arg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_local_pref,
	    no_set_local_pref_cmd,
	    "no set local-preference [WORD]",
	    NO_STR
	    SET_STR
	    "BGP local preference path attribute\n"
	    "Preference value (0-4294967295)\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-local-preference']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (set_weight,
	    set_weight_cmd,
	    "set weight (0-4294967295)",
	    SET_STR
	    "BGP weight for routing table\n"
	    "Weight value\n")
{
	int idx_number = 2;
	const char *xpath = "./set-action[action='frr-bgp-route-map:weight']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:weight", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			      argv[idx_number]->arg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_weight,
	    no_set_weight_cmd,
	    "no set weight [(0-4294967295)]",
	    NO_STR
	    SET_STR
	    "BGP weight for routing table\n"
	    "Weight value\n")
{
	const char *xpath = "./set-action[action='frr-bgp-route-map:weight']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (set_label_index,
	    set_label_index_cmd,
	    "set label-index (0-1048560)",
	    SET_STR
	    "Label index to associate with the prefix\n"
	    "Label index value\n")
{
	int idx_number = 2;
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:label-index']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:label-index", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			      argv[idx_number]->arg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_label_index,
	    no_set_label_index_cmd,
	    "no set label-index [(0-1048560)]",
	    NO_STR
	    SET_STR
	    "Label index to associate with the prefix\n"
	    "Label index value\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:label-index']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (set_aspath_prepend_lastas,
	    set_aspath_prepend_lastas_cmd,
	    "set as-path prepend last-as (1-10)",
	    SET_STR
	    "Transform BGP AS_PATH attribute\n"
	    "Prepend to the as-path\n"
	    "Use the last AS-number in the as-path\n"
	    "Number of times to insert\n")
{
	int idx_num = 4;

	const char *xpath =
		"./set-action[action='frr-bgp-route-map:as-path-prepend']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:last-as", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			      argv[idx_num]->arg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(set_aspath_replace_asn, set_aspath_replace_asn_cmd,
	   "set as-path replace <any|ASNUM>$replace [<ASNUM>$configured_asn]",
	   SET_STR
	   "Transform BGP AS_PATH attribute\n"
	   "Replace AS number to local or configured AS number\n"
	   "Replace any AS number to local or configured AS number\n"
	   "Replace a specific AS number to local or configured AS number\n"
	   "Define the configured AS number\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:as-path-replace']";
	char xpath_value[XPATH_MAXLEN];
	as_t as_value, as_configured_value;
	char replace_value[ASN_STRING_MAX_SIZE * 2];

	if (!strmatch(replace, "any") && !asn_str2asn(replace, &as_value)) {
		vty_out(vty, "%% Invalid AS value %s\n", replace);
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (configured_asn_str &&
	    !asn_str2asn(configured_asn_str, &as_configured_value)) {
		vty_out(vty, "%% Invalid AS configured value %s\n",
			configured_asn_str);
		return CMD_WARNING_CONFIG_FAILED;
	}
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:replace-as-path", xpath);
	snprintf(replace_value, sizeof(replace_value), "%s%s%s", replace,
		 configured_asn_str ? " " : "",
		 configured_asn_str ? configured_asn_str : "");
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, replace_value);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_set_aspath_replace_asn, no_set_aspath_replace_asn_cmd,
	   "no set as-path replace [<any|ASNUM>] [<ASNUM>$configured_asn]",
	   NO_STR SET_STR
	   "Transform BGP AS_PATH attribute\n"
	   "Replace AS number to local or configured AS number\n"
	   "Replace any AS number to local or configured AS number\n"
	   "Replace a specific AS number to local or configured AS number\n"
	   "Define the configured AS number\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:as-path-replace']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	set_aspath_replace_access_list, set_aspath_replace_access_list_cmd,
	"set as-path replace as-path-access-list AS_PATH_FILTER_NAME$aspath_filter_name [<ASNUM>$configured_asn]",
	SET_STR
	"Transform BGP AS-path attribute\n"
	"Replace AS number to local or configured AS number\n"
	"Specify an as path access list name\n"
	"AS path access list name\n"
	"Define the configured AS number\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:as-path-replace']";
	char xpath_value[XPATH_MAXLEN];
	as_t as_configured_value;

	if (configured_asn_str &&
	    !asn_str2asn(configured_asn_str, &as_configured_value)) {
		vty_out(vty, "%% Invalid AS configured value %s\n",
			configured_asn_str);
		return CMD_WARNING_CONFIG_FAILED;
	}

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:replace-as-path-access-list",
		 xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			      aspath_filter_name);

	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:replace-as-path-access-list-configured-asn",
		 xpath);
	if (configured_asn_str)
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
				      configured_asn_str);
	else
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_set_aspath_replace_access_list, no_set_aspath_replace_access_list_cmd,
	"no set as-path replace as-path-access-list [AS_PATH_FILTER_NAME] [<ASNUM>$configured_asn]",
	NO_STR
	SET_STR
	"Transform BGP AS_PATH attribute\n"
	"Replace AS number to local or configured AS number\n"
	"Specify an as path access list name\n"
	"AS path access list name\n"
	"Define the configured AS number\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:as-path-replace']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_aspath_prepend,
	    no_set_aspath_prepend_last_as_cmd,
	    "no set as-path prepend [last-as [(1-10)]]",
	    NO_STR
	    SET_STR
	    "Transform BGP AS_PATH attribute\n"
	    "Prepend to the as-path\n"
	    "Use the peers AS-number\n"
	    "Number of times to insert\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:as-path-prepend']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_YANG (no_set_aspath_prepend,
            no_set_aspath_prepend_as_cmd,
            "no set as-path prepend ASNUM...",
            NO_STR
            SET_STR
            "Transform BGP AS_PATH attribute\n"
            "Prepend to the as-path\n"
            AS_STR)

DEFPY_YANG(set_aspath_exclude_all, set_aspath_exclude_all_cmd,
	   "[no$no] set as-path exclude all$all",
	   NO_STR SET_STR
	   "Transform BGP AS-path attribute\n"
	   "Exclude from the as-path\n"
	   "Exclude all AS numbers from the as-path\n")
{
	int ret;
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:as-path-exclude']";
	char xpath_value[XPATH_MAXLEN];

	if (no)
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	else {
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		snprintf(xpath_value, sizeof(xpath_value),
			 "%s/rmap-set-action/frr-bgp-route-map:exclude-as-path",
			 xpath);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, all);
	}
	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFUN_YANG (no_set_aspath_exclude,
	    no_set_aspath_exclude_cmd,
	    "no set as-path exclude ASNUM...",
	    NO_STR
	    SET_STR
	    "Transform BGP AS_PATH attribute\n"
	    "Exclude from the as-path\n"
	    "AS number\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:as-path-exclude']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(set_aspath_exclude_access_list, set_aspath_exclude_access_list_cmd,
	   "set as-path exclude as-path-access-list AS_PATH_FILTER_NAME",
	   SET_STR
	   "Transform BGP AS-path attribute\n"
	   "Exclude from the as-path\n"
	   "Specify an as path access list name\n"
	   "AS path access list name\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:as-path-exclude']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:exclude-as-path-access-list",
		 xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			      as_path_filter_name);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_set_aspath_exclude_access_list, no_set_aspath_exclude_access_list_cmd,
	   "no set as-path exclude as-path-access-list [AS_PATH_FILTER_NAME]",
	   NO_STR
	   SET_STR
	   "Transform BGP AS_PATH attribute\n"
	   "Exclude from the as-path\n"
	   "Specify an as path access list name\n"
	   "AS path access list name\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:as-path-exclude']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_YANG (no_set_aspath_exclude, no_set_aspath_exclude_all_cmd,
            "no set as-path exclude",
            NO_STR SET_STR
            "Transform BGP AS_PATH attribute\n"
            "Exclude from the as-path\n")

DEFUN_YANG (set_community_none,
	    set_community_none_cmd,
	    "set community none",
	    SET_STR
	    "BGP community attribute\n"
	    "No community attribute\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-community']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:community-none", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_community,
	    no_set_community_cmd,
	    "no set community AA:NN...",
	    NO_STR
	    SET_STR
	    "BGP community attribute\n"
	    COMMUNITY_VAL_STR)
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-community']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_YANG (no_set_community,
            no_set_community_short_cmd,
            "no set community",
            NO_STR
            SET_STR
            "BGP community attribute\n")

static int _set_community_change_cmd(struct vty *vty, const char *name, bool delete, bool add,
				     bool replace)
{
	char xpath_value[XPATH_MAXLEN];
	char xpath_set[2 * XPATH_MAXLEN];
	const char *action_type = NULL;

	if (delete)
		action_type = "-delete";
	else if (add)
		action_type = "-add";
	else if (replace)
		action_type = "-replace";

	snprintf(xpath_value, XPATH_MAXLEN, "./set-action[action='frr-bgp-route-map:comm-list%s']",
		 action_type);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_CREATE, NULL);

	snprintf(xpath_set, 2 * XPATH_MAXLEN,
		 "%s/rmap-set-action/frr-bgp-route-map:comm-list-name%s", xpath_value, action_type);

	nb_cli_enqueue_change(vty, xpath_set, NB_OP_MODIFY, name);
	return nb_cli_apply_changes(vty, NULL);
}

#if CONFDATE > 20270527
CPP_NOTICE("Remove `[no] set comm-list <COMM_LIST> delete` commands")
#endif

DEFPY_YANG_HIDDEN (set_community_delete,
       set_community_delete_cmd,
       "set comm-list <(1-99)|(100-500)|COMMUNITY_LIST_NAME> delete",
       SET_STR
       "set BGP community list (for deletion)\n"
       "Community-list number (standard)\n"
       "Community-list number (expanded)\n"
       "Community-list name\n"
       "Delete matching communities\n")
{
	int idx_comm_list = 2;

	return _set_community_change_cmd(vty, argv[idx_comm_list]->arg, true, false, false);
}

DEFUN_YANG_HIDDEN (no_set_community_delete,
	    no_set_community_delete_cmd,
	    "no set comm-list [<(1-99)|(100-500)|COMMUNITY_LIST_NAME> delete]",
	    NO_STR
	    SET_STR
	    "set BGP community list (for deletion)\n"
	    "Community-list number (standard)\n"
	    "Community-list number (expanded)\n"
	    "Community-list name\n"
	    "Delete matching communities\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:comm-list-delete']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (set_community_change,
       set_community_change_cmd,
       "set comm-list <delete$del|add$add|replace$rep> <(1-99)|(100-500)|COMMUNITY_LIST_NAME>$name",
       SET_STR
       "Set BGP community list\n"
       "Delete matching communities\n"
       "Add communities\n"
       "Replace communities\n"
       "Community-list number (standard)\n"
       "Community-list number (expanded)\n"
       "Community-list name\n")
{
	return _set_community_change_cmd(vty, name, del, add, rep);
}


DEFPY_YANG (no_set_community_change,
	    no_set_community_change_cmd,
	    "no set comm-list <delete$del|add$add|replace$rep> [<(1-99)|(100-500)|COMMUNITY_LIST_NAME>$name]",
	    NO_STR
	    SET_STR
	    "Set BGP community list\n"
	    "Delete matching communities\n"
	    "Add communities\n"
	    "Replace communities\n"
	    "Community-list number (standard)\n"
	    "Community-list number (expanded)\n"
	    "Community-list name\n")
{
	char xpath_value[XPATH_MAXLEN];
	const char *action_type = NULL;

	if (del)
		action_type = "comm-list-delete";
	else if (add)
		action_type = "comm-list-add";
	else if (rep)
		action_type = "comm-list-replace";

	snprintf(xpath_value, XPATH_MAXLEN, "./set-action[action='frr-bgp-route-map:%s']",
		 action_type);

	nb_cli_enqueue_change(vty, xpath_value, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/* Parse a 'GA:LD1:LD2' token: exactly three all-digit decimal parts,
 * each <= 4294967295 (lcommunity_gettoken()'s numeric acceptance). */
static bool set_lcommunity_token_member(const char *token, unsigned long *ga,
					unsigned long *ld1, unsigned long *ld2)
{
	unsigned long *part[] = { ga, ld1, ld2 };
	const char *p = token;
	char *endptr;

	for (int i = 0; i < 3; i++) {
		if (!isdigit((unsigned char)*p))
			return false;
		errno = 0;
		*part[i] = strtoul(p, &endptr, 10);
		if (errno || *part[i] > UINT32_MAX)
			return false;
		if (i < 2) {
			if (*endptr != ':')
				return false;
			p = endptr + 1;
		} else if (*endptr != '\0') {
			return false;
		}
	}

	return true;
}

/*
 * The structured 'set community', 'set large-community' and 'set extcommunity
 * <rt|soo|nt|color>' CLIs can enqueue more per-token northbound edits than one
 * transaction's change budget (VTY_MAXCFGCHANGES), so they apply the edits in
 * batches. Under mgmtd each nb_cli_apply_changes() would otherwise trigger its
 * own implicit commit; the first one locks the shared candidate datastore and
 * queues an asynchronous commit, so a second implicit commit from the next
 * batch would assert on the still-locked candidate and abort mgmtd
 * (mgmt_vty_frontend.c: vty_mgmt_lock_candidate_inline()).
 *
 * Group every batch after the first into that single queued commit: mark the
 * vty pending so the later applies only edit the still-locked candidate in
 * place. Because the queued commit is processed after the command returns, it
 * sees the whole edited candidate and applies all the members at once -- the
 * same "many edits, one commit" path a config file uses. Outside mgmtd (no
 * frontend callback installed) this is a no-op and the classic per-daemon
 * commit path is untouched.
 */
static void set_comm_batch_group_begin(struct vty *vty, bool *grouped)
{
	if (*grouped || !nb_cli_apply_changes_mgmt_cb)
		return;
	*grouped = true;
	vty->pending_allowed = true;
}

static void set_comm_batch_group_end(struct vty *vty, bool grouped)
{
	if (!grouped)
		return;
	vty->pending_allowed = false;
	/* The queued commit covers the deferred edits; clear the pending
	 * set-config accounting so a later config-end issues no extra commit. */
	vty->mgmt_num_pending_setcfg = 0;
}

DEFUN_YANG (set_lcommunity,
	    set_lcommunity_cmd,
	    "set large-community AA:BB:CC...",
	    SET_STR
	    "BGP large community attribute\n"
	    "Large Community number in aa:bb:cc format or additive\n")
{
	int idx_val = 2;
	int i;
	int nqueued;
	int ret;
	bool grouped = false;
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-large-community']";
	char xpath_comm[XPATH_MAXLEN];
	char xpath_value[XPATH_MAXLEN * 2];

	snprintf(xpath_comm, sizeof(xpath_comm),
		 "%s/rmap-set-action/frr-bgp-route-map:large-communities",
		 xpath);

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	/* Replace, not merge, whatever an earlier line left. */
	nb_cli_enqueue_change(vty, xpath_comm, NB_OP_DESTROY, NULL);
	nqueued = 2;

	/* One config line's tokens can exceed one transaction's change
	 * budget (VTY_MAXCFGCHANGES); apply in batches. Only the first
	 * batch carries the replace-destroy above, later ones merge
	 * more tokens into the already-created container. */
	for (i = idx_val; i < argc; i++) {
		const char *tok = argv[i]->arg;
		unsigned long ga, ld1, ld2;

		if (nqueued == VTY_MAXCFGCHANGES) {
			ret = nb_cli_apply_changes(vty, NULL);
			if (ret != CMD_SUCCESS) {
				set_comm_batch_group_end(vty, grouped);
				return ret;
			}
			nqueued = 0;
			/* nb_cli_apply_changes() consumes the pending
			 * changes into the candidate but does not clear
			 * vty->num_cfg_changes (only cmd_execute does, once
			 * per command), so reset it too or the next enqueue
			 * overflows VTY_MAXCFGCHANGES and silently drops
			 * tokens. */
			vty->num_cfg_changes = 0;
			/* This first apply already locked the candidate and
			 * queued the implicit commit; fold every later batch
			 * into it so we do not re-lock and abort mgmtd. */
			set_comm_batch_group_begin(vty, &grouped);
		}
		nqueued++;

		if (strcmp(tok, "additive") == 0) {
			snprintf(xpath_value, sizeof(xpath_value),
				 "%s/additive", xpath_comm);
			nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
					      "true");
		} else if (set_lcommunity_token_member(tok, &ga, &ld1, &ld2)) {
			snprintf(xpath_value, sizeof(xpath_value),
				 "%s/member[global-admin='%lu'][local-data-1='%lu'][local-data-2='%lu']",
				 xpath_comm, ga, ld1, ld2);
			nb_cli_enqueue_change(vty, xpath_value, NB_OP_CREATE,
					      NULL);
		} else {
			/* Kept verbatim; the apply-time compile rejects
			 * it, as it did for the old free-form string. */
			snprintf(xpath_value, sizeof(xpath_value),
				 "%s/raw[.='%s']", xpath_comm, tok);
			nb_cli_enqueue_change(vty, xpath_value, NB_OP_CREATE,
					      NULL);
		}
	}

	ret = nb_cli_apply_changes(vty, NULL);
	set_comm_batch_group_end(vty, grouped);
	return ret;
}

DEFUN_YANG (set_lcommunity_none,
	    set_lcommunity_none_cmd,
	    "set large-community none",
	    SET_STR
	    "BGP large community attribute\n"
	    "No large community attribute\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-large-community']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:large-community-none",
		 xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_lcommunity,
	    no_set_lcommunity_cmd,
	    "no set large-community none",
	    NO_STR
	    SET_STR
	    "BGP large community attribute\n"
	    "No community attribute\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-large-community']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_lcommunity1,
	    no_set_lcommunity1_cmd,
	    "no set large-community AA:BB:CC...",
	    NO_STR
	    SET_STR
	    "BGP large community attribute\n"
	    "Large community in AA:BB:CC... format or additive\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-large-community']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_YANG (no_set_lcommunity1,
            no_set_lcommunity1_short_cmd,
            "no set large-community",
            NO_STR
            SET_STR
            "BGP large community attribute\n")

static int _set_lcommunity_delete_cmd(struct vty *vty, const char *name)
{
	const char *xpath = "./set-action[action='frr-bgp-route-map:large-comm-list-delete']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:comm-list-name", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, name);
	return nb_cli_apply_changes(vty, NULL);
}

#if CONFDATE > 20270527
CPP_NOTICE("Remove `[no] set large-comm-list <COMM_LIST> delete` commands")
#endif

DEFPY_YANG (set_lcommunity_delete,
       set_lcommunity_delete_cmd,
       "set large-comm-list <(1-99)|(100-500)|LCOMMUNITY_LIST_NAME> delete",
       SET_STR
       "set BGP large community list (for deletion)\n"
       "Large Community-list number (standard)\n"
       "Large Communitly-list number (expanded)\n"
       "Large Community-list name\n"
       "Delete matching large communities\n")
{
	int idx_lcomm_list = 2;

	return _set_lcommunity_delete_cmd(vty, argv[idx_lcomm_list]->arg);
}

DEFUN_YANG (no_set_lcommunity_delete,
	    no_set_lcommunity_delete_cmd,
	    "no set large-comm-list <(1-99)|(100-500)|LCOMMUNITY_LIST_NAME> [delete]",
	    NO_STR
	    SET_STR
	    "set BGP large community list (for deletion)\n"
	    "Large Community-list number (standard)\n"
	    "Large Communitly-list number (expanded)\n"
	    "Large Community-list name\n"
	    "Delete matching large communities\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:large-comm-list-delete']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_YANG (no_set_lcommunity_delete,
            no_set_lcommunity_delete_short_cmd,
            "no set large-comm-list",
            NO_STR
            SET_STR
            "set BGP large community list (for deletion)\n")

DEFPY_YANG (set_lcommunity_delete_method2,
       set_lcommunity_delete_method2_cmd,
       "set large-comm-list delete <(1-99)|(100-500)|LCOMMUNITY_LIST_NAME>",
       SET_STR
       "set BGP large community list (for deletion)\n"
       "Delete matching large communities\n"
       "Large Community-list number (standard)\n"
       "Large Communitly-list number (expanded)\n"
       "Large Community-list name\n")
{
	int idx_lcomm_list = 3;

	return _set_lcommunity_delete_cmd(vty, argv[idx_lcomm_list]->arg);
}

DEFUN_YANG (no_set_lcommunity_delete_method2,
	    no_set_lcommunity_delete_method2_cmd,
	    "no set large-comm-list delete [<(1-99)|(100-500)|LCOMMUNITY_LIST_NAME>]",
	    NO_STR
	    SET_STR
	    "set BGP large community list (for deletion)\n"
	    "Delete matching large communities\n"
	    "Large Community-list number (standard)\n"
	    "Large Communitly-list number (expanded)\n"
	    "Large Community-list name\n")
{
	const char *xpath = "./set-action[action='frr-bgp-route-map:large-comm-list-delete']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/* How one 'ASN:NN' or 'A.B.C.D:NN' token of the rt/soo commands maps
 * onto the structured route-target/route-origin set. */
enum set_ecomm_token_kind {
	SET_ECOMM_TOKEN_RAW,
	SET_ECOMM_TOKEN_AS2,
	SET_ECOMM_TOKEN_AS4,
	SET_ECOMM_TOKEN_IPV4,
};

/* Parse an all-digit decimal number bounded by 'max'. */
static bool set_ecommunity_token_number(const char *str, const char *end,
					unsigned long max, unsigned long *num)
{
	char *endptr;

	if (!isdigit((unsigned char)*str))
		return false;
	errno = 0;
	*num = strtoul(str, &endptr, 10);
	if (errno || endptr != end || *num > max)
		return false;

	return true;
}

/* Classify one token the way the daemon's tokenizer encodes it:
 * 'A.B.C.D:NN' (NN <= 65535) is IPv4-encoded, 'AS:NN' with
 * AS <= 65535 is 2-byte-AS-encoded (4-byte value), a bigger plain AS
 * or an asdot 'A.B' AS is 4-byte-AS-encoded (2-byte value). Anything
 * else stays a raw token. */
static enum set_ecomm_token_kind
set_ecommunity_token_classify(const char *token, char *addr, size_t addr_size,
			      unsigned long *global_admin,
			      unsigned long *local_admin)
{
	const char *colon = strchr(token, ':');
	const char *p;
	unsigned long high, low;
	int ndot = 0;

	if (!colon || colon == token || strchr(colon + 1, ':'))
		return SET_ECOMM_TOKEN_RAW;
	for (p = token; p < colon; p++)
		if (*p == '.')
			ndot++;

	if (ndot == 0) {
		/* Plain AS number. */
		if (!set_ecommunity_token_number(token, colon, UINT32_MAX,
						 global_admin))
			return SET_ECOMM_TOKEN_RAW;
		if (*global_admin <= UINT16_MAX) {
			if (!set_ecommunity_token_number(colon + 1, colon + 1 +
							 strlen(colon + 1),
							 UINT32_MAX,
							 local_admin))
				return SET_ECOMM_TOKEN_RAW;
			return SET_ECOMM_TOKEN_AS2;
		}
		if (!set_ecommunity_token_number(colon + 1,
						 colon + 1 + strlen(colon + 1),
						 UINT16_MAX, local_admin))
			return SET_ECOMM_TOKEN_RAW;
		return SET_ECOMM_TOKEN_AS4;
	}

	if (ndot == 1) {
		/* Asdot 'A.B' AS number; always a 4-byte AS. */
		const char *dot = strchr(token, '.');

		if (!set_ecommunity_token_number(token, dot, UINT16_MAX, &high) ||
		    !set_ecommunity_token_number(dot + 1, colon, UINT16_MAX,
						 &low) ||
		    !set_ecommunity_token_number(colon + 1,
						 colon + 1 + strlen(colon + 1),
						 UINT16_MAX, local_admin))
			return SET_ECOMM_TOKEN_RAW;
		*global_admin = (high << 16) + low;
		return SET_ECOMM_TOKEN_AS4;
	}

	if (ndot == 3) {
		/* IPv4 global administrator. */
		struct in_addr ip;

		if ((size_t)(colon - token) >= addr_size)
			return SET_ECOMM_TOKEN_RAW;
		memcpy(addr, token, colon - token);
		addr[colon - token] = '\0';
		if (inet_pton(AF_INET, addr, &ip) != 1 ||
		    !set_ecommunity_token_number(colon + 1,
						 colon + 1 + strlen(colon + 1),
						 UINT16_MAX, local_admin))
			return SET_ECOMM_TOKEN_RAW;
		return SET_ECOMM_TOKEN_IPV4;
	}

	return SET_ECOMM_TOKEN_RAW;
}

/* Turn the rt/soo token list into edits against a structured
 * route-target/route-origin container rooted at 'xpath_set'. */
static int set_ecommunity_structured(struct vty *vty, const char *xpath_action,
				     const char *xpath_set,
				     struct cmd_token *argv[], int argc,
				     int idx_start)
{
	char xpath_value[XPATH_MAXLEN * 2];
	int i, nqueued, ret;
	bool grouped = false;

	nb_cli_enqueue_change(vty, xpath_action, NB_OP_CREATE, NULL);
	/* Replace, not merge, whatever an earlier line left. */
	nb_cli_enqueue_change(vty, xpath_set, NB_OP_DESTROY, NULL);
	nqueued = 2;

	/* One config line's tokens can exceed one transaction's change
	 * budget (VTY_MAXCFGCHANGES); apply in batches. Only the first
	 * batch carries the replace-destroy above, later ones merge
	 * more tokens into the already-created container. */
	for (i = idx_start; i < argc; i++) {
		const char *tok = argv[i]->arg;
		char addr[INET_ADDRSTRLEN];
		unsigned long ga = 0, la = 0;

		if (nqueued == VTY_MAXCFGCHANGES) {
			ret = nb_cli_apply_changes(vty, NULL);
			if (ret != CMD_SUCCESS) {
				set_comm_batch_group_end(vty, grouped);
				return ret;
			}
			nqueued = 0;
			/* nb_cli_apply_changes() consumes the pending
			 * changes into the candidate but does not clear
			 * vty->num_cfg_changes (only cmd_execute does, once
			 * per command), so reset it too or the next enqueue
			 * overflows VTY_MAXCFGCHANGES and silently drops
			 * tokens. */
			vty->num_cfg_changes = 0;
			/* This first apply already locked the candidate and
			 * queued the implicit commit; fold every later batch
			 * into it so we do not re-lock and abort mgmtd. */
			set_comm_batch_group_begin(vty, &grouped);
		}
		nqueued++;

		switch (set_ecommunity_token_classify(tok, addr, sizeof(addr),
						      &ga, &la)) {
		case SET_ECOMM_TOKEN_AS2:
			snprintf(xpath_value, sizeof(xpath_value),
				 "%s/as2[global-admin='%lu'][local-admin='%lu']",
				 xpath_set, ga, la);
			break;
		case SET_ECOMM_TOKEN_AS4:
			snprintf(xpath_value, sizeof(xpath_value),
				 "%s/as4[global-admin='%lu'][local-admin='%lu']",
				 xpath_set, ga, la);
			break;
		case SET_ECOMM_TOKEN_IPV4:
			snprintf(xpath_value, sizeof(xpath_value),
				 "%s/ipv4[global-admin='%s'][local-admin='%lu']",
				 xpath_set, addr, la);
			break;
		case SET_ECOMM_TOKEN_RAW:
			/* Kept verbatim; the apply-time compile rejects
			 * it, as it did for the old free-form string. */
			snprintf(xpath_value, sizeof(xpath_value),
				 "%s/raw[.='%s']", xpath_set, tok);
			break;
		}
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_CREATE, NULL);
	}

	ret = nb_cli_apply_changes(vty, NULL);
	set_comm_batch_group_end(vty, grouped);
	return ret;
}

DEFUN_YANG (set_ecommunity_rt,
	    set_ecommunity_rt_cmd,
	    "set extcommunity rt ASN:NN_OR_IP-ADDRESS:NN...",
	    SET_STR
	    "BGP extended community attribute\n"
	    "Route Target extended community\n"
	    "VPN extended community\n")
{
	int idx_asn_nn = 3;
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-extcommunity-rt']";
	char xpath_rt[XPATH_MAXLEN];

	snprintf(xpath_rt, sizeof(xpath_rt),
		 "%s/rmap-set-action/frr-bgp-route-map:extcommunity-rt", xpath);

	return set_ecommunity_structured(vty, xpath, xpath_rt, argv, argc,
					 idx_asn_nn);
}

DEFUN_YANG (no_set_ecommunity_rt,
	    no_set_ecommunity_rt_cmd,
	    "no set extcommunity rt ASN:NN_OR_IP-ADDRESS:NN...",
	    NO_STR
	    SET_STR
	    "BGP extended community attribute\n"
	    "Route Target extended community\n"
	    "VPN extended community\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-extcommunity-rt']";
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_YANG (no_set_ecommunity_rt,
            no_set_ecommunity_rt_short_cmd,
            "no set extcommunity rt",
            NO_STR
            SET_STR
            "BGP extended community attribute\n"
            "Route Target extended community\n")

DEFUN_YANG (set_ecommunity_soo,
	    set_ecommunity_soo_cmd,
	    "set extcommunity soo ASN:NN_OR_IP-ADDRESS:NN...",
	    SET_STR
	   "BGP extended community attribute\n"
	   "Site-of-Origin extended community\n"
	   "VPN extended community\n")
{
	int idx_asn_nn = 3;
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-extcommunity-soo']";
	char xpath_soo[XPATH_MAXLEN];

	snprintf(xpath_soo, sizeof(xpath_soo),
		 "%s/rmap-set-action/frr-bgp-route-map:extcommunity-soo",
		 xpath);

	return set_ecommunity_structured(vty, xpath, xpath_soo, argv, argc,
					 idx_asn_nn);
}

DEFUN_YANG (no_set_ecommunity_soo,
	    no_set_ecommunity_soo_cmd,
	    "no set extcommunity soo ASN:NN_OR_IP-ADDRESS:NN...",
	    NO_STR
	    SET_STR
	    "BGP extended community attribute\n"
	    "Site-of-Origin extended community\n"
	    "VPN extended community\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-extcommunity-soo']";
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_YANG (no_set_ecommunity_soo,
            no_set_ecommunity_soo_short_cmd,
            "no set extcommunity soo",
            NO_STR
            SET_STR
            "GP extended community attribute\n"
            "Site-of-Origin extended community\n")

DEFUN_YANG(set_ecommunity_none, set_ecommunity_none_cmd,
	   "set extcommunity none",
	   SET_STR
	   "BGP extended community attribute\n"
	   "No extended community attribute\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-extcommunity-none']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:extcommunity-none",
		 xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_set_ecommunity_none, no_set_ecommunity_none_cmd,
	   "no set extcommunity none",
	   NO_STR SET_STR
	   "BGP extended community attribute\n"
	   "No extended community attribute\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-extcommunity-none']";
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (set_ecommunity_lb,
	    set_ecommunity_lb_cmd,
	    "set extcommunity bandwidth <(0-4294967295)|cumulative|num-multipaths> [non-transitive]",
	    SET_STR
	    "BGP extended community attribute\n"
	    "Link bandwidth extended community\n"
	    "Bandwidth value in Mbps\n"
	    "Cumulative bandwidth of all multipaths (outbound-only)\n"
	    "Internally computed bandwidth based on number of multipaths (outbound-only)\n"
	    "Attribute is set as non-transitive\n")
{
	int idx_lb = 3;
	int idx_non_transitive = 0;
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-extcommunity-lb']";
	char xpath_lb_type[XPATH_MAXLEN];
	char xpath_bandwidth[XPATH_MAXLEN];
	char xpath_non_transitive[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_lb_type, sizeof(xpath_lb_type),
		 "%s/rmap-set-action/frr-bgp-route-map:extcommunity-lb/lb-type",
		 xpath);
	snprintf(xpath_bandwidth, sizeof(xpath_bandwidth),
		 "%s/rmap-set-action/frr-bgp-route-map:extcommunity-lb/bandwidth",
		 xpath);
	snprintf(xpath_non_transitive, sizeof(xpath_non_transitive),
		 "%s/rmap-set-action/frr-bgp-route-map:extcommunity-lb/two-octet-as-specific",
		 xpath);

	if ((strcmp(argv[idx_lb]->arg, "cumulative")) == 0)
		nb_cli_enqueue_change(vty, xpath_lb_type, NB_OP_MODIFY,
				      "cumulative-bandwidth");
	else if ((strcmp(argv[idx_lb]->arg, "num-multipaths")) == 0)
		nb_cli_enqueue_change(vty, xpath_lb_type, NB_OP_MODIFY,
				      "computed-bandwidth");
	else {
		nb_cli_enqueue_change(vty, xpath_lb_type, NB_OP_MODIFY,
				      "explicit-bandwidth");
		nb_cli_enqueue_change(vty, xpath_bandwidth, NB_OP_MODIFY,
				      argv[idx_lb]->arg);
	}

	if (argv_find(argv, argc, "non-transitive", &idx_non_transitive))
		nb_cli_enqueue_change(vty, xpath_non_transitive, NB_OP_MODIFY,
				      "true");
	else
		nb_cli_enqueue_change(vty, xpath_non_transitive, NB_OP_MODIFY,
				      "false");

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_ecommunity_lb,
	    no_set_ecommunity_lb_cmd,
	    "no set extcommunity bandwidth <(0-4294967295)|cumulative|num-multipaths> [non-transitive]",
	    NO_STR
	    SET_STR
	    "BGP extended community attribute\n"
	    "Link bandwidth extended community\n"
	    "Bandwidth value in Mbps\n"
	    "Cumulative bandwidth of all multipaths (outbound-only)\n"
	    "Internally computed bandwidth based on number of multipaths (outbound-only)\n"
	    "Attribute is set as non-transitive\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-extcommunity-lb']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_YANG (no_set_ecommunity_lb,
            no_set_ecommunity_lb_short_cmd,
            "no set extcommunity bandwidth",
            NO_STR
            SET_STR
            "BGP extended community attribute\n"
            "Link bandwidth extended community\n")

/* A node target is just an IPv4 node id; the daemon encodes only the
 * address and renders it back as 'A.B.C.D:0', so a ':NN' decimal
 * suffix is accepted and stripped here. */
static bool set_ecommunity_nt_token_node_id(const char *token, char *addr,
					    size_t addr_size)
{
	const char *colon = strchr(token, ':');
	const char *end = colon ? colon : token + strlen(token);
	const char *p;
	struct in_addr ip;

	if (colon) {
		if (*(colon + 1) == '\0')
			return false;
		for (p = colon + 1; *p != '\0'; p++)
			if (!isdigit((unsigned char)*p))
				return false;
	}
	if ((size_t)(end - token) >= addr_size)
		return false;
	memcpy(addr, token, end - token);
	addr[end - token] = '\0';

	return inet_pton(AF_INET, addr, &ip) == 1;
}

DEFPY_YANG (set_ecommunity_nt,
	    set_ecommunity_nt_cmd,
	    "set extcommunity nt RTLIST...",
	    SET_STR
	    "BGP extended community attribute\n"
	    "Node Target extended community\n"
	    "Node Target ID\n")
{
	int idx_nt = 3;
	int i, nqueued, ret;
	bool grouped = false;
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-extcommunity-nt']";
	char xpath_nt[XPATH_MAXLEN];
	char xpath_value[XPATH_MAXLEN * 2];

	snprintf(xpath_nt, sizeof(xpath_nt),
		 "%s/rmap-set-action/frr-bgp-route-map:extcommunity-nt", xpath);

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	/* Replace, not merge, whatever an earlier line left. */
	nb_cli_enqueue_change(vty, xpath_nt, NB_OP_DESTROY, NULL);
	nqueued = 2;

	/* One config line's tokens can exceed one transaction's change
	 * budget (VTY_MAXCFGCHANGES); apply in batches. Only the first
	 * batch carries the replace-destroy above, later ones merge
	 * more tokens into the already-created container. */
	for (i = idx_nt; i < argc; i++) {
		const char *tok = argv[i]->arg;
		char addr[INET_ADDRSTRLEN];

		if (nqueued == VTY_MAXCFGCHANGES) {
			ret = nb_cli_apply_changes(vty, NULL);
			if (ret != CMD_SUCCESS) {
				set_comm_batch_group_end(vty, grouped);
				return ret;
			}
			nqueued = 0;
			/* nb_cli_apply_changes() consumes the pending
			 * changes into the candidate but does not clear
			 * vty->num_cfg_changes (only cmd_execute does, once
			 * per command), so reset it too or the next enqueue
			 * overflows VTY_MAXCFGCHANGES and silently drops
			 * tokens. */
			vty->num_cfg_changes = 0;
			/* This first apply already locked the candidate and
			 * queued the implicit commit; fold every later batch
			 * into it so we do not re-lock and abort mgmtd. */
			set_comm_batch_group_begin(vty, &grouped);
		}
		nqueued++;

		if (set_ecommunity_nt_token_node_id(tok, addr, sizeof(addr)))
			snprintf(xpath_value, sizeof(xpath_value),
				 "%s/node-id[.='%s']", xpath_nt, addr);
		else
			/* Kept verbatim; the apply-time compile rejects
			 * it, as it did for the old free-form string. */
			snprintf(xpath_value, sizeof(xpath_value),
				 "%s/raw[.='%s']", xpath_nt, tok);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_CREATE, NULL);
	}

	ret = nb_cli_apply_changes(vty, NULL);
	set_comm_batch_group_end(vty, grouped);
	return ret;
}

DEFPY_YANG (no_set_ecommunity_nt,
	    no_set_ecommunity_nt_cmd,
	    "no set extcommunity nt RTLIST...",
	    NO_STR
	    SET_STR
	    "BGP extended community attribute\n"
	    "Node Target extended community\n"
	    "Node Target ID\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-extcommunity-nt']";
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/* Classify one 'set extcommunity color' token the way the daemon's
 * tokenizer parses it: '<CO>:<value>' with the CO steering bits as a
 * binary number up to 3, or a bare '<value>'. A bare nonzero value
 * implies CO 01; a bare zero keeps CO 00, matching the daemon's
 * encoding of that token. */
static bool set_ecommunity_color_token(const char *token, const char **co,
				       unsigned long *value)
{
	static const char *const co_names[] = { "00", "01", "10", "11" };
	const char *colon = strchr(token, ':');
	const char *p;
	char *endptr;
	unsigned long bits;

	if (colon) {
		if (colon == token || strchr(colon + 1, ':'))
			return false;
		for (p = token; p < colon; p++)
			if (*p != '0' && *p != '1')
				return false;
		errno = 0;
		bits = strtoul(token, &endptr, 2);
		if (errno || endptr != colon || bits > 3)
			return false;
		if (!set_ecommunity_token_number(colon + 1,
						 colon + 1 + strlen(colon + 1),
						 UINT32_MAX, value))
			return false;
		*co = co_names[bits];
		return true;
	}

	if (!set_ecommunity_token_number(token, token + strlen(token),
					 UINT32_MAX, value))
		return false;
	*co = *value ? co_names[1] : co_names[0];
	return true;
}

DEFPY_YANG(set_ecommunity_color, set_ecommunity_color_cmd,
	   "set extcommunity color RTLIST...",
	   SET_STR
	   "BGP extended community attribute\n"
	   "Color extended community\n"
	   "Color ID\n")
{
	int idx_color = 3;
	int i, nqueued, ret;
	bool grouped = false;
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-extcommunity-color']";
	char xpath_color[XPATH_MAXLEN];
	char xpath_value[XPATH_MAXLEN * 2];

	snprintf(xpath_color, sizeof(xpath_color),
		 "%s/rmap-set-action/frr-bgp-route-map:extcommunity-color",
		 xpath);

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	/* Replace, not merge, whatever an earlier line left. */
	nb_cli_enqueue_change(vty, xpath_color, NB_OP_DESTROY, NULL);
	nqueued = 2;

	/* One config line's tokens can exceed one transaction's change
	 * budget (VTY_MAXCFGCHANGES); apply in batches. Only the first
	 * batch carries the replace-destroy above, later ones merge
	 * more tokens into the already-created container. */
	for (i = idx_color; i < argc; i++) {
		const char *tok = argv[i]->arg;
		const char *co = NULL;
		unsigned long value = 0;

		if (nqueued == VTY_MAXCFGCHANGES) {
			ret = nb_cli_apply_changes(vty, NULL);
			if (ret != CMD_SUCCESS) {
				set_comm_batch_group_end(vty, grouped);
				return ret;
			}
			nqueued = 0;
			/* nb_cli_apply_changes() consumes the pending
			 * changes into the candidate but does not clear
			 * vty->num_cfg_changes (only cmd_execute does, once
			 * per command), so reset it too or the next enqueue
			 * overflows VTY_MAXCFGCHANGES and silently drops
			 * tokens. */
			vty->num_cfg_changes = 0;
			/* This first apply already locked the candidate and
			 * queued the implicit commit; fold every later batch
			 * into it so we do not re-lock and abort mgmtd. */
			set_comm_batch_group_begin(vty, &grouped);
		}
		nqueued++;

		if (set_ecommunity_color_token(tok, &co, &value))
			snprintf(xpath_value, sizeof(xpath_value),
				 "%s/color[value='%lu'][co-flag='%s']",
				 xpath_color, value, co);
		else
			/* Kept verbatim; the apply-time compile rejects
			 * it, as it did for the old free-form string. */
			snprintf(xpath_value, sizeof(xpath_value),
				 "%s/raw[.='%s']", xpath_color, tok);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_CREATE, NULL);
	}

	ret = nb_cli_apply_changes(vty, NULL);
	set_comm_batch_group_end(vty, grouped);
	return ret;
}

DEFPY_YANG(no_set_ecommunity_color_all, no_set_ecommunity_color_all_cmd,
	   "no set extcommunity color",
	   NO_STR SET_STR
	   "BGP extended community attribute\n"
	   "Color extended community\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-extcommunity-color']";
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_set_ecommunity_color, no_set_ecommunity_color_cmd,
	   "no set extcommunity color RTLIST...",
	   NO_STR SET_STR
	   "BGP extended community attribute\n"
	   "Color extended community\n"
	   "Color ID\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-extcommunity-color']";
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_YANG (no_set_ecommunity_nt,
            no_set_ecommunity_nt_short_cmd,
            "no set extcommunity nt",
            NO_STR
            SET_STR
            "BGP extended community attribute\n"
            "Node Target extended community\n")

DEFUN_YANG (set_origin,
	    set_origin_cmd,
	    "set origin <egp|igp|incomplete>",
	    SET_STR
	    "BGP origin code\n"
	    "remote EGP\n"
	    "local IGP\n"
	    "unknown heritage\n")
{
	int idx_origin = 2;
	const char *origin_type;
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-origin']";
	char xpath_value[XPATH_MAXLEN];

	if (strncmp(argv[idx_origin]->arg, "igp", 2) == 0)
		origin_type = "igp";
	else if (strncmp(argv[idx_origin]->arg, "egp", 1) == 0)
		origin_type = "egp";
	else if (strncmp(argv[idx_origin]->arg, "incomplete", 2) == 0)
		origin_type = "incomplete";
	else {
		vty_out(vty, "%% Invalid match origin type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:origin", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, origin_type);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_origin,
	    no_set_origin_cmd,
	    "no set origin [<egp|igp|incomplete>]",
	    NO_STR
	    SET_STR
	    "BGP origin code\n"
	    "remote EGP\n"
	    "local IGP\n"
	    "unknown heritage\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-origin']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (set_atomic_aggregate,
	    set_atomic_aggregate_cmd,
	    "set atomic-aggregate",
	    SET_STR
	    "BGP atomic aggregate attribute\n" )
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:atomic-aggregate']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:atomic-aggregate",
		 xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_atomic_aggregate,
	    no_set_atomic_aggregate_cmd,
	    "no set atomic-aggregate",
	    NO_STR
	    SET_STR
	    "BGP atomic aggregate attribute\n" )
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:atomic-aggregate']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (set_aigp_metric,
	    set_aigp_metric_cmd,
	    "set aigp-metric <igp-metric|(0-4294967295)>$aigp_metric",
	    SET_STR
	    "BGP AIGP attribute (AIGP Metric TLV)\n"
	    "AIGP Metric value from IGP protocol\n"
	    "Manual AIGP Metric value\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:aigp-metric']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:aigp-metric", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, aigp_metric);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (no_set_aigp_metric,
	    no_set_aigp_metric_cmd,
	    "no set aigp-metric [<igp-metric|(0-4294967295)>]",
	    NO_STR
	    SET_STR
	    "BGP AIGP attribute (AIGP Metric TLV)\n"
	    "AIGP Metric value from IGP protocol\n"
	    "Manual AIGP Metric value\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:aigp-metric']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (set_aggregator_as,
	    set_aggregator_as_cmd,
	    "set aggregator as ASNUM A.B.C.D",
	    SET_STR
	    "BGP aggregator attribute\n"
	    "AS number of aggregator\n"
	    AS_STR
	    "IP address of aggregator\n")
{
	int idx_number = 3;
	int idx_ipv4 = 4;
	char xpath_asn[XPATH_MAXLEN];
	char xpath_addr[XPATH_MAXLEN];
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:aggregator']";
	as_t as_value;

	if (!asn_str2asn(argv[idx_number]->arg, &as_value)) {
		vty_out(vty, "%% Invalid AS value %s\n", argv[idx_number]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(
		xpath_asn, sizeof(xpath_asn),
		"%s/rmap-set-action/frr-bgp-route-map:aggregator/aggregator-asn",
		xpath);
	nb_cli_enqueue_change(vty, xpath_asn, NB_OP_MODIFY,
			      argv[idx_number]->arg);

	snprintf(
		xpath_addr, sizeof(xpath_addr),
		"%s/rmap-set-action/frr-bgp-route-map:aggregator/aggregator-address",
		xpath);
	nb_cli_enqueue_change(vty, xpath_addr, NB_OP_MODIFY,
			      argv[idx_ipv4]->arg);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_aggregator_as,
	    no_set_aggregator_as_cmd,
	    "no set aggregator as [ASNUM A.B.C.D]",
	    NO_STR
	    SET_STR
	    "BGP aggregator attribute\n"
	    "AS number of aggregator\n"
	    AS_STR
	    "IP address of aggregator\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:aggregator']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (match_ipv6_next_hop_address,
	    match_ipv6_next_hop_address_cmd,
	    "match ipv6 next-hop address X:X::X:X",
	    MATCH_STR
	    IPV6_STR
	    "Match IPv6 next-hop address of route\n"
	    "IPv6 address\n"
	    "IPv6 address of next hop\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:ipv6-nexthop']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:ipv6-address",
		 xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			      argv[argc - 1]->arg);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_match_ipv6_next_hop_address,
	    no_match_ipv6_next_hop_address_cmd,
	    "no match ipv6 next-hop address X:X::X:X",
	    NO_STR
	    MATCH_STR
	    IPV6_STR
	    "Match IPv6 next-hop address of route\n"
	    "IPv6 address\n"
	    "IPv6 address of next hop\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:ipv6-nexthop']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_HIDDEN (match_ipv6_next_hop_address,
	      match_ipv6_next_hop_old_cmd,
	      "match ipv6 next-hop X:X::X:X",
	      MATCH_STR
	      IPV6_STR
	      "Match IPv6 next-hop address of route\n"
	      "IPv6 address of next hop\n")

ALIAS_HIDDEN (no_match_ipv6_next_hop_address,
	      no_match_ipv6_next_hop_old_cmd,
	      "no match ipv6 next-hop X:X::X:X",
	      NO_STR
	      MATCH_STR
	      IPV6_STR
	      "Match IPv6 next-hop address of route\n"
	      "IPv6 address of next hop\n")

DEFPY_YANG (match_ipv4_next_hop,
       match_ipv4_next_hop_cmd,
       "match ip next-hop address A.B.C.D",
       MATCH_STR
       IP_STR
       "Match IP next-hop address of route\n"
       "IP address\n"
       "IP address of next-hop\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:ipv4-nexthop']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:ipv4-address",
		 xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, argv[4]->arg);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (no_match_ipv4_next_hop,
       no_match_ipv4_next_hop_cmd,
       "no match ip next-hop address [A.B.C.D]",
       NO_STR
       MATCH_STR
       IP_STR
       "Match IP next-hop address of route\n"
       "IP address\n"
       "IP address of next-hop\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:ipv4-nexthop']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (set_ipv6_nexthop_peer,
	    set_ipv6_nexthop_peer_cmd,
	    "set ipv6 next-hop peer-address",
	    SET_STR
	    IPV6_STR
	    "Next hop address\n"
	    "Use peer address (for BGP only)\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:ipv6-peer-address']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:preference", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, "true");

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_ipv6_nexthop_peer,
	    no_set_ipv6_nexthop_peer_cmd,
	    "no set ipv6 next-hop peer-address",
	    NO_STR
	    SET_STR
	    IPV6_STR
	    "IPv6 next-hop address\n"
	    "Use peer address (for BGP only)\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:ipv6-peer-address']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (set_ipv6_nexthop_prefer_global,
	    set_ipv6_nexthop_prefer_global_cmd,
	    "set ipv6 next-hop prefer-global",
	    SET_STR
	    IPV6_STR
	    "IPv6 next-hop address\n"
	    "Prefer global over link-local if both exist\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:ipv6-prefer-global']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:preference", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, "true");

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_ipv6_nexthop_prefer_global,
	    no_set_ipv6_nexthop_prefer_global_cmd,
	    "no set ipv6 next-hop prefer-global",
	    NO_STR
	    SET_STR
	    IPV6_STR
	    "IPv6 next-hop address\n"
	    "Prefer global over link-local if both exist\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:ipv6-prefer-global']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (set_ipv6_nexthop_global,
	    set_ipv6_nexthop_global_cmd,
	    "set ipv6 next-hop global X:X::X:X",
	    SET_STR
	    IPV6_STR
	    "IPv6 next-hop address\n"
	    "IPv6 global address\n"
	    "IPv6 address of next hop\n")
{
	int idx_ipv6 = 4;
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:ipv6-nexthop-global']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:ipv6-address", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			      argv[idx_ipv6]->arg);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_ipv6_nexthop_global,
	    no_set_ipv6_nexthop_global_cmd,
	    "no set ipv6 next-hop global X:X::X:X",
	    NO_STR
	    SET_STR
	    IPV6_STR
	    "IPv6 next-hop address\n"
	    "IPv6 global address\n"
	    "IPv6 address of next hop\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:ipv6-nexthop-global']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (set_originator_id,
	    set_originator_id_cmd,
	    "set originator-id A.B.C.D",
	    SET_STR
	   "BGP originator ID attribute\n"
	   "IP address of originator\n")
{
	int idx_ipv4 = 2;
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:originator-id']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:originator-id", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			      argv[idx_ipv4]->arg);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_originator_id,
	    no_set_originator_id_cmd,
	    "no set originator-id [A.B.C.D]",
	    NO_STR
	    SET_STR
	    "BGP originator ID attribute\n"
	    "IP address of originator\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:originator-id']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (match_rpki_extcommunity,
       match_rpki_extcommunity_cmd,
       "[no$no] match rpki-extcommunity <valid|invalid|notfound>",
       NO_STR
       MATCH_STR
       "BGP RPKI (Origin Validation State) extended community attribute\n"
       "Valid prefix\n"
       "Invalid prefix\n"
       "Prefix not found\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:rpki-extcommunity']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	if (!no) {
		snprintf(
			xpath_value, sizeof(xpath_value),
			"%s/rmap-match-condition/frr-bgp-route-map:rpki-extcommunity",
			xpath);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
				      argv[2]->arg);
	}

	return nb_cli_apply_changes(vty, NULL);
}

/* 'match source-protocol': the grammar is identical to zebra's, which is
 * also hosted in mgmtd (zebra_cli.c) -- two installs of the same string in
 * one daemon parse as ambiguous. zebra_cli.c's handler is the single owner
 * and writes the frr-bgp-route-map:source-protocol condition too. */

DEFPY_YANG (match_vpn_dataplane,
       match_vpn_dataplane_cmd,
       "[no$no] match vpn dataplane [<mpls|srv6|vxlan>$dataplane]",
       NO_STR
       MATCH_STR
       "VPN operations\n"
       "Dataplane operation\n"
       "Valid MPLS path\n"
       "Valid SRv6 path\n"
       "Valid VXLAN path\n")
{
	const char *xpath = "./match-condition[condition='frr-bgp-route-map:match-vpn-dataplane']";
	char xpath_value[XPATH_MAXLEN];
	enum nb_operation operation = NB_OP_CREATE;

	if (no || !dataplane)
		operation = NB_OP_DESTROY;

	nb_cli_enqueue_change(vty, xpath, operation, NULL);

	if (!no && dataplane) {
		snprintf(xpath_value, sizeof(xpath_value),
			 "%s/rmap-match-condition/frr-bgp-route-map:vpn-dataplane", xpath);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, dataplane);
	}

	return nb_cli_apply_changes(vty, NULL);
}

/*
 * The nine commands below (match/no_match alias, set_aspath_prepend_asn,
 * set_aspath_exclude, set_community, set/no_set_vpn_nexthop,
 * set/no_set_ipx_vpn_nexthop) were left out of the original B-RM3 split
 * because their CLI bodies called validation helpers that live in
 * bgpd-only compilation units (bgp_community_alias.c, bgp_aspath.c,
 * bgp_community.c, bgp_vty.c, bgp_mplsvpn.c), none of which mgmtd
 * links. M3 B-RM1 needs bgpd to stop installing any route-map CLI
 * locally (see bgp_route_map_init(), bgp_routemap.c), so these move
 * here too, with the bgpd-only calls dropped:
 *
 *  - match_alias/no_match_alias: the CLI used to reject an unknown
 *    alias name eagerly via bgp_ca_alias_lookup(). The northbound
 *    apply path never validated this (route_match_alias_compile()
 *    just XSTRDUPs the string; an alias that doesn't exist yet simply
 *    never matches any route), so dropping the eager check makes
 *    "match alias" a forward-reference like every other name-based
 *    match clause in this file (community-list, prefix-list, ...)
 *    instead of a special case -- not a validation regression, since
 *    apply-time behavior is unchanged.
 *  - set_aspath_prepend_asn/set_aspath_exclude/set_community: the CLI
 *    used to pre-validate via route_aspath_compile()/
 *    community_str2com() and reject before enqueuing. The northbound
 *    apply path (generic_set_add() -> route_set_aspath_prepend_cmd /
 *    route_set_community_cmd's compile hooks in bgp_routemap.c, both
 *    bgpd-only and unchanged) already re-validates with the same
 *    compile functions and fails the transaction (NB_ERR_INCONSISTENCY)
 *    on malformed input, so no unvalidated value can reach running
 *    config; a bad value now surfaces as an apply-time error instead
 *    of a CLI-parse-time one, same as the other commands in this file.
 *    set_community's stored community-string leaf is the raw,
 *    space-joined token text instead of community_str2com()'s
 *    canonical pretty-printed form (a "show running-config" cosmetic
 *    difference only -- community_str()/community_free() are not
 *    reachable from mgmtd either).
 *  - set_vpn_nexthop/no_set_vpn_nexthop/set_ipx_vpn_nexthop/
 *    no_set_ipx_vpn_nexthop: argv_find_and_parse_vpnvx()/
 *    argv_find_and_parse_afi() (bgp_mplsvpn.c/bgp_vty.c) are thin
 *    wrappers around lib/command.c's argv_find() with a fixed literal
 *    token ("vpnv4"/"vpnv6"/"ipv4"/"ipv6"); inlined directly below.
 *    No validation was ever done beyond the CLI grammar's own
 *    A.B.C.D/X:X::X:X address-syntax matching, so there is nothing to
 *    relocate.
 */

DEFUN_YANG(match_alias, match_alias_cmd, "match alias ALIAS_NAME",
	   MATCH_STR
	   "Match BGP community alias name\n"
	   "BGP community alias name\n")
{
	const char *alias = argv[2]->arg;
	const char *xpath = "./match-condition[condition='frr-bgp-route-map:match-alias']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:alias", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, alias);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_match_alias, no_match_alias_cmd, "no match alias [ALIAS_NAME]",
	   NO_STR MATCH_STR
	   "Match BGP community alias name\n"
	   "BGP community alias name\n")
{
	int idx_alias = 3;
	const char *xpath = "./match-condition[condition='frr-bgp-route-map:match-alias']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	if (argc <= idx_alias)
		return nb_cli_apply_changes(vty, NULL);

	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:alias", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_DESTROY, argv[idx_alias]->arg);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (set_aspath_prepend_asn,
	    set_aspath_prepend_asn_cmd,
	    "set as-path prepend ASNUM...",
	    SET_STR
	    "Transform BGP AS_PATH attribute\n"
	    "Prepend to the as-path\n"
	    AS_STR)
{
	int idx_asn = 3;
	int ret;
	char *str;

	str = argv_concat(argv, argc, idx_asn);

	const char *xpath = "./set-action[action='frr-bgp-route-map:as-path-prepend']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:prepend-as-path", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, str);
	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, str);
	return ret;
}

DEFUN_YANG (set_aspath_exclude,
	    set_aspath_exclude_cmd,
	    "set as-path exclude ASNUM...",
	    SET_STR
	    "Transform BGP AS-path attribute\n"
	    "Exclude from the as-path\n"
	    AS_STR)
{
	int idx_asn = 3;
	int ret;
	char *str;

	str = argv_concat(argv, argc, idx_asn);

	const char *xpath = "./set-action[action='frr-bgp-route-map:as-path-exclude']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:exclude-as-path", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, str);
	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, str);
	return ret;
}

/* Parse an 'AA:NN' token: both halves all-digit decimal <= 65535
 * (community_gettoken()'s numeric acceptance). */
static bool set_community_token_member(const char *token, unsigned long *ga,
				       unsigned long *la)
{
	const char *lstart;
	char *endptr;

	if (!isdigit((unsigned char)token[0]))
		return false;
	errno = 0;
	*ga = strtoul(token, &endptr, 10);
	if (errno || *endptr != ':' || *ga > UINT16_MAX)
		return false;
	lstart = endptr + 1;
	if (!isdigit((unsigned char)*lstart))
		return false;
	errno = 0;
	*la = strtoul(lstart, &endptr, 10);
	if (errno || *endptr != '\0' || *la > UINT16_MAX)
		return false;

	return true;
}

DEFUN_YANG (set_community,
	    set_community_cmd,
	    "set community AA:NN...",
	    SET_STR
	    "BGP community attribute\n"
	    COMMUNITY_VAL_STR)
{
	int idx_aa_nn = 2;
	int i;
	int nqueued;
	int ret;
	bool grouped = false;

	const char *xpath = "./set-action[action='frr-bgp-route-map:set-community']";
	char xpath_comm[XPATH_MAXLEN];
	char xpath_value[XPATH_MAXLEN * 2];

	snprintf(xpath_comm, sizeof(xpath_comm),
		 "%s/rmap-set-action/frr-bgp-route-map:communities", xpath);

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	/* Replace, not merge, whatever an earlier 'set community' left. */
	nb_cli_enqueue_change(vty, xpath_comm, NB_OP_DESTROY, NULL);
	nqueued = 2;

	/* One config line's tokens can exceed one transaction's change
	 * budget (VTY_MAXCFGCHANGES); apply in batches. Only the first
	 * batch carries the replace-destroy above, later ones merge
	 * more tokens into the already-created container. */
	for (i = idx_aa_nn; i < argc; i++) {
		const char *tok = argv[i]->arg;
		unsigned long ga, la;

		if (nqueued == VTY_MAXCFGCHANGES) {
			ret = nb_cli_apply_changes(vty, NULL);
			if (ret != CMD_SUCCESS) {
				set_comm_batch_group_end(vty, grouped);
				return ret;
			}
			nqueued = 0;
			/* nb_cli_apply_changes() consumes the pending
			 * changes into the candidate but does not clear
			 * vty->num_cfg_changes (only cmd_execute does, once
			 * per command), so reset it too or the next enqueue
			 * overflows VTY_MAXCFGCHANGES and silently drops
			 * tokens. */
			vty->num_cfg_changes = 0;
			/* This first apply already locked the candidate and
			 * queued the implicit commit; fold every later batch
			 * into it so we do not re-lock and abort mgmtd. */
			set_comm_batch_group_begin(vty, &grouped);
		}
		nqueued++;

		if (strncmp(tok, "additive", strlen(tok)) == 0) {
			snprintf(xpath_value, sizeof(xpath_value),
				 "%s/additive", xpath_comm);
			nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
					      "true");
			continue;
		}

		/* The legacy command expanded these user-typed
		 * abbreviations itself; keep accepting them. */
		if (strncmp(tok, "local-AS", strlen(tok)) == 0)
			tok = "local-AS";
		else if (strncmp(tok, "no-a", strlen("no-a")) == 0 &&
			 strncmp(tok, "no-advertise", strlen(tok)) == 0)
			tok = "no-advertise";
		else if (strncmp(tok, "no-e", strlen("no-e")) == 0 &&
			 strncmp(tok, "no-export", strlen(tok)) == 0)
			tok = "no-export";
		else if (strncmp(tok, "blackhole", strlen(tok)) == 0)
			tok = "blackhole";
		else if (strncmp(tok, "graceful-shutdown", strlen(tok)) == 0)
			tok = "graceful-shutdown";

		if (bgp_filter_well_known_community(tok, NULL))
			snprintf(xpath_value, sizeof(xpath_value),
				 "%s/well-known[.='%s']", xpath_comm, tok);
		else if (set_community_token_member(tok, &ga, &la))
			snprintf(xpath_value, sizeof(xpath_value),
				 "%s/member[global-admin='%lu'][local-admin='%lu']",
				 xpath_comm, ga, la);
		else
			/* Kept verbatim; the apply-time compile rejects
			 * it, as it did for the old free-form string. */
			snprintf(xpath_value, sizeof(xpath_value),
				 "%s/raw[.='%s']", xpath_comm, tok);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_CREATE, NULL);
	}

	ret = nb_cli_apply_changes(vty, NULL);
	set_comm_batch_group_end(vty, grouped);
	return ret;
}

#ifdef KEEP_OLD_VPN_COMMANDS
DEFUN_YANG (set_vpn_nexthop,
	    set_vpn_nexthop_cmd,
	    "set <vpnv4 next-hop A.B.C.D|vpnv6 next-hop X:X::X:X>",
	    SET_STR
	    "VPNv4 information\n"
	    "VPN next-hop address\n"
	    "IP address of next hop\n"
	    "VPNv6 information\n"
	    "VPN next-hop address\n"
	    "IPv6 address of next hop\n")
{
	int idx_ip = 3;
	afi_t afi;
	int idx = 0;
	char xpath_value[XPATH_MAXLEN];

	if (argv_find(argv, argc, "vpnv4", &idx))
		afi = AFI_IP;
	else if (argv_find(argv, argc, "vpnv6", &idx))
		afi = AFI_IP6;
	else
		return CMD_SUCCESS;

	if (afi == AFI_IP) {
		const char *xpath = "./set-action[action='frr-bgp-route-map:ipv4-vpn-address']";

		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		snprintf(xpath_value, sizeof(xpath_value),
			 "%s/rmap-set-action/frr-bgp-route-map:ipv4-address", xpath);
	} else {
		const char *xpath = "./set-action[action='frr-bgp-route-map:ipv6-vpn-address']";

		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		snprintf(xpath_value, sizeof(xpath_value),
			 "%s/rmap-set-action/frr-bgp-route-map:ipv6-address", xpath);
	}

	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, argv[idx_ip]->arg);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_vpn_nexthop,
	   no_set_vpn_nexthop_cmd,
	   "no set <vpnv4 next-hop A.B.C.D|vpnv6 next-hop X:X::X:X>",
	   NO_STR
	   SET_STR
	   "VPNv4 information\n"
	   "VPN next-hop address\n"
	   "IP address of next hop\n"
	   "VPNv6 information\n"
	   "VPN next-hop address\n"
	   "IPv6 address of next hop\n")
{
	afi_t afi;
	int idx = 0;

	if (argv_find(argv, argc, "vpnv4", &idx))
		afi = AFI_IP;
	else if (argv_find(argv, argc, "vpnv6", &idx))
		afi = AFI_IP6;
	else
		return CMD_SUCCESS;

	if (afi == AFI_IP) {
		const char *xpath = "./set-action[action='frr-bgp-route-map:ipv4-vpn-address']";
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	} else {
		const char *xpath = "./set-action[action='frr-bgp-route-map:ipv6-vpn-address']";
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	}
	return nb_cli_apply_changes(vty, NULL);
}
#endif /* KEEP_OLD_VPN_COMMANDS */

DEFPY_YANG (set_ipx_vpn_nexthop,
	    set_ipx_vpn_nexthop_cmd,
	    "set <ipv4|ipv6> vpn next-hop <A.B.C.D$addrv4|X:X::X:X$addrv6>",
	    SET_STR
	    "IPv4 information\n"
	    "IPv6 information\n"
	    "VPN information\n"
	    "VPN next-hop address\n"
	    "IP address of next hop\n"
	    "IPv6 address of next hop\n")
{
	int idx_ip = 4;
	afi_t afi;
	int idx = 0;
	char xpath_value[XPATH_MAXLEN];

	if (argv_find(argv, argc, "ipv4", &idx))
		afi = AFI_IP;
	else if (argv_find(argv, argc, "ipv6", &idx))
		afi = AFI_IP6;
	else
		return CMD_SUCCESS;

	if (afi == AFI_IP) {
		if (addrv6_str) {
			vty_out(vty, "%% IPv4 next-hop expected\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		const char *xpath = "./set-action[action='frr-bgp-route-map:ipv4-vpn-address']";

		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		snprintf(xpath_value, sizeof(xpath_value),
			 "%s/rmap-set-action/frr-bgp-route-map:ipv4-address", xpath);
	} else {
		if (addrv4_str) {
			vty_out(vty, "%% IPv6 next-hop expected\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		const char *xpath = "./set-action[action='frr-bgp-route-map:ipv6-vpn-address']";

		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		snprintf(xpath_value, sizeof(xpath_value),
			 "%s/rmap-set-action/frr-bgp-route-map:ipv6-address", xpath);
	}
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, argv[idx_ip]->arg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_ipx_vpn_nexthop,
	    no_set_ipx_vpn_nexthop_cmd,
	    "no set <ipv4|ipv6> vpn next-hop [<A.B.C.D|X:X::X:X>]",
	    NO_STR
	    SET_STR
	    "IPv4 information\n"
	    "IPv6 information\n"
	    "VPN information\n"
	    "VPN next-hop address\n"
	    "IP address of next hop\n"
	    "IPv6 address of next hop\n")
{
	afi_t afi;
	int idx = 0;

	if (argv_find(argv, argc, "ipv4", &idx))
		afi = AFI_IP;
	else if (argv_find(argv, argc, "ipv6", &idx))
		afi = AFI_IP6;
	else
		return CMD_SUCCESS;

	if (afi == AFI_IP) {
		const char *xpath = "./set-action[action='frr-bgp-route-map:ipv4-vpn-address']";
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	} else {
		const char *xpath = "./set-action[action='frr-bgp-route-map:ipv6-vpn-address']";
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	}
	return nb_cli_apply_changes(vty, NULL);
}

void bgp_routemap_cli_init(void)
{
	install_element(RMAP_NODE, &match_peer_cmd);
	install_element(RMAP_NODE, &match_peer_local_cmd);
	install_element(RMAP_NODE, &match_src_peer_cmd);
	install_element(RMAP_NODE, &no_match_src_peer_cmd);
	install_element(RMAP_NODE, &no_match_peer_cmd);
	install_element(RMAP_NODE, &match_ip_route_source_cmd);
	install_element(RMAP_NODE, &no_match_ip_route_source_cmd);
	install_element(RMAP_NODE, &match_ip_route_source_prefix_list_cmd);
	install_element(RMAP_NODE, &no_match_ip_route_source_prefix_list_cmd);
	install_element(RMAP_NODE, &match_mac_address_cmd);
	install_element(RMAP_NODE, &no_match_mac_address_cmd);
	install_element(RMAP_NODE, &match_evpn_vni_cmd);
	install_element(RMAP_NODE, &no_match_evpn_vni_cmd);
	install_element(RMAP_NODE, &match_evpn_route_type_cmd);
	install_element(RMAP_NODE, &no_match_evpn_route_type_cmd);
	install_element(RMAP_NODE, &match_evpn_rd_cmd);
	install_element(RMAP_NODE, &no_match_evpn_rd_cmd);
	install_element(RMAP_NODE, &match_evpn_default_route_cmd);
	install_element(RMAP_NODE, &no_match_evpn_default_route_cmd);
	install_element(RMAP_NODE, &set_evpn_gw_ip_ipv4_cmd);
	install_element(RMAP_NODE, &no_set_evpn_gw_ip_ipv4_cmd);
	install_element(RMAP_NODE, &set_evpn_gw_ip_ipv6_cmd);
	install_element(RMAP_NODE, &no_set_evpn_gw_ip_ipv6_cmd);
	install_element(RMAP_NODE, &set_ecommunity_evpn_rmac_cmd);
	install_element(RMAP_NODE, &no_set_ecommunity_evpn_rmac_cmd);
	install_element(RMAP_NODE, &match_vrl_source_vrf_cmd);
	install_element(RMAP_NODE, &no_match_vrl_source_vrf_cmd);

	install_element(RMAP_NODE, &match_aspath_cmd);
	install_element(RMAP_NODE, &no_match_aspath_cmd);
	install_element(RMAP_NODE, &match_aspath_count_cmd);
	install_element(RMAP_NODE, &match_local_pref_cmd);
	install_element(RMAP_NODE, &no_match_local_pref_cmd);
	install_element(RMAP_NODE, &match_community_cmd);
	install_element(RMAP_NODE, &no_match_community_cmd);
	install_element(RMAP_NODE, &match_community_limit_cmd);
	install_element(RMAP_NODE, &match_extcommunity_limit_cmd);
	install_element(RMAP_NODE, &match_lcommunity_cmd);
	install_element(RMAP_NODE, &no_match_lcommunity_cmd);
	install_element(RMAP_NODE, &match_ecommunity_cmd);
	install_element(RMAP_NODE, &no_match_ecommunity_cmd);
	install_element(RMAP_NODE, &match_origin_cmd);
	install_element(RMAP_NODE, &no_match_origin_cmd);
	install_element(RMAP_NODE, &match_probability_cmd);
	install_element(RMAP_NODE, &no_match_probability_cmd);

	install_element(RMAP_NODE, &no_set_table_id_cmd);
	install_element(RMAP_NODE, &set_table_id_cmd);
	install_element(RMAP_NODE, &set_ip_nexthop_peer_cmd);
	install_element(RMAP_NODE, &set_ip_nexthop_unchanged_cmd);
	install_element(RMAP_NODE, &set_local_pref_cmd);
	install_element(RMAP_NODE, &set_distance_cmd);
	install_element(RMAP_NODE, &no_set_distance_cmd);
	install_element(RMAP_NODE, &no_set_local_pref_cmd);
	install_element(RMAP_NODE, &set_weight_cmd);
	install_element(RMAP_NODE, &set_label_index_cmd);
	install_element(RMAP_NODE, &no_set_weight_cmd);
	install_element(RMAP_NODE, &no_set_label_index_cmd);
	install_element(RMAP_NODE, &set_aspath_prepend_lastas_cmd);
	install_element(RMAP_NODE, &set_aspath_exclude_all_cmd);
	install_element(RMAP_NODE, &set_aspath_exclude_access_list_cmd);
	install_element(RMAP_NODE, &set_aspath_replace_asn_cmd);
	install_element(RMAP_NODE, &set_aspath_replace_access_list_cmd);
	install_element(RMAP_NODE, &no_set_aspath_prepend_last_as_cmd);
	install_element(RMAP_NODE, &no_set_aspath_prepend_as_cmd);
	install_element(RMAP_NODE, &no_set_aspath_exclude_cmd);
	install_element(RMAP_NODE, &no_set_aspath_exclude_all_cmd);
	install_element(RMAP_NODE, &no_set_aspath_exclude_access_list_cmd);
	install_element(RMAP_NODE, &no_set_aspath_replace_asn_cmd);
	install_element(RMAP_NODE, &no_set_aspath_replace_access_list_cmd);
	install_element(RMAP_NODE, &set_origin_cmd);
	install_element(RMAP_NODE, &no_set_origin_cmd);
	install_element(RMAP_NODE, &set_atomic_aggregate_cmd);
	install_element(RMAP_NODE, &no_set_atomic_aggregate_cmd);
	install_element(RMAP_NODE, &set_aigp_metric_cmd);
	install_element(RMAP_NODE, &no_set_aigp_metric_cmd);
	install_element(RMAP_NODE, &set_aggregator_as_cmd);
	install_element(RMAP_NODE, &no_set_aggregator_as_cmd);
	install_element(RMAP_NODE, &set_community_none_cmd);
	install_element(RMAP_NODE, &no_set_community_cmd);
	install_element(RMAP_NODE, &no_set_community_short_cmd);
#if CONFDATE > 20270527
	CPP_NOTICE("Remove `[no] set comm-list <COMM_LIST> delete` commands")
#endif
	install_element(RMAP_NODE, &set_community_delete_cmd);
	install_element(RMAP_NODE, &no_set_community_delete_cmd);
	install_element(RMAP_NODE, &set_community_change_cmd);
	install_element(RMAP_NODE, &no_set_community_change_cmd);
	install_element(RMAP_NODE, &set_lcommunity_cmd);
	install_element(RMAP_NODE, &set_lcommunity_none_cmd);
	install_element(RMAP_NODE, &no_set_lcommunity_cmd);
	install_element(RMAP_NODE, &no_set_lcommunity1_cmd);
	install_element(RMAP_NODE, &no_set_lcommunity1_short_cmd);
#if CONFDATE > 20270527
	CPP_NOTICE("Remove `[no] set large-comm-list <COMM_LIST> delete` commands")
#endif
	install_element(RMAP_NODE, &set_lcommunity_delete_cmd);
	install_element(RMAP_NODE, &no_set_lcommunity_delete_cmd);
	install_element(RMAP_NODE, &set_lcommunity_delete_method2_cmd);
	install_element(RMAP_NODE, &no_set_lcommunity_delete_method2_cmd);
	install_element(RMAP_NODE, &no_set_lcommunity_delete_short_cmd);
	install_element(RMAP_NODE, &set_ecommunity_rt_cmd);
	install_element(RMAP_NODE, &no_set_ecommunity_rt_cmd);
	install_element(RMAP_NODE, &no_set_ecommunity_rt_short_cmd);
	install_element(RMAP_NODE, &set_ecommunity_soo_cmd);
	install_element(RMAP_NODE, &no_set_ecommunity_soo_cmd);
	install_element(RMAP_NODE, &no_set_ecommunity_soo_short_cmd);
	install_element(RMAP_NODE, &set_ecommunity_lb_cmd);
	install_element(RMAP_NODE, &no_set_ecommunity_lb_cmd);
	install_element(RMAP_NODE, &no_set_ecommunity_lb_short_cmd);
	install_element(RMAP_NODE, &set_ecommunity_none_cmd);
	install_element(RMAP_NODE, &no_set_ecommunity_none_cmd);
	install_element(RMAP_NODE, &set_ecommunity_nt_cmd);
	install_element(RMAP_NODE, &no_set_ecommunity_nt_cmd);
	install_element(RMAP_NODE, &no_set_ecommunity_nt_short_cmd);
	install_element(RMAP_NODE, &set_ecommunity_color_cmd);
	install_element(RMAP_NODE, &no_set_ecommunity_color_cmd);
	install_element(RMAP_NODE, &no_set_ecommunity_color_all_cmd);
#if CONFDATE > 20270527
	CPP_NOTICE("Remove `[no] set ext-comm-list <COMM_LIST> delete` commands")
#endif
	install_element(RMAP_NODE, &set_ecommunity_delete_cmd);
	install_element(RMAP_NODE, &no_set_ecommunity_delete_cmd);
	install_element(RMAP_NODE, &set_ecommunity_delete_method2_cmd);
	install_element(RMAP_NODE, &no_set_ecommunity_delete_method2_cmd);
	install_element(RMAP_NODE, &set_originator_id_cmd);
	install_element(RMAP_NODE, &no_set_originator_id_cmd);
	install_element(RMAP_NODE, &set_l3vpn_nexthop_encapsulation_cmd);


	install_element(RMAP_NODE, &match_vpn_dataplane_cmd);
	install_element(RMAP_NODE, &match_ipv6_next_hop_address_cmd);
	install_element(RMAP_NODE, &no_match_ipv6_next_hop_address_cmd);
	install_element(RMAP_NODE, &match_ipv6_next_hop_old_cmd);
	install_element(RMAP_NODE, &no_match_ipv6_next_hop_old_cmd);
	install_element(RMAP_NODE, &match_ipv4_next_hop_cmd);
	install_element(RMAP_NODE, &no_match_ipv4_next_hop_cmd);
	install_element(RMAP_NODE, &set_ipv6_nexthop_global_cmd);
	install_element(RMAP_NODE, &no_set_ipv6_nexthop_global_cmd);
	install_element(RMAP_NODE, &set_ipv6_nexthop_prefer_global_cmd);
	install_element(RMAP_NODE, &no_set_ipv6_nexthop_prefer_global_cmd);
	install_element(RMAP_NODE, &set_ipv6_nexthop_peer_cmd);
	install_element(RMAP_NODE, &no_set_ipv6_nexthop_peer_cmd);
	install_element(RMAP_NODE, &match_rpki_extcommunity_cmd);
#ifdef HAVE_SCRIPTING
	install_element(RMAP_NODE, &match_script_cmd);
#endif

	install_element(RMAP_NODE, &match_alias_cmd);
	install_element(RMAP_NODE, &no_match_alias_cmd);
	install_element(RMAP_NODE, &set_aspath_prepend_asn_cmd);
	install_element(RMAP_NODE, &set_aspath_exclude_cmd);
	install_element(RMAP_NODE, &set_community_cmd);
#ifdef KEEP_OLD_VPN_COMMANDS
	install_element(RMAP_NODE, &set_vpn_nexthop_cmd);
	install_element(RMAP_NODE, &no_set_vpn_nexthop_cmd);
#endif /* KEEP_OLD_VPN_COMMANDS */
	install_element(RMAP_NODE, &set_ipx_vpn_nexthop_cmd);
	install_element(RMAP_NODE, &no_set_ipx_vpn_nexthop_cmd);
}
