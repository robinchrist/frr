// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Robin Christ, partimus GmbH */
/* 'router bgp' node entry and instance-scope CLI (DEFPYs + northbound cli_show callbacks) for the proteus-bgp conversion.
 *
 * Split out of bgpd/bgp_cli.c (bgpd-yang-conversion intermezzo): pure code
 * motion for the DEFPY/cli_show bodies below. bgp_cli_init()'s body could
 * not move verbatim -- see bgp_cli_common.c and bgp_cli_instance_init()
 * in this file for why.
 */
#include <zebra.h>
#include <inttypes.h>
#include "command.h"
#include "northbound.h"
#include "northbound_cli.h"
#include "vty.h"
#include "vrf.h"
#include "asn.h"

#include "frrdistance.h"

#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_cli.h"
#include "bgpd/bgp_damp.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_evpn_private.h"
#include "bgpd/proteus/bgp_cli_local.h"
#include "bgpd/proteus/bgp_cli_instance_clippy.c"

static struct cmd_node bgp_node = {
	.name = "bgp",
	.node = BGP_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-router)# ",
	.config_write = NULL,
};

/*
 * Milestone 5 batch B0: parallel mgmtd-side address-family node entry/exit.
 *
 * The legacy 'address-family <afi> [<safi>]' / 'exit-address-family'
 * DEFUN_NOSH in bgpd/bgp_vty.c stay native and keep pushing bgpd's
 * BGP_*_NODE, so still-unconverted per-AF lines attach to bgpd during file
 * load. These parallel DEFPY_YANG_NOSH commands give mgmtd the same node
 * tracking: they set the SAME vty->node and re-push the enclosing instance
 * base xpath, performing NO northbound create -- the afi-safis/<af>
 * sub-containers are non-presence and auto-instantiate on the first child
 * leaf (M5 B1+), so entering an AF block commits nothing. vtysh dual-routes
 * both to VTYSH_BGPD|VTYSH_MGMTD via the node-entry DEFUNSH masks in
 * vtysh/vtysh.c (the router_bgp milestone-1 pattern); NOSH commands are
 * skipped by python/xref2vtysh.py, so that routing lives in vtysh.c, not in
 * the generated vtysh_cmd.c table.
 *
 * bgp_node_type()/bgp_node_afi()/bgp_node_safi() are defined in bgp_vty.c,
 * which is not linked into mgmtd, so the node <-> (container, header)
 * mapping is reproduced locally.
 */

/* AF sub-nodes mirrored into mgmtd (config_write NULL -- mgmtd renders via
 * cli_show). parent_node BGP_NODE and the default no_xpath=false let
 * cmd_exit() pop the instance base pushed on entry. The four non-proteus
 * families (flowspec, unreachability) are tracked too so mgmtd follows the
 * node transitions when it reads a legacy bgpd.conf directly, even though
 * proteus models no per-AF config for them. */
static struct cmd_node bgp_af_cmd_nodes[] = {
	{ .name = "bgp ipv4 unicast",
	  .node = BGP_IPV4_NODE,
	  .parent_node = BGP_NODE,
	  .prompt = "%s(config-router-af)# " },
	{ .name = "bgp ipv4 multicast",
	  .node = BGP_IPV4M_NODE,
	  .parent_node = BGP_NODE,
	  .prompt = "%s(config-router-af)# " },
	{ .name = "bgp ipv4 labeled unicast",
	  .node = BGP_IPV4L_NODE,
	  .parent_node = BGP_NODE,
	  .prompt = "%s(config-router-af)# " },
	{ .name = "bgp vpnv4",
	  .node = BGP_VPNV4_NODE,
	  .parent_node = BGP_NODE,
	  .prompt = "%s(config-router-af)# " },
	{ .name = "bgp ipv6 unicast",
	  .node = BGP_IPV6_NODE,
	  .parent_node = BGP_NODE,
	  .prompt = "%s(config-router-af)# " },
	{ .name = "bgp ipv6 multicast",
	  .node = BGP_IPV6M_NODE,
	  .parent_node = BGP_NODE,
	  .prompt = "%s(config-router-af)# " },
	{ .name = "bgp ipv6 labeled unicast",
	  .node = BGP_IPV6L_NODE,
	  .parent_node = BGP_NODE,
	  .prompt = "%s(config-router-af)# " },
	{ .name = "bgp vpnv6",
	  .node = BGP_VPNV6_NODE,
	  .parent_node = BGP_NODE,
	  .prompt = "%s(config-router-af-vpnv6)# " },
	{ .name = "bgp evpn",
	  .node = BGP_EVPN_NODE,
	  .parent_node = BGP_NODE,
	  .prompt = "%s(config-router-evpn)# " },
	{ .name = "bgp ipv4 flowspec",
	  .node = BGP_FLOWSPECV4_NODE,
	  .parent_node = BGP_NODE,
	  .prompt = "%s(config-router-af)# " },
	{ .name = "bgp ipv6 flowspec",
	  .node = BGP_FLOWSPECV6_NODE,
	  .parent_node = BGP_NODE,
	  .prompt = "%s(config-router-af)# " },
	{ .name = "bgp ipv4 unreachability",
	  .node = BGP_IPV4U_NODE,
	  .parent_node = BGP_NODE,
	  .prompt = "%s(config-router-af)# " },
	{ .name = "bgp ipv6 unreachability",
	  .node = BGP_IPV6U_NODE,
	  .parent_node = BGP_NODE,
	  .prompt = "%s(config-router-af)# " },
	{ .name = "bgp link-state",
	  .node = BGP_LS_NODE,
	  .parent_node = BGP_NODE,
	  .prompt = "%s(config-router-af)# " },
};

/* The nine proteus afi-safis/<af> containers: node <-> container name and
 * the exact 'address-family <...>' header text bgp_config_write_family()
 * (bgp_vty.c) emits per family. B1+ per-AF leaf commands build
 * '<instance-base>/afi-safis/<container>/...' from vty->node via
 * bgp_afi_safi_container_name(); the cli_show header/trailer wrap those
 * converted leaves in an address-family block byte-identical to bgpd's, so
 * vtysh folds the two daemons' emissions by matching header text. */
static const struct {
	int node;
	const char *container;
	const char *cli_header;
} bgp_afi_safi_map[] = {
	{ BGP_IPV4_NODE, "ipv4-unicast", "ipv4 unicast" },
	{ BGP_IPV4M_NODE, "ipv4-multicast", "ipv4 multicast" },
	{ BGP_IPV4L_NODE, "ipv4-labeled-unicast", "ipv4 labeled-unicast" },
	{ BGP_VPNV4_NODE, "ipv4-vpn", "ipv4 vpn" },
	{ BGP_IPV6_NODE, "ipv6-unicast", "ipv6 unicast" },
	{ BGP_IPV6M_NODE, "ipv6-multicast", "ipv6 multicast" },
	{ BGP_IPV6L_NODE, "ipv6-labeled-unicast", "ipv6 labeled-unicast" },
	{ BGP_VPNV6_NODE, "ipv6-vpn", "ipv6 vpn" },
	{ BGP_EVPN_NODE, "l2vpn-evpn", "l2vpn evpn" },
	/* M8.5 B-fs-af: flowspec joins the modeled AFs (9 -> 11). */
	{ BGP_FLOWSPECV4_NODE, "ipv4-flowspec", "ipv4 flowspec" },
	{ BGP_FLOWSPECV6_NODE, "ipv6-flowspec", "ipv6 flowspec" },
};

/* Reverse of bgp_node_type(): the proteus afi-safis child container name
 * for a BGP_*_NODE, or NULL for a non-proteus AF node. Exposed for M5 B1+
 * per-AF leaf commands to build their xpath from vty->node. */
const char *bgp_afi_safi_container_name(int node)
{
	for (size_t i = 0; i < array_size(bgp_afi_safi_map); i++)
		if (bgp_afi_safi_map[i].node == node)
			return bgp_afi_safi_map[i].container;
	return NULL;
}

static const char *bgp_afi_safi_cli_header(const char *container)
{
	for (size_t i = 0; i < array_size(bgp_afi_safi_map); i++)
		if (strmatch(bgp_afi_safi_map[i].container, container))
			return bgp_afi_safi_map[i].cli_header;
	return NULL;
}

/* Enter an address-family sub-node: re-push the enclosing instance base
 * (VTY_CURR_XPATH, pushed by router_bgp) under the AF node so per-AF
 * subcommands resolve './afi-safis/<af>/...' against it. No northbound
 * change -- non-presence containers auto-instantiate on the first child
 * leaf. */
static int bgp_af_node_enter(struct vty *vty, int node)
{
	char xpath[XPATH_MAXLEN];

	if (vty->xpath_index == 0) {
		vty_out(vty, "%% Not in a BGP instance context\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	strlcpy(xpath, VTY_CURR_XPATH, sizeof(xpath));
	VTY_PUSH_XPATH(node, xpath);
	return CMD_SUCCESS;
}

DEFPY_YANG_NOSH(
	address_family_ipv4_safi, address_family_ipv4_safi_cli_cmd,
	"address-family ipv4 [<unicast|multicast|vpn|labeled-unicast|flowspec|unreachability>]$safi",
	"Enter Address Family command mode\n" BGP_AF_STR BGP_SAFI_WITH_LABEL_HELP_STR)
{
	int node = BGP_IPV4_NODE;

	if (safi) {
		if (strmatch(safi, "multicast"))
			node = BGP_IPV4M_NODE;
		else if (strmatch(safi, "vpn"))
			node = BGP_VPNV4_NODE;
		else if (strmatch(safi, "labeled-unicast"))
			node = BGP_IPV4L_NODE;
		else if (strmatch(safi, "flowspec"))
			node = BGP_FLOWSPECV4_NODE;
		else if (strmatch(safi, "unreachability"))
			node = BGP_IPV4U_NODE;
	}

	return bgp_af_node_enter(vty, node);
}

DEFPY_YANG_NOSH(
	address_family_ipv6_safi, address_family_ipv6_safi_cli_cmd,
	"address-family ipv6 [<unicast|multicast|vpn|labeled-unicast|flowspec|unreachability>]$safi",
	"Enter Address Family command mode\n" BGP_AF_STR BGP_SAFI_WITH_LABEL_HELP_STR)
{
	int node = BGP_IPV6_NODE;

	if (safi) {
		if (strmatch(safi, "multicast"))
			node = BGP_IPV6M_NODE;
		else if (strmatch(safi, "vpn"))
			node = BGP_VPNV6_NODE;
		else if (strmatch(safi, "labeled-unicast"))
			node = BGP_IPV6L_NODE;
		else if (strmatch(safi, "flowspec"))
			node = BGP_FLOWSPECV6_NODE;
		else if (strmatch(safi, "unreachability"))
			node = BGP_IPV6U_NODE;
	}

	return bgp_af_node_enter(vty, node);
}

#ifdef KEEP_OLD_VPN_COMMANDS
DEFPY_YANG_NOSH(
	address_family_vpnv4, address_family_vpnv4_cli_cmd,
	"address-family vpnv4 [unicast]",
	"Enter Address Family command mode\n" BGP_AF_STR BGP_AF_MODIFIER_STR)
{
	return bgp_af_node_enter(vty, BGP_VPNV4_NODE);
}

DEFPY_YANG_NOSH(
	address_family_vpnv6, address_family_vpnv6_cli_cmd,
	"address-family vpnv6 [unicast]",
	"Enter Address Family command mode\n" BGP_AF_STR BGP_AF_MODIFIER_STR)
{
	return bgp_af_node_enter(vty, BGP_VPNV6_NODE);
}
#endif /* KEEP_OLD_VPN_COMMANDS */

DEFPY_YANG_NOSH(
	address_family_evpn, address_family_evpn_cli_cmd,
	"address-family l2vpn evpn",
	"Enter Address Family command mode\n" BGP_AF_STR BGP_AF_MODIFIER_STR)
{
	return bgp_af_node_enter(vty, BGP_EVPN_NODE);
}

/* 'segment-routing srv6' sub-node (M8.5 B-srv6-block): the M8 no-op parse
 * shims became the real mgmtd-side implementation. The node is entered
 * without touching the datastore; the presence container is created
 * implicitly by the first child change (libyang creates presence ancestors
 * on descendant edits). 'no segment-routing srv6' destroys the whole
 * container, whose backend DESTROY runs the composite legacy unset.
 * bgpd's native DEFPYs stay installed via the bare _install_element for
 * its own split-config file read, emission-retired. */
static struct cmd_node bgp_srv6_cmd_node = {
	.name = "bgp srv6",
	.node = BGP_SRV6_NODE,
	.parent_node = BGP_NODE,
	.prompt = "%s(config-router-srv6)# ",
};

DEFPY_YANG_NOSH(
	bgp_segment_routing_srv6, bgp_segment_routing_srv6_cli_cmd,
	"segment-routing srv6",
	"Segment-Routing configuration\n"
	"Segment-Routing SRv6 configuration\n")
{
	char xpath[XPATH_MAXLEN];
	int rv;

	if (vty->xpath_index == 0) {
		vty_out(vty, "%% Not in a BGP instance context\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Real CREATE on entry (the M6 vni NOSH pattern): the presence
	 * container must exist in the candidate before relative child edits
	 * pass nb_cli_apply_changes' xpath liveness check. An empty block
	 * still emits nothing (vty_frame suppression), matching legacy's
	 * bare-entry-not-persisted behavior. */
	snprintf(xpath, sizeof(xpath), "%s/segment-routing-srv6", VTY_CURR_XPATH);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	rv = nb_cli_apply_changes(vty, NULL);
	if (rv == CMD_SUCCESS)
		VTY_PUSH_XPATH(BGP_SRV6_NODE, xpath);

	return rv;
}

DEFPY_YANG(
	no_bgp_segment_routing_srv6, no_bgp_segment_routing_srv6_cli_cmd,
	"no segment-routing srv6",
	NO_STR
	"Segment-Routing configuration\n"
	"Segment-Routing SRv6 configuration\n")
{
	nb_cli_enqueue_change(vty, "./segment-routing-srv6", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_srv6_locator, bgp_srv6_locator_cli_cmd,
	"locator NAME$name",
	"Specify SRv6 locator\n"
	"Specify SRv6 locator\n")
{
	nb_cli_enqueue_change(vty, "./locator", NB_OP_MODIFY, name);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_srv6_locator, no_bgp_srv6_locator_cli_cmd,
	"no locator NAME$name",
	NO_STR
	"Specify SRv6 locator\n"
	"Specify SRv6 locator\n")
{
	/* Legacy validates the name matches the configured locator; the
	 * northbound destroy is tolerant of an absent leaf, so only the
	 * mismatch case needs the guard here. */
	if (yang_dnode_existsf(vty->candidate_config->dnode, "%s/locator", VTY_CURR_XPATH) &&
	    !strmatch(yang_dnode_get_string(vty->candidate_config->dnode, "%s/locator",
					    VTY_CURR_XPATH),
		      name)) {
		vty_out(vty, "%% No srv6 locator is configured\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	nb_cli_enqueue_change(vty, "./locator", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_srv6_only, bgp_srv6_only_cli_cmd,
	"[no] srv6-only",
	NO_STR
	"Only allow SRv6 and disallow MPLS routes\n")
{
	/* Tier A default-on: 'no' writes an explicit false, the positive
	 * form destroys back to the true default. */
	if (no)
		nb_cli_enqueue_change(vty, "./srv6-only", NB_OP_MODIFY, "false");
	else
		nb_cli_enqueue_change(vty, "./srv6-only", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_srv6_encap_behavior, bgp_srv6_encap_behavior_cli_cmd,
	"[no$no] encap-behavior <H_Encaps|H_Encaps_Red>$encap_behavior",
	NO_STR
	"Configure SRv6 encap mode\n"
	"H.Encaps\n"
	"H.Encaps.Red\n")
{
	/* Token strings equal the enum names. Tier A default
	 * (H_Encaps): negative form destroys back to it. */
	if (no)
		nb_cli_enqueue_change(vty, "./encap-behavior", NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, "./encap-behavior", NB_OP_MODIFY, encap_behavior);
	return nb_cli_apply_changes(vty, NULL);
}

/* Emitters: vty_frame/vty_endframe reproduce legacy's empty-block
 * suppression (bgp_config_write's srv6 arm) byte-for-byte. */
void instance_srv6_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_frame(vty, " !\n segment-routing srv6\n");
}

void instance_srv6_cli_write_end(struct vty *vty, const struct lyd_node *dnode)
{
	vty_endframe(vty, " exit\n");
}

void instance_srv6_locator_cli_write(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults)
{
	vty_out(vty, "  locator %s\n", yang_dnode_get_string(dnode, NULL));
}

void instance_srv6_encap_behavior_cli_write(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults)
{
	if (strmatch(yang_dnode_get_string(dnode, NULL), "H_Encaps"))
		return;
	vty_out(vty, "  encap-behavior %s\n", yang_dnode_get_string(dnode, NULL));
}

void instance_srv6_only_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "  no srv6-only\n");
}

/* 'sid vpn per-vrf export' (M8.5 B-srv6-pervrf): presence container +
 * choice, converged once per commit in the container apply_finish
 * (bgp_nb_instance.c). Mutual exclusions and mode-change rejection live
 * in the container VALIDATE. */
DEFPY_YANG(
	bgp_sid_vpn_export, bgp_sid_vpn_export_cli_cmd,
	"[no] sid vpn per-vrf export <(1-4294967295)$sid_idx|auto$sid_auto|explicit$sid_explicit X:X::X:X$sid_value>",
	NO_STR
	"sid value for VRF\n"
	"Between current vrf and vpn\n"
	"sid per-VRF (both IPv4 and IPv6 address families)\n"
	"For routes leaked from current vrf to vpn\n"
	"Sid allocation index\n"
	"Automatically assign a label\n"
	"Explicitly assign a sid value\n"
	"Sid value\n")
{
	char xpath[XPATH_MAXLEN];

	if (no) {
		nb_cli_enqueue_change(vty, "./sid-vpn-export", NB_OP_DESTROY, NULL);
		return nb_cli_apply_changes(vty, NULL);
	}

	if (sid_auto) {
		snprintf(xpath, sizeof(xpath), "./sid-vpn-export/auto");
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, "true");
	} else if (sid_explicit) {
		snprintf(xpath, sizeof(xpath), "./sid-vpn-export/explicit");
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, sid_value_str);
	} else {
		snprintf(xpath, sizeof(xpath), "./sid-vpn-export/index");
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, sid_idx_str);
	}
	return nb_cli_apply_changes(vty, NULL);
}

ALIAS (bgp_sid_vpn_export,
       no_bgp_sid_vpn_export_cli_cmd,
       "no$no sid vpn per-vrf export",
       NO_STR
       "sid value for VRF\n"
       "Between current vrf and vpn\n"
       "sid per-VRF (both IPv4 and IPv6 address families)\n"
       "For routes leaked from current vrf to vpn\n")

/* One ' sid vpn per-vrf export <auto|N|explicit X>' line, matching
 * bgp_config_write()'s retired arm byte-for-byte (position: right after
 * the segment-routing srv6 block). */
void instance_sid_vpn_export_cli_write(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults)
{
	if (yang_dnode_exists(dnode, "auto") && yang_dnode_get_bool(dnode, "auto"))
		vty_out(vty, " sid vpn per-vrf export auto\n");
	else if (yang_dnode_exists(dnode, "explicit"))
		vty_out(vty, " sid vpn per-vrf export explicit %s\n",
			yang_dnode_get_string(dnode, "explicit"));
	else if (yang_dnode_exists(dnode, "index"))
		vty_out(vty, " sid vpn per-vrf export %s\n", yang_dnode_get_string(dnode, "index"));
}

/* Per-AF 'sid vpn export' (M8.5 B-srv6-peraf-vpn), unicast AF nodes. */
DEFPY_YANG(
	af_sid_vpn_export, af_sid_vpn_export_cli_cmd,
	"[no] sid vpn export <(1-4294967295)$sid_idx|auto$sid_auto|explicit$sid_explicit X:X::X:X$sid_value>",
	NO_STR
	"sid value for VRF\n"
	"Between current address-family and vpn\n"
	"For routes leaked from current address-family to vpn\n"
	"Sid allocation index\n"
	"Automatically assign a label\n"
	"Explicitly assign a sid value\n"
	"Sid value\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (no) {
		xpath = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/vpn/sid-export", VTY_CURR_XPATH,
				   container);
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	} else if (sid_auto) {
		xpath = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/vpn/sid-export/auto",
				   VTY_CURR_XPATH, container);
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, "true");
	} else if (sid_explicit) {
		xpath = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/vpn/sid-export/explicit",
				   VTY_CURR_XPATH, container);
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, sid_value_str);
	} else {
		xpath = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/vpn/sid-export/index",
				   VTY_CURR_XPATH, container);
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, sid_idx_str);
	}

	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, xpath);
	return ret;
}

/* One '  sid vpn export <auto|N|explicit X>' line inside the af-vpn
 * interleave, matching bgp_vpn_policy_config_write_afi()'s retired arm. */
void afi_safis_vpn_sid_export_cli_write(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults)
{
	if (yang_dnode_exists(dnode, "auto") && yang_dnode_get_bool(dnode, "auto"))
		vty_out(vty, "  sid vpn export auto\n");
	else if (yang_dnode_exists(dnode, "explicit"))
		vty_out(vty, "  sid vpn export explicit %s\n",
			yang_dnode_get_string(dnode, "explicit"));
	else if (yang_dnode_exists(dnode, "index"))
		vty_out(vty, "  sid vpn export %s\n", yang_dnode_get_string(dnode, "index"));
}

/* Unicast 'sid export' (M8.5 B-srv6-unicast), default-VRF ipv4/ipv6
 * unicast AF nodes. Full-line declarative semantics with one legacy
 * asymmetry preserved: re-issuing without 'route-map' keeps an existing
 * route-map (legacy's "no rmap change" path), while 'behavior dt46' is
 * always rewritten from the line. */
DEFPY_YANG(
	sid_export, sid_export_cli_cmd,
	"[no] sid export <(1-1048575)$sid_idx|auto$sid_auto|explicit$sid_explicit X:X::X:X$sid_value> [behavior dt46$behavior_dt46] [route-map RMAP$rmap_str]",
	NO_STR
	"Sid value for VRF\n"
	"Encapsulation SRv6 over default vrf\n"
	"Sid allocation index\n"
	"Automatically assign a label\n"
	"Explicitly assign a sid value\n"
	"Sid value\n"
	"Specify SRv6 SID behavior\n"
	"Allocate a DT46 SID\n"
	"Specify route-map name\n"
	"Name of route-map\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char base[XPATH_MAXLEN], xpath[XPATH_MAXLEN + 64];

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	snprintf(base, sizeof(base), "%s/afi-safis/%s/srv6-sid-export", VTY_CURR_XPATH, container);

	if (no) {
		nb_cli_enqueue_change(vty, base, NB_OP_DESTROY, NULL);
		return nb_cli_apply_changes(vty, NULL);
	}

	if (sid_auto) {
		snprintf(xpath, sizeof(xpath), "%s/auto", base);
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, "true");
	} else if (sid_explicit) {
		snprintf(xpath, sizeof(xpath), "%s/explicit", base);
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, sid_value_str);
	} else {
		snprintf(xpath, sizeof(xpath), "%s/index", base);
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, sid_idx_str);
	}

	snprintf(xpath, sizeof(xpath), "%s/behavior-dt46", base);
	nb_cli_enqueue_change(vty, xpath, behavior_dt46 ? NB_OP_MODIFY : NB_OP_DESTROY,
			      behavior_dt46 ? "true" : NULL);

	if (rmap_str) {
		snprintf(xpath, sizeof(xpath), "%s/route-map", base);
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, rmap_str);
	}

	return nb_cli_apply_changes(vty, NULL);
}

/* One '  sid export ...' line, matching bgp_config_write_family()'s
 * retired arm. */
void afi_safis_srv6_sid_export_cli_write(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	if (yang_dnode_exists(dnode, "auto") && yang_dnode_get_bool(dnode, "auto"))
		vty_out(vty, "  sid export auto");
	else if (yang_dnode_exists(dnode, "explicit"))
		vty_out(vty, "  sid export explicit %s", yang_dnode_get_string(dnode, "explicit"));
	else if (yang_dnode_exists(dnode, "index"))
		vty_out(vty, "  sid export %s", yang_dnode_get_string(dnode, "index"));
	else
		return;

	if (yang_dnode_get_bool(dnode, "behavior-dt46"))
		vty_out(vty, " behavior dt46");
	if (yang_dnode_exists(dnode, "route-map"))
		vty_out(vty, " route-map %s", yang_dnode_get_string(dnode, "route-map"));
	vty_out(vty, "\n");
}

/* flowspec 'local-install' (M8.5 B-fs-extras). */
DEFPY_YANG(
	bgp_fs_local_install, bgp_fs_local_install_cli_cmd,
	"[no] local-install INTERFACE$ifname",
	NO_STR
	"Apply local policy routing\n"
	"Interface name\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char xpath[XPATH_MAXLEN + 128];

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	snprintf(xpath, sizeof(xpath), "%s/afi-safis/%s/local-install/interfaces[.='%s']",
		 VTY_CURR_XPATH, container, ifname);
	nb_cli_enqueue_change(vty, xpath, no ? NB_OP_DESTROY : NB_OP_CREATE, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/* Per-entry '  local-install %s' line (registered on the interfaces
 * leaf-list), matching bgp_fs_config_write_pbr()'s retired output. */
void afi_safis_fs_local_install_iface_cli_write(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults)
{
	vty_out(vty, "  local-install %s\n", yang_dnode_get_string(dnode, NULL));
}

/* flowspec 'rt|rt6 redirect import' (M8.5 B-fs-extras), unicast AF
 * nodes. Full-replace: the container is destroyed and re-created with
 * the given list in one commit, like legacy's wholesale
 * import_redirect_rtlist swap. */
DEFPY_YANG(
	af_routetarget_import, af_routetarget_import_cli_cmd,
	"[no] <rt|route-target|route-target6|rt6>$rtkw redirect import RTLIST...",
	NO_STR
	"Specify route target list\n"
	"Specify route target list\n"
	"Specify route target list\n"
	"Specify route target list\n"
	"Flow-spec redirect type route target\n"
	"Import routes to this address-family\n"
	"Space separated route target list (A.B.C.D:MN|EF:OPQR|GHJK:MN|IPV6:MN)\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char base[XPATH_MAXLEN], xpath[XPATH_MAXLEN + 192];
	bool rt6 = strmatch(rtkw, "rt6") || strmatch(rtkw, "route-target6");
	int i;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (rt6 && vty->node != BGP_IPV6_NODE) {
		vty_out(vty, "%% rt6 is only valid under ipv6 unicast\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	snprintf(base, sizeof(base), "%s/afi-safis/%s/vpn/flowspec-redirect-import",
		 VTY_CURR_XPATH, container);
	nb_cli_enqueue_change(vty, base, NB_OP_DESTROY, NULL);
	if (!no) {
		for (i = 0; i < argc; i++) {
			if (!argv[i]->arg || argv[i]->type != VARIABLE_TKN)
				continue;
			snprintf(xpath, sizeof(xpath), "%s/route-targets[.='%s']", base,
				 argv[i]->arg);
			nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		}
		if (rt6) {
			snprintf(xpath, sizeof(xpath), "%s/ipv6-format", base);
			nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, "true");
		}
	}
	return nb_cli_apply_changes(vty, NULL);
}

/* One '  rt[6] redirect import <list>' line, matching the retired tail
 * of bgp_vpn_policy_config_write_afi(). */
void afi_safis_fs_redirect_import_cli_write(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults)
{
	const struct lyd_node *entry;
	bool first = true;

	vty_out(vty, "  rt%s redirect import",
		yang_dnode_get_bool(dnode, "ipv6-format") ? "6" : "");
	LY_LIST_FOR (lyd_child(dnode), entry) {
		if (strcmp(entry->schema->name, "route-targets"))
			continue;
		vty_out(vty, " %s", lyd_get_value(entry));
		(void)first;
	}
	vty_out(vty, "\n");
}

/* No proteus container for link-state; the node exists here only so mgmtd
 * tracks the block and accepts its exit-address-family (LS subcommands stay
 * native to bgpd). */
DEFPY_YANG_NOSH(
	address_family_link_state, address_family_link_state_cli_cmd,
	"address-family link-state [link-state]",
	"Enter Address Family command mode\n"
	"Link-State Address Family\n"
	"Link-State Subsequent Address Family\n")
{
	return bgp_af_node_enter(vty, BGP_LS_NODE);
}

DEFPY_YANG_NOSH(
	exit_address_family, exit_address_family_cli_cmd,
	"exit-address-family",
	"Exit from Address Family configuration mode\n")
{
	/* Only installed at the AF sub-nodes, so vty->node is always one of
	 * them here; drop back to BGP_NODE and pop the instance base pushed
	 * on entry (mirrors cmd_exit() for these no_xpath=false nodes). */
	vty->node = BGP_NODE;
	if (vty->xpath_index > 0)
		vty->xpath_index--;
	return CMD_SUCCESS;
}

/*
 * Milestone 6 batch B1: parallel mgmtd-side 'vni N' ... 'exit-vni' sub-node.
 *
 * Unlike the M5 B0 address-family entries (node-only, non-presence
 * containers), 'vni N' performs a REAL keyed-list CREATE on entry -- the M3
 * route-map DEFPY_YANG_NOSH pattern -- because the vni list entry is a
 * genuine object (evpn_create_update_vni). The legacy bgp_evpn_vni
 * DEFUN_NOSH in bgp_evpn_vty.c stays native so unconverted VNI subcommands
 * (rd, route-target, ...) attach to bgpd's bgpevpn mid-load during the
 * coexistence window; evpn_create_update_vni() is idempotent by VNI id, so
 * both paths converge. 'no vni N' is a plain DEFPY_YANG whose backend
 * destroy tolerates an already-gone VNI. vtysh dual-routes 'vni'/'exit-vni'
 * (NOSH) via vtysh/vtysh.c and 'no vni' (non-NOSH) via the generated table.
 */

static struct cmd_node bgp_evpn_vni_node = {
	.name = "bgp evpn vni",
	.node = BGP_EVPN_VNI_NODE,
	.parent_node = BGP_EVPN_NODE,
	.prompt = "%s(config-router-af-vni)# ",
};

DEFPY_YANG_NOSH(
	bgp_evpn_vni, bgp_evpn_vni_cli_cmd,
	"vni " CMD_VNI_RANGE,
	"VXLAN Network Identifier\n"
	"VNI number\n")
{
	char xpath[XPATH_MAXLEN + 64];
	int rv;

	if (vty->xpath_index == 0) {
		vty_out(vty, "%% Not in a BGP EVPN address-family context\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	snprintf(xpath, sizeof(xpath), "%s/afi-safis/l2vpn-evpn/vni[vni-id='%s']", VTY_CURR_XPATH,
		 vni_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	rv = nb_cli_apply_changes(vty, NULL);
	if (rv == CMD_SUCCESS)
		VTY_PUSH_XPATH(BGP_EVPN_VNI_NODE, xpath);

	return rv;
}

DEFPY_YANG(
	no_bgp_evpn_vni, no_bgp_evpn_vni_cli_cmd,
	"no vni " CMD_VNI_RANGE,
	NO_STR
	"VXLAN Network Identifier\n"
	"VNI number\n")
{
	char xpath[XPATH_MAXLEN + 64];

	snprintf(xpath, sizeof(xpath), "%s/afi-safis/l2vpn-evpn/vni[vni-id='%s']", VTY_CURR_XPATH,
		 vni_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG_NOSH(
	exit_vni, exit_vni_cli_cmd,
	"exit-vni",
	"Exit from VNI mode\n")
{
	/* Only installed at BGP_EVPN_VNI_NODE; drop back to BGP_EVPN_NODE and
	 * pop the vni xpath pushed on entry (mirrors exit_address_family). */
	if (vty->node == BGP_EVPN_VNI_NODE) {
		vty->node = BGP_EVPN_NODE;
		if (vty->xpath_index > 0)
			vty->xpath_index--;
	}
	return CMD_SUCCESS;
}

/*
 * Milestone 6 batch B2: instance-level l2vpn-evpn advertise-flag leaves,
 * mgmtd side. All four are Tier-A default-false booleans (YANG
 * 'type boolean; default "false"'): the positive legacy form maps to
 * NB_OP_MODIFY "true", 'no ...' destroys back to the false default, and
 * cli_show emits the bare positive line iff the leaf reads true. The xpath
 * is relative to the instance base pushed at BGP_EVPN_NODE
 * (VTY_CURR_XPATH), so it appends './afi-safis/l2vpn-evpn/<leaf>'. Grammar
 * and help strings are kept identical to the retired bgp_evpn_vty.c DEFPYs.
 * The EVPN role guards those DEFUNs carried (EVPN_ENABLED / bgp_get_evpn)
 * live in the backend apply callbacks (bgp_nb_evpn.c), except
 * advertise-all-vni's single-EVPN-instance guard which is a hard
 * NB_EV_VALIDATE rejection.
 */

DEFPY_YANG(
	bgp_evpn_advertise_all_vni, bgp_evpn_advertise_all_vni_cli_cmd,
	"advertise-all-vni",
	"Advertise All local VNIs\n")
{
	nb_cli_enqueue_change(vty, "./afi-safis/l2vpn-evpn/advertise-all-vni", NB_OP_MODIFY,
			      "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_evpn_advertise_all_vni, no_bgp_evpn_advertise_all_vni_cli_cmd,
	"no advertise-all-vni",
	NO_STR
	"Advertise All local VNIs\n")
{
	nb_cli_enqueue_change(vty, "./afi-safis/l2vpn-evpn/advertise-all-vni", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_evpn_advertise_default_gw, bgp_evpn_advertise_default_gw_cli_cmd,
	"advertise-default-gw",
	"Advertise All default g/w mac-ip routes in EVPN\n")
{
	nb_cli_enqueue_change(vty, "./afi-safis/l2vpn-evpn/advertise-default-gw", NB_OP_MODIFY,
			      "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_evpn_advertise_default_gw, no_bgp_evpn_advertise_default_gw_cli_cmd,
	"no advertise-default-gw",
	NO_STR
	"Withdraw All default g/w mac-ip routes from EVPN\n")
{
	nb_cli_enqueue_change(vty, "./afi-safis/l2vpn-evpn/advertise-default-gw", NB_OP_DESTROY,
			      NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_evpn_advertise_svi_ip, bgp_evpn_advertise_svi_ip_cli_cmd,
	"[no$no] advertise-svi-ip",
	NO_STR
	"Advertise svi mac-ip routes in EVPN\n")
{
	if (no)
		nb_cli_enqueue_change(vty, "./afi-safis/l2vpn-evpn/advertise-svi-ip", NB_OP_DESTROY,
				      NULL);
	else
		nb_cli_enqueue_change(vty, "./afi-safis/l2vpn-evpn/advertise-svi-ip", NB_OP_MODIFY,
				      "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_evpn_enable_resolve_overlay_index, bgp_evpn_enable_resolve_overlay_index_cli_cmd,
	"[no$no] enable-resolve-overlay-index",
	NO_STR
	"Enable Recursive Resolution of type-5 route overlay index\n")
{
	if (no)
		nb_cli_enqueue_change(vty, "./afi-safis/l2vpn-evpn/enable-resolve-overlay-index",
				      NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, "./afi-safis/l2vpn-evpn/enable-resolve-overlay-index",
				      NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

/*
 * M6 batch B3: instance-level 'mac-vrf soo' + 'flooding', mgmtd side.
 * mac-vrf-soo reuses bgp_cli_soo_parse() (bgp_cli_neighbor.c, un-static'd)
 * to turn the legacy ASN:NN_OR_IP-ADDRESS:NN token into a case name plus
 * the two typed leaves, exactly like M5 B3's per-AF 'neighbor X soo' --
 * only the base xpath differs ('./afi-safis/l2vpn-evpn/mac-vrf-soo/...'
 * here, vs a peer/group base there). 'no mac-vrf soo [...]' destroys the
 * whole presence container regardless of the optional trailing token,
 * matching legacy's grammar (the token is accepted but never inspected on
 * the negative form).
 *
 * flooding's grammar/logic is kept identical to the retired
 * bgp_evpn_flood_control_cmd: 'flooding disable' and 'no flooding
 * <either form>' are the only two effective states FRR ever stores
 * (VXLAN_FLOOD_DISABLED / VXLAN_FLOOD_HEAD_END_REPL), so 'no' always
 * destroys back to the YANG-default-less "unset" (which the backend
 * resolves to head-end-replication), and the positive form writes
 * whichever of the two enum values was given.
 */
DEFPY_YANG(
	bgp_evpn_macvrf_soo, bgp_evpn_macvrf_soo_cli_cmd,
	"mac-vrf soo ASN:NN_OR_IP-ADDRESS:NN$soo",
	"EVPN MAC-VRF\n"
	"Site-of-Origin extended community\n"
	"VPN extended community\n")
{
	enum bgp_cli_soo_case soo_case;
	char global_admin[INET_ADDRSTRLEN], local_admin[12];
	char xpath[XPATH_MAXLEN];
	const char *case_name;

	if (!bgp_cli_soo_parse(soo, &soo_case, global_admin, sizeof(global_admin), local_admin,
			       sizeof(local_admin))) {
		vty_out(vty, "%% Malformed SoO extended community\n");
		return CMD_WARNING;
	}

	switch (soo_case) {
	case BGP_CLI_SOO_AS2:
		case_name = "as2";
		break;
	case BGP_CLI_SOO_AS4:
		case_name = "as4";
		break;
	case BGP_CLI_SOO_IPV4:
	default:
		case_name = "ipv4";
		break;
	}

	snprintf(xpath, sizeof(xpath), "./afi-safis/l2vpn-evpn/mac-vrf-soo/%s/global-admin",
		 case_name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, global_admin);

	snprintf(xpath, sizeof(xpath), "./afi-safis/l2vpn-evpn/mac-vrf-soo/%s/local-admin",
		 case_name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, local_admin);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_evpn_macvrf_soo, no_bgp_evpn_macvrf_soo_cli_cmd,
	"no mac-vrf soo [ASN:NN_OR_IP-ADDRESS:NN]",
	NO_STR
	"EVPN MAC-VRF\n"
	"Site-of-Origin extended community\n"
	"VPN extended community\n")
{
	nb_cli_enqueue_change(vty, "./afi-safis/l2vpn-evpn/mac-vrf-soo", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_evpn_flood_control, bgp_evpn_flood_control_cli_cmd,
	"[no$no] flooding <disable$disable|head-end-replication$her>",
	NO_STR
	"Specify handling for BUM packets\n"
	"Do not flood any BUM packets\n"
	"Flood BUM packets using head-end replication\n")
{
	if (no)
		nb_cli_enqueue_change(vty, "./afi-safis/l2vpn-evpn/flooding", NB_OP_DESTROY, NULL);
	else if (disable)
		nb_cli_enqueue_change(vty, "./afi-safis/l2vpn-evpn/flooding", NB_OP_MODIFY,
				      "disable");
	else
		nb_cli_enqueue_change(vty, "./afi-safis/l2vpn-evpn/flooding", NB_OP_MODIFY,
				      "head-end-replication");
	return nb_cli_apply_changes(vty, NULL);
}

/*
 * M6 batch B6: per-VNI 'rd', 'flooding', 'advertise-default-gw',
 * 'advertise-svi-ip' and 'advertise-subnet' (mgmtd side, all installed at
 * BGP_EVPN_VNI_NODE -- reached only after 'vni N' pushes the vni entry's own
 * xpath as the current context base, M6 B1).
 *
 * 'rd ASN:NN_OR_IP-ADDRESS:NN' reuses bgp_cli_soo_parse() (same
 * ASN:NN_OR_IP-ADDRESS:NN token grammar, same as2-vs-as4-vs-ipv4 magnitude
 * split as str2prefix_rd()) to route the token to the matching as2/as4/ipv4
 * case's two leaves -- 'administrator'/'assigned-number' rather than
 * soo/RT's 'global-admin'/'local-admin', but the same byte widths per case
 * (RD types 0/1/2 use the identical AS-vs-IP administrator / 4-vs-2-byte
 * assigned-number split as RFC 4360 extended communities). 'no rd [...]'
 * destroys the whole presence container regardless of the optional
 * trailing token, matching mac-vrf-soo's 'no' form (M6 B3) rather than
 * legacy's own value-matching negative-form guard (bgp_nb_evpn.c's doc
 * comment on bgp_nb_evpn_vni_rd_set() has the detail).
 *
 * 'flooding' keeps the identical grammar/logic as the AF-level form above:
 * 'flooding disable'/'flooding head-end-replication' write the given case,
 * 'no flooding <either form>' always destroys back to the per-VNI-only
 * "inherit" tri-state (VXLAN_FLOOD_INHERIT_GLOBAL, bgp_nb_evpn.c), which has
 * no AF-level equivalent (that leaf's DESTROY instead restores
 * head-end-replication).
 *
 * 'advertise-default-gw'/'advertise-svi-ip'/'advertise-subnet' are plain
 * Tier A booleans, same MODIFY-true/DESTROY shape as their instance-level
 * counterparts above (M6 B2); 'advertise-subnet' keeps DEFPY_YANG_HIDDEN,
 * matching legacy's DEFUN_HIDDEN.
 */
DEFPY_YANG(
	bgp_evpn_vni_rd, bgp_evpn_vni_rd_cli_cmd,
	"rd ASN:NN_OR_IP-ADDRESS:NN$rd",
	EVPN_RT_DIST_HELP_STR
	EVPN_ASN_IP_HELP_STR)
{
	enum bgp_cli_soo_case rd_case;
	char administrator[INET_ADDRSTRLEN], assigned_number[12];
	char xpath[XPATH_MAXLEN];
	const char *case_name;

	if (!bgp_cli_soo_parse(rd, &rd_case, administrator, sizeof(administrator),
			       assigned_number, sizeof(assigned_number))) {
		vty_out(vty, "%% Malformed Route Distinguisher\n");
		return CMD_WARNING;
	}

	switch (rd_case) {
	case BGP_CLI_SOO_AS2:
		case_name = "as2";
		break;
	case BGP_CLI_SOO_AS4:
		case_name = "as4";
		break;
	case BGP_CLI_SOO_IPV4:
	default:
		case_name = "ipv4";
		break;
	}

	snprintf(xpath, sizeof(xpath), "./rd/%s/administrator", case_name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, administrator);

	snprintf(xpath, sizeof(xpath), "./rd/%s/assigned-number", case_name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, assigned_number);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_evpn_vni_rd, no_bgp_evpn_vni_rd_cli_cmd,
	"no rd [ASN:NN_OR_IP-ADDRESS:NN]",
	NO_STR
	EVPN_RT_DIST_HELP_STR
	EVPN_ASN_IP_HELP_STR)
{
	nb_cli_enqueue_change(vty, "./rd", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_evpn_flood_control_vni, bgp_evpn_flood_control_vni_cli_cmd,
	"[no$no] flooding <disable$disable|head-end-replication$her>",
	NO_STR
	"Specify handling for BUM packets\n"
	"Do not flood any BUM packets\n"
	"Flood BUM packets using head-end replication\n")
{
	if (no)
		nb_cli_enqueue_change(vty, "./flooding", NB_OP_DESTROY, NULL);
	else if (disable)
		nb_cli_enqueue_change(vty, "./flooding", NB_OP_MODIFY, "disable");
	else
		nb_cli_enqueue_change(vty, "./flooding", NB_OP_MODIFY, "head-end-replication");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_evpn_advertise_default_gw_vni, bgp_evpn_advertise_default_gw_vni_cli_cmd,
	"advertise-default-gw",
	"Advertise default g/w mac-ip routes in EVPN for a VNI\n")
{
	nb_cli_enqueue_change(vty, "./advertise-default-gw", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_evpn_advertise_default_gw_vni, no_bgp_evpn_advertise_default_gw_vni_cli_cmd,
	"no advertise-default-gw",
	NO_STR
	"Withdraw default g/w mac-ip routes from EVPN for a VNI\n")
{
	nb_cli_enqueue_change(vty, "./advertise-default-gw", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_evpn_advertise_svi_ip_vni, bgp_evpn_advertise_svi_ip_vni_cli_cmd,
	"[no$no] advertise-svi-ip",
	NO_STR
	"Advertise svi mac-ip routes in EVPN for a VNI\n")
{
	if (no)
		nb_cli_enqueue_change(vty, "./advertise-svi-ip", NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, "./advertise-svi-ip", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG_HIDDEN(
	bgp_evpn_advertise_vni_subnet, bgp_evpn_advertise_vni_subnet_cli_cmd,
	"advertise-subnet",
	"Advertise the subnet corresponding to VNI\n")
{
	nb_cli_enqueue_change(vty, "./advertise-subnet", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG_HIDDEN(
	no_bgp_evpn_advertise_vni_subnet, no_bgp_evpn_advertise_vni_subnet_cli_cmd,
	"no advertise-subnet",
	NO_STR
	"Advertise All local VNIs\n")
{
	nb_cli_enqueue_change(vty, "./advertise-subnet", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/*
 * M6 batch B7: per-VRF-instance role (mgmtd side), installed at
 * BGP_EVPN_NODE like the instance-level B2/B3 commands above (context base
 * is the instance's own xpath, not per-VNI's).
 *
 * 'rd' is the VRF-level twin of B6's per-VNI 'rd': same
 * bgp_cli_soo_parse()-based as2/as4/ipv4 case routing, base xpath
 * './afi-safis/l2vpn-evpn/rd/...' instead of the per-VNI form's relative
 * './rd/...'. 'no rd [...]' destroys the whole presence container
 * regardless of the optional trailing token, same as every other 'no ...
 * [value]' form in this file.
 *
 * 'default-originate <ipv4|ipv6>' is a plain [no]-prefixed Tier A boolean
 * pair, same MODIFY-true/DESTROY shape as advertise-svi-ip above.
 *
 * 'advertise <ipv4|ipv6> unicast [gateway-ip] [route-map WORD]' was
 * scouted for this batch but reject-stubbed over its then-leafref
 * 'route-map' leaf; converted in M6 B9b (below) after B9a retyped the
 * leaf to a plain string.
 */
DEFPY_YANG(
	bgp_evpn_vrf_rd, bgp_evpn_vrf_rd_cli_cmd,
	"rd ASN:NN_OR_IP-ADDRESS:NN$rd",
	EVPN_RT_DIST_HELP_STR
	EVPN_ASN_IP_HELP_STR)
{
	enum bgp_cli_soo_case rd_case;
	char administrator[INET_ADDRSTRLEN], assigned_number[12];
	char xpath[XPATH_MAXLEN];
	const char *case_name;

	if (!bgp_cli_soo_parse(rd, &rd_case, administrator, sizeof(administrator),
			       assigned_number, sizeof(assigned_number))) {
		vty_out(vty, "%% Malformed Route Distinguisher\n");
		return CMD_WARNING;
	}

	switch (rd_case) {
	case BGP_CLI_SOO_AS2:
		case_name = "as2";
		break;
	case BGP_CLI_SOO_AS4:
		case_name = "as4";
		break;
	case BGP_CLI_SOO_IPV4:
	default:
		case_name = "ipv4";
		break;
	}

	snprintf(xpath, sizeof(xpath), "./afi-safis/l2vpn-evpn/rd/%s/administrator", case_name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, administrator);

	snprintf(xpath, sizeof(xpath), "./afi-safis/l2vpn-evpn/rd/%s/assigned-number", case_name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, assigned_number);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_evpn_vrf_rd, no_bgp_evpn_vrf_rd_cli_cmd,
	"no rd [ASN:NN_OR_IP-ADDRESS:NN]",
	NO_STR
	EVPN_RT_DIST_HELP_STR
	EVPN_ASN_IP_HELP_STR)
{
	nb_cli_enqueue_change(vty, "./afi-safis/l2vpn-evpn/rd", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_evpn_default_originate, bgp_evpn_default_originate_cli_cmd,
	"[no$no] default-originate <ipv4$ipv4|ipv6$ipv6>",
	NO_STR
	"originate a default route\n"
	"ipv4 address family\n"
	"ipv6 address family\n")
{
	const char *xpath = ipv4 ? "./afi-safis/l2vpn-evpn/default-originate/ipv4"
				 : "./afi-safis/l2vpn-evpn/default-originate/ipv6";

	if (no)
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

/*
 * M6 batch B4: 'dup-addr-detection max-moves ... time ...' and
 * 'dup-addr-detection freeze <permanent|N>' (dup_addr_detection_cmd /
 * dup_addr_detection_auto_recovery_cmd's value-bearing sub-forms). The bare
 * enable/disable toggle converted in M6 B9b (its 'enabled' leaf gained the
 * missing 'default "true"' in B9a); the value-bearing forms below also
 * delete './enabled' back to that default, reproducing legacy's
 * detection-back-on side effect. max-moves and
 * time are legacy's one paired DEFPY line and always issued together here
 * (matching B8 dampening's "always rewrite from scratch" idiom); freeze is
 * the separate auto-recovery DEFPY. 'no' forms destroy regardless of the
 * value given, same as legacy's own 'freeze permanent' vs 'freeze N'
 * value-match guard being dropped in favor of plain NB_OP_DESTROY (the
 * token is accepted but ignored, matching flooding's 'no' form above).
 */
DEFPY_YANG(
	bgp_evpn_dup_addr_detection, bgp_evpn_dup_addr_detection_cli_cmd,
	"dup-addr-detection max-moves (2-1000)$max_moves time (2-1800)$time",
	"Duplicate address detection\n"
	"Max allowed moves before address detected as duplicate\n"
	"Num of max allowed moves (2-1000) default 5\n"
	"Duplicate address detection time\n"
	"Time in seconds (2-1800) default 180\n")
{
	/* M6 B9b: legacy's value-bearing forms also (re)asserted
	 * dup_addr_detect; delete 'enabled' back to its true default so the
	 * datastore says the same. */
	nb_cli_enqueue_change(vty, "./afi-safis/l2vpn-evpn/dup-addr-detection/enabled",
			      NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./afi-safis/l2vpn-evpn/dup-addr-detection/max-moves",
			      NB_OP_MODIFY, max_moves_str);
	nb_cli_enqueue_change(vty, "./afi-safis/l2vpn-evpn/dup-addr-detection/time", NB_OP_MODIFY,
			      time_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_evpn_dup_addr_detection, no_bgp_evpn_dup_addr_detection_cli_cmd,
	"no dup-addr-detection max-moves (2-1000)$max_moves time (2-1800)$time",
	NO_STR
	"Duplicate address detection\n"
	"Max allowed moves before address detected as duplicate\n"
	"Num of max allowed moves (2-1000) default 5\n"
	"Duplicate address detection time\n"
	"Time in seconds (2-1800) default 180\n")
{
	nb_cli_enqueue_change(vty, "./afi-safis/l2vpn-evpn/dup-addr-detection/max-moves",
			      NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./afi-safis/l2vpn-evpn/dup-addr-detection/time", NB_OP_DESTROY,
			      NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_evpn_dup_addr_detection_freeze, bgp_evpn_dup_addr_detection_freeze_cli_cmd,
	"dup-addr-detection freeze <permanent$permanent|(30-3600)$freeze_time>",
	"Duplicate address detection\n"
	"Duplicate address detection freeze\n"
	"Duplicate address detection permanent freeze\n"
	"Duplicate address detection freeze time (30-3600)\n")
{
	/* Same 'enabled' re-assertion as the max-moves/time form above. */
	nb_cli_enqueue_change(vty, "./afi-safis/l2vpn-evpn/dup-addr-detection/enabled",
			      NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./afi-safis/l2vpn-evpn/dup-addr-detection/freeze",
			      NB_OP_MODIFY, permanent ? permanent : freeze_time_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_evpn_dup_addr_detection_freeze, no_bgp_evpn_dup_addr_detection_freeze_cli_cmd,
	"no dup-addr-detection freeze [<permanent|(30-3600)>]",
	NO_STR
	"Duplicate address detection\n"
	"Duplicate address detection freeze\n"
	"Duplicate address detection permanent freeze\n"
	"Duplicate address detection freeze time (30-3600)\n")
{
	nb_cli_enqueue_change(vty, "./afi-safis/l2vpn-evpn/dup-addr-detection/freeze",
			      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/*
 * M6 batch B5: instance-level EVPN multihoming, mgmtd side.
 * 'ead-es-frag evi-limit' keeps legacy's single-DEFPY 'no'-with-mandatory-
 * value grammar (bgp_evpn_ead_es_frag_evi_limit_cmd): both directions
 * always carry the '(1-1000)' token, even though 'no' ignores it, same as
 * flooding's/dup-addr-detection freeze's 'no' forms above.
 *
 * 'ead-es-route-target export RT' reuses bgp_cli_soo_parse() (same
 * ASN:NN_OR_IP-ADDRESS:NN token grammar as 'mac-vrf soo' and the per-(peer,
 * afi,safi) 'soo' above) to route the token to the matching as2/as4/ipv4
 * keyed-list entry under multihoming/ead-es-route-target-export. Every
 * configured RT is its own list entry (key = global-admin + local-admin),
 * so 'export RT' / 'no ... export RT' map directly to a single list-entry
 * CREATE/DESTROY -- no separate leaf writes needed, unlike mac-vrf-soo's
 * presence-container choice shape.
 */
DEFPY_YANG(
	bgp_evpn_ead_es_frag_evi_limit, bgp_evpn_ead_es_frag_evi_limit_cli_cmd,
	"[no$no] ead-es-frag evi-limit (1-1000)$limit",
	NO_STR
	"EAD ES fragment config\n"
	"EVIs per-fragment\n"
	"limit\n")
{
	if (no)
		nb_cli_enqueue_change(vty,
				      "./afi-safis/l2vpn-evpn/multihoming/ead-es-frag-evi-limit",
				      NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty,
				      "./afi-safis/l2vpn-evpn/multihoming/ead-es-frag-evi-limit",
				      NB_OP_MODIFY, limit_str);
	return nb_cli_apply_changes(vty, NULL);
}

static const char *bgp_cli_ead_es_rt_case_name(enum bgp_cli_soo_case rt_case)
{
	switch (rt_case) {
	case BGP_CLI_SOO_AS2:
		return "as2";
	case BGP_CLI_SOO_AS4:
		return "as4";
	case BGP_CLI_SOO_IPV4:
	default:
		return "ipv4";
	}
}

DEFPY_YANG(
	bgp_evpn_ead_es_rt, bgp_evpn_ead_es_rt_cli_cmd,
	"ead-es-route-target export RT$rt",
	"EAD ES Route Target\n"
	"export\n"
	"Route target (A.B.C.D:MN|EF:OPQR|GHJK:MN)\n")
{
	enum bgp_cli_soo_case rt_case;
	char global_admin[INET_ADDRSTRLEN], local_admin[12];
	char *xpath;

	if (!bgp_cli_soo_parse(rt, &rt_case, global_admin, sizeof(global_admin), local_admin,
			       sizeof(local_admin))) {
		vty_out(vty, "%% Malformed Route Target list\n");
		return CMD_WARNING;
	}

	xpath = asprintfrr(MTYPE_TMP,
			   "./afi-safis/l2vpn-evpn/multihoming/ead-es-route-target-export/%s[global-admin='%s'][local-admin='%s']",
			   bgp_cli_ead_es_rt_case_name(rt_case), global_admin, local_admin);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	XFREE(MTYPE_TMP, xpath);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_evpn_ead_es_rt, no_bgp_evpn_ead_es_rt_cli_cmd,
	"no ead-es-route-target export RT$rt",
	NO_STR
	"EAD ES Route Target\n"
	"export\n" EVPN_ASN_IP_HELP_STR)
{
	enum bgp_cli_soo_case rt_case;
	char global_admin[INET_ADDRSTRLEN], local_admin[12];
	char *xpath;

	if (!bgp_cli_soo_parse(rt, &rt_case, global_admin, sizeof(global_admin), local_admin,
			       sizeof(local_admin))) {
		vty_out(vty, "%% Malformed Route Target list\n");
		return CMD_WARNING;
	}

	xpath = asprintfrr(MTYPE_TMP,
			   "./afi-safis/l2vpn-evpn/multihoming/ead-es-route-target-export/%s[global-admin='%s'][local-admin='%s']",
			   bgp_cli_ead_es_rt_case_name(rt_case), global_admin, local_admin);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath);

	return nb_cli_apply_changes(vty, NULL);
}

/*
 * M6 batch B9b: the reopened EVPN families, mgmtd side.
 *
 * Route-targets (VRF level at BGP_EVPN_NODE, per-VNI at
 * BGP_EVPN_VNI_NODE) parse legacy's variadic RTLIST grammar and expand
 * both the list and the 'both' direction alias into individual typed
 * changes on B9a's direction-primary tree
 * (route-target/<import|export>/{rts/<as2|as4|ipv4>, wildcard-rts,
 * auto/{mode[,rfc8365-compatible]}}). Fully qualified RTs reuse
 * bgp_cli_soo_parse() (the same as2-vs-as4-vs-ipv4 magnitude split
 * ecommunity_str2com() applies to RT tokens; established by the B5
 * ead-es-route-target-export commands above); wildcard '*:NN' tokens --
 * import-only, and legacy rejected them for 'both' too
 * (wildcard_ok was direction == RT_TYPE_IMPORT exactly) -- become
 * wildcard-rts leaf-list entries. Every configured RT is its own
 * (keyed-list or leaf-list) entry, so add/remove map to plain
 * CREATE/DESTROY per token.
 *
 * 'auto-route-target <dir> <add-mode>' writes the auto/mode leaf (the
 * YANG enum reuses the exact CLI keywords); the VRF-only
 * 'auto-route-target <dir> rfc8365-compatible' form writes the
 * orthogonal default-false rfc8365-compatible leaf instead. The 'no'
 * forms destroy unconditionally, dropping legacy's exact-value-match
 * rejections in favor of plain NB_OP_DESTROY like every other
 * 'no ... [value]' form in this file; a bare 'no auto-route-target
 * [<dir>]' clears both the mode and (VRF level) the rfc8365 switch,
 * matching legacy. The deprecated aliases ('route-target <dir> auto'
 * for 'auto-route-target <dir> add-always', 'autort rfc8365-compatible'
 * for 'auto-route-target both rfc8365-compatible') stay CMD_ATTR_YANG |
 * CMD_ATTR_DEPRECATED | CMD_ATTR_HIDDEN CLI-layer mappings printing the
 * same deprecation warnings the legacy DEFPY_ATTRs did.
 */
/* One parsed route-target token: the xpath fragment below the
 * direction container it maps to. */
struct bgp_cli_evpn_rt_token {
	char suffix[96];
};

/* Parse one RTLIST token into its rts/wildcard-rts xpath fragment.
 * Legacy note on failures: the retired DEFPYs' parser
 * (ecommunity_gettoken) silently WRAPPED an overflowing local
 * administrator (uint32 'val = val * 10 + digit'), so a nonsense value
 * like 100:100000010000010000101010 was accepted and stored as its
 * wrapped remainder; evpn_type5_test_topo1's boundary-value case
 * encodes the resulting contract: the config load must not abort, and
 * the literal value must not appear in the configuration. This parser
 * rejects such tokens outright (no wrap), and the callers return
 * CMD_WARNING -- which vtysh tolerates from a daemon without failing
 * the file load -- with nothing enqueued (tokens are parsed to
 * completion BEFORE the first enqueue: a partial enqueue without an
 * apply would leak stale changes into the next command's transaction).
 */
static bool bgp_cli_evpn_rt_token_parse(struct vty *vty, const char *token, bool wildcard_ok,
					struct bgp_cli_evpn_rt_token *parsed)
{
	if (token[0] == '*') {
		unsigned long val;
		char *endptr;

		if (!wildcard_ok) {
			vty_out(vty, "%% Wildcard '*' only applicable for import: %s\n", token);
			return false;
		}

		if (token[1] != ':') {
			vty_out(vty, "%% Malformed Route Target: %s\n", token);
			return false;
		}

		errno = 0;
		val = strtoul(token + 2, &endptr, 10);
		if (endptr == token + 2 || *endptr != '\0' || errno || val > UINT32_MAX) {
			vty_out(vty, "%% Malformed Route Target: %s\n", token);
			return false;
		}

		snprintf(parsed->suffix, sizeof(parsed->suffix), "/wildcard-rts[.='%lu']", val);
		return true;
	}

	{
		enum bgp_cli_soo_case rt_case;
		char global_admin[INET_ADDRSTRLEN], local_admin[12];

		if (!bgp_cli_soo_parse(token, &rt_case, global_admin, sizeof(global_admin),
				       local_admin, sizeof(local_admin))) {
			vty_out(vty, "%% Malformed Route Target: %s\n", token);
			return false;
		}

		snprintf(parsed->suffix, sizeof(parsed->suffix),
			 "/rts/%s[global-admin='%s'][local-admin='%s']",
			 bgp_cli_ead_es_rt_case_name(rt_case), global_admin, local_admin);
		return true;
	}
}

/* Shared body of the four rtlist DEFPYs: parse every token from
 * rt_argv[0 .. n_rts-1], then enqueue each for the direction(s),
 * 'both' expanding to import plus export. Legacy's wildcard_ok =
 * (direction == import) exactly: wildcards are rejected for 'both'
 * too. */
static int bgp_cli_evpn_rt_list(struct vty *vty, const char *base_prefix, bool import, bool export,
				struct cmd_token **rt_argv, int n_rts, enum nb_operation op)
{
	struct bgp_cli_evpn_rt_token *parsed;
	char xpath[XPATH_MAXLEN];
	bool wildcard_ok = import && !export;

	if (strmatch(rt_argv[0]->arg, "auto")) {
		vty_out(vty, "%% Use \"%sauto-route-target\" to %sconfigure the automatic route-target\n",
			op == NB_OP_DESTROY ? "no " : "", op == NB_OP_DESTROY ? "un" : "");
		return CMD_WARNING_CONFIG_FAILED;
	}

	parsed = XCALLOC(MTYPE_TMP, n_rts * sizeof(*parsed));

	for (int i = 0; i < n_rts; i++) {
		if (!bgp_cli_evpn_rt_token_parse(vty, rt_argv[i]->arg, wildcard_ok, &parsed[i])) {
			XFREE(MTYPE_TMP, parsed);
			return CMD_WARNING;
		}
	}

	for (int i = 0; i < n_rts; i++) {
		if (import) {
			snprintf(xpath, sizeof(xpath), "%s/route-target/import%s", base_prefix,
				 parsed[i].suffix);
			nb_cli_enqueue_change(vty, xpath, op, NULL);
		}
		if (export) {
			snprintf(xpath, sizeof(xpath), "%s/route-target/export%s", base_prefix,
				 parsed[i].suffix);
			nb_cli_enqueue_change(vty, xpath, op, NULL);
		}
	}

	XFREE(MTYPE_TMP, parsed);

	return nb_cli_apply_changes(vty, NULL);
}

#define BGP_EVPN_VRF_RT_BASE "./afi-safis/l2vpn-evpn"
#define BGP_EVPN_VNI_RT_BASE "."

DEFPY_YANG(
	bgp_evpn_vrf_rt, bgp_evpn_vrf_rt_cli_cmd,
	"route-target <both$both|import$import|export$export> RTLIST...",
	"Route Target\n"
	"import and export\n"
	"import\n"
	"export\n"
	"Space separated route target list (A.B.C.D:MN|EF:OPQR|GHJK:MN|*:OPQR|*:MN)\n")
{
	return bgp_cli_evpn_rt_list(vty, BGP_EVPN_VRF_RT_BASE, import || both, export || both,
				    argv + 2, argc - 2, NB_OP_CREATE);
}

DEFPY_YANG(
	no_bgp_evpn_vrf_rt, no_bgp_evpn_vrf_rt_cli_cmd,
	"no route-target <both$both|import$import|export$export> RTLIST...",
	NO_STR
	"Route Target\n"
	"import and export\n"
	"import\n"
	"export\n"
	"Space separated route target list (A.B.C.D:MN|EF:OPQR|GHJK:MN|*:OPQR|*:MN)\n")
{
	return bgp_cli_evpn_rt_list(vty, BGP_EVPN_VRF_RT_BASE, import || both, export || both,
				    argv + 3, argc - 3, NB_OP_DESTROY);
}

DEFPY_YANG(
	bgp_evpn_vrf_auto_rt, bgp_evpn_vrf_auto_rt_cli_cmd,
	"auto-route-target <both|import|export>$type <add-always|add-never|add-if-no-manual|rfc8365-compatible>$mode",
	"Automatic route-target configuration\n"
	"Import and export\n"
	"Import\n"
	"Export\n"
	"Always add the automatic route-target, even when manual route-targets are configured\n"
	"Never add the automatic route-target\n"
	"Add the automatic route-target only when no manual route-target is configured (default)\n"
	"Encode the automatic route-target as RFC 8365 compatible (set the VXLAN encapsulation bits in the local admin field)\n")
{
	const char *leaf = strmatch(mode, "rfc8365-compatible") ? "rfc8365-compatible" : "mode";
	const char *value = strmatch(mode, "rfc8365-compatible") ? "true" : mode;
	char xpath[XPATH_MAXLEN];

	if (strmatch(type, "import") || strmatch(type, "both")) {
		snprintf(xpath, sizeof(xpath),
			 "./afi-safis/l2vpn-evpn/route-target/import/auto/%s", leaf);
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, value);
	}
	if (strmatch(type, "export") || strmatch(type, "both")) {
		snprintf(xpath, sizeof(xpath),
			 "./afi-safis/l2vpn-evpn/route-target/export/auto/%s", leaf);
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, value);
	}

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_evpn_vrf_auto_rt, no_bgp_evpn_vrf_auto_rt_cli_cmd,
	"no auto-route-target [<both|import|export>$type [<add-always|add-never|add-if-no-manual|rfc8365-compatible>$mode]]",
	NO_STR
	"Automatic route-target configuration\n"
	"Import and export\n"
	"Import\n"
	"Export\n"
	"Always add the automatic route-target, even when manual route-targets are configured\n"
	"Never add the automatic route-target\n"
	"Add the automatic route-target only when no manual route-target is configured (default)\n"
	"Encode the automatic route-target as RFC 8365 compatible (set the VXLAN encapsulation bits in the local admin field)\n")
{
	bool rfc8365 = mode && strmatch(mode, "rfc8365-compatible");
	bool do_import = !type || strmatch(type, "import") || strmatch(type, "both");
	bool do_export = !type || strmatch(type, "export") || strmatch(type, "both");
	char xpath[XPATH_MAXLEN];
	const char *dirs[2];
	int n_dirs = 0;

	if (do_import)
		dirs[n_dirs++] = "import";
	if (do_export)
		dirs[n_dirs++] = "export";

	for (int i = 0; i < n_dirs; i++) {
		if (!mode || !rfc8365) {
			snprintf(xpath, sizeof(xpath),
				 "./afi-safis/l2vpn-evpn/route-target/%s/auto/mode", dirs[i]);
			nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
		}
		if (!mode || rfc8365) {
			snprintf(xpath, sizeof(xpath),
				 "./afi-safis/l2vpn-evpn/route-target/%s/auto/rfc8365-compatible",
				 dirs[i]);
			nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
		}
	}

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_ATTR(
	bgp_evpn_vrf_rt_auto, bgp_evpn_vrf_rt_auto_cli_cmd,
	"route-target <both|import|export>$type auto",
	"Route Target\n"
	"import and export\n"
	"import\n"
	"export\n"
	"Automatically derive route target\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED | CMD_ATTR_HIDDEN)
{
	char xpath[XPATH_MAXLEN];

	vty_out(vty,
		"%% \"route-target %s auto\" is deprecated, use \"auto-route-target %s add-always\"\n",
		type, type);

	if (strmatch(type, "import") || strmatch(type, "both")) {
		snprintf(xpath, sizeof(xpath),
			 "./afi-safis/l2vpn-evpn/route-target/import/auto/mode");
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, "add-always");
	}
	if (strmatch(type, "export") || strmatch(type, "both")) {
		snprintf(xpath, sizeof(xpath),
			 "./afi-safis/l2vpn-evpn/route-target/export/auto/mode");
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, "add-always");
	}

	return nb_cli_apply_changes(vty, NULL);
}

/* Unlike legacy's exact ADD_ALWAYS-match guard, this destroys the mode
 * unconditionally (the value-match-guard-dropping precedent of every
 * other deprecated/no form here); a new-style non-add-always mode
 * removed by the deprecated alias was misuse under legacy too. */
DEFPY_ATTR(
	no_bgp_evpn_vrf_rt_auto, no_bgp_evpn_vrf_rt_auto_cli_cmd,
	"no route-target <both|import|export>$type auto",
	NO_STR
	"Route Target\n"
	"import and export\n"
	"import\n"
	"export\n"
	"Automatically derive route target\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED | CMD_ATTR_HIDDEN)
{
	char xpath[XPATH_MAXLEN];

	vty_out(vty,
		"%% \"no route-target %s auto\" is deprecated, use \"no auto-route-target %s add-always\"\n",
		type, type);

	if (strmatch(type, "import") || strmatch(type, "both")) {
		snprintf(xpath, sizeof(xpath),
			 "./afi-safis/l2vpn-evpn/route-target/import/auto/mode");
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	}
	if (strmatch(type, "export") || strmatch(type, "both")) {
		snprintf(xpath, sizeof(xpath),
			 "./afi-safis/l2vpn-evpn/route-target/export/auto/mode");
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	}

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_ATTR(
	bgp_evpn_advertise_autort_rfc8365, bgp_evpn_advertise_autort_rfc8365_cli_cmd,
	"autort rfc8365-compatible",
	"Auto-derivation of RT\n"
	"Auto-derivation of RT using RFC8365\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED | CMD_ATTR_HIDDEN)
{
	vty_out(vty,
		"%% \"autort rfc8365-compatible\" is deprecated, use \"auto-route-target both rfc8365-compatible\"\n");

	nb_cli_enqueue_change(vty,
			      "./afi-safis/l2vpn-evpn/route-target/import/auto/rfc8365-compatible",
			      NB_OP_MODIFY, "true");
	nb_cli_enqueue_change(vty,
			      "./afi-safis/l2vpn-evpn/route-target/export/auto/rfc8365-compatible",
			      NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_ATTR(
	no_bgp_evpn_advertise_autort_rfc8365, no_bgp_evpn_advertise_autort_rfc8365_cli_cmd,
	"no autort rfc8365-compatible",
	NO_STR
	"Auto-derivation of RT\n"
	"Auto-derivation of RT using RFC8365\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED | CMD_ATTR_HIDDEN)
{
	vty_out(vty,
		"%% \"no autort rfc8365-compatible\" is deprecated, use \"no auto-route-target both rfc8365-compatible\"\n");

	nb_cli_enqueue_change(vty,
			      "./afi-safis/l2vpn-evpn/route-target/import/auto/rfc8365-compatible",
			      NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty,
			      "./afi-safis/l2vpn-evpn/route-target/export/auto/rfc8365-compatible",
			      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_evpn_vni_rt, bgp_evpn_vni_rt_cli_cmd,
	"route-target <both$both|import$import|export$export> RTLIST...",
	"Route Target\n"
	"import and export\n"
	"import\n"
	"export\n"
	"Space separated route target list (A.B.C.D:MN|EF:OPQR|GHJK:MN|*:OPQR|*:MN)\n")
{
	return bgp_cli_evpn_rt_list(vty, BGP_EVPN_VNI_RT_BASE, import || both, export || both,
				    argv + 2, argc - 2, NB_OP_CREATE);
}

DEFPY_YANG(
	no_bgp_evpn_vni_rt, no_bgp_evpn_vni_rt_cli_cmd,
	"no route-target <both$both|import$import|export$export> RTLIST...",
	NO_STR
	"Route Target\n"
	"import and export\n"
	"import\n"
	"export\n"
	"Space separated route target list (A.B.C.D:MN|EF:OPQR|GHJK:MN|*:OPQR|*:MN)\n")
{
	return bgp_cli_evpn_rt_list(vty, BGP_EVPN_VNI_RT_BASE, import || both, export || both,
				    argv + 3, argc - 3, NB_OP_DESTROY);
}

/* Bulk 'no route-target <import|export>': legacy removed every MANUAL RT
 * of the direction -- including wildcards, which share the one
 * configured-RT list in bgpd -- but never the auto-route-target mode.
 * Destroy the rts container (all three case lists at once) and every
 * wildcard-rts instance; auto/ stays untouched. */
static int no_bgp_evpn_vni_rt_wildcard_iter_cb(const struct lyd_node *dnode, void *arg)
{
	struct vty *vty = arg;
	char *xpath = asprintfrr(MTYPE_TMP, "./route-target/%s/wildcard-rts[.='%s']",
				 strmatch(lyd_parent(dnode)->schema->name, "import") ? "import"
										     : "export",
				 yang_dnode_get_string(dnode, NULL));

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath);

	return YANG_ITER_CONTINUE;
}

DEFPY_YANG(
	no_bgp_evpn_vni_rt_without_val, no_bgp_evpn_vni_rt_without_val_cli_cmd,
	"no route-target <import$import|export$export>",
	NO_STR
	"Route Target\n"
	"import\n"
	"export\n")
{
	const char *dir = import ? "import" : "export";
	const struct lyd_node *vni_dnode =
		yang_dnode_get(vty->candidate_config->dnode, VTY_CURR_XPATH);
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "./route-target/%s/rts", dir);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	if (vni_dnode)
		yang_dnode_iterate(no_bgp_evpn_vni_rt_wildcard_iter_cb, vty, vni_dnode,
				   "./route-target/%s/wildcard-rts", dir);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_evpn_vni_auto_rt, bgp_evpn_vni_auto_rt_cli_cmd,
	"auto-route-target <both|import|export>$type <add-always|add-never|add-if-no-manual>$mode",
	"Automatic route-target configuration\n"
	"Import and export\n"
	"Import\n"
	"Export\n"
	"Always add the automatic route-target, even when manual route-targets are configured\n"
	"Never add the automatic route-target\n"
	"Add the automatic route-target only when no manual route-target is configured (default)\n")
{
	if (strmatch(type, "import") || strmatch(type, "both"))
		nb_cli_enqueue_change(vty, "./route-target/import/auto/mode", NB_OP_MODIFY, mode);
	if (strmatch(type, "export") || strmatch(type, "both"))
		nb_cli_enqueue_change(vty, "./route-target/export/auto/mode", NB_OP_MODIFY, mode);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_evpn_vni_auto_rt, no_bgp_evpn_vni_auto_rt_cli_cmd,
	"no auto-route-target [<both|import|export>$type [<add-always|add-never|add-if-no-manual>$mode]]",
	NO_STR
	"Automatic route-target configuration\n"
	"Import and export\n"
	"Import\n"
	"Export\n"
	"Always add the automatic route-target, even when manual route-targets are configured\n"
	"Never add the automatic route-target\n"
	"Add the automatic route-target only when no manual route-target is configured (default)\n")
{
	if (!type || strmatch(type, "import") || strmatch(type, "both"))
		nb_cli_enqueue_change(vty, "./route-target/import/auto/mode", NB_OP_DESTROY, NULL);
	if (!type || strmatch(type, "export") || strmatch(type, "both"))
		nb_cli_enqueue_change(vty, "./route-target/export/auto/mode", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

/*
 * 'advertise <ipv4|ipv6> unicast [gateway-ip] [route-map WORD]': the
 * three leaves of one advertise-<afi>-unicast container. enabled and
 * gateway-ip are the two alternatives of the same command (FRR stores
 * and writes exactly one), so each positive form writes its own leaf
 * and destroys the other back to false; a positive form without
 * route-map also clears any configured route-map, matching legacy's
 * rmap_changed handling. 'no advertise ... [route-map WORD]' destroys
 * all three (the optional token is accepted but ignored, like every
 * other 'no ... [value]' form here). The grammar narrows legacy's
 * BGP_AFI_CMD_STR/BGP_SAFI_CMD_STR token set to the ipv4/ipv6 unicast
 * combinations -- everything else was a runtime "%% Only ipv4 or
 * ipv6 ... supported" rejection in the retired DEFUN, now a parse
 * error.
 */
DEFPY_YANG(
	bgp_evpn_advertise_type5, bgp_evpn_advertise_type5_cli_cmd,
	"advertise <ipv4$ipv4|ipv6> unicast [gateway-ip$gateway_ip] [route-map RMAP_NAME$rmap]",
	"Advertise prefix routes\n"
	"IPv4 Address Family\n"
	"IPv6 Address Family\n"
	"Address Family modifier\n"
	"advertise gateway IP overlay index\n"
	"route-map for filtering specific routes\n"
	"Name of the route map\n")
{
	const char *af = ipv4 ? "ipv4" : "ipv6";
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "./afi-safis/l2vpn-evpn/advertise-%s-unicast/enabled", af);
	if (gateway_ip)
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, "true");

	snprintf(xpath, sizeof(xpath), "./afi-safis/l2vpn-evpn/advertise-%s-unicast/gateway-ip",
		 af);
	if (gateway_ip)
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, "true");
	else
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	snprintf(xpath, sizeof(xpath), "./afi-safis/l2vpn-evpn/advertise-%s-unicast/route-map",
		 af);
	if (rmap)
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, rmap);
	else
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_evpn_advertise_type5, no_bgp_evpn_advertise_type5_cli_cmd,
	"no advertise <ipv4$ipv4|ipv6> unicast [route-map RMAP_NAME]",
	NO_STR
	"Advertise prefix routes\n"
	"IPv4 Address Family\n"
	"IPv6 Address Family\n"
	"Address Family modifier\n"
	"route-map for filtering specific routes\n"
	"Name of the route map\n")
{
	const char *af = ipv4 ? "ipv4" : "ipv6";
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "./afi-safis/l2vpn-evpn/advertise-%s-unicast/enabled", af);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	snprintf(xpath, sizeof(xpath), "./afi-safis/l2vpn-evpn/advertise-%s-unicast/gateway-ip",
		 af);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	snprintf(xpath, sizeof(xpath), "./afi-safis/l2vpn-evpn/advertise-%s-unicast/route-map",
		 af);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

/*
 * '[no] advertise-pip [ip A.B.C.D [mac ...]]': one atomic legacy
 * command over the advertise-pip container's enabled/ip/mac bundle
 * (B9a's must constraints bind ip to enabled and mac to ip).
 * - positive without ip: (re)enable only -- destroy enabled back to its
 *   true default, leave any static ip/mac alone (legacy's argc==1 early
 *   return kept them too);
 * - positive with ip [mac]: enable plus set the statics, an absent mac
 *   clearing a previously configured one (the reread container is the
 *   whole desired state);
 * - 'no advertise-pip': disable and clear the statics (enabled
 *   explicit false, ip/mac destroyed);
 * - 'no advertise-pip ip ... [mac ...]': legacy's remove-statics-only
 *   form -- destroy ip/mac, keep the enabled state, dropping the
 *   legacy value-match rejections per the established precedent.
 */
DEFPY_YANG(
	bgp_evpn_advertise_pip_ip_mac, bgp_evpn_advertise_pip_ip_mac_cli_cmd,
	"[no$no] advertise-pip [ip A.B.C.D$ip [mac <X:X:X:X:X:X|X:X:X:X:X:X/M>$mac]]",
	NO_STR
	"evpn system primary IP\n"
	IP_STR
	"ip address\n"
	MAC_STR MAC_STR MAC_STR)
{
	if (!no) {
		nb_cli_enqueue_change(vty, "./afi-safis/l2vpn-evpn/advertise-pip/enabled",
				      NB_OP_DESTROY, NULL);
		if (ip_str) {
			nb_cli_enqueue_change(vty, "./afi-safis/l2vpn-evpn/advertise-pip/ip",
					      NB_OP_MODIFY, ip_str);
			if (mac_str)
				nb_cli_enqueue_change(vty,
						      "./afi-safis/l2vpn-evpn/advertise-pip/mac",
						      NB_OP_MODIFY, mac_str);
			else
				nb_cli_enqueue_change(vty,
						      "./afi-safis/l2vpn-evpn/advertise-pip/mac",
						      NB_OP_DESTROY, NULL);
		}
	} else {
		if (!ip_str)
			nb_cli_enqueue_change(vty, "./afi-safis/l2vpn-evpn/advertise-pip/enabled",
					      NB_OP_MODIFY, "false");
		nb_cli_enqueue_change(vty, "./afi-safis/l2vpn-evpn/advertise-pip/mac",
				      NB_OP_DESTROY, NULL);
		nb_cli_enqueue_change(vty, "./afi-safis/l2vpn-evpn/advertise-pip/ip",
				      NB_OP_DESTROY, NULL);
	}

	return nb_cli_apply_changes(vty, NULL);
}

/* Bare 'dup-addr-detection' / 'no dup-addr-detection' enable toggle
 * (Tier-A-inverted 'enabled' leaf, default true): positive deletes back
 * to the default, negative writes an explicit false AND resets
 * max-moves/time/freeze to their defaults, exactly legacy's
 * no_dup_addr_detection_cmd ("Reset all parameters to default"). */
DEFPY_YANG(
	bgp_evpn_dup_addr_detection_enable, bgp_evpn_dup_addr_detection_enable_cli_cmd,
	"dup-addr-detection",
	"Duplicate address detection\n")
{
	nb_cli_enqueue_change(vty, "./afi-safis/l2vpn-evpn/dup-addr-detection/enabled",
			      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_evpn_dup_addr_detection_enable, no_bgp_evpn_dup_addr_detection_enable_cli_cmd,
	"no dup-addr-detection",
	NO_STR
	"Duplicate address detection\n")
{
	nb_cli_enqueue_change(vty, "./afi-safis/l2vpn-evpn/dup-addr-detection/enabled",
			      NB_OP_MODIFY, "false");
	nb_cli_enqueue_change(vty, "./afi-safis/l2vpn-evpn/dup-addr-detection/max-moves",
			      NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./afi-safis/l2vpn-evpn/dup-addr-detection/time",
			      NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./afi-safis/l2vpn-evpn/dup-addr-detection/freeze",
			      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/* Tier A multihoming toggles (defaults added by B9a: use-es-l3nhg true,
 * the two disable-* leaves false). Legacy grammar kept verbatim. */
DEFPY_YANG(
	bgp_evpn_use_es_l3nhg, bgp_evpn_use_es_l3nhg_cli_cmd,
	"[no$no] use-es-l3nhg",
	NO_STR
	"use L3 nexthop group for host routes with ES destination\n")
{
	if (no)
		nb_cli_enqueue_change(vty, "./afi-safis/l2vpn-evpn/multihoming/use-es-l3nhg",
				      NB_OP_MODIFY, "false");
	else
		nb_cli_enqueue_change(vty, "./afi-safis/l2vpn-evpn/multihoming/use-es-l3nhg",
				      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_evpn_ead_evi_rx_disable, bgp_evpn_ead_evi_rx_disable_cli_cmd,
	"[no$no] disable-ead-evi-rx",
	NO_STR
	"Activate PE on EAD-ES even if EAD-EVI is not received\n")
{
	if (no)
		nb_cli_enqueue_change(vty, "./afi-safis/l2vpn-evpn/multihoming/disable-ead-evi-rx",
				      NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, "./afi-safis/l2vpn-evpn/multihoming/disable-ead-evi-rx",
				      NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_evpn_ead_evi_tx_disable, bgp_evpn_ead_evi_tx_disable_cli_cmd,
	"[no$no] disable-ead-evi-tx",
	NO_STR
	"Don't advertise EAD-EVI for local ESs\n")
{
	if (no)
		nb_cli_enqueue_change(vty, "./afi-safis/l2vpn-evpn/multihoming/disable-ead-evi-tx",
				      NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, "./afi-safis/l2vpn-evpn/multihoming/disable-ead-evi-tx",
				      NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

/*
 * EVPN type-5 static 'network' statement, keyed by prefix (B9a's shape).
 * The rd token routes through bgp_cli_soo_parse() to the matching
 * as2/as4/ipv4 case (same magnitude split as str2prefix_rd(), the B6/B7
 * 'rd' precedent); every other token lands on its typed leaf verbatim,
 * so a non-numeric ethtag/label WORD is now a candidate-validation error
 * instead of legacy's silent strtoul() misparse. The 'no' form destroys
 * the whole list entry by prefix -- its rd/ethtag/label/esi/gwip tokens
 * are accepted but ignored per the established 'no ... [value]'
 * precedent (legacy matched them against the stored entry).
 */
DEFPY_YANG(
	evpnrt5_network, evpnrt5_network_cli_cmd,
	"network <A.B.C.D/M|X:X::X:X/M>$prefix rd ASN:NN_OR_IP-ADDRESS:NN$rd ethtag WORD$ethtag label WORD$label esi WORD$esi gwip <A.B.C.D|X:X::X:X>$gwip routermac WORD$routermac [route-map RMAP_NAME$rmap]",
	"Specify a network to announce via BGP\n"
	"IP prefix\n"
	"IPv6 prefix\n"
	"Specify Route Distinguisher\n"
	"VPN Route Distinguisher\n"
	"Ethernet Tag\n"
	"Ethernet Tag Value\n"
	"BGP label\n"
	"label value\n"
	"Ethernet Segment Identifier\n"
	"ESI value ( 00:11:22:33:44:55:66:77:88:99 format) \n"
	"Gateway IP\n"
	"Gateway IP ( A.B.C.D )\n"
	"Gateway IPv6 ( X:X::X:X )\n"
	"Router Mac Ext Comm\n"
	"Router Mac address Value ( aa:bb:cc:dd:ee:ff format)\n"
	"Route-map to modify the attributes\n"
	"Name of the route map\n")
{
	enum bgp_cli_soo_case rd_case;
	char administrator[INET_ADDRSTRLEN], assigned_number[12];
	char base[128], xpath[XPATH_MAXLEN];

	if (!bgp_cli_soo_parse(rd, &rd_case, administrator, sizeof(administrator),
			       assigned_number, sizeof(assigned_number))) {
		vty_out(vty, "%% Malformed Route Distinguisher\n");
		return CMD_WARNING;
	}

	snprintf(base, sizeof(base), "./afi-safis/l2vpn-evpn/network[prefix='%s']", prefix_str);
	nb_cli_enqueue_change(vty, base, NB_OP_CREATE, NULL);

	snprintf(xpath, sizeof(xpath), "%s/rd/%s/administrator", base,
		 bgp_cli_ead_es_rt_case_name(rd_case));
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, administrator);
	snprintf(xpath, sizeof(xpath), "%s/rd/%s/assigned-number", base,
		 bgp_cli_ead_es_rt_case_name(rd_case));
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, assigned_number);

	snprintf(xpath, sizeof(xpath), "%s/ethtag", base);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, ethtag);
	snprintf(xpath, sizeof(xpath), "%s/label", base);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, label);
	snprintf(xpath, sizeof(xpath), "%s/esi", base);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, esi);
	snprintf(xpath, sizeof(xpath), "%s/gwip", base);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, gwip_str);
	snprintf(xpath, sizeof(xpath), "%s/routermac", base);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, routermac);

	snprintf(xpath, sizeof(xpath), "%s/route-map", base);
	if (rmap)
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, rmap);
	else
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_evpnrt5_network, no_evpnrt5_network_cli_cmd,
	"no network <A.B.C.D/M|X:X::X:X/M>$prefix rd ASN:NN_OR_IP-ADDRESS:NN ethtag WORD label WORD esi WORD gwip <A.B.C.D|X:X::X:X>",
	NO_STR
	"Specify a network to announce via BGP\n"
	"IP prefix\n"
	"IPv6 prefix\n"
	"Specify Route Distinguisher\n"
	"VPN Route Distinguisher\n"
	"Ethernet Tag\n"
	"Ethernet Tag Value\n"
	"BGP label\n"
	"label value\n"
	"Ethernet Segment Identifier\n"
	"ESI value ( 00:11:22:33:44:55:66:77:88:99 format) \n"
	"Gateway IP\n" "Gateway IP ( A.B.C.D )\n" "Gateway IPv6 ( X:X::X:X )\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "./afi-safis/l2vpn-evpn/network[prefix='%s']", prefix_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

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

DEFPY_YANG(
	bgp_graceful_restart_restart_time, bgp_graceful_restart_restart_time_cli_cmd,
	"bgp graceful-restart restart-time (0-4095)$restart_time",
	BGP_STR
	"Graceful restart capability parameters\n"
	"Set the time to wait to delete stale routes before a BGP open message is received\n"
	"Delay value (seconds)\n")
{
	nb_cli_enqueue_change(vty, "./graceful-restart/restart-time", NB_OP_MODIFY,
			      restart_time_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_graceful_restart_restart_time, no_bgp_graceful_restart_restart_time_cli_cmd,
	"no bgp graceful-restart restart-time [(0-4095)]",
	NO_STR
	BGP_STR
	"Graceful restart capability parameters\n"
	"Set the time to wait to delete stale routes before a BGP open message is received\n"
	"Delay value (seconds)\n")
{
	nb_cli_enqueue_change(vty, "./graceful-restart/restart-time", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_graceful_restart_stalepath_time, bgp_graceful_restart_stalepath_time_cli_cmd,
	"bgp graceful-restart stalepath-time (1-4095)$stalepath_time",
	BGP_STR
	"Graceful restart capability parameters\n"
	"Set the max time to hold onto restarting peer's stale paths\n"
	"Delay value (seconds)\n")
{
	nb_cli_enqueue_change(vty, "./graceful-restart/stalepath-time", NB_OP_MODIFY,
			      stalepath_time_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_graceful_restart_stalepath_time, no_bgp_graceful_restart_stalepath_time_cli_cmd,
	"no bgp graceful-restart stalepath-time [(1-4095)]",
	NO_STR
	BGP_STR
	"Graceful restart capability parameters\n"
	"Set the max time to hold onto restarting peer's stale paths\n"
	"Delay value (seconds)\n")
{
	nb_cli_enqueue_change(vty, "./graceful-restart/stalepath-time", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_graceful_restart_select_defer_time, bgp_graceful_restart_select_defer_time_cli_cmd,
	"bgp graceful-restart select-defer-time (0-3600)$defer_time",
	BGP_STR
	"Graceful restart capability parameters\n"
	"Set the time to defer the BGP route selection after restart\n"
	"Delay value (seconds, 0 - disable)\n")
{
	nb_cli_enqueue_change(vty, "./graceful-restart/select-defer-time", NB_OP_MODIFY,
			      defer_time_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_graceful_restart_select_defer_time, no_bgp_graceful_restart_select_defer_time_cli_cmd,
	"no bgp graceful-restart select-defer-time [(0-3600)]",
	NO_STR
	BGP_STR
	"Graceful restart capability parameters\n"
	"Set the time to defer the BGP route selection after restart\n"
	"Delay value (seconds)\n")
{
	nb_cli_enqueue_change(vty, "./graceful-restart/select-defer-time", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_graceful_restart_rib_stale_time, bgp_graceful_restart_rib_stale_time_cli_cmd,
	"bgp graceful-restart rib-stale-time (1-3600)$stale_time",
	BGP_STR
	"Graceful restart configuration parameters\n"
	"Specify the stale route removal timer in rib\n"
	"Delay value (seconds)\n")
{
	nb_cli_enqueue_change(vty, "./graceful-restart/rib-stale-time", NB_OP_MODIFY,
			      stale_time_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_graceful_restart_rib_stale_time, no_bgp_graceful_restart_rib_stale_time_cli_cmd,
	"no bgp graceful-restart rib-stale-time [(1-3600)]",
	NO_STR
	BGP_STR
	"Graceful restart configuration parameters\n"
	"Specify the stale route removal timer in rib\n"
	"Delay value (seconds)\n")
{
	nb_cli_enqueue_change(vty, "./graceful-restart/rib-stale-time", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/* M7 batch B5: 'bgp graceful-restart disable-eor'. Hidden in legacy
 * (bgp_graceful_restart_disable_eor's DEFUN_HIDDEN pair, bgp_vty.c,
 * retired) and stays hidden here.
 */
DEFPY_YANG_HIDDEN(
	bgp_graceful_restart_disable_eor, bgp_graceful_restart_disable_eor_cli_cmd,
	"bgp graceful-restart disable-eor",
	BGP_STR
	"Graceful restart configuration parameters\n"
	"Disable EOR Check\n")
{
	nb_cli_enqueue_change(vty, "./graceful-restart/disable-eor", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG_HIDDEN(
	no_bgp_graceful_restart_disable_eor, no_bgp_graceful_restart_disable_eor_cli_cmd,
	"no bgp graceful-restart disable-eor",
	NO_STR
	BGP_STR
	"Graceful restart configuration parameters\n"
	"Disable EOR Check\n")
{
	nb_cli_enqueue_change(vty, "./graceful-restart/disable-eor", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/* M7 batch B5: instance administrative shutdown ('bgp shutdown [message
 * MSG...]'), the instance-scope twin of neighbor_shutdown*_cli_cmd above
 * in spirit (bgp_cli_neighbor.c, M4 batch B4) and the same YANG shape
 * (administrative-shutdown/{enabled,message}). Unlike the neighbor form
 * legacy never stored the instance message anywhere -- it was consumed by
 * the CEASE notifications of the enabling transition and then lost, so a
 * saved config forgot it ('bgp_config_write()' only ever emitted plain
 * 'bgp shutdown'). Modeling it as a config leaf fixes that round-trip
 * hole: the message now persists and re-arms across restarts. Both 'no'
 * forms destroy 'enabled' and 'message' together, mirroring the
 * neighbor-form composite destroy (see that comment for the rationale of
 * doing it at the CLI layer).
 */
DEFPY_YANG(
	bgp_instance_shutdown, bgp_instance_shutdown_cli_cmd,
	"bgp shutdown",
	BGP_STR
	"Administrative shutdown of the BGP instance\n")
{
	nb_cli_enqueue_change(vty, "./administrative-shutdown/enabled", NB_OP_MODIFY, "true");
	nb_cli_enqueue_change(vty, "./administrative-shutdown/message", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_instance_shutdown_message, bgp_instance_shutdown_message_cli_cmd,
	"bgp shutdown message MSG...",
	BGP_STR
	"Administrative shutdown of the BGP instance\n"
	"Add a shutdown message (RFC 8203)\n"
	"Shutdown message\n")
{
	char *msgstr;
	int ret;

	msgstr = argv_concat(argv, argc, 3);

	nb_cli_enqueue_change(vty, "./administrative-shutdown/enabled", NB_OP_MODIFY, "true");
	nb_cli_enqueue_change(vty, "./administrative-shutdown/message", NB_OP_MODIFY, msgstr);

	ret = nb_cli_apply_changes(vty, NULL);

	XFREE(MTYPE_TMP, msgstr);

	return ret;
}

DEFPY_YANG(
	no_bgp_instance_shutdown, no_bgp_instance_shutdown_cli_cmd,
	"no bgp shutdown",
	NO_STR
	BGP_STR
	"Administrative shutdown of the BGP instance\n")
{
	nb_cli_enqueue_change(vty, "./administrative-shutdown/enabled", NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./administrative-shutdown/message", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/* Legacy accepts (and ignores) a trailing MSG... on the 'no' form too
 * (no_bgp_shutdown_msg_cmd's ALIAS, bgp_vty.c, retired).
 */
DEFPY_YANG(
	no_bgp_instance_shutdown_message, no_bgp_instance_shutdown_message_cli_cmd,
	"no bgp shutdown message MSG...",
	NO_STR
	BGP_STR
	"Administrative shutdown of the BGP instance\n"
	"Add a shutdown message (RFC 8203)\n"
	"Shutdown message\n")
{
	nb_cli_enqueue_change(vty, "./administrative-shutdown/enabled", NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./administrative-shutdown/message", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/* M7 batch B5: misc instance flags -- all static default-off booleans
 * with positive-only emission, so the 'no' forms destroy back to the
 * YANG default (modify-only callbacks, bgp_nb_instance.c).
 */
DEFPY_YANG(
	bgp_allow_martian, bgp_allow_martian_cli_cmd,
	"[no]$no bgp allow-martian-nexthop",
	NO_STR
	BGP_STR
	"Allow Martian nexthops to be received in the NLRI from a peer\n")
{
	if (no)
		nb_cli_enqueue_change(vty, "./allow-martian-nexthop", NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, "./allow-martian-nexthop", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_use_underlays_nexthop_weight, bgp_use_underlays_nexthop_weight_cli_cmd,
	"[no]$no use-underlays-nexthop-weight",
	NO_STR
	"Tell Zebra when resolving a route to use the underlays nexthop weight for when nexthops are resolved\n")
{
	if (no)
		nb_cli_enqueue_change(vty, "./use-underlays-nexthop-weight", NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, "./use-underlays-nexthop-weight", NB_OP_MODIFY,
				      "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_fast_convergence, bgp_fast_convergence_cli_cmd,
	"[no]$no bgp fast-convergence",
	NO_STR
	BGP_STR
	"Fast convergence for bgp sessions\n")
{
	if (no)
		nb_cli_enqueue_change(vty, "./fast-convergence", NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, "./fast-convergence", NB_OP_MODIFY, "true");
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
	bgp_listen_limit, bgp_listen_limit_cli_cmd,
	"bgp listen limit (1-65535)$limit",
	BGP_STR
	"BGP Dynamic Neighbors listen commands\n"
	"Maximum number of BGP Dynamic Neighbors that can be created\n"
	"Configure Dynamic Neighbors listen limit value\n")
{
	nb_cli_enqueue_change(vty, "./listen-limit", NB_OP_MODIFY, limit_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bgp_listen_limit, no_bgp_listen_limit_cli_cmd,
	"no bgp listen limit [(1-65535)]",
	NO_STR
	BGP_STR
	"BGP Dynamic Neighbors listen commands\n"
	"Maximum number of BGP Dynamic Neighbors that can be created\n"
	"Configure Dynamic Neighbors listen limit value\n")
{
	nb_cli_enqueue_change(vty, "./listen-limit", NB_OP_DESTROY, NULL);
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
void instance_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
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

void instance_cli_write_end(struct vty *vty, const struct lyd_node *dnode)
{
	vty_out(vty, "exit\n");
	vty_out(vty, "!\n");
}

/* M6 B1: a 'vni N' list entry that carries no converted (non-key,
 * non-default) child leaf is emitted in full -- 'vni N' ... 'exit-vni'
 * plus every sub-line -- natively by bgpd's write_vni_config during the
 * coexistence window (only the node-entry create/destroy is converted in
 * B1, not the sub-leaves). mgmtd must stay silent for such an entry so the
 * two daemons' running-config folds to one byte-identical vni block instead
 * of a duplicate/empty frame. Returns true once a sub-leaf converts (B6+)
 * and materializes real content under the entry. */
static bool bgp_evpn_vni_dnode_has_cfg(const struct lyd_node *dnode)
{
	const struct lyd_node *child;

	LY_LIST_FOR (lyd_child(dnode), child) {
		if (lysc_is_key(child->schema))
			continue;
		if (!yang_dnode_is_default_recursive(child))
			return true;
	}
	return false;
}

/* True if an instance afi-safis/<af> container has anything mgmtd should
 * render, treating a content-free 'vni N' entry (bgpd-owned during M6
 * coexistence) as nothing. Keeps afi_safi_cli_write from emitting an empty
 * 'address-family l2vpn evpn' wrapper around a vni entry whose sub-lines
 * are still bgpd's. For the eight non-evpn families this reduces to the
 * pre-existing "materialized => has a non-default child" invariant, so
 * their emission is unchanged. */
static bool afi_safi_dnode_has_output(const struct lyd_node *dnode)
{
	const struct lyd_node *child;

	LY_LIST_FOR (lyd_child(dnode), child) {
		if (yang_dnode_is_default_recursive(child))
			continue;
		if (child->schema->nodetype == LYS_LIST &&
		    strmatch(child->schema->name, "vni") &&
		    !bgp_evpn_vni_dnode_has_cfg(child))
			continue;
		return true;
	}
	return false;
}

/* Header/trailer for a proteus afi-safis/<af> container. Registered on the
 * nine instance afi-safis containers (M5 B0); reused for the neighbor and
 * peer-group afi-safis containers as those per-AF leaves convert (B1+).
 * Reproduces bgp_config_write_family()'s exact ' !\n address-family <...>'
 * frame and ' exit-address-family' trailer (bgp_vty.c) so vtysh folds the
 * bgpd and mgmtd emissions into one block by matching header text -- the
 * per-AF analog of instance_cli_write()'s 'router bgp' header. Fires only
 * once a child leaf materializes the non-presence container, so B0 (no
 * per-AF leaves) emits nothing; skips a container whose only content is a
 * still-native 'vni N' entry (M6 B1) via afi_safi_dnode_has_output(). */
void afi_safi_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const char *header = bgp_afi_safi_cli_header(dnode->schema->name);

	if (!header)
		return;

	if (!afi_safi_dnode_has_output(dnode))
		return;

	vty_out(vty, " !\n address-family %s\n", header);
}

void afi_safi_cli_write_end(struct vty *vty, const struct lyd_node *dnode)
{
	if (!bgp_afi_safi_cli_header(dnode->schema->name))
		return;

	if (!afi_safi_dnode_has_output(dnode))
		return;

	vty_out(vty, " exit-address-family\n");
}

/* M6 B1: 'vni N' ... 'exit-vni' frame for a converted vni list entry.
 * Gated identically to afi_safi_dnode_has_output()'s vni handling: while
 * the entry has no converted sub-leaf (B1) bgpd's write_vni_config emits
 * the whole block, so mgmtd emits nothing and the running-config stays
 * byte-identical. Once sub-leaves convert (B6+) this renders the two-space
 * 'vni N' header and 'exit-vni' trailer that write_vni_config used, with
 * the converted sub-leaves nested between via the datastore DFS. */
void instance_evpn_vni_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	if (!bgp_evpn_vni_dnode_has_cfg(dnode))
		return;

	vty_out(vty, "  vni %s\n", yang_dnode_get_string(dnode, "vni-id"));
}

void instance_evpn_vni_cli_write_end(struct vty *vty, const struct lyd_node *dnode)
{
	if (!bgp_evpn_vni_dnode_has_cfg(dnode))
		return;

	vty_out(vty, "  exit-vni\n");
}

/* M6 B2: instance-level l2vpn-evpn advertise-flag emitters. Tier-A
 * default-false booleans: emit the two-space-indented positive line iff the
 * leaf reads true, reproducing bgp_config_write_evpn_info()'s exact tokens
 * (that native emission is now gated off for these four lines). */
void instance_evpn_advertise_all_vni_cli_write(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "  advertise-all-vni\n");
}

void instance_evpn_advertise_default_gw_cli_write(struct vty *vty, const struct lyd_node *dnode,
						  bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "  advertise-default-gw\n");
}

void instance_evpn_advertise_svi_ip_cli_write(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "  advertise-svi-ip\n");
}

void instance_evpn_enable_resolve_overlay_index_cli_write(struct vty *vty,
							  const struct lyd_node *dnode,
							  bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "  enable-resolve-overlay-index\n");
}

/* M6 B3: instance-level l2vpn-evpn mac-vrf-soo + flooding emitters.
 * mac-vrf-soo mirrors neighbor_af_soo_cli_write() (bgp_cli_neighbor.c):
 * registered on each case's local-admin leaf (the one point reached
 * regardless of which of the three cases is set), reprinting
 * 'mac-vrf soo <global-admin>:<local-admin>'. flooding reproduces
 * bgp_config_write_evpn_info()'s "only 'flooding disable' is ever written
 * back" behavior -- head-end-replication (the unset default) emits
 * nothing. */
void instance_evpn_mac_vrf_soo_cli_write(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	const struct lyd_node *soo = yang_dnode_get_parent(dnode, "mac-vrf-soo");
	const char *case_name;

	if (yang_dnode_exists(soo, "as2"))
		case_name = "as2";
	else if (yang_dnode_exists(soo, "as4"))
		case_name = "as4";
	else if (yang_dnode_exists(soo, "ipv4"))
		case_name = "ipv4";
	else
		return;

	vty_out(vty, "  mac-vrf soo %s:%s\n", yang_dnode_get_string(soo, "%s/global-admin", case_name),
		yang_dnode_get_string(soo, "%s/local-admin", case_name));
}

void instance_evpn_flooding_cli_write(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	if (strmatch(yang_dnode_get_string(dnode, NULL), "disable"))
		vty_out(vty, "  flooding disable\n");
}

/* M6 batch B6: per-VNI 'rd'/'flooding'/'advertise-default-gw'/
 * 'advertise-svi-ip'/'advertise-subnet' emitters, reproducing
 * write_vni_config()'s (bgp_evpn_vty.c) per-VNI lines at their three-space
 * indent -- nested one level under the two-space 'vni N' header/'exit-vni'
 * trailer emitted by instance_evpn_vni_cli_write()/_end() above. 'rd'
 * mirrors mac-vrf-soo above: registered on each choice case's
 * assigned-number leaf, reprinting '<administrator>:<assigned-number>'
 * (RD-specific field names, not soo/RT's global-admin/local-admin).
 *
 * 'flooding' differs from the AF-level emitter above: legacy's
 * write_vni_config() writes BOTH 'flooding disable' and 'flooding
 * head-end-replication' as real per-VNI overrides (unlike the AF level,
 * where head-end-replication is the compiled default and so never needs
 * writing back) -- because the per-VNI leaf's own unset state means
 * "inherit the address-family/tenant-VRF setting", a third state distinct
 * from head-end-replication. Legacy additionally suppressed the line
 * entirely when the per-VNI value equalled the VNI's tenant-VRF bgp
 * instance's own flood_ctrl (a redundant-override dedup); that comparison
 * has no clean northbound equivalent (it would require this cli_show to
 * cross-reference a different bgp instance's own AF-level leaf) and is not
 * reproduced here -- a documented, narrow verbosity difference (an
 * explicit per-VNI override that happens to match its tenant VRF's own
 * flooding setting now always renders, where legacy suppressed it),
 * harmless for config-apply correctness since re-applying the same value
 * is idempotent either way.
 */
void instance_evpn_vni_rd_cli_write(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults)
{
	const struct lyd_node *rd = yang_dnode_get_parent(dnode, "rd");
	const char *case_name;

	if (yang_dnode_exists(rd, "as2"))
		case_name = "as2";
	else if (yang_dnode_exists(rd, "as4"))
		case_name = "as4";
	else if (yang_dnode_exists(rd, "ipv4"))
		case_name = "ipv4";
	else
		return;

	vty_out(vty, "   rd %s:%s\n", yang_dnode_get_string(rd, "%s/administrator", case_name),
		yang_dnode_get_string(rd, "%s/assigned-number", case_name));
}

void instance_evpn_vni_flooding_cli_write(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	if (strmatch(yang_dnode_get_string(dnode, NULL), "disable"))
		vty_out(vty, "   flooding disable\n");
	else
		vty_out(vty, "   flooding head-end-replication\n");
}

void instance_evpn_vni_advertise_default_gw_cli_write(struct vty *vty, const struct lyd_node *dnode,
						       bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "   advertise-default-gw\n");
}

void instance_evpn_vni_advertise_svi_ip_cli_write(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "   advertise-svi-ip\n");
}

void instance_evpn_vni_advertise_subnet_cli_write(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "   advertise-subnet\n");
}

/* M6 batch B7: instance-level (per-VRF-instance role) 'rd'/'default-originate'
 * emitters, reproducing bgp_config_write_evpn_info()'s (bgp_evpn_vty.c)
 * lines at the two-space instance-AF indent -- 'rd' mirrors the per-VNI
 * form above (M6 B6): registered on each choice case's assigned-number
 * leaf. 'advertise ipv4/ipv6 unicast' has no emitter here -- it stays
 * native, see the reject-stub doc comment on its retired-in-name-only
 * DEFPYs above.
 */
void instance_evpn_rd_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const struct lyd_node *rd = yang_dnode_get_parent(dnode, "rd");
	const char *case_name;

	if (yang_dnode_exists(rd, "as2"))
		case_name = "as2";
	else if (yang_dnode_exists(rd, "as4"))
		case_name = "as4";
	else if (yang_dnode_exists(rd, "ipv4"))
		case_name = "ipv4";
	else
		return;

	vty_out(vty, "  rd %s:%s\n", yang_dnode_get_string(rd, "%s/administrator", case_name),
		yang_dnode_get_string(rd, "%s/assigned-number", case_name));
}

void instance_evpn_default_originate_ipv4_cli_write(struct vty *vty, const struct lyd_node *dnode,
						     bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "  default-originate ipv4\n");
}

void instance_evpn_default_originate_ipv6_cli_write(struct vty *vty, const struct lyd_node *dnode,
						     bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "  default-originate ipv6\n");
}

/* M6 batch B4 (max-moves/time/freeze) + B9b ('enabled'): reproduces
 * bgp_config_write_evpn_info()'s retired dup-addr-detection lines
 * (bgp_evpn_vty.c) -- the negative bare toggle first, then the
 * value-bearing sub-forms.
 */
void instance_evpn_dup_addr_detection_cli_write(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults)
{
	uint16_t max_moves = yang_dnode_exists(dnode, "max-moves")
				      ? yang_dnode_get_uint16(dnode, "max-moves")
				      : EVPN_DAD_DEFAULT_MAX_MOVES;
	uint16_t time = yang_dnode_exists(dnode, "time") ? yang_dnode_get_uint16(dnode, "time")
							  : EVPN_DAD_DEFAULT_TIME;

	/* M6 B9b: the bare toggle's negative form, printed first exactly as
	 * the retired native emitter did. */
	if (!yang_dnode_get_bool(dnode, "enabled"))
		vty_out(vty, "  no dup-addr-detection\n");

	if (max_moves != EVPN_DAD_DEFAULT_MAX_MOVES || time != EVPN_DAD_DEFAULT_TIME)
		vty_out(vty, "  dup-addr-detection max-moves %u time %u\n", max_moves, time);

	if (yang_dnode_exists(dnode, "freeze")) {
		const char *freeze = yang_dnode_get_string(dnode, "freeze");

		if (strmatch(freeze, "permanent"))
			vty_out(vty, "  dup-addr-detection freeze permanent\n");
		else
			vty_out(vty, "  dup-addr-detection freeze %s\n", freeze);
	}
}

/* M6 batch B5: multihoming ead-es-frag-evi-limit + ead-es-route-target-export
 * emitters, reproducing bgp_config_write_evpn_info()'s two lines
 * (bgp_evpn_vty.c). ead-es-route-target-export's three case-list emitters
 * are registered one per as2/as4/ipv4 list (bgp_cli_common.c) and fire once
 * per configured RT, same as afi_safis_network_ipv4_cli_write()'s per-entry
 * shape (M5 B9).
 */
void instance_evpn_multihoming_ead_es_frag_evi_limit_cli_write(struct vty *vty,
								const struct lyd_node *dnode,
								bool show_defaults)
{
	vty_out(vty, "  ead-es-frag evi-limit %u\n", yang_dnode_get_uint16(dnode, NULL));
}

void instance_evpn_ead_es_route_target_export_as2_cli_write(struct vty *vty,
							     const struct lyd_node *dnode,
							     bool show_defaults)
{
	vty_out(vty, "  ead-es-route-target export %u:%u\n",
		yang_dnode_get_uint16(dnode, "global-admin"),
		yang_dnode_get_uint32(dnode, "local-admin"));
}

void instance_evpn_ead_es_route_target_export_as4_cli_write(struct vty *vty,
							     const struct lyd_node *dnode,
							     bool show_defaults)
{
	vty_out(vty, "  ead-es-route-target export %u:%u\n",
		yang_dnode_get_uint32(dnode, "global-admin"),
		yang_dnode_get_uint16(dnode, "local-admin"));
}

void instance_evpn_ead_es_route_target_export_ipv4_cli_write(struct vty *vty,
							      const struct lyd_node *dnode,
							      bool show_defaults)
{
	vty_out(vty, "  ead-es-route-target export %s:%u\n",
		yang_dnode_get_string(dnode, "global-admin"),
		yang_dnode_get_uint16(dnode, "local-admin"));
}

/* M6 batch B9b: route-target emitters. One cli_show per
 * route-target/<import|export> container (VRF and per-VNI variants
 * differ only in indent) renders the whole direction's manual set in
 * legacy's sorted order -- bgp_evpn_cfgd_rt_cmp sorted the one
 * configured-RT list by type first (wildcard, as2, ipv4, as4), so the
 * emitter walks the wildcard-rts leaf-list first and the rts case lists
 * in that type order rather than schema/DFS order. The auto/mode and
 * (VRF-only) auto/rfc8365-compatible leaves have their own cli_shows,
 * reached by the datastore DFS after the container's -- reproducing
 * legacy's rt-lines-then-auto-route-target-lines order per direction.
 */
static void bgp_cli_evpn_rt_lines_write(struct vty *vty, const struct lyd_node *dir_dnode,
					const char *indent)
{
	const char *dir_name = dir_dnode->schema->name;
	const struct lyd_node *rts = yang_dnode_get(dir_dnode, "rts");
	const struct lyd_node *child;

	LY_LIST_FOR (lyd_child(dir_dnode), child) {
		if (strmatch(child->schema->name, "wildcard-rts"))
			vty_out(vty, "%sroute-target %s *:%s\n", indent, dir_name,
				yang_dnode_get_string(child, NULL));
	}

	if (!rts)
		return;

	LY_LIST_FOR (lyd_child(rts), child) {
		if (strmatch(child->schema->name, "as2"))
			vty_out(vty, "%sroute-target %s %s:%s\n", indent, dir_name,
				yang_dnode_get_string(child, "global-admin"),
				yang_dnode_get_string(child, "local-admin"));
	}
	LY_LIST_FOR (lyd_child(rts), child) {
		if (strmatch(child->schema->name, "ipv4"))
			vty_out(vty, "%sroute-target %s %s:%s\n", indent, dir_name,
				yang_dnode_get_string(child, "global-admin"),
				yang_dnode_get_string(child, "local-admin"));
	}
	LY_LIST_FOR (lyd_child(rts), child) {
		if (strmatch(child->schema->name, "as4"))
			vty_out(vty, "%sroute-target %s %s:%s\n", indent, dir_name,
				yang_dnode_get_string(child, "global-admin"),
				yang_dnode_get_string(child, "local-admin"));
	}
}

void instance_evpn_rt_direction_cli_write(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	bgp_cli_evpn_rt_lines_write(vty, dnode, "  ");
}

void instance_evpn_vni_rt_direction_cli_write(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults)
{
	bgp_cli_evpn_rt_lines_write(vty, dnode, "   ");
}

/* The auto/mode leaf's direction is its grandparent container's name. */
static const char *bgp_cli_evpn_rt_auto_dir(const struct lyd_node *dnode)
{
	return yang_dnode_get_parent(dnode, "import") ? "import" : "export";
}

void instance_evpn_rt_auto_mode_cli_write(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	vty_out(vty, "  auto-route-target %s %s\n", bgp_cli_evpn_rt_auto_dir(dnode),
		yang_dnode_get_string(dnode, NULL));
}

void instance_evpn_vni_rt_auto_mode_cli_write(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults)
{
	vty_out(vty, "   auto-route-target %s %s\n", bgp_cli_evpn_rt_auto_dir(dnode),
		yang_dnode_get_string(dnode, NULL));
}

void instance_evpn_rt_auto_rfc8365_cli_write(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "  auto-route-target %s rfc8365-compatible\n",
			bgp_cli_evpn_rt_auto_dir(dnode));
}

/* M6 batch B9b: 'advertise <ipv4|ipv6> unicast [gateway-ip]
 * [route-map NAME]' emitter, one per AF container, the AF token taken
 * from the container's own name (advertise-<af>-unicast). enabled and
 * gateway-ip are the command's two alternatives; exactly one line
 * renders, reproducing bgp_config_write_evpn_info()'s retired
 * four-branch block. */
void instance_evpn_advertise_unicast_cli_write(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults)
{
	bool gateway_ip = yang_dnode_get_bool(dnode, "gateway-ip");
	char af[8] = "";

	if (!yang_dnode_get_bool(dnode, "enabled") && !gateway_ip)
		return;

	/* "advertise-ipv4-unicast" -> "ipv4" */
	if (sscanf(dnode->schema->name, "advertise-%7[^-]", af) != 1)
		return;

	vty_out(vty, "  advertise %s unicast%s", af, gateway_ip ? " gateway-ip" : "");
	if (yang_dnode_exists(dnode, "route-map"))
		vty_out(vty, " route-map %s", yang_dnode_get_string(dnode, "route-map"));
	vty_out(vty, "\n");
}

/* M6 batch B9b: '[no] advertise-pip [ip ... [mac ...]]' emitter.
 * Deliberate emission cleanup vs legacy: bgp_config_write_evpn_info()
 * printed a redundant bare '  advertise-pip' line for every VRF
 * instance sitting at the compiled default (enabled, no statics); under
 * the Tier A default "true" model the all-default state emits nothing
 * (this cli_show is not even reached then), and only an explicit 'no
 * advertise-pip' or a static ip/mac renders. The mac is printed from
 * its own configured leaf; legacy printed pip_rmac (the effective MAC,
 * equal to the static whenever one was configured -- same bytes). */
void instance_evpn_advertise_pip_cli_write(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, "enabled")) {
		vty_out(vty, "  no advertise-pip\n");
		return;
	}

	if (yang_dnode_exists(dnode, "ip")) {
		vty_out(vty, "  advertise-pip ip %s", yang_dnode_get_string(dnode, "ip"));
		if (yang_dnode_exists(dnode, "mac"))
			vty_out(vty, " mac %s", yang_dnode_get_string(dnode, "mac"));
		vty_out(vty, "\n");
	}
}

/* M6 batch B9b: Tier A multihoming toggles -- value-checked shape,
 * printing whichever form differs from the (YANG, == compiled) default;
 * the at-default value is skipped by the DFS before this is called. */
void instance_evpn_multihoming_use_es_l3nhg_cli_write(struct vty *vty,
						      const struct lyd_node *dnode,
						      bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "  use-es-l3nhg\n");
	else
		vty_out(vty, "  no use-es-l3nhg\n");
}

void instance_evpn_multihoming_disable_ead_evi_rx_cli_write(struct vty *vty,
							    const struct lyd_node *dnode,
							    bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "  disable-ead-evi-rx\n");
	else
		vty_out(vty, "  no disable-ead-evi-rx\n");
}

void instance_evpn_multihoming_disable_ead_evi_tx_cli_write(struct vty *vty,
							    const struct lyd_node *dnode,
							    bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "  disable-ead-evi-tx\n");
	else
		vty_out(vty, "  no disable-ead-evi-tx\n");
}

/* M6 batch B9b: EVPN type-5 'network' list emitter, one line per entry,
 * reproducing the retired bgp_config_write_network_evpn()'s
 * every-field-present line (bgp_route.c) -- plus the optional
 * route-map, which legacy parsed but never stored or wrote back. */
void instance_evpn_network_cli_write(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults)
{
	const struct lyd_node *rd_dnode = yang_dnode_get(dnode, "rd");
	const char *case_name;

	if (yang_dnode_exists(rd_dnode, "as2"))
		case_name = "as2";
	else if (yang_dnode_exists(rd_dnode, "as4"))
		case_name = "as4";
	else if (yang_dnode_exists(rd_dnode, "ipv4"))
		case_name = "ipv4";
	else
		return;

	vty_out(vty, "  network %s rd %s:%s ethtag %s label %s esi %s gwip %s routermac %s",
		yang_dnode_get_string(dnode, "prefix"),
		yang_dnode_get_string(rd_dnode, "%s/administrator", case_name),
		yang_dnode_get_string(rd_dnode, "%s/assigned-number", case_name),
		yang_dnode_get_string(dnode, "ethtag"), yang_dnode_get_string(dnode, "label"),
		yang_dnode_get_string(dnode, "esi"), yang_dnode_get_string(dnode, "gwip"),
		yang_dnode_get_string(dnode, "routermac"));
	if (yang_dnode_exists(dnode, "route-map"))
		vty_out(vty, " route-map %s", yang_dnode_get_string(dnode, "route-map"));
	vty_out(vty, "\n");
}

void instance_router_id_cli_write(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	vty_out(vty, " bgp router-id %s\n", yang_dnode_get_string(dnode, NULL));
}

void instance_log_neighbor_changes_cli_write(struct vty *vty, const struct lyd_node *dnode,
						    bool show_defaults)
{
	vty_out(vty, " bgp log-neighbor-changes %s\n",
		yang_dnode_get_bool(dnode, NULL) ? "enabled" : "disabled");
}

void instance_write_quanta_cli_write(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults)
{
	vty_out(vty, " write-quanta %u\n", yang_dnode_get_uint8(dnode, NULL));
}

void instance_read_quanta_cli_write(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	vty_out(vty, " read-quanta %u\n", yang_dnode_get_uint8(dnode, NULL));
}

void instance_coalesce_time_cli_write(struct vty *vty, const struct lyd_node *dnode,
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
void instance_timers_cli_write(struct vty *vty, const struct lyd_node *dnode,
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

void instance_timers_minimum_holdtime_cli_write(struct vty *vty,
						       const struct lyd_node *dnode,
						       bool show_defaults)
{
	vty_out(vty, " bgp minimum-holdtime %u\n", yang_dnode_get_uint16(dnode, NULL));
}

void instance_timers_conditional_advertisement_cli_write(struct vty *vty,
								const struct lyd_node *dnode,
								bool show_defaults)
{
	vty_out(vty, " bgp conditional-advertisement timer %u\n",
		yang_dnode_get_uint8(dnode, NULL));
}

void instance_timers_default_originate_cli_write(struct vty *vty,
							const struct lyd_node *dnode,
							bool show_defaults)
{
	vty_out(vty, " bgp default-originate timer %u\n", yang_dnode_get_uint16(dnode, NULL));
}

void instance_cluster_id_cli_write(struct vty *vty, const struct lyd_node *dnode,
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

void instance_fast_external_failover_cli_write(struct vty *vty, const struct lyd_node *dnode,
						      bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no bgp fast-external-failover\n");
}

void instance_ipv6_auto_ra_cli_write(struct vty *vty, const struct lyd_node *dnode,
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
void instance_suppress_fib_pending_cli_write(struct vty *vty, const struct lyd_node *dnode,
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
void instance_update_delay_cli_write(struct vty *vty, const struct lyd_node *dnode,
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
void instance_advertisement_delay_cli_write(struct vty *vty, const struct lyd_node *dnode,
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
void instance_graceful_shutdown_cli_write(struct vty *vty, const struct lyd_node *dnode,
						 bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp graceful-shutdown\n");
}

void instance_always_compare_med_cli_write(struct vty *vty, const struct lyd_node *dnode,
						  bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp always-compare-med\n");
}

void instance_labeled_unicast_explicit_null_cli_write(struct vty *vty,
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

void instance_reject_as_sets_cli_write(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no bgp reject-as-sets\n");
}

void instance_client_to_client_reflection_cli_write(struct vty *vty,
							   const struct lyd_node *dnode,
							   bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no bgp client-to-client reflection\n");
}

void instance_disable_ebgp_connected_route_check_cli_write(struct vty *vty,
								  const struct lyd_node *dnode,
								  bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp disable-ebgp-connected-route-check\n");
}

void instance_bestpath_as_path_ignore_cli_write(struct vty *vty,
						       const struct lyd_node *dnode,
						       bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp bestpath as-path ignore\n");
}

void instance_bestpath_as_path_confed_cli_write(struct vty *vty,
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
void instance_bestpath_as_path_multipath_relax_cli_write(struct vty *vty,
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

void instance_bestpath_compare_routerid_cli_write(struct vty *vty,
							 const struct lyd_node *dnode,
							 bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp bestpath compare-routerid\n");
}

void instance_bestpath_use_imported_attributes_cli_write(struct vty *vty,
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
void instance_bestpath_med_cli_write(struct vty *vty, const struct lyd_node *dnode,
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

void instance_bestpath_peer_type_multipath_relax_cli_write(struct vty *vty,
								  const struct lyd_node *dnode,
								  bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp bestpath peer-type multipath-relax\n");
}

void instance_bestpath_bandwidth_cli_write(struct vty *vty, const struct lyd_node *dnode,
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
void instance_default_ipv4_unicast_cli_write(struct vty *vty, const struct lyd_node *dnode,
						    bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no bgp default ipv4-unicast\n");
}

void instance_default_ipv4_multicast_cli_write(struct vty *vty, const struct lyd_node *dnode,
						      bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp default ipv4-multicast\n");
}

void instance_default_ipv4_labeled_unicast_cli_write(struct vty *vty,
							    const struct lyd_node *dnode,
							    bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp default ipv4-labeled-unicast\n");
}

void instance_default_ipv4_vpn_cli_write(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp default ipv4-vpn\n");
}

void instance_default_ipv4_flowspec_cli_write(struct vty *vty, const struct lyd_node *dnode,
						     bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp default ipv4-flowspec\n");
}

void instance_default_ipv6_unicast_cli_write(struct vty *vty, const struct lyd_node *dnode,
						    bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp default ipv6-unicast\n");
}

void instance_default_ipv6_multicast_cli_write(struct vty *vty, const struct lyd_node *dnode,
						      bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp default ipv6-multicast\n");
}

void instance_default_ipv6_labeled_unicast_cli_write(struct vty *vty,
							    const struct lyd_node *dnode,
							    bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp default ipv6-labeled-unicast\n");
}

void instance_default_ipv6_vpn_cli_write(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp default ipv6-vpn\n");
}

void instance_default_ipv6_flowspec_cli_write(struct vty *vty, const struct lyd_node *dnode,
						     bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp default ipv6-flowspec\n");
}

void instance_default_l2vpn_evpn_cli_write(struct vty *vty, const struct lyd_node *dnode,
						  bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp default l2vpn-evpn\n");
}

void instance_default_shutdown_cli_write(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp default shutdown\n");
}

/* 'bgp default shutdown' (M8 batch B2): Tier A default-off boolean, the
 * negative form deletes back to the false default. Future-peers-only, see
 * instance_default_shutdown_modify (bgp_nb_instance.c) for the FRR #2286
 * ordering analysis. */
DEFPY_YANG(
	bgp_default_shutdown, bgp_default_shutdown_cli_cmd,
	"[no] bgp default shutdown",
	NO_STR
	BGP_STR
	"Configure BGP defaults\n"
	"Apply administrative shutdown to newly configured peers\n")
{
	nb_cli_enqueue_change(vty, "./default/shutdown", no ? NB_OP_DESTROY : NB_OP_MODIFY,
			      no ? NULL : "true");
	return nb_cli_apply_changes(vty, NULL);
}

/* Static default-on scalars (batch B6): value-checked against the YANG
 * default, matching bgp_config_write()'s "if (bgp->default_local_pref !=
 * BGP_DEFAULT_LOCAL_PREF)" / subgroup-pkt-queue-max arms exactly.
 */
void instance_default_local_preference_cli_write(struct vty *vty,
							const struct lyd_node *dnode,
							bool show_defaults)
{
	if (yang_dnode_get_uint32(dnode, NULL) != 100)
		vty_out(vty, " bgp default local-preference %u\n",
			yang_dnode_get_uint32(dnode, NULL));
}

void instance_default_subgroup_pkt_queue_max_cli_write(struct vty *vty,
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
void instance_max_med_on_startup_cli_write(struct vty *vty, const struct lyd_node *dnode,
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
void instance_max_med_administrative_cli_write(struct vty *vty, const struct lyd_node *dnode,
						      bool show_defaults)
{
	if (!yang_dnode_exists(dnode, "enabled") || !yang_dnode_get_bool(dnode, "enabled"))
		return;

	vty_out(vty, " bgp max-med administrative");
	if (yang_dnode_exists(dnode, "med"))
		vty_out(vty, " %u", yang_dnode_get_uint32(dnode, "med"));
	vty_out(vty, "\n");
}

void instance_confederation_identifier_cli_write(struct vty *vty,
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
void instance_confederation_peers_cli_write(struct vty *vty, const struct lyd_node *dnode,
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
void instance_tcp_keepalive_cli_write(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults)
{
	if (!yang_dnode_exists(dnode, "idle"))
		return;

	vty_out(vty, " bgp tcp-keepalive %u %u %u\n", yang_dnode_get_uint16(dnode, "idle"),
		yang_dnode_get_uint16(dnode, "interval"), yang_dnode_get_uint8(dnode, "probes"));
}

void instance_long_lived_graceful_restart_stale_time_cli_write(struct vty *vty,
								      const struct lyd_node *dnode,
								      bool show_defaults)
{
	vty_out(vty, " bgp long-lived-graceful-restart stale-time %u\n",
		yang_dnode_get_uint32(dnode, NULL));
}

/* Tri-state, presence-based (see B8 DEFPY comment above): always emits an
 * explicit enabled|disabled value, never the legacy bare/negative form.
 */
void instance_graceful_restart_notification_cli_write(struct vty *vty,
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
void instance_graceful_restart_mode_cli_write(struct vty *vty, const struct lyd_node *dnode,
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
void instance_graceful_restart_preserve_fw_state_cli_write(struct vty *vty,
								  const struct lyd_node *dnode,
								  bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp graceful-restart preserve-fw-state\n");
}

/* Batch B14: 'bgp graceful-restart restart-time/stalepath-time/
 * select-defer-time/rib-stale-time', per-instance form. None of the four
 * carry a YANG default, so each is presence-based -- same no-gating
 * reasoning as the mode/preserve-fw-state leaves above (the process-wide
 * mirror loop writes struct bgp fields directly, bypassing the northbound
 * datastore, so these leaves are only ever present when this exact
 * per-instance command was used).
 */
void instance_graceful_restart_restart_time_cli_write(struct vty *vty,
							     const struct lyd_node *dnode,
							     bool show_defaults)
{
	vty_out(vty, " bgp graceful-restart restart-time %u\n", yang_dnode_get_uint16(dnode, NULL));
}

void instance_graceful_restart_stalepath_time_cli_write(struct vty *vty,
							       const struct lyd_node *dnode,
							       bool show_defaults)
{
	vty_out(vty, " bgp graceful-restart stalepath-time %u\n",
		yang_dnode_get_uint16(dnode, NULL));
}

void instance_graceful_restart_select_defer_time_cli_write(struct vty *vty,
								  const struct lyd_node *dnode,
								  bool show_defaults)
{
	vty_out(vty, " bgp graceful-restart select-defer-time %u\n",
		yang_dnode_get_uint16(dnode, NULL));
}

void instance_graceful_restart_rib_stale_time_cli_write(struct vty *vty,
							       const struct lyd_node *dnode,
							       bool show_defaults)
{
	vty_out(vty, " bgp graceful-restart rib-stale-time %u\n",
		yang_dnode_get_uint16(dnode, NULL));
}

void instance_graceful_restart_disable_eor_cli_write(struct vty *vty,
							    const struct lyd_node *dnode,
							    bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp graceful-restart disable-eor\n");
}

/* M7 batch B5: 'enabled' renders the whole 'bgp shutdown [message
 * MSG...]' line -- the 'message' leaf has no cli_show of its own, same
 * split as the neighbor form (bgp_cli_neighbor.c). Legacy only ever
 * emitted plain 'bgp shutdown' (the message was never stored); emitting
 * the persisted message is the deliberate round-trip fix, see the
 * bgp_instance_shutdown*_cli_cmd block comment.
 */
void instance_administrative_shutdown_enabled_cli_write(struct vty *vty,
							       const struct lyd_node *dnode,
							       bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		return;

	if (yang_dnode_exists(dnode, "../message"))
		vty_out(vty, " bgp shutdown message %s\n",
			yang_dnode_get_string(dnode, "../message"));
	else
		vty_out(vty, " bgp shutdown\n");
}

void instance_allow_martian_nexthop_cli_write(struct vty *vty, const struct lyd_node *dnode,
						     bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp allow-martian-nexthop\n");
}

void instance_use_underlays_nexthop_weight_cli_write(struct vty *vty,
							    const struct lyd_node *dnode,
							    bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " use-underlays-nexthop-weight\n");
}

void instance_fast_convergence_cli_write(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp fast-convergence\n");
}

void instance_ebgp_requires_policy_cli_write(struct vty *vty, const struct lyd_node *dnode,
						    bool show_defaults)
{
	vty_out(vty, " bgp ebgp-requires-policy %s\n",
		yang_dnode_get_bool(dnode, NULL) ? "enabled" : "disabled");
}

void instance_enforce_first_as_cli_write(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults)
{
	vty_out(vty, " bgp enforce-first-as %s\n",
		yang_dnode_get_bool(dnode, NULL) ? "enabled" : "disabled");
}

void instance_suppress_duplicates_cli_write(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults)
{
	vty_out(vty, " bgp suppress-duplicates %s\n",
		yang_dnode_get_bool(dnode, NULL) ? "enabled" : "disabled");
}

void instance_hard_administrative_reset_cli_write(struct vty *vty,
							 const struct lyd_node *dnode,
							 bool show_defaults)
{
	vty_out(vty, " bgp hard-administrative-reset %s\n",
		yang_dnode_get_bool(dnode, NULL) ? "enabled" : "disabled");
}

void instance_listen_limit_cli_write(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults)
{
	vty_out(vty, " bgp listen limit %u\n", yang_dnode_get_uint16(dnode, NULL));
}

void instance_deterministic_med_cli_write(struct vty *vty, const struct lyd_node *dnode,
						 bool show_defaults)
{
	vty_out(vty, " bgp deterministic-med %s\n",
		yang_dnode_get_bool(dnode, NULL) ? "enabled" : "disabled");
}

void instance_network_import_check_cli_write(struct vty *vty, const struct lyd_node *dnode,
						    bool show_defaults)
{
	vty_out(vty, " bgp network import-check %s\n",
		yang_dnode_get_bool(dnode, NULL) ? "enabled" : "disabled");
}

void instance_bestpath_aigp_cli_write(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults)
{
	vty_out(vty, " bgp bestpath aigp %s\n",
		yang_dnode_get_bool(dnode, NULL) ? "enabled" : "disabled");
}

void instance_default_show_hostname_cli_write(struct vty *vty, const struct lyd_node *dnode,
						     bool show_defaults)
{
	vty_out(vty, " bgp default show-hostname %s\n",
		yang_dnode_get_bool(dnode, NULL) ? "enabled" : "disabled");
}

void instance_default_show_nexthop_hostname_cli_write(struct vty *vty,
							     const struct lyd_node *dnode,
							     bool show_defaults)
{
	vty_out(vty, " bgp default show-nexthop-hostname %s\n",
		yang_dnode_get_bool(dnode, NULL) ? "enabled" : "disabled");
}

void instance_default_software_version_capability_cli_write(struct vty *vty,
								   const struct lyd_node *dnode,
								   bool show_defaults)
{
	vty_out(vty, " bgp default software-version-capability %s\n",
		yang_dnode_get_bool(dnode, NULL) ? "enabled" : "disabled");
}

void instance_default_software_version_capability_latest_encoding_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " bgp default software-version-capability latest-encoding %s\n",
		yang_dnode_get_bool(dnode, NULL) ? "enabled" : "disabled");
}

void instance_default_link_local_capability_cli_write(struct vty *vty,
							     const struct lyd_node *dnode,
							     bool show_defaults)
{
	vty_out(vty, " bgp default link-local-capability %s\n",
		yang_dnode_get_bool(dnode, NULL) ? "enabled" : "disabled");
}

void instance_default_dynamic_capability_cli_write(struct vty *vty,
							  const struct lyd_node *dnode,
							  bool show_defaults)
{
	vty_out(vty, " bgp default dynamic-capability %s\n",
		yang_dnode_get_bool(dnode, NULL) ? "enabled" : "disabled");
}

void instance_route_reflector_allow_outbound_policy_cli_write(struct vty *vty,
								     const struct lyd_node *dnode,
								     bool show_defaults)
{
	vty_out(vty, " bgp route-reflector allow-outbound-policy %s\n",
		yang_dnode_get_bool(dnode, NULL) ? "enabled" : "disabled");
}

/*
 * M5 batch B9: instance-AF 'network' (af-network-ipv4/-ipv6 in
 * proteus-bgp.yang), the six ipv4/ipv6 x unicast/multicast/labeled-unicast
 * containers. A keyed list (key 'prefix') with three option children
 * (route-map, label-index, ipv4-only backdoor); collapses legacy's
 * bgp_network/ipv6_bgp_network DEFPYs (bgp_route.c) into one CREATE on the
 * list entry plus one MODIFY/DESTROY per option child, always issued
 * together (never partial) so a re-typed 'network' line always rewrites
 * every option from scratch, matching bgp_static_set()'s own "unconditional
 * overwrite" semantics for route-map/backdoor. ipv4-vpn/ipv6-vpn (M7) and
 * l2vpn-evpn (M6) are out of scope; bgp_afi_safi_container_name() guards
 * against any other unmodeled AF node.
 */
DEFPY_YANG(
	instance_afi_safis_network, instance_afi_safis_network_cli_cmd,
	"[no] network \
	<A.B.C.D/M$prefix|A.B.C.D$address [mask A.B.C.D$netmask]> \
	[{route-map RMAP_NAME$map_name|label-index (0-1048560)$label_index| \
	backdoor$backdoor}]",
	NO_STR
	"Specify a network to announce via BGP\n"
	"IPv4 prefix\n"
	"Network number\n"
	"Network mask\n"
	"Network mask\n"
	"Route-map to modify the attributes\n"
	"Name of the route map\n"
	"Label index to associate with the prefix\n"
	"Label index value\n"
	"Specify a BGP backdoor route\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char addr_prefix_str[BUFSIZ];
	const char *prefix_use;
	char *xpath, *xpath_child;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (address_str) {
		if (!netmask_str2prefix_str(address_str, netmask_str, addr_prefix_str,
					    sizeof(addr_prefix_str))) {
			vty_out(vty, "%% Inconsistent address and mask\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		prefix_use = addr_prefix_str;
	} else {
		prefix_use = prefix_str;
	}

	xpath = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/network[prefix='%s']", VTY_CURR_XPATH,
			   container, prefix_use);

	if (no) {
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	} else {
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/route-map", xpath);
		nb_cli_enqueue_change(vty, xpath_child, map_name ? NB_OP_MODIFY : NB_OP_DESTROY,
				      map_name);
		XFREE(MTYPE_TMP, xpath_child);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/label-index", xpath);
		nb_cli_enqueue_change(vty, xpath_child,
				      label_index_str ? NB_OP_MODIFY : NB_OP_DESTROY,
				      label_index_str);
		XFREE(MTYPE_TMP, xpath_child);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/backdoor", xpath);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, backdoor ? "true" : "false");
		XFREE(MTYPE_TMP, xpath_child);
	}

	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, xpath);
	return ret;
}

DEFPY_YANG(
	instance_afi_safis_network_ipv6, instance_afi_safis_network_ipv6_cli_cmd,
	"[no] network X:X::X:X/M$prefix \
	[{route-map RMAP_NAME$map_name|label-index (0-1048560)$label_index}]",
	NO_STR
	"Specify a network to announce via BGP\n"
	"IPv6 prefix\n"
	"Route-map to modify the attributes\n"
	"Name of the route map\n"
	"Label index to associate with the prefix\n"
	"Label index value\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath, *xpath_child;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/network[prefix='%s']", VTY_CURR_XPATH,
			   container, prefix_str);

	if (no) {
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	} else {
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/route-map", xpath);
		nb_cli_enqueue_change(vty, xpath_child, map_name ? NB_OP_MODIFY : NB_OP_DESTROY,
				      map_name);
		XFREE(MTYPE_TMP, xpath_child);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/label-index", xpath);
		nb_cli_enqueue_change(vty, xpath_child,
				      label_index_str ? NB_OP_MODIFY : NB_OP_DESTROY,
				      label_index_str);
		XFREE(MTYPE_TMP, xpath_child);
	}

	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, xpath);
	return ret;
}

/* One 'network PFX [label-index N] [route-map NAME] [backdoor]' line per
 * ipv4 list entry, matching bgp_config_write_network()'s field order
 * (bgp_route.c, retired for these six AFs in M5 batch B9). */
void afi_safis_network_ipv4_cli_write(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	vty_out(vty, "  network %s", yang_dnode_get_string(dnode, "prefix"));

	if (yang_dnode_exists(dnode, "label-index"))
		vty_out(vty, " label-index %u", yang_dnode_get_uint32(dnode, "label-index"));

	if (yang_dnode_exists(dnode, "route-map"))
		vty_out(vty, " route-map %s", yang_dnode_get_string(dnode, "route-map"));

	if (yang_dnode_get_bool(dnode, "backdoor"))
		vty_out(vty, " backdoor");

	vty_out(vty, "\n");
}

/* ipv6 counterpart: no 'backdoor' child (af-network-ipv6 doesn't model it). */
void afi_safis_network_ipv6_cli_write(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	vty_out(vty, "  network %s", yang_dnode_get_string(dnode, "prefix"));

	if (yang_dnode_exists(dnode, "label-index"))
		vty_out(vty, " label-index %u", yang_dnode_get_uint32(dnode, "label-index"));

	if (yang_dnode_exists(dnode, "route-map"))
		vty_out(vty, " route-map %s", yang_dnode_get_string(dnode, "route-map"));

	vty_out(vty, "\n");
}

/*
 * M5 batch B10: instance-AF 'aggregate-address' (af-aggregate-ipv4/-ipv6 in
 * proteus-bgp.yang), the same six ipv4/ipv6 x
 * unicast/multicast/labeled-unicast containers B9 established for
 * 'network'. A keyed list (key 'prefix') with six option children
 * (as-set, summary-only, route-map, origin, matching-med-only,
 * suppress-map); collapses legacy's aggregate_addressv4/v6 DEFPYs
 * (bgp_route.c) into one CREATE on the list entry plus one MODIFY/DESTROY
 * per option child, always issued together (never partial) so a re-typed
 * 'aggregate-address' line always rewrites every option from scratch,
 * matching bgp_aggregate_set()'s own "unconditional overwrite" semantics.
 * as-set/summary-only/matching-MED-only are Tier A default-false booleans
 * (unconditional MODIFY); route-map/origin/suppress-map are no-default
 * leaves (MODIFY if present, DESTROY otherwise). One grammar serves both
 * the 'A.B.C.D/M' and 'A.B.C.D A.B.C.D' (address+mask) ipv4 forms, matching
 * legacy; the ipv6 form has no mask alternative, also matching legacy.
 * ipv4-vpn/ipv6-vpn (M7) and l2vpn-evpn (M6) are out of scope;
 * bgp_afi_safi_container_name() guards against any other unmodeled AF node.
 */
DEFPY_YANG(
	instance_afi_safis_aggregate_address, instance_afi_safis_aggregate_address_cli_cmd,
	"[no] aggregate-address <A.B.C.D/M$prefix|A.B.C.D$addr A.B.C.D$mask> \
	[{as-set$as_set|summary-only$summary_only|route-map RMAP_NAME$rmap_name| \
	origin <egp|igp|incomplete>$origin_s|matching-MED-only$match_med| \
	suppress-map RMAP_NAME$suppress_map}]",
	NO_STR
	"Configure BGP aggregate entries\n"
	"Aggregate prefix\n"
	"Aggregate address\n"
	"Aggregate mask\n"
	"Generate AS set path information\n"
	"Filter more specific routes from updates\n"
	"Apply route map to aggregate network\n"
	"Route map name\n"
	"BGP origin code\n"
	"Remote EGP\n"
	"Local IGP\n"
	"Unknown heritage\n"
	"Only aggregate routes with matching MED\n"
	"Suppress the selected more specific routes\n"
	"Route map with the route selectors\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char addr_prefix_str[BUFSIZ];
	const char *prefix_use;
	char *xpath, *xpath_child;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (addr_str) {
		if (!netmask_str2prefix_str(addr_str, mask_str, addr_prefix_str,
					    sizeof(addr_prefix_str))) {
			vty_out(vty, "%% Inconsistent address and mask\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		prefix_use = addr_prefix_str;
	} else {
		prefix_use = prefix_str;
	}

	xpath = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/aggregate-address[prefix='%s']",
			   VTY_CURR_XPATH, container, prefix_use);

	if (no) {
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	} else {
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/as-set", xpath);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, as_set ? "true" : "false");
		XFREE(MTYPE_TMP, xpath_child);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/summary-only", xpath);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY,
				      summary_only ? "true" : "false");
		XFREE(MTYPE_TMP, xpath_child);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/route-map", xpath);
		nb_cli_enqueue_change(vty, xpath_child, rmap_name ? NB_OP_MODIFY : NB_OP_DESTROY,
				      rmap_name);
		XFREE(MTYPE_TMP, xpath_child);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/origin", xpath);
		nb_cli_enqueue_change(vty, xpath_child, origin_s ? NB_OP_MODIFY : NB_OP_DESTROY,
				      origin_s);
		XFREE(MTYPE_TMP, xpath_child);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/matching-med-only", xpath);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, match_med ? "true" : "false");
		XFREE(MTYPE_TMP, xpath_child);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/suppress-map", xpath);
		nb_cli_enqueue_change(vty, xpath_child,
				      suppress_map ? NB_OP_MODIFY : NB_OP_DESTROY, suppress_map);
		XFREE(MTYPE_TMP, xpath_child);
	}

	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, xpath);
	return ret;
}

DEFPY_YANG(
	instance_afi_safis_aggregate_address_ipv6,
	instance_afi_safis_aggregate_address_ipv6_cli_cmd,
	"[no] aggregate-address X:X::X:X/M$prefix \
	[{as-set$as_set|summary-only$summary_only|route-map RMAP_NAME$rmap_name| \
	origin <egp|igp|incomplete>$origin_s|matching-MED-only$match_med| \
	suppress-map RMAP_NAME$suppress_map}]",
	NO_STR
	"Configure BGP aggregate entries\n"
	"Aggregate prefix\n"
	"Generate AS set path information\n"
	"Filter more specific routes from updates\n"
	"Apply route map to aggregate network\n"
	"Route map name\n"
	"BGP origin code\n"
	"Remote EGP\n"
	"Local IGP\n"
	"Unknown heritage\n"
	"Only aggregate routes with matching MED\n"
	"Suppress the selected more specific routes\n"
	"Route map with the route selectors\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath, *xpath_child;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/aggregate-address[prefix='%s']",
			   VTY_CURR_XPATH, container, prefix_str);

	if (no) {
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	} else {
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/as-set", xpath);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, as_set ? "true" : "false");
		XFREE(MTYPE_TMP, xpath_child);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/summary-only", xpath);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY,
				      summary_only ? "true" : "false");
		XFREE(MTYPE_TMP, xpath_child);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/route-map", xpath);
		nb_cli_enqueue_change(vty, xpath_child, rmap_name ? NB_OP_MODIFY : NB_OP_DESTROY,
				      rmap_name);
		XFREE(MTYPE_TMP, xpath_child);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/origin", xpath);
		nb_cli_enqueue_change(vty, xpath_child, origin_s ? NB_OP_MODIFY : NB_OP_DESTROY,
				      origin_s);
		XFREE(MTYPE_TMP, xpath_child);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/matching-med-only", xpath);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, match_med ? "true" : "false");
		XFREE(MTYPE_TMP, xpath_child);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/suppress-map", xpath);
		nb_cli_enqueue_change(vty, xpath_child,
				      suppress_map ? NB_OP_MODIFY : NB_OP_DESTROY, suppress_map);
		XFREE(MTYPE_TMP, xpath_child);
	}

	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, xpath);
	return ret;
}

/* One 'aggregate-address PFX [as-set] [summary-only] [route-map NAME]
 * [origin O] [matching-MED-only] [suppress-map NAME]' line per list entry,
 * matching bgp_config_write_network()'s former aggregate field order
 * (bgp_route.c, retired for these six AFs in M5 batch B10). Shared by both
 * ipv4 and ipv6 -- af-aggregate-ipv4/-ipv6 model identical option leaves. */
void afi_safis_aggregate_address_cli_write(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	vty_out(vty, "  aggregate-address %s", yang_dnode_get_string(dnode, "prefix"));

	if (yang_dnode_get_bool(dnode, "as-set"))
		vty_out(vty, " as-set");

	if (yang_dnode_get_bool(dnode, "summary-only"))
		vty_out(vty, " summary-only");

	if (yang_dnode_exists(dnode, "route-map"))
		vty_out(vty, " route-map %s", yang_dnode_get_string(dnode, "route-map"));

	if (yang_dnode_exists(dnode, "origin"))
		vty_out(vty, " origin %s", yang_dnode_get_string(dnode, "origin"));

	if (yang_dnode_get_bool(dnode, "matching-med-only"))
		vty_out(vty, " matching-MED-only");

	if (yang_dnode_exists(dnode, "suppress-map"))
		vty_out(vty, " suppress-map %s", yang_dnode_get_string(dnode, "suppress-map"));

	vty_out(vty, "\n");
}

/*
 * M5 batch B11: instance-AF 'redistribute' (af-redistribute in
 * proteus-bgp.yang), the two unicast-only instance AFs (ipv4-unicast,
 * ipv6-unicast). A keyed list (key 'protocol instance') with two option
 * children (metric, route-map); collapses legacy's bgp_redistribute_ipv4-
 * and bgp_redistribute_ipv6-family DEFUNs (bgp_vty.c) into one grammar shared by both
 * AFs -- af-redistribute is the same grouping for both containers, and the
 * v4-only/v6-only protocols (rip/ospf vs ripng/ospf6) aren't cross-checked
 * against afi in the model itself; the apply-side proto_redistnum()
 * NB_EV_VALIDATE rejects a wrong-AF protocol (e.g. 'redistribute rip' under
 * ipv6-unicast), matching the grouping's own "FRR rejects the wrong ones at
 * load time" description. A second grammar covers the instance-numbered
 * form ('redistribute <ospf|table|table-direct> (1-65535)'), matching
 * af-redistribute's description verbatim; legacy only ever exposed a subset
 * of this per AF (ipv4: numbered ospf/table/table-direct; ipv6: numbered
 * table-direct only, via the separate bgp_redistribute_ipv6_table DEFPY) --
 * offering the full set symmetrically on both AFs is a side effect of
 * following the shared af-redistribute grouping and its own instance-number
 * description, the same kind of AF-set widening B9/B10 accepted for
 * network/aggregate-address's ipv6-multicast coverage, not a deliberate
 * behavior change.
 *
 * One CREATE plus a MODIFY-or-DESTROY on each of metric/route-map, always
 * issued together (B9/B10 idiom) so a re-typed 'redistribute' line rewrites
 * both options from scratch.
 */
static int bgp_cli_redistribute_apply(struct vty *vty, const char *no, const char *proto,
				      const char *instance_str, const char *metric_str,
				      const char *rmap)
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath, *xpath_child;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/redistribute[protocol='%s'][instance='%s']",
			   VTY_CURR_XPATH, container, proto, instance_str ? instance_str : "0");

	if (no) {
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	} else {
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/metric", xpath);
		nb_cli_enqueue_change(vty, xpath_child, metric_str ? NB_OP_MODIFY : NB_OP_DESTROY,
				      metric_str);
		XFREE(MTYPE_TMP, xpath_child);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/route-map", xpath);
		nb_cli_enqueue_change(vty, xpath_child, rmap ? NB_OP_MODIFY : NB_OP_DESTROY, rmap);
		XFREE(MTYPE_TMP, xpath_child);
	}

	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, xpath);
	return ret;
}

DEFPY_YANG(
	instance_afi_safis_redistribute, instance_afi_safis_redistribute_cli_cmd,
	"[no] redistribute <babel|connected|eigrp|isis|kernel|local|nhrp|openfabric|ospf|ospf6|rip|ripng|sharp|static>$proto \
	[{metric (0-4294967295)$metric|route-map RMAP_NAME$rmap}]",
	NO_STR
	"Redistribute information from another routing protocol\n"
	"Babel routing protocol (Babel)\n"
	"Connected routes (directly attached subnet or host)\n"
	"Enhanced Interior Gateway Routing Protocol (EIGRP)\n"
	"Intermediate System to Intermediate System (IS-IS)\n"
	"Kernel routes (not installed via the zebra RIB)\n"
	"Local routes (directly attached host route)\n"
	"Next Hop Resolution Protocol (NHRP)\n"
	"OpenFabric Routing Protocol\n"
	"Open Shortest Path First (OSPFv2)\n"
	"Open Shortest Path First (IPv6) (OSPFv3)\n"
	"Routing Information Protocol (RIP)\n"
	"Routing Information Protocol next-generation (IPv6) (RIPng)\n"
	"Super Happy Advanced Routing Protocol (SHARP)\n"
	"Statically configured routes\n"
	"Metric for redistributed routes\n"
	"Default metric\n"
	"Route map reference\n"
	"Pointer to route-map entries\n")
{
	return bgp_cli_redistribute_apply(vty, no, proto, NULL, metric_str, rmap);
}

DEFPY_YANG(
	instance_afi_safis_redistribute_instance, instance_afi_safis_redistribute_instance_cli_cmd,
	"[no] redistribute <ospf|table|table-direct>$proto (1-65535)$instance \
	[{metric (0-4294967295)$metric|route-map RMAP_NAME$rmap}]",
	NO_STR
	"Redistribute information from another routing protocol\n"
	"Open Shortest Path First (OSPFv2)\n"
	"Non-main Kernel Routing Table\n"
	"Non-main Kernel Routing Table - Direct\n"
	"Instance ID/Table ID\n"
	"Metric for redistributed routes\n"
	"Default metric\n"
	"Route map reference\n"
	"Pointer to route-map entries\n")
{
	return bgp_cli_redistribute_apply(vty, no, proto, instance_str, metric_str, rmap);
}

/* One 'redistribute PROTO [INSTANCE] [metric M] [route-map NAME]' line per
 * list entry, matching bgp_config_write_redistribute()'s field order
 * (bgp_vty.c, retired for these two AFs in M5 batch B11). Shared by both
 * ipv4-unicast and ipv6-unicast -- af-redistribute models identical leaves
 * for both. */
void afi_safis_redistribute_cli_write(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	uint16_t instance = yang_dnode_get_uint16(dnode, "instance");

	vty_out(vty, "  redistribute %s", yang_dnode_get_string(dnode, "protocol"));

	if (instance)
		vty_out(vty, " %u", instance);

	if (yang_dnode_exists(dnode, "metric"))
		vty_out(vty, " metric %u", yang_dnode_get_uint32(dnode, "metric"));

	if (yang_dnode_exists(dnode, "route-map"))
		vty_out(vty, " route-map %s", yang_dnode_get_string(dnode, "route-map"));

	vty_out(vty, "\n");
}

/*
 * M5 batch B12: instance-AF 'maximum-paths (1-N)' / 'maximum-paths ibgp
 * (1-N) [equal-cluster-length]' (af-route-selection/maximum-paths in
 * proteus-bgp.yang), across all eight instance AFs that 'uses'
 * af-route-selection. The container's three leaves (ebgp, ibgp,
 * ibgp-equal-cluster-length) are independent, but legacy only ever exposed
 * 'equal-cluster-length' as a suffix of 'maximum-paths ibgp N' -- so the
 * positive ibgp form always issues a concrete MODIFY of both 'ibgp' and
 * 'ibgp-equal-cluster-length' together (the "always rewrite from scratch"
 * idiom B6/B8 established), and the bare 'no maximum-paths ibgp' form
 * DESTROYs 'ibgp' while resetting 'ibgp-equal-cluster-length' back to its
 * false default in the same call, matching
 * bgp_maximum_paths_unset()'s own same_clusterlen=false reset
 * (bgp_mpath.c). The grammar's own range is the full uint16 span
 * (1-65535), not legacy's compile-time CMD_RANGE_STR(1, MULTIPATH_NUM) --
 * DEFPY_YANG's grammar string is parsed by a tool that does not run the C
 * preprocessor, so a macro-built range string is not an option here, and
 * the YANG leaf itself is deliberately unbounded ("modeled ... without a
 * tighter range on purpose"). The real, run-time-configurable bound
 * against 'multipath_num' is enforced uniformly for every northbound
 * client (CLI included) by the apply side's NB_EV_VALIDATE
 * (bgp_nb_af_maximum_paths_validate(), bgpd/proteus/bgp_nb_util.c).
 */
DEFPY_YANG(
	instance_afi_safis_maximum_paths, instance_afi_safis_maximum_paths_cli_cmd,
	"[no] maximum-paths (1-65535)$mpaths",
	NO_STR
	"Forward packets over multiple paths\n"
	"Number of paths\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/maximum-paths/ebgp", VTY_CURR_XPATH,
			   container);
	nb_cli_enqueue_change(vty, xpath, no ? NB_OP_DESTROY : NB_OP_MODIFY, mpaths_str);
	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, xpath);

	return ret;
}

DEFPY_YANG(
	instance_afi_safis_no_maximum_paths, instance_afi_safis_no_maximum_paths_cli_cmd,
	"no maximum-paths",
	NO_STR
	"Forward packets over multiple paths\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/maximum-paths/ebgp", VTY_CURR_XPATH,
			   container);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, xpath);

	return ret;
}

DEFPY_YANG(
	instance_afi_safis_maximum_paths_ibgp, instance_afi_safis_maximum_paths_ibgp_cli_cmd,
	"[no] maximum-paths ibgp (1-65535)$mpaths [equal-cluster-length$cluster]",
	NO_STR
	"Forward packets over multiple paths\n"
	"iBGP-multipath\n"
	"Number of paths\n"
	"Match the cluster length\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath_base, *xpath_child;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath_base = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/maximum-paths", VTY_CURR_XPATH,
				container);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/ibgp", xpath_base);
	nb_cli_enqueue_change(vty, xpath_child, no ? NB_OP_DESTROY : NB_OP_MODIFY, mpaths_str);
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/ibgp-equal-cluster-length", xpath_base);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, (no || !cluster) ? "false" : "true");
	XFREE(MTYPE_TMP, xpath_child);

	XFREE(MTYPE_TMP, xpath_base);
	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	instance_afi_safis_no_maximum_paths_ibgp, instance_afi_safis_no_maximum_paths_ibgp_cli_cmd,
	"no maximum-paths ibgp",
	NO_STR
	"Forward packets over multiple paths\n"
	"iBGP-multipath\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath_base, *xpath_child;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath_base = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/maximum-paths", VTY_CURR_XPATH,
				container);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/ibgp", xpath_base);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/ibgp-equal-cluster-length", xpath_base);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "false");
	XFREE(MTYPE_TMP, xpath_child);

	XFREE(MTYPE_TMP, xpath_base);
	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

/* Registered on the container xpath: bgp_config_write_maxpaths()'s own
 * two-line rendering (bgp_vty.c, retired for these eight AFs in M5 batch
 * B12), one line per leaf that is set. */
void afi_safis_maximum_paths_cli_write(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults)
{
	if (yang_dnode_exists(dnode, "ebgp"))
		vty_out(vty, "  maximum-paths %u\n", yang_dnode_get_uint16(dnode, "ebgp"));

	if (yang_dnode_exists(dnode, "ibgp")) {
		vty_out(vty, "  maximum-paths ibgp %u", yang_dnode_get_uint16(dnode, "ibgp"));
		if (yang_dnode_exists(dnode, "ibgp-equal-cluster-length") &&
		    yang_dnode_get_bool(dnode, "ibgp-equal-cluster-length"))
			vty_out(vty, " equal-cluster-length");
		vty_out(vty, "\n");
	}
}

/*
 * M5 batch B12: instance-AF 'table-map WORD' (af-route-selection/table-map
 * leaf), across the same eight instance AFs. A plain string leaf (policy
 * name, per the established plain-string rule -- never a leafref).
 */
DEFPY_YANG(
	instance_afi_safis_table_map, instance_afi_safis_table_map_cli_cmd,
	"[no] table-map WORD$rmap",
	NO_STR
	"BGP table to RIB route download filter\n"
	"Name of the route map\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/table-map", VTY_CURR_XPATH, container);
	nb_cli_enqueue_change(vty, xpath, no ? NB_OP_DESTROY : NB_OP_MODIFY, rmap);
	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, xpath);

	return ret;
}

void afi_safis_table_map_cli_write(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults)
{
	vty_out(vty, "  table-map %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * M7 batch B1: instance-AF VPN leaking, simple knobs (af-vpn-leaking's
 * export-vpn/import-vpn/import-vrf/import-vrf-route-map leaves), at
 * ipv4-unicast/ipv6-unicast. Mirrors the legacy bgp_imexport_vpn /
 * bgp_imexport_vrf / af_import_vrf_route_map DEFPYs (bgp_vty.c), installed on
 * BGP_IPV4_NODE/BGP_IPV6_NODE. The 'import vrf route-map NAME' keyword form
 * shares its 'import vrf ...' prefix with the 'import vrf VIEWVRFNAME'
 * leaf-list command; CLI keyword-token matching resolves the two.
 */
DEFPY_YANG(
	instance_afi_safis_imexport_vpn, instance_afi_safis_imexport_vpn_cli_cmd,
	"[no] <import|export>$direction vpn",
	NO_STR
	"Import routes to this address-family\n"
	"Export routes from this address-family\n"
	"to/from default instance VPN RIB\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/%s-vpn", VTY_CURR_XPATH, container, direction);
	nb_cli_enqueue_change(vty, xpath, no ? NB_OP_DESTROY : NB_OP_MODIFY, "true");
	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, xpath);

	return ret;
}

DEFPY_YANG(
	instance_afi_safis_import_vrf, instance_afi_safis_import_vrf_cli_cmd,
	"[no] import vrf VIEWVRFNAME$import_name",
	NO_STR
	"Import routes from another VRF\n"
	"VRF to import from\n"
	"The name of the VRF\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/import-vrf[.='%s']", VTY_CURR_XPATH,
			   container, import_name);
	nb_cli_enqueue_change(vty, xpath, no ? NB_OP_DESTROY : NB_OP_CREATE, NULL);
	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, xpath);

	return ret;
}

DEFPY_YANG(
	instance_afi_safis_import_vrf_route_map, instance_afi_safis_import_vrf_route_map_cli_cmd,
	"import vrf route-map RMAP$rmap",
	"Import routes from another VRF\n"
	"Vrf routes being filtered\n"
	"Specify route map\n"
	"name of route-map\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/import-vrf-route-map", VTY_CURR_XPATH,
			   container);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, rmap);
	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, xpath);

	return ret;
}

DEFPY_YANG(
	instance_afi_safis_no_import_vrf_route_map,
	instance_afi_safis_no_import_vrf_route_map_cli_cmd,
	"no import vrf route-map [RMAP]",
	NO_STR
	"Import routes from another VRF\n"
	"Vrf routes being filtered\n"
	"Specify route map\n"
	"name of route-map\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/import-vrf-route-map", VTY_CURR_XPATH,
			   container);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, xpath);

	return ret;
}

/* Positive-only default-false booleans: emit the line only when set (mirrors
 * the master writer's SAFI_UNICAST tail, retired for these AFs in M7 B1). */
void afi_safis_export_vpn_cli_write(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "  export vpn\n");
}

void afi_safis_import_vpn_cli_write(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "  import vpn\n");
}

/* Registered on the import-vrf leaf-list: one line per configured VRF. */
void afi_safis_import_vrf_cli_write(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults)
{
	vty_out(vty, "  import vrf %s\n", yang_dnode_get_string(dnode, NULL));
}

/* Renders bgp_vpn_policy_config_write_afi()'s 'import vrf route-map' line
 * (retired for these AFs in M7 B1). */
void afi_safis_import_vrf_route_map_cli_write(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults)
{
	vty_out(vty, "  import vrf route-map %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * M7 batch B2: instance-AF VPN leaking, detailed vpn-policy block
 * (af-vpn-leaking's 'vpn' container), ipv4-unicast/ipv6-unicast, installed on
 * BGP_IPV4_NODE/BGP_IPV6_NODE like B1. Mirrors the legacy
 * af_route_map_vpn_imexport / af_label_vpn_export{, _allocation_mode} /
 * af_rd_vpn_export / af_nexthop_vpn_export / af_rt_vpn_imexport DEFPYs
 * (bgp_vty.c). 'rd vpn export' reuses bgp_cli_soo_parse() exactly like the
 * per-VNI/per-VRF 'rd' commands above (same ASN:NN_OR_IP-ADDRESS:NN token
 * grammar and as2/as4/ipv4 case split as str2prefix_rd()); 'rt vpn
 * <import|export|both>' reuses the same helper plus
 * bgp_cli_ead_es_rt_case_name() to route each RTLIST token to its keyed list
 * entry -- unlike bgp_cli_evpn_rt_list() (EVPN VRF/VNI route-target), there
 * is no wildcard grammar here (af_rt_vpn_imexport_cmd never supported '*'),
 * so token parsing is the plain soo_parse case only. Tokens are parsed to
 * completion before the first enqueue, same "no partial enqueue without an
 * apply" discipline as bgp_cli_evpn_rt_list().
 */
DEFPY_YANG(
	instance_afi_safis_vpn_route_map, instance_afi_safis_vpn_route_map_cli_cmd,
	"route-map vpn <import$direction|export$direction> RMAP$rmap",
	"Specify route map\n"
	"Between current address-family and vpn\n"
	"For routes leaked from vpn to current address-family\n"
	"For routes leaked from current address-family to vpn\n"
	"name of route-map\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/vpn/route-map-%s", VTY_CURR_XPATH, container,
			   direction);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, rmap);
	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, xpath);

	return ret;
}

DEFPY_YANG(
	no_instance_afi_safis_vpn_route_map, no_instance_afi_safis_vpn_route_map_cli_cmd,
	"no route-map vpn <import$direction|export$direction> [RMAP]",
	NO_STR
	"Specify route map\n"
	"Between current address-family and vpn\n"
	"For routes leaked from vpn to current address-family\n"
	"For routes leaked from current address-family to vpn\n"
	"name of route-map\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/vpn/route-map-%s", VTY_CURR_XPATH, container,
			   direction);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, xpath);

	return ret;
}

void afi_safis_vpn_route_map_import_cli_write(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults)
{
	vty_out(vty, "  route-map vpn import %s\n", yang_dnode_get_string(dnode, NULL));
}

void afi_safis_vpn_route_map_export_cli_write(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults)
{
	vty_out(vty, "  route-map vpn export %s\n", yang_dnode_get_string(dnode, NULL));
}

DEFPY_YANG(
	instance_afi_safis_vpn_label_export, instance_afi_safis_vpn_label_export_cli_cmd,
	"label vpn export <(0-1048575)$label_val|auto$label_auto>",
	"label value for VRF\n"
	"Between current address-family and vpn\n"
	"For routes leaked from current address-family to vpn\n"
	"Label Value <0-1048575>\n"
	"Automatically assign a label\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath;
	int ret;
	/* Declared at function scope, not inside the branch below:
	 * nb_cli_enqueue_change() stores the passed value pointer as-is
	 * (does not copy it), so the buffer must stay alive until
	 * nb_cli_apply_changes() actually consumes the queued change --
	 * a buffer scoped to the 'else' block was a stack-use-after-scope
	 * (caught by ASan: mgmtd aborted parsing 'label vpn export N'). */
	char label_buf[16];

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (label_auto) {
		xpath = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/vpn/label-export/auto",
				   VTY_CURR_XPATH, container);
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, "true");
	} else {
		snprintf(label_buf, sizeof(label_buf), "%lld", (long long)label_val);
		xpath = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/vpn/label-export/value",
				   VTY_CURR_XPATH, container);
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, label_buf);
	}
	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, xpath);

	return ret;
}

DEFPY_YANG(
	no_instance_afi_safis_vpn_label_export, no_instance_afi_safis_vpn_label_export_cli_cmd,
	"no label vpn export [<(0-1048575)|auto>]",
	NO_STR
	"label value for VRF\n"
	"Between current address-family and vpn\n"
	"For routes leaked from current address-family to vpn\n"
	"Label Value <0-1048575>\n"
	"Automatically assign a label\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/vpn/label-export", VTY_CURR_XPATH, container);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, xpath);

	return ret;
}

void afi_safis_vpn_label_export_value_cli_write(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults)
{
	vty_out(vty, "  label vpn export %s\n", yang_dnode_get_string(dnode, NULL));
}

void afi_safis_vpn_label_export_auto_cli_write(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "  label vpn export auto\n");
}

DEFPY_YANG(
	instance_afi_safis_vpn_label_export_allocation_mode,
	instance_afi_safis_vpn_label_export_allocation_mode_cli_cmd,
	"label vpn export allocation-mode <per-vrf$per_vrf|per-nexthop$per_nexthop>",
	"label value for VRF\n"
	"Between current address-family and vpn\n"
	"For routes leaked from current address-family to vpn\n"
	"Label allocation mode\n"
	"Allocate one label for all BGP updates of the VRF\n"
	"Allocate a label per connected next-hop in the VRF\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/vpn/label-export/allocation-mode",
			   VTY_CURR_XPATH, container);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, per_vrf ? "per-vrf" : "per-nexthop");
	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, xpath);

	return ret;
}

DEFPY_YANG(
	no_instance_afi_safis_vpn_label_export_allocation_mode,
	no_instance_afi_safis_vpn_label_export_allocation_mode_cli_cmd,
	"no label vpn export allocation-mode [<per-vrf|per-nexthop>]",
	NO_STR
	"label value for VRF\n"
	"Between current address-family and vpn\n"
	"For routes leaked from current address-family to vpn\n"
	"Label allocation mode\n"
	"Allocate one label for all BGP updates of the VRF\n"
	"Allocate a label per connected next-hop in the VRF\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/vpn/label-export/allocation-mode",
			   VTY_CURR_XPATH, container);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, xpath);

	return ret;
}

void afi_safis_vpn_label_export_allocation_mode_cli_write(struct vty *vty,
							   const struct lyd_node *dnode,
							   bool show_defaults)
{
	if (strmatch(yang_dnode_get_string(dnode, NULL), "per-nexthop"))
		vty_out(vty, "  label vpn export allocation-mode per-nexthop\n");
}

DEFPY_YANG(
	instance_afi_safis_vpn_rd_export, instance_afi_safis_vpn_rd_export_cli_cmd,
	"rd vpn export ASN:NN_OR_IP-ADDRESS:NN$rd",
	"Specify route distinguisher\n"
	"Between current address-family and vpn\n"
	"For routes leaked from current address-family to vpn\n"
	"Route Distinguisher (<as-number>:<number> | <ip-address>:<number>)\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	enum bgp_cli_soo_case rd_case;
	char administrator[INET_ADDRSTRLEN], assigned_number[12];
	char *xpath;
	const char *case_name;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (!bgp_cli_soo_parse(rd, &rd_case, administrator, sizeof(administrator),
			       assigned_number, sizeof(assigned_number))) {
		vty_out(vty, "%% Malformed rd\n");
		return CMD_WARNING;
	}

	switch (rd_case) {
	case BGP_CLI_SOO_AS2:
		case_name = "as2";
		break;
	case BGP_CLI_SOO_AS4:
		case_name = "as4";
		break;
	case BGP_CLI_SOO_IPV4:
	default:
		case_name = "ipv4";
		break;
	}

	xpath = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/vpn/rd-export/%s/administrator",
			   VTY_CURR_XPATH, container, case_name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, administrator);
	XFREE(MTYPE_TMP, xpath);

	xpath = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/vpn/rd-export/%s/assigned-number",
			   VTY_CURR_XPATH, container, case_name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, assigned_number);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	no_instance_afi_safis_vpn_rd_export, no_instance_afi_safis_vpn_rd_export_cli_cmd,
	"no rd vpn export [ASN:NN_OR_IP-ADDRESS:NN]",
	NO_STR
	"Specify route distinguisher\n"
	"Between current address-family and vpn\n"
	"For routes leaked from current address-family to vpn\n"
	"Route Distinguisher (<as-number>:<number> | <ip-address>:<number>)\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/vpn/rd-export", VTY_CURR_XPATH, container);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, xpath);

	return ret;
}

void afi_safis_vpn_rd_export_cli_write(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults)
{
	const struct lyd_node *rd = yang_dnode_get_parent(dnode, "rd-export");
	const char *case_name;

	if (yang_dnode_exists(rd, "as2"))
		case_name = "as2";
	else if (yang_dnode_exists(rd, "as4"))
		case_name = "as4";
	else if (yang_dnode_exists(rd, "ipv4"))
		case_name = "ipv4";
	else
		return;

	vty_out(vty, "  rd vpn export %s:%s\n", yang_dnode_get_string(rd, "%s/administrator", case_name),
		yang_dnode_get_string(rd, "%s/assigned-number", case_name));
}

DEFPY_YANG(
	instance_afi_safis_vpn_nexthop_export, instance_afi_safis_vpn_nexthop_export_cli_cmd,
	"nexthop vpn export <A.B.C.D|X:X::X:X>$nexthop",
	"Specify next hop to use for VRF advertised prefixes\n"
	"Between current address-family and vpn\n"
	"For routes leaked from current address-family to vpn\n"
	"IPv4 prefix\n"
	"IPv6 prefix\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/vpn/nexthop-export", VTY_CURR_XPATH,
			   container);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, nexthop_str);
	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, xpath);

	return ret;
}

DEFPY_YANG(
	no_instance_afi_safis_vpn_nexthop_export, no_instance_afi_safis_vpn_nexthop_export_cli_cmd,
	"no nexthop vpn export [<A.B.C.D|X:X::X:X>]",
	NO_STR
	"Specify next hop to use for VRF advertised prefixes\n"
	"Between current address-family and vpn\n"
	"For routes leaked from current address-family to vpn\n"
	"IPv4 prefix\n"
	"IPv6 prefix\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/vpn/nexthop-export", VTY_CURR_XPATH,
			   container);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, xpath);

	return ret;
}

void afi_safis_vpn_nexthop_export_cli_write(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults)
{
	vty_out(vty, "  nexthop vpn export %s\n", yang_dnode_get_string(dnode, NULL));
}

/* One parsed RTLIST token: the xpath fragment below 'vpn/rt-import' or
 * 'vpn/rt-export' it maps to. No wildcard support -- af_rt_vpn_imexport_cmd
 * never had one. */
struct bgp_cli_vpn_rt_token {
	char suffix[96];
};

static bool bgp_cli_vpn_rt_token_parse(struct vty *vty, const char *token,
				       struct bgp_cli_vpn_rt_token *parsed)
{
	enum bgp_cli_soo_case rt_case;
	char global_admin[INET_ADDRSTRLEN], local_admin[12];

	if (!bgp_cli_soo_parse(token, &rt_case, global_admin, sizeof(global_admin), local_admin,
			       sizeof(local_admin))) {
		vty_out(vty, "%% Malformed Route Target: %s\n", token);
		return false;
	}

	snprintf(parsed->suffix, sizeof(parsed->suffix), "/%s[global-admin='%s'][local-admin='%s']",
		 bgp_cli_ead_es_rt_case_name(rt_case), global_admin, local_admin);
	return true;
}

/* af_rt_vpn_imexport_cmd's positive form unconditionally REPLACES the whole
 * rtlist[dir] ecommunity on every invocation (bgp_vty.c: ecommunity_free()
 * the old set, then ecommunity_dup() the freshly parsed one) -- it is not
 * additive, unlike a plain YANG list create. Reproduce that here at the CLI
 * layer: DESTROY the whole rt-import/rt-export container for each targeted
 * direction first, then CREATE an entry for every RTLIST token, all in one
 * transaction (mirrors the destroy-then-recreate idiom the codebase already
 * uses for 'no ... [value]' forms elsewhere). The negative form -- like the
 * legacy ALIAS 'no <rt|route-target> vpn <import|export|both>' -- has no
 * RTLIST of its own; it just clears the container(s), so it does not go
 * through this helper at all. */
static int bgp_cli_vpn_rt_list(struct vty *vty, const char *base_prefix, bool import, bool export,
			       struct cmd_token **rt_argv, int n_rts)
{
	struct bgp_cli_vpn_rt_token *parsed;
	char xpath[XPATH_MAXLEN];

	parsed = XCALLOC(MTYPE_TMP, n_rts * sizeof(*parsed));

	for (int i = 0; i < n_rts; i++) {
		if (!bgp_cli_vpn_rt_token_parse(vty, rt_argv[i]->arg, &parsed[i])) {
			XFREE(MTYPE_TMP, parsed);
			return CMD_WARNING;
		}
	}

	if (import) {
		snprintf(xpath, sizeof(xpath), "%s/rt-import", base_prefix);
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	}
	if (export) {
		snprintf(xpath, sizeof(xpath), "%s/rt-export", base_prefix);
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	}

	for (int i = 0; i < n_rts; i++) {
		if (import) {
			snprintf(xpath, sizeof(xpath), "%s/rt-import%s", base_prefix,
				 parsed[i].suffix);
			nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		}
		if (export) {
			snprintf(xpath, sizeof(xpath), "%s/rt-export%s", base_prefix,
				 parsed[i].suffix);
			nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		}
	}

	XFREE(MTYPE_TMP, parsed);

	return nb_cli_apply_changes(vty, NULL);
}

/* Shared body of both negative rt-vpn forms (bare and with-RTLIST, see the
 * doc comment on no_instance_afi_safis_vpn_rt_list_cli_cmd below): just
 * destroy the targeted container(s) wholesale. */
static int bgp_cli_vpn_rt_clear(struct vty *vty, bool import, bool export)
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *base_prefix;
	char xpath[XPATH_MAXLEN];
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	base_prefix = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/vpn", VTY_CURR_XPATH, container);
	if (import) {
		snprintf(xpath, sizeof(xpath), "%s/rt-import", base_prefix);
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	}
	if (export) {
		snprintf(xpath, sizeof(xpath), "%s/rt-export", base_prefix);
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	}
	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, base_prefix);

	return ret;
}

DEFPY_YANG(
	instance_afi_safis_vpn_rt, instance_afi_safis_vpn_rt_cli_cmd,
	"rt vpn <import$import|export$export|both$both> RTLIST...",
	"Specify route target list\n"
	"Between current address-family and vpn\n"
	"For routes leaked from vpn to current address-family: match any\n"
	"For routes leaked from current address-family to vpn: set\n"
	"both import: match any and export: set\n"
	"Space separated route target list (A.B.C.D:MN|EF:OPQR|GHJK:MN)\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *base_prefix;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	base_prefix = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/vpn", VTY_CURR_XPATH, container);
	/* argv[0]='rt', argv[1]='vpn', argv[2]=direction keyword -- RTLIST
	 * starts at argv[3] (one more prefix token than
	 * bgp_cli_evpn_rt_list()'s 'route-target <dir> RTLIST...' callers,
	 * which skip only 2). */
	ret = bgp_cli_vpn_rt_list(vty, base_prefix, import || both, export || both, argv + 3,
				  argc - 3);
	XFREE(MTYPE_TMP, base_prefix);

	return ret;
}

DEFPY_YANG(
	no_instance_afi_safis_vpn_rt, no_instance_afi_safis_vpn_rt_cli_cmd,
	"no rt vpn <import$import|export$export|both$both>",
	NO_STR
	"Specify route target list\n"
	"Between current address-family and vpn\n"
	"For routes leaked from vpn to current address-family\n"
	"For routes leaked from current address-family to vpn\n"
	"both import and export\n")
{
	return bgp_cli_vpn_rt_clear(vty, import || both, export || both);
}

/* af_rt_vpn_imexport_cmd's negative form is reachable two ways in legacy:
 * the bare ALIAS above ('no rt vpn <dir>', no RTLIST) and the main DEFPY's
 * own '[no] ... RTLIST...' with 'no' set -- which the topotests actually use
 * ('no rt vpn import 192.0.2.2:300'). Either way the given RTLIST is
 * IGNORED for the negative form (bgp_vty.c's dir loop unconditionally frees
 * rtlist[dir] to NULL when !yes, never consulting the parsed tokens), so
 * this second command shares bgp_cli_vpn_rt_clear() and only exists to
 * accept-and-discard the trailing tokens for grammar compatibility. */
DEFPY_YANG(
	no_instance_afi_safis_vpn_rt_list, no_instance_afi_safis_vpn_rt_list_cli_cmd,
	"no rt vpn <import$import|export$export|both$both> RTLIST...",
	NO_STR
	"Specify route target list\n"
	"Between current address-family and vpn\n"
	"For routes leaked from vpn to current address-family\n"
	"For routes leaked from current address-family to vpn\n"
	"both import and export\n"
	"Space separated route target list (A.B.C.D:MN|EF:OPQR|GHJK:MN)\n")
{
	return bgp_cli_vpn_rt_clear(vty, import || both, export || both);
}

/* Registered per keyed-list entry (as2/as4/ipv4), like the ead-es-route-target
 * cli_show functions above: one 'rt vpn <import|export> RT' line per entry
 * rather than legacy's single space-separated line. Loadable either way --
 * FRR parses repeated single-RT lines and one multi-RT line to the same
 * final set. */
void afi_safis_vpn_rt_import_as2_cli_write(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	vty_out(vty, "  rt vpn import %u:%u\n", yang_dnode_get_uint16(dnode, "global-admin"),
		yang_dnode_get_uint32(dnode, "local-admin"));
}

void afi_safis_vpn_rt_import_as4_cli_write(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	vty_out(vty, "  rt vpn import %u:%u\n", yang_dnode_get_uint32(dnode, "global-admin"),
		yang_dnode_get_uint16(dnode, "local-admin"));
}

void afi_safis_vpn_rt_import_ipv4_cli_write(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults)
{
	vty_out(vty, "  rt vpn import %s:%u\n", yang_dnode_get_string(dnode, "global-admin"),
		yang_dnode_get_uint16(dnode, "local-admin"));
}

void afi_safis_vpn_rt_export_as2_cli_write(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	vty_out(vty, "  rt vpn export %u:%u\n", yang_dnode_get_uint16(dnode, "global-admin"),
		yang_dnode_get_uint32(dnode, "local-admin"));
}

void afi_safis_vpn_rt_export_as4_cli_write(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	vty_out(vty, "  rt vpn export %u:%u\n", yang_dnode_get_uint32(dnode, "global-admin"),
		yang_dnode_get_uint16(dnode, "local-admin"));
}

void afi_safis_vpn_rt_export_ipv4_cli_write(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults)
{
	vty_out(vty, "  rt vpn export %s:%u\n", yang_dnode_get_string(dnode, "global-admin"),
		yang_dnode_get_uint16(dnode, "local-admin"));
}

/*
 * M7 batch B3: MPLS-VPN static 'network' statements (af-network-vpn-ipv4/
 * -ipv6 in proteus-bgp.yang), ipv4-vpn/ipv6-vpn only. Legacy is
 * vpnv4_network/vpnv4_network_route_map/no_vpnv4_network and
 * vpnv6_network/no_vpnv6_network (bgp_mplsvpn.c); the RD-encoding case
 * split (as2/ipv4/as4) reuses bgp_cli_soo_parse() exactly like B2's 'rd vpn
 * export' above, and 'raw' has no legacy parser for an arbitrary RD string
 * (same reasoning as B2's rd-export/raw) so is not reachable from the CLI.
 * One combined [no] grammar collapses vpnv4_network[_route_map]/
 * no_vpnv4_network into a single CREATE (list entry + label + optional
 * route-map, always issued together) or DESTROY, the same idiom B9
 * established for 'network'; label is YANG-mandatory but not part of the
 * key, so it is always enqueued alongside the CREATE. The ipv6 form
 * mirrors legacy's single vpnv6_network DEFUN (route-map already optional
 * there).
 */
DEFPY_YANG(
	instance_afi_safis_vpn_network, instance_afi_safis_vpn_network_cli_cmd,
	"[no] network A.B.C.D/M$prefix rd ASN:NN_OR_IP-ADDRESS:NN$rd <tag|label> (0-1048575)$label \
	[route-map RMAP_NAME$map_name]",
	NO_STR
	"Specify a network to announce via BGP\n"
	"IPv4 prefix\n"
	"Specify Route Distinguisher\n"
	"VPN Route Distinguisher\n"
	"VPN NLRI label (tag)\n"
	"VPN NLRI label (tag)\n"
	"Label value\n"
	"Route-map to modify the attributes\n"
	"Name of the route map\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	enum bgp_cli_soo_case rd_case;
	char administrator[INET_ADDRSTRLEN], assigned_number[12];
	const char *case_name;
	char *xpath, *xpath_child;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (!bgp_cli_soo_parse(rd, &rd_case, administrator, sizeof(administrator),
			       assigned_number, sizeof(assigned_number))) {
		vty_out(vty, "%% Malformed rd\n");
		return CMD_WARNING;
	}

	switch (rd_case) {
	case BGP_CLI_SOO_AS2:
		case_name = "as2";
		break;
	case BGP_CLI_SOO_AS4:
		case_name = "as4";
		break;
	case BGP_CLI_SOO_IPV4:
	default:
		case_name = "ipv4";
		break;
	}

	xpath = asprintfrr(MTYPE_TMP,
			   "%s/afi-safis/%s/network/%s[prefix='%s'][administrator='%s'][assigned-number='%s']",
			   VTY_CURR_XPATH, container, case_name, prefix_str, administrator,
			   assigned_number);

	if (no) {
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	} else {
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/label", xpath);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, label_str);
		XFREE(MTYPE_TMP, xpath_child);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/route-map", xpath);
		nb_cli_enqueue_change(vty, xpath_child, map_name ? NB_OP_MODIFY : NB_OP_DESTROY,
				      map_name);
		XFREE(MTYPE_TMP, xpath_child);
	}

	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, xpath);
	return ret;
}

DEFPY_YANG(
	instance_afi_safis_vpn_network_ipv6, instance_afi_safis_vpn_network_ipv6_cli_cmd,
	"[no] network X:X::X:X/M$prefix rd ASN:NN_OR_IP-ADDRESS:NN$rd <tag|label> (0-1048575)$label \
	[route-map RMAP_NAME$map_name]",
	NO_STR
	"Specify a network to announce via BGP\n"
	"IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
	"Specify Route Distinguisher\n"
	"VPN Route Distinguisher\n"
	"VPN NLRI label (tag)\n"
	"VPN NLRI label (tag)\n"
	"Label value\n"
	"Route-map to modify the attributes\n"
	"Name of the route map\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	enum bgp_cli_soo_case rd_case;
	char administrator[INET_ADDRSTRLEN], assigned_number[12];
	const char *case_name;
	char *xpath, *xpath_child;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (!bgp_cli_soo_parse(rd, &rd_case, administrator, sizeof(administrator),
			       assigned_number, sizeof(assigned_number))) {
		vty_out(vty, "%% Malformed rd\n");
		return CMD_WARNING;
	}

	switch (rd_case) {
	case BGP_CLI_SOO_AS2:
		case_name = "as2";
		break;
	case BGP_CLI_SOO_AS4:
		case_name = "as4";
		break;
	case BGP_CLI_SOO_IPV4:
	default:
		case_name = "ipv4";
		break;
	}

	xpath = asprintfrr(MTYPE_TMP,
			   "%s/afi-safis/%s/network/%s[prefix='%s'][administrator='%s'][assigned-number='%s']",
			   VTY_CURR_XPATH, container, case_name, prefix_str, administrator,
			   assigned_number);

	if (no) {
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	} else {
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/label", xpath);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, label_str);
		XFREE(MTYPE_TMP, xpath_child);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/route-map", xpath);
		nb_cli_enqueue_change(vty, xpath_child, map_name ? NB_OP_MODIFY : NB_OP_DESTROY,
				      map_name);
		XFREE(MTYPE_TMP, xpath_child);
	}

	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, xpath);
	return ret;
}

/* One 'network PFX rd ADMIN:ASSIGNED label N [route-map NAME]' line per
 * list entry, matching bgp_config_write_network_vpn()'s field order
 * (bgp_route.c, retired for ipv4-vpn/ipv6-vpn in M7 batch B3). Shared
 * across both AFs (dnode-driven, no AF distinction needed), like B2's
 * rt-import/rt-export writers above. */
void afi_safis_vpn_network_as2_cli_write(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	vty_out(vty, "  network %s rd %u:%u label %u", yang_dnode_get_string(dnode, "prefix"),
		yang_dnode_get_uint16(dnode, "administrator"),
		yang_dnode_get_uint32(dnode, "assigned-number"),
		yang_dnode_get_uint32(dnode, "label"));
	if (yang_dnode_exists(dnode, "route-map"))
		vty_out(vty, " route-map %s", yang_dnode_get_string(dnode, "route-map"));
	vty_out(vty, "\n");
}

void afi_safis_vpn_network_as4_cli_write(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	vty_out(vty, "  network %s rd %u:%u label %u", yang_dnode_get_string(dnode, "prefix"),
		yang_dnode_get_uint32(dnode, "administrator"),
		yang_dnode_get_uint16(dnode, "assigned-number"),
		yang_dnode_get_uint32(dnode, "label"));
	if (yang_dnode_exists(dnode, "route-map"))
		vty_out(vty, " route-map %s", yang_dnode_get_string(dnode, "route-map"));
	vty_out(vty, "\n");
}

void afi_safis_vpn_network_ipv4_cli_write(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	vty_out(vty, "  network %s rd %s:%u label %u", yang_dnode_get_string(dnode, "prefix"),
		yang_dnode_get_string(dnode, "administrator"),
		yang_dnode_get_uint16(dnode, "assigned-number"),
		yang_dnode_get_uint32(dnode, "label"));
	if (yang_dnode_exists(dnode, "route-map"))
		vty_out(vty, " route-map %s", yang_dnode_get_string(dnode, "route-map"));
	vty_out(vty, "\n");
}

/* M7: '[no] bgp retain route-target all' (af-retain-route-target in
 * proteus-bgp.yang), ipv4-vpn/ipv6-vpn only. Static default-on boolean,
 * fast-external-failover shape at the AF level: the positive form destroys
 * back to the true default, 'no' modifies an explicit false, and only the
 * 'no' form is ever rendered (retired bgp_retain_route_target /
 * bgp_vpn_config_write, bgp_vty.c). */
DEFPY_YANG(
	instance_afi_safis_retain_route_target,
	instance_afi_safis_retain_route_target_cli_cmd,
	"[no] bgp retain route-target all",
	NO_STR
	BGP_STR
	"Retain BGP updates\n"
	"Retain BGP updates based on route-target values\n"
	"Retain all BGP updates\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/retain-route-target-all", VTY_CURR_XPATH,
			   container);
	nb_cli_enqueue_change(vty, xpath, no ? NB_OP_MODIFY : NB_OP_DESTROY, no ? "false" : NULL);
	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, xpath);

	return ret;
}

void afi_safis_retain_route_target_all_cli_write(struct vty *vty, const struct lyd_node *dnode,
						 bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "  no bgp retain route-target all\n");
}

/*
 * M5 batch B12: instance-AF 'bgp dampening [(1-45) [(1-20000) (1-50000)
 * (1-255)]]' (af-route-selection/dampening in proteus-bgp.yang), across the
 * same eight instance AFs. Same container shape (and the same
 * all-or-nothing 'must' on the four number leaves) as B8's per-neighbor
 * dampening; this reuses that batch's CLI idiom verbatim, at the instance
 * base xpath instead of a peer/group xpath, and with the suppress-threshold
 * range legacy's own instance-level bgp_damp_set_cmd used ((1-50000), vs
 * the per-neighbor variant's (1-20000)). The positive form always issues a
 * concrete MODIFY of 'enabled' plus all four number leaves -- reproducing
 * legacy's own default-filling ('bgp dampening' bare ->
 * DEFAULT_HALF_LIFE/_REUSE/_SUPPRESS/half*4; 'bgp dampening H' -> given
 * half-life, defaults for the rest, both computed here exactly as legacy's
 * own DEFUN body did) -- never a partial update. The negative form destroys
 * the whole container in one shot.
 */
DEFPY_YANG(
	instance_afi_safis_dampening, instance_afi_safis_dampening_cli_cmd,
	"[no] bgp dampening [(1-45)$half [(1-20000)$reuse (1-50000)$suppress (1-255)$max]]",
	NO_STR
	"BGP Specific commands\n"
	"Enable route-flap dampening\n"
	"Half-life time for the penalty\n"
	"Value to start reusing a route\n"
	"Value to start suppressing a route\n"
	"Maximum duration to suppress a stable route\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath_base, *xpath_child;
	char half_buf[24], reuse_buf[24], suppress_buf[24], max_buf[24];
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath_base = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/dampening", VTY_CURR_XPATH, container);

	if (no) {
		nb_cli_enqueue_change(vty, xpath_base, NB_OP_DESTROY, NULL);
		XFREE(MTYPE_TMP, xpath_base);
		return nb_cli_apply_changes(vty, NULL);
	}

	if (!half)
		half = DEFAULT_HALF_LIFE;
	if (!reuse) {
		reuse = DEFAULT_REUSE;
		suppress = DEFAULT_SUPPRESS;
		max = half * 4;
	}
	if (suppress < reuse) {
		vty_out(vty, "%% Suppress value cannot be less than reuse value\n");
		XFREE(MTYPE_TMP, xpath_base);
		return CMD_WARNING_CONFIG_FAILED;
	}

	snprintf(half_buf, sizeof(half_buf), "%lld", (long long)half);
	snprintf(reuse_buf, sizeof(reuse_buf), "%lld", (long long)reuse);
	snprintf(suppress_buf, sizeof(suppress_buf), "%lld", (long long)suppress);
	snprintf(max_buf, sizeof(max_buf), "%lld", (long long)max);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/enabled", xpath_base);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "true");
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/half-life", xpath_base);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, half_buf);
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/reuse-threshold", xpath_base);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, reuse_buf);
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/suppress-threshold", xpath_base);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, suppress_buf);
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/max-suppress-time", xpath_base);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, max_buf);
	XFREE(MTYPE_TMP, xpath_child);

	XFREE(MTYPE_TMP, xpath_base);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

/* Registered on the container xpath, reproducing bgp_config_write_damp()'s
 * three-way rendering: bare 'bgp dampening' when every number matches the
 * legacy defaults, 'bgp dampening <half>' when only half-life differs, else
 * the full four-number form. */
void afi_safis_dampening_cli_write(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults)
{
	int64_t half, reuse, suppress, max;

	if (!yang_dnode_exists(dnode, "enabled") || !yang_dnode_get_bool(dnode, "enabled"))
		return;

	half = yang_dnode_exists(dnode, "half-life") ? yang_dnode_get_uint8(dnode, "half-life")
						     : DEFAULT_HALF_LIFE;
	reuse = yang_dnode_exists(dnode, "reuse-threshold")
			? yang_dnode_get_uint16(dnode, "reuse-threshold")
			: DEFAULT_REUSE;
	suppress = yang_dnode_exists(dnode, "suppress-threshold")
			   ? yang_dnode_get_uint16(dnode, "suppress-threshold")
			   : DEFAULT_SUPPRESS;
	max = yang_dnode_exists(dnode, "max-suppress-time")
			  ? yang_dnode_get_uint8(dnode, "max-suppress-time")
			  : half * 4;

	if (half == DEFAULT_HALF_LIFE && reuse == DEFAULT_REUSE && suppress == DEFAULT_SUPPRESS &&
	    max == half * 4)
		vty_out(vty, "  bgp dampening\n");
	else if (reuse == DEFAULT_REUSE && suppress == DEFAULT_SUPPRESS && max == half * 4)
		vty_out(vty, "  bgp dampening %" PRId64 "\n", half);
	else
		vty_out(vty, "  bgp dampening %" PRId64 " %" PRId64 " %" PRId64 " %" PRId64 "\n",
			half, reuse, suppress, max);
}

/*
 * M5 batch B13: instance-AF 'distance bgp (1-255) (1-255) (1-255)'
 * (af-distance-ipv4/-ipv6's distance/{ebgp,ibgp,local} in proteus-bgp.yang),
 * across all eight instance AFs that 'uses' af-distance. The container's
 * 'must' enforces "all three together or none", so the positive form always
 * MODIFYs ebgp/ibgp/local together and the negative form always DESTROYs all
 * three (the 'no' form's optional values, kept for legacy grammar parity,
 * are ignored -- a keyed container has no per-value delete). afi/safi are
 * derived from the enclosing AF node via bgp_afi_safi_container_name().
 */
DEFPY_YANG(
	instance_afi_safis_distance_bgp, instance_afi_safis_distance_bgp_cli_cmd,
	"distance bgp (1-255)$ebgp (1-255)$ibgp (1-255)$local",
	"Define an administrative distance\n"
	"BGP distance\n"
	"Distance for routes external to the AS\n"
	"Distance for routes internal to the AS\n"
	"Distance for local routes\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath_base, *xpath_child;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath_base = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/distance", VTY_CURR_XPATH, container);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/ebgp", xpath_base);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, ebgp_str);
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/ibgp", xpath_base);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, ibgp_str);
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/local", xpath_base);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, local_str);
	XFREE(MTYPE_TMP, xpath_child);

	XFREE(MTYPE_TMP, xpath_base);
	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	instance_afi_safis_no_distance_bgp, instance_afi_safis_no_distance_bgp_cli_cmd,
	"no distance bgp [(1-255) (1-255) (1-255)]",
	NO_STR
	"Define an administrative distance\n"
	"BGP distance\n"
	"Distance for routes external to the AS\n"
	"Distance for routes internal to the AS\n"
	"Distance for local routes\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath_base, *xpath_child;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath_base = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/distance", VTY_CURR_XPATH, container);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/ebgp", xpath_base);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/ibgp", xpath_base);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/local", xpath_base);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);

	XFREE(MTYPE_TMP, xpath_base);
	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

/* Registered on the 'distance' container xpath: bgp_config_write_distance()'s
 * admin-triple line (retired for these eight AFs in M5 batch B13). Emitted
 * only when the stored triple differs from the compiled-in defaults, exactly
 * as the legacy emitter suppressed the all-default case. */
void afi_safis_distance_cli_write(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults)
{
	uint8_t ebgp, ibgp, local;

	if (!yang_dnode_exists(dnode, "ebgp"))
		return;

	ebgp = yang_dnode_get_uint8(dnode, "ebgp");
	ibgp = yang_dnode_get_uint8(dnode, "ibgp");
	local = yang_dnode_get_uint8(dnode, "local");

	if (ebgp != ZEBRA_EBGP_DISTANCE_DEFAULT || ibgp != ZEBRA_IBGP_DISTANCE_DEFAULT ||
	    local != ZEBRA_IBGP_DISTANCE_DEFAULT)
		vty_out(vty, "  distance bgp %u %u %u\n", ebgp, ibgp, local);
}

/*
 * M5 batch B13: instance-AF per-prefix 'distance (1-255) PREFIX
 * [ACCESSLIST_NAME]' (af-distance-*'s distance/prefix list), a keyed list
 * (key 'prefix') with a mandatory 'distance' and an optional 'access-list'
 * name (a policy-attachment name: plain string, never a leafref). Two DEFPYs
 * -- IPv4 and IPv6 -- mirror legacy's two grammars; each collapses to one
 * CREATE on the list entry plus a MODIFY of 'distance' and a MODIFY/DESTROY
 * of 'access-list' (the B9 keyed-list idiom). The 'no' form's typed distance,
 * kept for legacy grammar parity, is ignored -- the entry is keyed by prefix
 * alone.
 */
DEFPY_YANG(
	instance_afi_safis_distance_source, instance_afi_safis_distance_source_cli_cmd,
	"[no] distance (1-255)$distance A.B.C.D/M$prefix [WORD$acl]",
	NO_STR
	"Define an administrative distance\n"
	"Administrative distance\n"
	"IP source prefix\n"
	"Access list name\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath, *xpath_child;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/distance/prefix[prefix='%s']",
			   VTY_CURR_XPATH, container, prefix_str);

	if (no) {
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	} else {
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/distance", xpath);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, distance_str);
		XFREE(MTYPE_TMP, xpath_child);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/access-list", xpath);
		nb_cli_enqueue_change(vty, xpath_child, acl ? NB_OP_MODIFY : NB_OP_DESTROY, acl);
		XFREE(MTYPE_TMP, xpath_child);
	}

	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, xpath);

	return ret;
}

DEFPY_YANG(
	instance_afi_safis_distance_source_ipv6, instance_afi_safis_distance_source_ipv6_cli_cmd,
	"[no] distance (1-255)$distance X:X::X:X/M$prefix [WORD$acl]",
	NO_STR
	"Define an administrative distance\n"
	"Administrative distance\n"
	"IP source prefix\n"
	"Access list name\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath, *xpath_child;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/distance/prefix[prefix='%s']",
			   VTY_CURR_XPATH, container, prefix_str);

	if (no) {
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	} else {
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/distance", xpath);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, distance_str);
		XFREE(MTYPE_TMP, xpath_child);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/access-list", xpath);
		nb_cli_enqueue_change(vty, xpath_child, acl ? NB_OP_MODIFY : NB_OP_DESTROY, acl);
		XFREE(MTYPE_TMP, xpath_child);
	}

	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, xpath);

	return ret;
}

/* Registered on the 'distance/prefix' list xpath, one line per entry in
 * bgp_config_write_distance()'s field order (distance, prefix, access-list);
 * the trailing '%s' is the access-list name or empty, byte-for-byte matching
 * the legacy '  distance %d %pBD %s\n' rendering (empty leaves a trailing
 * space). */
void afi_safis_distance_prefix_cli_write(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	vty_out(vty, "  distance %u %s %s\n", yang_dnode_get_uint8(dnode, "distance"),
		yang_dnode_get_string(dnode, "prefix"),
		yang_dnode_exists(dnode, "access-list")
			? yang_dnode_get_string(dnode, "access-list")
			: "");
}

/*
 * M5 batch B14: instance-AF 'nexthop prefer-global' (proteus-bgp.yang's
 * ipv6-unicast/nexthop-prefer-global leaf), the ipv6-unicast container
 * only -- the leaf is 'type boolean;' with no 'default' statement (legacy's
 * own compile-time default, DFLT_BGP_IPV6_NEXTHOP_PREFER_GLOBAL,
 * bgp_vty.c, is currently false but is not a YANG default), so this is a
 * no-default leaf: modify on the positive form, destroy on 'no' (rather
 * than an explicit modify-to-false), matching the hard rule for
 * no-default leaves and mirroring instance_ipv6_auto_ra_modify/_destroy's
 * shape (bgp_nb_instance.c). Legacy's DEFUN (bgp_af_nexthop_prefer_global,
 * bgp_vty.c) is also installed on BGP_IPV6M_NODE/BGP_IPV6L_NODE, which
 * proteus-bgp.yang does not model under this leaf (only ipv6-unicast) --
 * those two nodes are left native, only the BGP_IPV6_NODE install is
 * retired here.
 */
DEFPY_YANG(
	instance_afi_safis_ipv6_unicast_nexthop_prefer_global,
	instance_afi_safis_ipv6_unicast_nexthop_prefer_global_cli_cmd,
	"[no] nexthop prefer-global",
	NO_STR
	"Nexthop\n"
	"Prefer global over link-local if both exist\n")
{
	nb_cli_enqueue_change(vty, "./afi-safis/ipv6-unicast/nexthop-prefer-global",
			      no ? NB_OP_DESTROY : NB_OP_MODIFY, no ? NULL : "true");
	return nb_cli_apply_changes(vty, NULL);
}

/* Registered on the leaf's own xpath; reproduces
 * bgp_config_write_ipv6_nexthop_prefer_global()'s '  [no ]nexthop
 * prefer-global\n' line. mgmtd only calls cli_show when the leaf is
 * present (i.e. explicitly configured), matching legacy's own
 * SAVE_BGP_IPV6_NEXTHOP_PREFER_GLOBAL "only render if non-default"
 * guard. */
void afi_safis_ipv6_unicast_nexthop_prefer_global_cli_write(struct vty *vty,
							     const struct lyd_node *dnode,
							     bool show_defaults)
{
	vty_out(vty, "  %snexthop prefer-global\n", yang_dnode_get_bool(dnode, NULL) ? "" : "no ");
}

void bgp_cli_instance_init(void)
{
	install_node(&bgp_node);
	install_default(BGP_NODE);

	install_element(CONFIG_NODE, &router_bgp_cli_cmd);
	install_element(CONFIG_NODE, &no_router_bgp_cli_cmd);

	/* M5 B0: address-family node entry/exit (mgmtd side). Register the AF
	 * sub-nodes and their default exit/quit/end commands (install_element
	 * needs a compile-time-constant node, so exit-address-family is
	 * installed with literal nodes below). */
	for (size_t i = 0; i < array_size(bgp_af_cmd_nodes); i++) {
		install_node(&bgp_af_cmd_nodes[i]);
		install_default(bgp_af_cmd_nodes[i].node);
	}
	install_element(BGP_NODE, &address_family_ipv4_safi_cli_cmd);
	install_element(BGP_NODE, &address_family_ipv6_safi_cli_cmd);
#ifdef KEEP_OLD_VPN_COMMANDS
	install_element(BGP_NODE, &address_family_vpnv4_cli_cmd);
	install_element(BGP_NODE, &address_family_vpnv6_cli_cmd);
#endif /* KEEP_OLD_VPN_COMMANDS */
	install_element(BGP_NODE, &address_family_evpn_cli_cmd);
	install_element(BGP_NODE, &address_family_link_state_cli_cmd);

	install_node(&bgp_srv6_cmd_node);
	install_default(BGP_SRV6_NODE);
	install_element(BGP_NODE, &bgp_segment_routing_srv6_cli_cmd);
	install_element(BGP_NODE, &no_bgp_segment_routing_srv6_cli_cmd);
	install_element(BGP_SRV6_NODE, &bgp_srv6_locator_cli_cmd);
	install_element(BGP_SRV6_NODE, &no_bgp_srv6_locator_cli_cmd);
	install_element(BGP_SRV6_NODE, &bgp_srv6_only_cli_cmd);
	install_element(BGP_SRV6_NODE, &bgp_srv6_encap_behavior_cli_cmd);
	install_element(BGP_NODE, &bgp_sid_vpn_export_cli_cmd);
	install_element(BGP_NODE, &no_bgp_sid_vpn_export_cli_cmd);
	install_element(BGP_IPV4_NODE, &af_sid_vpn_export_cli_cmd);
	install_element(BGP_IPV6_NODE, &af_sid_vpn_export_cli_cmd);
	install_element(BGP_IPV4_NODE, &sid_export_cli_cmd);
	install_element(BGP_IPV6_NODE, &sid_export_cli_cmd);
	install_element(BGP_FLOWSPECV4_NODE, &bgp_fs_local_install_cli_cmd);
	install_element(BGP_FLOWSPECV6_NODE, &bgp_fs_local_install_cli_cmd);
	install_element(BGP_IPV4_NODE, &af_routetarget_import_cli_cmd);
	install_element(BGP_IPV6_NODE, &af_routetarget_import_cli_cmd);

	install_element(BGP_IPV4_NODE, &exit_address_family_cli_cmd);
	install_element(BGP_IPV4M_NODE, &exit_address_family_cli_cmd);
	install_element(BGP_IPV4L_NODE, &exit_address_family_cli_cmd);
	install_element(BGP_VPNV4_NODE, &exit_address_family_cli_cmd);
	install_element(BGP_IPV6_NODE, &exit_address_family_cli_cmd);
	install_element(BGP_IPV6M_NODE, &exit_address_family_cli_cmd);
	install_element(BGP_IPV6L_NODE, &exit_address_family_cli_cmd);
	install_element(BGP_VPNV6_NODE, &exit_address_family_cli_cmd);
	install_element(BGP_EVPN_NODE, &exit_address_family_cli_cmd);
	install_element(BGP_FLOWSPECV4_NODE, &exit_address_family_cli_cmd);
	install_element(BGP_FLOWSPECV6_NODE, &exit_address_family_cli_cmd);
	install_element(BGP_IPV4U_NODE, &exit_address_family_cli_cmd);
	install_element(BGP_IPV6U_NODE, &exit_address_family_cli_cmd);
	install_element(BGP_LS_NODE, &exit_address_family_cli_cmd);

	/* M6 B1: 'vni N' ... 'exit-vni' sub-node (mgmtd side). */
	install_node(&bgp_evpn_vni_node);
	install_default(BGP_EVPN_VNI_NODE);
	install_element(BGP_EVPN_NODE, &bgp_evpn_vni_cli_cmd);
	install_element(BGP_EVPN_NODE, &no_bgp_evpn_vni_cli_cmd);
	install_element(BGP_EVPN_VNI_NODE, &exit_vni_cli_cmd);

	/* M6 B6: per-VNI 'rd'/'flooding'/'advertise-default-gw'/
	 * 'advertise-svi-ip'/'advertise-subnet' (mgmtd side). */
	install_element(BGP_EVPN_VNI_NODE, &bgp_evpn_vni_rd_cli_cmd);
	install_element(BGP_EVPN_VNI_NODE, &no_bgp_evpn_vni_rd_cli_cmd);
	install_element(BGP_EVPN_VNI_NODE, &bgp_evpn_flood_control_vni_cli_cmd);
	install_element(BGP_EVPN_VNI_NODE, &bgp_evpn_advertise_default_gw_vni_cli_cmd);
	install_element(BGP_EVPN_VNI_NODE, &no_bgp_evpn_advertise_default_gw_vni_cli_cmd);
	install_element(BGP_EVPN_VNI_NODE, &bgp_evpn_advertise_svi_ip_vni_cli_cmd);
	install_element(BGP_EVPN_VNI_NODE, &bgp_evpn_advertise_vni_subnet_cli_cmd);
	install_element(BGP_EVPN_VNI_NODE, &no_bgp_evpn_advertise_vni_subnet_cli_cmd);

	/* M6 B7: instance-level (per-VRF-instance role) 'rd'/'default-originate'
	 * (mgmtd side); 'advertise ipv4/ipv6 unicast' stays native -- see the
	 * reject-stub doc comment above its retired-in-name-only DEFPYs. */
	install_element(BGP_EVPN_NODE, &bgp_evpn_vrf_rd_cli_cmd);
	install_element(BGP_EVPN_NODE, &no_bgp_evpn_vrf_rd_cli_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_default_originate_cli_cmd);

	/* M6 B2: instance-level l2vpn-evpn advertise-flag leaves (mgmtd side). */
	install_element(BGP_EVPN_NODE, &bgp_evpn_advertise_all_vni_cli_cmd);
	install_element(BGP_EVPN_NODE, &no_bgp_evpn_advertise_all_vni_cli_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_advertise_default_gw_cli_cmd);
	install_element(BGP_EVPN_NODE, &no_bgp_evpn_advertise_default_gw_cli_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_advertise_svi_ip_cli_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_enable_resolve_overlay_index_cli_cmd);

	/* M6 B3: instance-level l2vpn-evpn mac-vrf-soo + flooding leaves
	 * (mgmtd side). */
	install_element(BGP_EVPN_NODE, &bgp_evpn_macvrf_soo_cli_cmd);
	install_element(BGP_EVPN_NODE, &no_bgp_evpn_macvrf_soo_cli_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_flood_control_cli_cmd);

	/* M6 B4: instance-level l2vpn-evpn dup-addr-detection max-moves/time/
	 * freeze leaves (mgmtd side); the bare enable/disable toggle stays
	 * native (bgp_evpn_vty.c). */
	install_element(BGP_EVPN_NODE, &bgp_evpn_dup_addr_detection_cli_cmd);
	install_element(BGP_EVPN_NODE, &no_bgp_evpn_dup_addr_detection_cli_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_dup_addr_detection_freeze_cli_cmd);
	install_element(BGP_EVPN_NODE, &no_bgp_evpn_dup_addr_detection_freeze_cli_cmd);

	/* M6 B5: instance-level l2vpn-evpn multihoming ead-es-frag-evi-limit
	 * + ead-es-route-target-export leaves (mgmtd side). */
	install_element(BGP_EVPN_NODE, &bgp_evpn_ead_es_frag_evi_limit_cli_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_ead_es_rt_cli_cmd);
	install_element(BGP_EVPN_NODE, &no_bgp_evpn_ead_es_rt_cli_cmd);

	/* M6 B9b: VRF-level and per-VNI route-target/auto-route-target
	 * (incl. the deprecated aliases), advertise <afi> unicast,
	 * advertise-pip, the bare dup-addr-detection toggle, the Tier A
	 * multihoming toggles and the EVPN type-5 'network' statement
	 * (mgmtd side). */
	install_element(BGP_EVPN_NODE, &bgp_evpn_vrf_rt_cli_cmd);
	install_element(BGP_EVPN_NODE, &no_bgp_evpn_vrf_rt_cli_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_vrf_auto_rt_cli_cmd);
	install_element(BGP_EVPN_NODE, &no_bgp_evpn_vrf_auto_rt_cli_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_vrf_rt_auto_cli_cmd);
	install_element(BGP_EVPN_NODE, &no_bgp_evpn_vrf_rt_auto_cli_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_advertise_autort_rfc8365_cli_cmd);
	install_element(BGP_EVPN_NODE, &no_bgp_evpn_advertise_autort_rfc8365_cli_cmd);
	install_element(BGP_EVPN_VNI_NODE, &bgp_evpn_vni_rt_cli_cmd);
	install_element(BGP_EVPN_VNI_NODE, &no_bgp_evpn_vni_rt_cli_cmd);
	install_element(BGP_EVPN_VNI_NODE, &no_bgp_evpn_vni_rt_without_val_cli_cmd);
	install_element(BGP_EVPN_VNI_NODE, &bgp_evpn_vni_auto_rt_cli_cmd);
	install_element(BGP_EVPN_VNI_NODE, &no_bgp_evpn_vni_auto_rt_cli_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_advertise_type5_cli_cmd);
	install_element(BGP_EVPN_NODE, &no_bgp_evpn_advertise_type5_cli_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_advertise_pip_ip_mac_cli_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_dup_addr_detection_enable_cli_cmd);
	install_element(BGP_EVPN_NODE, &no_bgp_evpn_dup_addr_detection_enable_cli_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_use_es_l3nhg_cli_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_ead_evi_rx_disable_cli_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_ead_evi_tx_disable_cli_cmd);
	install_element(BGP_EVPN_NODE, &evpnrt5_network_cli_cmd);
	install_element(BGP_EVPN_NODE, &no_evpnrt5_network_cli_cmd);

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
	install_element(BGP_NODE, &bgp_graceful_restart_restart_time_cli_cmd);
	install_element(BGP_NODE, &no_bgp_graceful_restart_restart_time_cli_cmd);
	install_element(BGP_NODE, &bgp_graceful_restart_stalepath_time_cli_cmd);
	install_element(BGP_NODE, &no_bgp_graceful_restart_stalepath_time_cli_cmd);
	install_element(BGP_NODE, &bgp_graceful_restart_select_defer_time_cli_cmd);
	install_element(BGP_NODE, &no_bgp_graceful_restart_select_defer_time_cli_cmd);
	install_element(BGP_NODE, &bgp_graceful_restart_rib_stale_time_cli_cmd);
	install_element(BGP_NODE, &no_bgp_graceful_restart_rib_stale_time_cli_cmd);
	install_element(BGP_NODE, &bgp_graceful_restart_disable_eor_cli_cmd);
	install_element(BGP_NODE, &no_bgp_graceful_restart_disable_eor_cli_cmd);

	install_element(BGP_NODE, &bgp_instance_shutdown_cli_cmd);
	install_element(BGP_NODE, &bgp_instance_shutdown_message_cli_cmd);
	install_element(BGP_NODE, &no_bgp_instance_shutdown_cli_cmd);
	install_element(BGP_NODE, &no_bgp_instance_shutdown_message_cli_cmd);
	install_element(BGP_NODE, &bgp_allow_martian_cli_cmd);
	install_element(BGP_NODE, &bgp_use_underlays_nexthop_weight_cli_cmd);
	install_element(BGP_NODE, &bgp_fast_convergence_cli_cmd);

	install_element(BGP_NODE, &bgp_wpkt_quanta_cli_cmd);
	install_element(BGP_NODE, &bgp_rpkt_quanta_cli_cmd);
	install_element(BGP_NODE, &bgp_coalesce_time_cli_cmd);
	install_element(BGP_NODE, &no_bgp_coalesce_time_cli_cmd);
	install_element(BGP_NODE, &bgp_timers_cli_cmd);
	install_element(BGP_NODE, &no_bgp_timers_cli_cmd);
	install_element(BGP_NODE, &bgp_minimum_holdtime_cli_cmd);
	install_element(BGP_NODE, &no_bgp_minimum_holdtime_cli_cmd);
	install_element(BGP_NODE, &bgp_listen_limit_cli_cmd);
	install_element(BGP_NODE, &no_bgp_listen_limit_cli_cmd);
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
	install_element(BGP_NODE, &bgp_default_shutdown_cli_cmd);

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
	/* Also at BGP_NODE for backwards compat, matching the legacy install:
	 * without it, vtysh's config-file node walkup matches the CONFIG_NODE
	 * entry mid-block and strands the parser outside router bgp, dropping
	 * every following line. */
	install_element(BGP_NODE, &bgp_route_map_delay_timer_cli_cmd);
	install_element(BGP_NODE, &no_bgp_route_map_delay_timer_cli_cmd);
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
	install_element(CONFIG_NODE, &no_bgp_process_ipv6_auto_ra_cli_cmd);

	/* M5 B9: instance-AF 'network' (ipv4/ipv6 x
	 * unicast/multicast/labeled-unicast). */
	install_element(BGP_IPV4_NODE, &instance_afi_safis_network_cli_cmd);
	install_element(BGP_IPV4M_NODE, &instance_afi_safis_network_cli_cmd);
	install_element(BGP_IPV4L_NODE, &instance_afi_safis_network_cli_cmd);
	install_element(BGP_IPV6_NODE, &instance_afi_safis_network_ipv6_cli_cmd);
	install_element(BGP_IPV6M_NODE, &instance_afi_safis_network_ipv6_cli_cmd);
	install_element(BGP_IPV6L_NODE, &instance_afi_safis_network_ipv6_cli_cmd);

	/* M5 B10: instance-AF 'aggregate-address' (ipv4/ipv6 x
	 * unicast/multicast/labeled-unicast). */
	install_element(BGP_IPV4_NODE, &instance_afi_safis_aggregate_address_cli_cmd);
	install_element(BGP_IPV4M_NODE, &instance_afi_safis_aggregate_address_cli_cmd);
	install_element(BGP_IPV4L_NODE, &instance_afi_safis_aggregate_address_cli_cmd);
	install_element(BGP_IPV6_NODE, &instance_afi_safis_aggregate_address_ipv6_cli_cmd);
	install_element(BGP_IPV6M_NODE, &instance_afi_safis_aggregate_address_ipv6_cli_cmd);
	install_element(BGP_IPV6L_NODE, &instance_afi_safis_aggregate_address_ipv6_cli_cmd);

	/* M5 B11: instance-AF 'redistribute' (ipv4-unicast/ipv6-unicast only
	 * -- af-redistribute is unicast-only). */
	install_element(BGP_IPV4_NODE, &instance_afi_safis_redistribute_cli_cmd);
	install_element(BGP_IPV4_NODE, &instance_afi_safis_redistribute_instance_cli_cmd);
	install_element(BGP_IPV6_NODE, &instance_afi_safis_redistribute_cli_cmd);
	install_element(BGP_IPV6_NODE, &instance_afi_safis_redistribute_instance_cli_cmd);

	/* M5 B12: instance-AF 'maximum-paths'/'table-map'/'bgp dampening',
	 * all eight instance AFs that 'uses' af-route-selection (ipv4/ipv6 x
	 * unicast/multicast/labeled-unicast/vpn -- l2vpn-evpn does not use
	 * the grouping and is deliberately excluded). */
	install_element(BGP_IPV4_NODE, &instance_afi_safis_maximum_paths_cli_cmd);
	install_element(BGP_IPV4_NODE, &instance_afi_safis_no_maximum_paths_cli_cmd);
	install_element(BGP_IPV4_NODE, &instance_afi_safis_maximum_paths_ibgp_cli_cmd);
	install_element(BGP_IPV4_NODE, &instance_afi_safis_no_maximum_paths_ibgp_cli_cmd);
	install_element(BGP_IPV4_NODE, &instance_afi_safis_table_map_cli_cmd);
	install_element(BGP_IPV4_NODE, &instance_afi_safis_dampening_cli_cmd);

	install_element(BGP_IPV4M_NODE, &instance_afi_safis_maximum_paths_cli_cmd);
	install_element(BGP_IPV4M_NODE, &instance_afi_safis_no_maximum_paths_cli_cmd);
	install_element(BGP_IPV4M_NODE, &instance_afi_safis_maximum_paths_ibgp_cli_cmd);
	install_element(BGP_IPV4M_NODE, &instance_afi_safis_no_maximum_paths_ibgp_cli_cmd);
	install_element(BGP_IPV4M_NODE, &instance_afi_safis_table_map_cli_cmd);
	install_element(BGP_IPV4M_NODE, &instance_afi_safis_dampening_cli_cmd);

	install_element(BGP_IPV4L_NODE, &instance_afi_safis_maximum_paths_cli_cmd);
	install_element(BGP_IPV4L_NODE, &instance_afi_safis_no_maximum_paths_cli_cmd);
	install_element(BGP_IPV4L_NODE, &instance_afi_safis_maximum_paths_ibgp_cli_cmd);
	install_element(BGP_IPV4L_NODE, &instance_afi_safis_no_maximum_paths_ibgp_cli_cmd);
	install_element(BGP_IPV4L_NODE, &instance_afi_safis_table_map_cli_cmd);
	install_element(BGP_IPV4L_NODE, &instance_afi_safis_dampening_cli_cmd);

	install_element(BGP_VPNV4_NODE, &instance_afi_safis_maximum_paths_cli_cmd);
	install_element(BGP_VPNV4_NODE, &instance_afi_safis_no_maximum_paths_cli_cmd);
	install_element(BGP_VPNV4_NODE, &instance_afi_safis_maximum_paths_ibgp_cli_cmd);
	install_element(BGP_VPNV4_NODE, &instance_afi_safis_no_maximum_paths_ibgp_cli_cmd);
	install_element(BGP_VPNV4_NODE, &instance_afi_safis_table_map_cli_cmd);
	install_element(BGP_VPNV4_NODE, &instance_afi_safis_dampening_cli_cmd);
	install_element(BGP_VPNV4_NODE, &instance_afi_safis_vpn_network_cli_cmd);
	install_element(BGP_VPNV4_NODE, &instance_afi_safis_retain_route_target_cli_cmd);

	install_element(BGP_IPV6_NODE, &instance_afi_safis_maximum_paths_cli_cmd);
	install_element(BGP_IPV6_NODE, &instance_afi_safis_no_maximum_paths_cli_cmd);
	install_element(BGP_IPV6_NODE, &instance_afi_safis_maximum_paths_ibgp_cli_cmd);
	install_element(BGP_IPV6_NODE, &instance_afi_safis_no_maximum_paths_ibgp_cli_cmd);
	install_element(BGP_IPV6_NODE, &instance_afi_safis_table_map_cli_cmd);
	install_element(BGP_IPV6_NODE, &instance_afi_safis_dampening_cli_cmd);

	install_element(BGP_IPV6M_NODE, &instance_afi_safis_maximum_paths_cli_cmd);
	install_element(BGP_IPV6M_NODE, &instance_afi_safis_no_maximum_paths_cli_cmd);
	install_element(BGP_IPV6M_NODE, &instance_afi_safis_maximum_paths_ibgp_cli_cmd);
	install_element(BGP_IPV6M_NODE, &instance_afi_safis_no_maximum_paths_ibgp_cli_cmd);
	install_element(BGP_IPV6M_NODE, &instance_afi_safis_table_map_cli_cmd);
	install_element(BGP_IPV6M_NODE, &instance_afi_safis_dampening_cli_cmd);

	install_element(BGP_IPV6L_NODE, &instance_afi_safis_maximum_paths_cli_cmd);
	install_element(BGP_IPV6L_NODE, &instance_afi_safis_no_maximum_paths_cli_cmd);
	install_element(BGP_IPV6L_NODE, &instance_afi_safis_maximum_paths_ibgp_cli_cmd);
	install_element(BGP_IPV6L_NODE, &instance_afi_safis_no_maximum_paths_ibgp_cli_cmd);
	install_element(BGP_IPV6L_NODE, &instance_afi_safis_table_map_cli_cmd);
	install_element(BGP_IPV6L_NODE, &instance_afi_safis_dampening_cli_cmd);

	install_element(BGP_VPNV6_NODE, &instance_afi_safis_maximum_paths_cli_cmd);
	install_element(BGP_VPNV6_NODE, &instance_afi_safis_no_maximum_paths_cli_cmd);
	install_element(BGP_VPNV6_NODE, &instance_afi_safis_maximum_paths_ibgp_cli_cmd);
	install_element(BGP_VPNV6_NODE, &instance_afi_safis_no_maximum_paths_ibgp_cli_cmd);
	install_element(BGP_VPNV6_NODE, &instance_afi_safis_table_map_cli_cmd);
	install_element(BGP_VPNV6_NODE, &instance_afi_safis_dampening_cli_cmd);
	install_element(BGP_VPNV6_NODE, &instance_afi_safis_vpn_network_ipv6_cli_cmd);
	install_element(BGP_VPNV6_NODE, &instance_afi_safis_retain_route_target_cli_cmd);

	/* M5 B13: instance-AF 'distance bgp ...' (all eight AFs) + per-prefix
	 * 'distance (1-255) PREFIX [ACCESSLIST]' (IPv4 grammar on the four IPv4
	 * AFs, IPv6 grammar on the four IPv6 AFs), all eight instance AFs that
	 * 'uses' af-distance (ipv4/ipv6 x unicast/multicast/labeled-unicast/vpn
	 * -- l2vpn-evpn does not use the grouping and is excluded). */
	install_element(BGP_IPV4_NODE, &instance_afi_safis_distance_bgp_cli_cmd);
	install_element(BGP_IPV4_NODE, &instance_afi_safis_no_distance_bgp_cli_cmd);
	install_element(BGP_IPV4_NODE, &instance_afi_safis_distance_source_cli_cmd);

	install_element(BGP_IPV4M_NODE, &instance_afi_safis_distance_bgp_cli_cmd);
	install_element(BGP_IPV4M_NODE, &instance_afi_safis_no_distance_bgp_cli_cmd);
	install_element(BGP_IPV4M_NODE, &instance_afi_safis_distance_source_cli_cmd);

	install_element(BGP_IPV4L_NODE, &instance_afi_safis_distance_bgp_cli_cmd);
	install_element(BGP_IPV4L_NODE, &instance_afi_safis_no_distance_bgp_cli_cmd);
	install_element(BGP_IPV4L_NODE, &instance_afi_safis_distance_source_cli_cmd);

	install_element(BGP_VPNV4_NODE, &instance_afi_safis_distance_bgp_cli_cmd);
	install_element(BGP_VPNV4_NODE, &instance_afi_safis_no_distance_bgp_cli_cmd);
	install_element(BGP_VPNV4_NODE, &instance_afi_safis_distance_source_cli_cmd);

	install_element(BGP_IPV6_NODE, &instance_afi_safis_distance_bgp_cli_cmd);
	install_element(BGP_IPV6_NODE, &instance_afi_safis_no_distance_bgp_cli_cmd);
	install_element(BGP_IPV6_NODE, &instance_afi_safis_distance_source_ipv6_cli_cmd);

	install_element(BGP_IPV6M_NODE, &instance_afi_safis_distance_bgp_cli_cmd);
	install_element(BGP_IPV6M_NODE, &instance_afi_safis_no_distance_bgp_cli_cmd);
	install_element(BGP_IPV6M_NODE, &instance_afi_safis_distance_source_ipv6_cli_cmd);

	install_element(BGP_IPV6L_NODE, &instance_afi_safis_distance_bgp_cli_cmd);
	install_element(BGP_IPV6L_NODE, &instance_afi_safis_no_distance_bgp_cli_cmd);
	install_element(BGP_IPV6L_NODE, &instance_afi_safis_distance_source_ipv6_cli_cmd);

	install_element(BGP_VPNV6_NODE, &instance_afi_safis_distance_bgp_cli_cmd);
	install_element(BGP_VPNV6_NODE, &instance_afi_safis_no_distance_bgp_cli_cmd);
	install_element(BGP_VPNV6_NODE, &instance_afi_safis_distance_source_ipv6_cli_cmd);

	/* M5 B14: 'nexthop prefer-global', ipv6-unicast only (see the DEFPY
	 * above); BGP_IPV6M_NODE/BGP_IPV6L_NODE keep the legacy DEFUN
	 * installed natively, bgp_vty.c. */
	install_element(BGP_IPV6_NODE, &instance_afi_safis_ipv6_unicast_nexthop_prefer_global_cli_cmd);

	/* M7 B1: instance-AF VPN leaking simple knobs ('import|export vpn',
	 * 'import vrf NAME', 'import vrf route-map NAME'), ipv4-unicast/
	 * ipv6-unicast only (the only AFs that 'uses' af-vpn-leaking; legacy
	 * installed these on BGP_IPV4_NODE/BGP_IPV6_NODE). */
	install_element(BGP_IPV4_NODE, &instance_afi_safis_imexport_vpn_cli_cmd);
	install_element(BGP_IPV4_NODE, &instance_afi_safis_import_vrf_cli_cmd);
	install_element(BGP_IPV4_NODE, &instance_afi_safis_import_vrf_route_map_cli_cmd);
	install_element(BGP_IPV4_NODE, &instance_afi_safis_no_import_vrf_route_map_cli_cmd);

	install_element(BGP_IPV6_NODE, &instance_afi_safis_imexport_vpn_cli_cmd);
	install_element(BGP_IPV6_NODE, &instance_afi_safis_import_vrf_cli_cmd);
	install_element(BGP_IPV6_NODE, &instance_afi_safis_import_vrf_route_map_cli_cmd);
	install_element(BGP_IPV6_NODE, &instance_afi_safis_no_import_vrf_route_map_cli_cmd);

	/* M7 B2: instance-AF VPN leaking, detailed vpn-policy block
	 * ('route-map vpn', 'label vpn export [allocation-mode]', 'rd vpn
	 * export', 'nexthop vpn export', 'rt vpn'), ipv4-unicast/ipv6-unicast
	 * only (legacy installed these on BGP_IPV4_NODE/BGP_IPV6_NODE too). */
	install_element(BGP_IPV4_NODE, &instance_afi_safis_vpn_route_map_cli_cmd);
	install_element(BGP_IPV4_NODE, &no_instance_afi_safis_vpn_route_map_cli_cmd);
	install_element(BGP_IPV4_NODE, &instance_afi_safis_vpn_label_export_cli_cmd);
	install_element(BGP_IPV4_NODE, &no_instance_afi_safis_vpn_label_export_cli_cmd);
	install_element(BGP_IPV4_NODE, &instance_afi_safis_vpn_label_export_allocation_mode_cli_cmd);
	install_element(BGP_IPV4_NODE,
			&no_instance_afi_safis_vpn_label_export_allocation_mode_cli_cmd);
	install_element(BGP_IPV4_NODE, &instance_afi_safis_vpn_rd_export_cli_cmd);
	install_element(BGP_IPV4_NODE, &no_instance_afi_safis_vpn_rd_export_cli_cmd);
	install_element(BGP_IPV4_NODE, &instance_afi_safis_vpn_nexthop_export_cli_cmd);
	install_element(BGP_IPV4_NODE, &no_instance_afi_safis_vpn_nexthop_export_cli_cmd);
	install_element(BGP_IPV4_NODE, &instance_afi_safis_vpn_rt_cli_cmd);
	install_element(BGP_IPV4_NODE, &no_instance_afi_safis_vpn_rt_cli_cmd);
	install_element(BGP_IPV4_NODE, &no_instance_afi_safis_vpn_rt_list_cli_cmd);

	install_element(BGP_IPV6_NODE, &instance_afi_safis_vpn_route_map_cli_cmd);
	install_element(BGP_IPV6_NODE, &no_instance_afi_safis_vpn_route_map_cli_cmd);
	install_element(BGP_IPV6_NODE, &instance_afi_safis_vpn_label_export_cli_cmd);
	install_element(BGP_IPV6_NODE, &no_instance_afi_safis_vpn_label_export_cli_cmd);
	install_element(BGP_IPV6_NODE, &instance_afi_safis_vpn_label_export_allocation_mode_cli_cmd);
	install_element(BGP_IPV6_NODE,
			&no_instance_afi_safis_vpn_label_export_allocation_mode_cli_cmd);
	install_element(BGP_IPV6_NODE, &instance_afi_safis_vpn_rd_export_cli_cmd);
	install_element(BGP_IPV6_NODE, &no_instance_afi_safis_vpn_rd_export_cli_cmd);
	install_element(BGP_IPV6_NODE, &instance_afi_safis_vpn_nexthop_export_cli_cmd);
	install_element(BGP_IPV6_NODE, &no_instance_afi_safis_vpn_nexthop_export_cli_cmd);
	install_element(BGP_IPV6_NODE, &instance_afi_safis_vpn_rt_cli_cmd);
	install_element(BGP_IPV6_NODE, &no_instance_afi_safis_vpn_rt_cli_cmd);
	install_element(BGP_IPV6_NODE, &no_instance_afi_safis_vpn_rt_list_cli_cmd);
}
