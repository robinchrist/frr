// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Robin Christ, partimus GmbH */
/* Interface-node CLI (DEFPYs + northbound cli_show callbacks) for the
 * proteus-interface module (M7 batch B4), compiled into mgmtd alongside its
 * bgp_cli_* siblings.
 *
 * mgmtd already owns the 'interface IFNAME' node entry itself: lib's
 * northbound interface_cmd (lib/if.c, if_cmd_init() from mgmt_main.c)
 * enters INTERFACE_NODE on the frr-interface tree. The two bgpd-owned
 * 'mpls bgp ...' flags below live on the separate /proteus-interface tree,
 * so their DEFPYs read the interface name off the current frr-interface
 * candidate dnode and enqueue against an absolute proteus-interface xpath;
 * the list entry is auto-created by the first leaf set, and the 'no' forms
 * destroy the whole entry again once nothing but the cleared leaf remains,
 * so no empty 'interface NAME' blocks linger in the rendered config
 * (legacy bgpd emitted the block only when a flag was set).
 */
#include <zebra.h>
#include "command.h"
#include "northbound.h"
#include "northbound_cli.h"
#include "vty.h"
#include "memory.h"

#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_cli.h"
#include "bgpd/proteus/bgp_cli_local.h"
#include "bgpd/proteus/bgp_cli_interface_clippy.c"

/* True when nothing explicit remains on the proteus-interface list entry
 * besides its key and the leaf about to be cleared -- the entry itself can
 * then be destroyed instead of the leaf. */
static bool bgp_cli_interface_entry_disposable(const struct lyd_node *entry, const char *leaf)
{
	const struct lyd_node *child;

	LY_LIST_FOR (lyd_child(entry), child) {
		if (child->flags & LYD_DEFAULT)
			continue;
		if (!strcmp(child->schema->name, "name") || !strcmp(child->schema->name, leaf))
			continue;
		return false;
	}

	return true;
}

static int bgp_cli_interface_mpls_flag(struct vty *vty, bool no, const char *leaf)
{
	const struct lyd_node *if_dnode, *entry;
	char *xpath, *xpath_leaf;
	int ret;

	if_dnode = yang_dnode_get(vty->candidate_config->dnode, VTY_CURR_XPATH);
	if (!if_dnode) {
		vty_out(vty, "%% Failed to get iface dnode in candidate db\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = asprintfrr(MTYPE_TMP, "/proteus-interface:interface[name='%s']",
			   yang_dnode_get_string(if_dnode, "name"));
	xpath_leaf = asprintfrr(MTYPE_TMP, "%s/%s", xpath, leaf);

	if (!no) {
		nb_cli_enqueue_change(vty, xpath_leaf, NB_OP_MODIFY, "true");
	} else {
		entry = yang_dnode_get(vty->candidate_config->dnode, xpath);
		if (entry && bgp_cli_interface_entry_disposable(entry, leaf))
			nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
		else
			nb_cli_enqueue_change(vty, xpath_leaf, NB_OP_DESTROY, NULL);
	}

	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, xpath_leaf);
	XFREE(MTYPE_TMP, xpath);

	return ret;
}

DEFPY_YANG(
	mpls_bgp_forwarding, mpls_bgp_forwarding_cli_cmd,
	"[no] mpls bgp forwarding",
	NO_STR MPLS_STR BGP_STR
	"Enable MPLS forwarding for eBGP directly connected peers\n")
{
	return bgp_cli_interface_mpls_flag(vty, !!no, "mpls-bgp-forwarding");
}

DEFPY_YANG(
	mpls_bgp_l3vpn_multi_domain_switching, mpls_bgp_l3vpn_multi_domain_switching_cli_cmd,
	"[no] mpls bgp l3vpn-multi-domain-switching",
	NO_STR MPLS_STR BGP_STR
	"Bind a local MPLS label to incoming L3VPN updates\n")
{
	return bgp_cli_interface_mpls_flag(vty, !!no, "mpls-bgp-l3vpn-multi-domain-switching");
}

/* Block header/trailer, matching lib's cli_show_interface shape (the netns
 * 'interface NAME vrf VRF' form is not modeled). The entry only exists
 * while at least one explicit leaf is set (see the 'no'-form cleanup
 * above), so no empty blocks are rendered; vtysh merges this block with
 * the frr-interface block of the same name, exactly as it merged bgpd's
 * retired native config_write_interface output. */
static void proteus_interface_cli_write(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults)
{
	vty_out(vty, "!\n");
	vty_out(vty, "interface %s\n", yang_dnode_get_string(dnode, "name"));
}

static void proteus_interface_cli_write_end(struct vty *vty, const struct lyd_node *dnode)
{
	vty_out(vty, "exit\n");
}

static void proteus_interface_mpls_bgp_forwarding_cli_write(struct vty *vty,
							    const struct lyd_node *dnode,
							    bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " mpls bgp forwarding\n");
}

static void proteus_interface_mpls_bgp_l3vpn_multi_domain_switching_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " mpls bgp l3vpn-multi-domain-switching\n");
}

/* clang-format off */
const struct frr_yang_module_info proteus_interface_cli_info = {
	.name = "proteus-interface",
	.ignore_cfg_cbs = true,
	.nodes = {
		{
			.xpath = "/proteus-interface:interface",
			.cbs = {
				.cli_show = proteus_interface_cli_write,
				.cli_show_end = proteus_interface_cli_write_end,
			}
		},
		{
			.xpath = "/proteus-interface:interface/mpls-bgp-forwarding",
			.cbs = {
				.cli_show = proteus_interface_mpls_bgp_forwarding_cli_write,
			}
		},
		{
			.xpath = "/proteus-interface:interface/mpls-bgp-l3vpn-multi-domain-switching",
			.cbs = {
				.cli_show = proteus_interface_mpls_bgp_l3vpn_multi_domain_switching_cli_write,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
/* clang-format on */

void bgp_cli_interface_init(void)
{
	install_element(INTERFACE_NODE, &mpls_bgp_forwarding_cli_cmd);
	install_element(INTERFACE_NODE, &mpls_bgp_l3vpn_multi_domain_switching_cli_cmd);
}
