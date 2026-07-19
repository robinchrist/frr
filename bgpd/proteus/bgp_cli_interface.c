// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Robin Christ, partimus GmbH */
/* Interface-node CLI (DEFPYs + northbound cli_show callbacks) for bgpd's
 * two interface-level 'mpls bgp ...' flags, compiled into mgmtd alongside
 * its bgp_cli_* siblings.
 *
 * mgmtd owns the 'interface IFNAME' node itself: lib's northbound
 * interface_cmd (lib/if.c, if_cmd_init() from mgmt_main.c) enters
 * INTERFACE_NODE with VTY_CURR_XPATH on the frr-interface interface list
 * entry. Since workstream C the two flags augment that very entry
 * (proteus-bgp.yang 'augment /frr-interface:lib/interface', container
 * 'bgp'), so the DEFPYs enqueue relative xpaths exactly like zebra's
 * interface commands (zebra/zebra_cli.c multicast_new_cmd), and the 'no'
 * forms just destroy the explicit leaf, reverting it to its false
 * default. The 'interface NAME' block header/trailer is emitted by lib's
 * frr-interface cli_show; the cli_show callbacks below (registered in
 * proteus_bgp_cli_info, bgp_cli_common.c) only render the two flag lines
 * inside it, and only when true -- so nothing is rendered for interfaces
 * without the flags, matching legacy bgpd's config_write_interface.
 */
#include <zebra.h>
#include "command.h"
#include "northbound.h"
#include "northbound_cli.h"
#include "vty.h"

#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_cli.h"
#include "bgpd/proteus/bgp_cli_local.h"
#include "bgpd/proteus/bgp_cli_interface_clippy.c"

DEFPY_YANG(
	mpls_bgp_forwarding, mpls_bgp_forwarding_cli_cmd,
	"[no] mpls bgp forwarding",
	NO_STR MPLS_STR BGP_STR
	"Enable MPLS forwarding for eBGP directly connected peers\n")
{
	if (!no)
		nb_cli_enqueue_change(vty, "./proteus-bgp:bgp/mpls-bgp-forwarding", NB_OP_MODIFY,
				      "true");
	else
		nb_cli_enqueue_change(vty, "./proteus-bgp:bgp/mpls-bgp-forwarding", NB_OP_DESTROY,
				      NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	mpls_bgp_l3vpn_multi_domain_switching, mpls_bgp_l3vpn_multi_domain_switching_cli_cmd,
	"[no] mpls bgp l3vpn-multi-domain-switching",
	NO_STR MPLS_STR BGP_STR
	"Bind a local MPLS label to incoming L3VPN updates\n")
{
	if (!no)
		nb_cli_enqueue_change(vty, "./proteus-bgp:bgp/mpls-bgp-l3vpn-multi-domain-switching",
				      NB_OP_MODIFY, "true");
	else
		nb_cli_enqueue_change(vty, "./proteus-bgp:bgp/mpls-bgp-l3vpn-multi-domain-switching",
				      NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void lib_interface_bgp_mpls_bgp_forwarding_cli_write(struct vty *vty, const struct lyd_node *dnode,
						     bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " mpls bgp forwarding\n");
}

void lib_interface_bgp_mpls_bgp_l3vpn_multi_domain_switching_cli_write(struct vty *vty,
								       const struct lyd_node *dnode,
								       bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " mpls bgp l3vpn-multi-domain-switching\n");
}

void bgp_cli_interface_init(void)
{
	install_element(INTERFACE_NODE, &mpls_bgp_forwarding_cli_cmd);
	install_element(INTERFACE_NODE, &mpls_bgp_l3vpn_multi_domain_switching_cli_cmd);
}
