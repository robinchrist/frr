// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Robin Christ, partimus GmbH */
/* Neighbor and peer-group lifecycle/remote-as CLI (DEFPYs + northbound cli_show callbacks) for the proteus-bgp conversion.
 *
 * Split out of bgpd/bgp_cli.c (bgpd-yang-conversion intermezzo): pure code
 * motion for the DEFPY/cli_show bodies below. bgp_cli_init()'s body could
 * not move verbatim -- see bgp_cli_common.c and bgp_cli_neighbor_init()
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
#include "bgpd/proteus/bgp_cli_neighbor_clippy.c"

/*
 * neighbor/peer-group session lifecycle + remote-as (M4 batch B1).
 *
 * bgp_cli.c commands run in mgmtd's process (bgp_cli_init() is called from
 * mgmtd/mgmt_vty.c, never from bgpd.c) -- there is no 'struct bgp'/'struct
 * peer' here, only the candidate datastore. Every disambiguation that
 * legacy did with a runtime peer_lookup_by_conf_if()/peer_group_lookup()
 * call is done here instead with yang_dnode_exists() against the current
 * instance's dnode (see bgp_cli_instance_dnode() below); the real runtime
 * lookups/legacy setters live in bgp_nb_config.c's APPLY callbacks
 * (bgpd's own process, as the northbound backend client for
 * /proteus-bgp:*).
 */

/* vty->candidate_config->dnode is the root of the WHOLE candidate data
 * tree (the first top-level sibling across every configured module), not
 * scoped to the BGP instance currently being edited. A relative "./..."
 * xpath query (yang_dnode_exists()/_existsf()/yang_dnode_iterate()) run
 * directly against it only matches if e.g. "neighbor"/"peer-group"
 * happen to be direct children of that particular top-level node, which
 * is not guaranteed (found by M4 batch B2 topotest triage: this silently
 * broke every existence check below, since 'neighbor'/'peer-group' are
 * two levels down, under the current '/proteus-bgp:instance[vrf=...]').
 * Resolve the real current-instance dnode via VTY_CURR_XPATH first,
 * mirroring what nb_cli_enqueue_change() does internally for relative
 * xpaths (lib/northbound_cli.c's create_xpath_base_abs()).
 */
static const struct lyd_node *bgp_cli_instance_dnode(struct vty *vty)
{
	return yang_dnode_get(vty->candidate_config->dnode, VTY_CURR_XPATH);
}

/* Shared remote-as encoder: mirrors router_bgp_cli_cmd's plain-vs-asdot
 * split for the instance-level autonomous-system leaf. asn_str2asn()
 * (lib/asn.c) parses both notations into a single 32-bit AS; which case
 * to populate is decided purely by whether the token contained a '.', so
 * cli_show can reproduce the notation the user typed.
 */
static void bgp_cli_enqueue_remote_as(struct vty *vty, const char *base_xpath,
				      const char *remote_as_str)
{
	char *xpath_child;
	as_t as = 0;

	if (strmatch(remote_as_str, "internal") || strmatch(remote_as_str, "external") ||
	    strmatch(remote_as_str, "auto")) {
		xpath_child = asprintfrr(MTYPE_TMP, "%s/remote-as/type", base_xpath);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, remote_as_str);
		XFREE(MTYPE_TMP, xpath_child);
		return;
	}

	asn_str2asn(remote_as_str, &as);

	/*
	 * nb_cli_enqueue_change() stores the value pointer as-is (it copies
	 * only the xpath), and the enqueued changes are not consumed until the
	 * caller's deferred nb_cli_apply_changes(). Any value string handed to
	 * it must therefore stay alive past this helper's return. The keyword
	 * and plain cases reuse remote_as_str (a DEFPY argument that lives
	 * through apply); the asdot case must reformat, so its high/low value
	 * buffers use static storage rather than this frame's stack (safe: FRR
	 * executes CLI commands one at a time and apply is not reentrant).
	 */
	if (strchr(remote_as_str, '.')) {
		static char highbuf[8], lowbuf[8];
		as_t high = as >> 16, low = as & 0xffff;

		snprintf(highbuf, sizeof(highbuf), "%u", high);
		snprintf(lowbuf, sizeof(lowbuf), "%u", low);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/remote-as/asdot/high", base_xpath);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, highbuf);
		XFREE(MTYPE_TMP, xpath_child);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/remote-as/asdot/low", base_xpath);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, lowbuf);
		XFREE(MTYPE_TMP, xpath_child);
	} else {
		xpath_child = asprintfrr(MTYPE_TMP, "%s/remote-as/plain", base_xpath);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, remote_as_str);
		XFREE(MTYPE_TMP, xpath_child);
	}
}

/* Destroy whichever remote-as case is populated. NB_OP_DESTROY on an
 * absent candidate node is a no-op (nb_candidate_edit(), lib/
 * northbound.c), so issuing all three unconditionally is safe. */
static void bgp_cli_enqueue_remote_as_destroy(struct vty *vty, const char *base_xpath)
{
	char *xpath_child;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/remote-as/plain", base_xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/remote-as/asdot", base_xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/remote-as/type", base_xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);
}

DEFPY_YANG(
	neighbor_remote_as, neighbor_remote_as_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer remote-as <ASNUM|internal|external|auto>$remote_as",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Specify a BGP neighbor\n"
	AS_STR
	"Internal BGP peer\n"
	"External BGP peer\n"
	"Automatically detect remote ASN\n")
{
	char *xpath;
	union sockunion su;
	bool is_addr = str2sockunion(peer, &su) == 0;
	int ret;

	if (is_addr) {
		xpath = asprintfrr(MTYPE_TMP, "./neighbor[address='%s']", peer);
		if (!yang_dnode_exists(bgp_cli_instance_dnode(vty), xpath))
			nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	} else if (yang_dnode_existsf(bgp_cli_instance_dnode(vty), "./neighbor[address='%s']",
				      peer)) {
		/* existing conf_if (unnumbered) neighbor */
		xpath = asprintfrr(MTYPE_TMP, "./neighbor[address='%s']", peer);
	} else if (yang_dnode_existsf(bgp_cli_instance_dnode(vty), "./peer-group[name='%s']",
				      peer)) {
		xpath = asprintfrr(MTYPE_TMP, "./peer-group[name='%s']", peer);
	} else {
		vty_out(vty, "%% Create the peer-group or interface first\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	bgp_cli_enqueue_remote_as(vty, xpath, remote_as);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	no_neighbor, no_neighbor_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X>$peer [remote-as <ASNUM|internal|external|auto>$remote_as]",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Specify a BGP neighbor\n"
	AS_STR
	"Internal BGP peer\n"
	"External BGP peer\n"
	"Automatically detect remote ASN\n")
{
	char *xpath;
	int ret;

	/* The 'remote-as ...' suffix is accepted but ignored, exactly like
	 * the legacy no_neighbor() DEFUN it replaces: this always deletes
	 * the whole neighbor, never just its remote-as. */
	xpath = asprintfrr(MTYPE_TMP, "./neighbor[address='%s']", peer_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	no_neighbor_word, no_neighbor_word_cli_cmd,
	"no neighbor WORD$peer",
	NO_STR
	NEIGHBOR_STR
	"Interface name or neighbor tag\n")
{
	char *xpath;
	int ret;

	if (yang_dnode_existsf(bgp_cli_instance_dnode(vty), "./neighbor[address='%s']", peer)) {
		xpath = asprintfrr(MTYPE_TMP, "./neighbor[address='%s']", peer);
	} else if (yang_dnode_existsf(bgp_cli_instance_dnode(vty), "./peer-group[name='%s']",
				      peer)) {
		xpath = asprintfrr(MTYPE_TMP, "./peer-group[name='%s']", peer);
	} else {
		vty_out(vty, "%% Create the peer-group first\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	no_neighbor_word_remote_as, no_neighbor_word_remote_as_cli_cmd,
	"no neighbor WORD$peer remote-as <ASNUM|internal|external|auto>",
	NO_STR
	NEIGHBOR_STR
	"Interface name or neighbor tag\n"
	"Specify a BGP neighbor\n"
	AS_STR
	"Internal BGP peer\n"
	"External BGP peer\n"
	"Automatically detect remote ASN\n")
{
	char *xpath;
	int ret;

	/* The parsed AS value is irrelevant: this always clears remote-as
	 * (whichever case is set), matching legacy's
	 * no_neighbor_interface_peer_group_remote_as() DEFUN. */
	(void)remote_as;

	if (yang_dnode_existsf(bgp_cli_instance_dnode(vty), "./neighbor[address='%s']", peer)) {
		xpath = asprintfrr(MTYPE_TMP, "./neighbor[address='%s']", peer);
	} else if (yang_dnode_existsf(bgp_cli_instance_dnode(vty), "./peer-group[name='%s']",
				      peer)) {
		xpath = asprintfrr(MTYPE_TMP, "./peer-group[name='%s']", peer);
	} else {
		vty_out(vty, "%% Create the peer-group or interface first\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	bgp_cli_enqueue_remote_as_destroy(vty, xpath);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_interface_config, neighbor_interface_config_cli_cmd,
	"neighbor WORD$ifname interface [v6only]$v6only [peer-group PGNAME$pgname]",
	NEIGHBOR_STR
	"Interface name or neighbor tag\n"
	"Enable BGP on interface\n"
	"Enable BGP with v6 link-local only\n"
	"Member of the peer-group\n"
	"Peer-group name\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = asprintfrr(MTYPE_TMP, "./neighbor[address='%s']", ifname);
	if (!yang_dnode_exists(bgp_cli_instance_dnode(vty), xpath)) {
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/interface-peer", xpath);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "true");
		XFREE(MTYPE_TMP, xpath_child);
	}

	xpath_child = asprintfrr(MTYPE_TMP, "%s/v6only", xpath);
	nb_cli_enqueue_change(vty, xpath_child, v6only ? NB_OP_MODIFY : NB_OP_DESTROY,
			      v6only ? "true" : NULL);
	XFREE(MTYPE_TMP, xpath_child);

	if (pgname) {
		xpath_child = asprintfrr(MTYPE_TMP, "%s/peer-group", xpath);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, pgname);
		XFREE(MTYPE_TMP, xpath_child);
	}

	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_interface_config_remote_as, neighbor_interface_config_remote_as_cli_cmd,
	"neighbor WORD$ifname interface [v6only]$v6only remote-as <ASNUM|internal|external|auto>$remote_as",
	NEIGHBOR_STR
	"Interface name or neighbor tag\n"
	"Enable BGP on interface\n"
	"Enable BGP with v6 link-local only\n"
	"Specify a BGP neighbor\n"
	AS_STR
	"Internal BGP peer\n"
	"External BGP peer\n"
	"Automatically detect remote ASN\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = asprintfrr(MTYPE_TMP, "./neighbor[address='%s']", ifname);
	if (!yang_dnode_exists(bgp_cli_instance_dnode(vty), xpath)) {
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/interface-peer", xpath);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "true");
		XFREE(MTYPE_TMP, xpath_child);
	}

	xpath_child = asprintfrr(MTYPE_TMP, "%s/v6only", xpath);
	nb_cli_enqueue_change(vty, xpath_child, v6only ? NB_OP_MODIFY : NB_OP_DESTROY,
			      v6only ? "true" : NULL);
	XFREE(MTYPE_TMP, xpath_child);

	bgp_cli_enqueue_remote_as(vty, xpath, remote_as);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_peer_group, neighbor_peer_group_cli_cmd,
	"neighbor WORD$name peer-group",
	NEIGHBOR_STR
	"Interface name or neighbor tag\n"
	"Configure peer-group\n")
{
	char *xpath;
	int ret;

	xpath = asprintfrr(MTYPE_TMP, "./peer-group[name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

/* Legacy peer_group_delete() (bgpd.c) implicitly peer_delete()s every
 * member bound to the group with no unbind primitive; the northbound
 * /proteus-bgp:instance/peer-group destroy callback (bgp_nb_config.c) is
 * intentionally stricter and VALIDATE-rejects a peer-group destroy while
 * any neighbor entry is still bound to it in the candidate datastore, to
 * keep datastore and runtime coherent (a destroy callback cannot itself
 * reach into sibling list entries to clean them up). This iterator
 * restores the one-command legacy UX at the CLI layer by enqueuing every
 * bound member's own destroy alongside the peer-group's.
 */
static int no_neighbor_peer_group_member_iter_cb(const struct lyd_node *dnode, void *arg)
{
	struct vty *vty = arg;
	const char *address = yang_dnode_get_string(dnode, "address");
	char *xpath = asprintfrr(MTYPE_TMP, "./neighbor[address='%s']", address);

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath);

	return YANG_ITER_CONTINUE;
}

DEFPY_YANG(
	no_neighbor_peer_group, no_neighbor_peer_group_cli_cmd,
	"no neighbor WORD$name peer-group",
	NO_STR
	NEIGHBOR_STR
	"Neighbor tag\n"
	"Configure peer-group\n")
{
	char *xpath;
	int ret;

	yang_dnode_iterate(no_neighbor_peer_group_member_iter_cb, vty, bgp_cli_instance_dnode(vty),
			   "./neighbor[peer-group='%s']", name);

	xpath = asprintfrr(MTYPE_TMP, "./peer-group[name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_set_peer_group, neighbor_set_peer_group_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer peer-group PGNAME$pgname",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Member of the peer-group\n"
	"Peer-group name\n")
{
	char *xpath, *xpath_child;
	union sockunion su;
	bool is_addr = str2sockunion(peer, &su) == 0;
	int ret;

	xpath = asprintfrr(MTYPE_TMP, "./neighbor[address='%s']", peer);

	if (!yang_dnode_exists(bgp_cli_instance_dnode(vty), xpath)) {
		if (!is_addr) {
			vty_out(vty, "%% Malformed address or name: %s\n", peer);
			XFREE(MTYPE_TMP, xpath);
			return CMD_WARNING_CONFIG_FAILED;
		}
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	}

	xpath_child = asprintfrr(MTYPE_TMP, "%s/peer-group", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, pgname);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	no_neighbor_set_peer_group, no_neighbor_set_peer_group_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer peer-group PGNAME$pgname",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Member of the peer-group\n"
	"Peer-group name\n")
{
	char *xpath;
	int ret;

	/* Destroys the WHOLE neighbor entry, exactly like legacy's
	 * no_neighbor_set_peer_group() DEFUN (peer_delete(), not an
	 * unbind) -- see M4 batch B1 commit message. */
	xpath = asprintfrr(MTYPE_TMP, "./neighbor[address='%s']", peer);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

/*
 * XPath: /proteus-bgp:instance/peer-group
 *
 * Reproduces the peer-group-only slice of bgp_config_write_peer_global()
 * (bgp_vty.c) byte-for-byte: the unconditional "neighbor PGNAME
 * peer-group" declaration line (peer-groups always have
 * PEER_STATUS_GROUP set and are never themselves peer_group_active()),
 * followed by "neighbor PGNAME remote-as ..." if set.
 */
DEFPY_YANG(
	bgp_listen_range, bgp_listen_range_cli_cmd,
	"bgp listen range <A.B.C.D/M|X:X::X:X/M>$range peer-group PGNAME$pgname",
	BGP_STR
	"Configure BGP dynamic neighbors listen range\n"
	"Configure BGP dynamic neighbors listen range\n"
	NEIGHBOR_ADDR_STR
	"Member of the peer-group\n"
	"Peer-group name\n")
{
	char *xpath;
	int ret;

	if (!yang_dnode_existsf(bgp_cli_instance_dnode(vty), "./peer-group[name='%s']", pgname)) {
		vty_out(vty, "%% Configure the peer-group first\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = asprintfrr(MTYPE_TMP, "./peer-group[name='%s']/listen-range[.='%s']", pgname,
			   range_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	no_bgp_listen_range, no_bgp_listen_range_cli_cmd,
	"no bgp listen range <A.B.C.D/M|X:X::X:X/M>$range peer-group PGNAME$pgname",
	NO_STR
	BGP_STR
	"Unconfigure BGP dynamic neighbors listen range\n"
	"Unconfigure BGP dynamic neighbors listen range\n"
	NEIGHBOR_ADDR_STR
	"Member of the peer-group\n"
	"Peer-group name\n")
{
	char *xpath;
	int ret;

	xpath = asprintfrr(MTYPE_TMP, "./peer-group[name='%s']/listen-range[.='%s']", pgname,
			   range_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

/*
 * XPath: /proteus-bgp:instance/peer-group/listen-range
 *
 * One "bgp listen range PFX peer-group PGNAME" line per leaf-list entry,
 * matching bgp_config_write_listen()'s per-range loop (bgp_vty.c, retired
 * in M4 batch B2). libyang's inet:ipv4-prefix/ipv6-prefix type plugins
 * canonicalize (mask) the stored value on write, same effect as legacy's
 * apply_mask() before storing into group->listen_range[], so the stored
 * string can be rendered as-is.
 */
void peer_group_listen_range_cli_write(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults)
{
	const struct lyd_node *pg_dnode = yang_dnode_get_parent(dnode, "peer-group");

	vty_out(vty, " bgp listen range %s peer-group %s\n", yang_dnode_get_string(dnode, NULL),
		yang_dnode_get_string(pg_dnode, "name"));
}

void peer_group_cli_write(struct vty *vty, const struct lyd_node *dnode,
				 bool show_defaults)
{
	const char *name = yang_dnode_get_string(dnode, "name");

	vty_out(vty, " neighbor %s peer-group\n", name);

	if (yang_dnode_exists(dnode, "remote-as/plain"))
		vty_out(vty, " neighbor %s remote-as %u\n", name,
			yang_dnode_get_uint32(dnode, "remote-as/plain"));
	else if (yang_dnode_exists(dnode, "remote-as/asdot/high"))
		vty_out(vty, " neighbor %s remote-as %u.%u\n", name,
			yang_dnode_get_uint16(dnode, "remote-as/asdot/high"),
			yang_dnode_get_uint16(dnode, "remote-as/asdot/low"));
	else if (yang_dnode_exists(dnode, "remote-as/type"))
		vty_out(vty, " neighbor %s remote-as %s\n", name,
			yang_dnode_get_string(dnode, "remote-as/type"));
}

/* addr == NULL renders the bare "remote-as ..." suffix used inline after
 * "neighbor IFNAME interface ..." (no leading "neighbor %s", no trailing
 * newline); addr != NULL renders a standalone "neighbor %s remote-as
 * ...\n" line. Mirrors the two rendering shapes in
 * bgp_config_write_peer_global()'s retired block. */
static void neighbor_cli_write_remote_as(struct vty *vty, const struct lyd_node *dnode,
					 const char *addr)
{
	if (yang_dnode_exists(dnode, "remote-as/plain")) {
		uint32_t as = yang_dnode_get_uint32(dnode, "remote-as/plain");

		if (addr)
			vty_out(vty, " neighbor %s remote-as %u\n", addr, as);
		else
			vty_out(vty, " remote-as %u", as);
	} else if (yang_dnode_exists(dnode, "remote-as/asdot/high")) {
		uint16_t high = yang_dnode_get_uint16(dnode, "remote-as/asdot/high");
		uint16_t low = yang_dnode_get_uint16(dnode, "remote-as/asdot/low");

		if (addr)
			vty_out(vty, " neighbor %s remote-as %u.%u\n", addr, high, low);
		else
			vty_out(vty, " remote-as %u.%u", high, low);
	} else if (yang_dnode_exists(dnode, "remote-as/type")) {
		const char *type = yang_dnode_get_string(dnode, "remote-as/type");

		if (addr)
			vty_out(vty, " neighbor %s remote-as %s\n", addr, type);
		else
			vty_out(vty, " remote-as %s", type);
	}
}

/*
 * XPath: /proteus-bgp:instance/neighbor
 *
 * Reproduces the neighbor-only slice of bgp_config_write_peer_global()
 * byte-for-byte, including the if_pg_printed/if_ras_printed suppression
 * for the interface form's inline peer-group/remote-as token. One
 * deliberate, documented divergence from legacy for a group-member's
 * remote-as line: legacy suppresses it by comparing the member's
 * *effective* (possibly inherited) AS against the group's, which can
 * under-suppress or over-suppress in edge cases (a member override that
 * numerically matches the group's AS is silently swallowed); this
 * renders it whenever the neighbor's own remote-as leaf is present in
 * the datastore, which is exactly the northbound mirror of "this peer
 * has flags_override set" (bgpd.c) -- i.e. exactly the invariant legacy
 * intends, without the value-comparison edge case.
 */
void neighbor_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const char *address = yang_dnode_get_string(dnode, "address");
	bool is_if = yang_dnode_exists(dnode, "interface-peer") &&
		    yang_dnode_get_bool(dnode, "interface-peer");
	bool v6only = yang_dnode_exists(dnode, "v6only") && yang_dnode_get_bool(dnode, "v6only");
	bool has_pg = yang_dnode_exists(dnode, "peer-group");
	bool has_ras = yang_dnode_exists(dnode, "remote-as/plain") ||
		      yang_dnode_exists(dnode, "remote-as/asdot/high") ||
		      yang_dnode_exists(dnode, "remote-as/type");
	bool if_pg_printed = false, if_ras_printed = false;

	if (is_if) {
		vty_out(vty, " neighbor %s interface%s", address, v6only ? " v6only" : "");

		if (has_pg) {
			vty_out(vty, " peer-group %s", yang_dnode_get_string(dnode, "peer-group"));
			if_pg_printed = true;
		} else if (has_ras) {
			neighbor_cli_write_remote_as(vty, dnode, NULL);
			if_ras_printed = true;
		}

		vty_out(vty, "\n");
	}

	if (has_pg && !if_pg_printed)
		vty_out(vty, " neighbor %s peer-group %s\n", address,
			yang_dnode_get_string(dnode, "peer-group"));

	if (has_ras && !if_ras_printed)
		neighbor_cli_write_remote_as(vty, dnode, address);
}

void bgp_cli_neighbor_init(void)
{
	/* "neighbor remote-as", interface-unnumbered creation and "neighbor
	 * peer-group" (declare/bind) commands (M4 batch B1). */
	install_element(BGP_NODE, &neighbor_remote_as_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_word_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_word_remote_as_cli_cmd);
	install_element(BGP_NODE, &neighbor_interface_config_cli_cmd);
	install_element(BGP_NODE, &neighbor_interface_config_remote_as_cli_cmd);
	install_element(BGP_NODE, &neighbor_peer_group_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_peer_group_cli_cmd);
	install_element(BGP_NODE, &neighbor_set_peer_group_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_set_peer_group_cli_cmd);

	/* "bgp listen range ... peer-group PGNAME" dynamic neighbors (M4
	 * batch B2). */
	install_element(BGP_NODE, &bgp_listen_range_cli_cmd);
	install_element(BGP_NODE, &no_bgp_listen_range_cli_cmd);
}
