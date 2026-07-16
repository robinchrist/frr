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
 * Session-level scalar leaves that attach to an already-existing peer or
 * peer-group (M4 batch B3: description, password, port, tcp-mss,
 * source-interface, solo, passive). Unlike B1's lifecycle commands, these
 * are pure subcommands -- they never create the underlying peer/
 * peer-group struct themselves, so (per the coordinator brief) they don't
 * need legacy DEFUN retention: by the time a config-file line reaches one
 * of these, B1's still-legacy-DEFUN-backed creation commands have already
 * built the struct directly in bgpd, independent of mgmtd's batched
 * backend-client push. The one shared xpath-resolution helper below
 * mirrors peer_and_group_lookup_vty()'s lookup order (bgp_vty.c,
 * retired for these leaves) for every DEFPY_YANG in this section.
 */
static char *bgp_cli_peer_or_group_xpath(struct vty *vty, const char *peer)
{
	if (yang_dnode_existsf(bgp_cli_instance_dnode(vty), "./neighbor[address='%s']", peer))
		return asprintfrr(MTYPE_TMP, "./neighbor[address='%s']", peer);
	if (yang_dnode_existsf(bgp_cli_instance_dnode(vty), "./peer-group[name='%s']", peer))
		return asprintfrr(MTYPE_TMP, "./peer-group[name='%s']", peer);

	vty_out(vty, "%% Specify remote-as or peer-group commands first\n");
	return NULL;
}

DEFPY_YANG(
	neighbor_description, neighbor_description_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer description LINE...",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Neighbor specific description\n"
	"Up to 80 characters describing this neighbor\n")
{
	char *xpath, *xpath_child, *desc;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	desc = argv_concat(argv, argc, 3);
	xpath_child = asprintfrr(MTYPE_TMP, "%s/description", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, desc);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	XFREE(MTYPE_TMP, desc);

	return ret;
}

DEFPY_YANG(
	no_neighbor_description, no_neighbor_description_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer description",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Neighbor specific description\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/description", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

/* Legacy accepts (and ignores) a trailing LINE... on the 'no' form too
 * (no_neighbor_description_comment_cmd ALIAS, bgp_vty.c, retired) --
 * reproduced as a second grammar sharing the same body rather than an
 * optional '[LINE...]' group, which DEFPY's grammar parser rejects.
 */
DEFPY_YANG(
	no_neighbor_description_comment, no_neighbor_description_comment_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer description LINE...",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Neighbor specific description\n"
	"Up to 80 characters describing this neighbor\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/description", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_password, neighbor_password_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer password LINE$password",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Set a password\n"
	"The password\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/password", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, password);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	no_neighbor_password, no_neighbor_password_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer password [LINE]",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Set a password\n"
	"The password\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/password", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_solo, neighbor_solo_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer solo",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Solo peer - part of its own update group\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/solo", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, no ? "false" : "true");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_port, neighbor_port_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer port (0-65535)$port",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Neighbor's BGP port\n"
	"TCP port number\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/port", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, port_str);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	no_neighbor_port, no_neighbor_port_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer port [(0-65535)]",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Neighbor's BGP port\n"
	"TCP port number\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/port", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

/* source-interface (peer->ifname): grammar deliberately restricted to a
 * real address in the first token (NEIGHBOR_ADDR_STR, no WORD
 * alternative), unlike every other command in this section --
 * distinguishes it from 'neighbor WORD interface [v6only] [peer-group
 * PGNAME]' (unnumbered peer creation, B1, neighbor_interface_config_cli_cmd)
 * which types its first token as a bare WORD. The command parser resolves
 * this the same way the two legacy DEFUNs it replaces always did: an
 * input matching a real address only ever completes the address-first
 * grammar below, never the WORD-first creation grammar. The northbound
 * VALIDATE callback (bgp_nb_neighbor.c) additionally rejects unnumbered
 * (interface-peer) neighbors, matching legacy's peer_interface_vty().
 */
DEFPY_YANG(
	neighbor_interface, neighbor_interface_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X>$peer interface WORD$ifname",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR
	"Interface\n"
	"Interface name\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer_str);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/source-interface", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, ifname);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	no_neighbor_interface, no_neighbor_interface_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X>$peer interface WORD",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR
	"Interface\n"
	"Interface name\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer_str);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/source-interface", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_tcp_mss, neighbor_tcp_mss_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer tcp-mss (1-65535)$tcp_mss",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"TCP max segment size\n"
	"TCP MSS value\n")
{
	char *xpath, *xpath_child;
	int ret;

	vty_out(vty, " Warning: Reset BGP session for tcp-mss value to take effect\n");

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/tcp-mss", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, tcp_mss_str);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	no_neighbor_tcp_mss, no_neighbor_tcp_mss_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer tcp-mss [(1-65535)]",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"TCP max segment size\n"
	"TCP MSS value\n")
{
	char *xpath, *xpath_child;
	int ret;

	vty_out(vty, " Warning: Reset BGP session for tcp-mss value to take effect\n");

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/tcp-mss", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_passive, neighbor_passive_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer passive",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Don't send open messages to this neighbor\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/passive", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, no ? "false" : "true");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

/*
 * shutdown (+ message, + rtt), graceful-shutdown, aigp, oad (M4 batch B4):
 * session-admin-control leaves shared between neighbor/peer-group via the
 * neighbor-session-parameters grouping. Pure subcommands like B3's, so no
 * legacy DEFUN retention (same rationale as bgp_cli_peer_or_group_xpath()'s
 * doc comment above).
 */

DEFPY_YANG(
	neighbor_shutdown, neighbor_shutdown_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer shutdown",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Administratively shut down this neighbor\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/shutdown/enabled", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "true");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_shutdown_message, neighbor_shutdown_message_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer shutdown message LINE...",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Administratively shut down this neighbor\n"
	"Add a shutdown message (RFC 8203)\n"
	"Shutdown message\n")
{
	char *xpath, *xpath_child, *msg;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	msg = argv_concat(argv, argc, 4);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/shutdown/enabled", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "true");
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/shutdown/message", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, msg);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	XFREE(MTYPE_TMP, msg);

	return ret;
}

/* Both 'no' forms below destroy 'enabled' *and* 'message' together --
 * reproducing peer_flag_modify_vty()'s (bgp_vty.c, retired) legacy side
 * effect of always clearing tx_shutdown_message whenever
 * PEER_FLAG_SHUTDOWN is unset, regardless of which 'no' grammar was used.
 * See the northbound callback's comment (bgp_nb_instance_gr.c) for why
 * that composite destroy lives here at the CLI layer instead of inside
 * the 'enabled' callback.
 */
DEFPY_YANG(
	no_neighbor_shutdown, no_neighbor_shutdown_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer shutdown",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Administratively shut down this neighbor\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/shutdown/enabled", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "false");
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/shutdown/message", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

/* Legacy accepts (and ignores) a trailing MSG... on the 'no' form too
 * (no_neighbor_shutdown_msg_cmd's own grammar, bgp_vty.c, retired) --
 * reproduced as a second grammar sharing the same body, same shape as
 * B3's no_neighbor_description_comment.
 */
DEFPY_YANG(
	no_neighbor_shutdown_message, no_neighbor_shutdown_message_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer shutdown message LINE...",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Administratively shut down this neighbor\n"
	"Remove a shutdown message (RFC 8203)\n"
	"Shutdown message\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/shutdown/enabled", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "false");
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/shutdown/message", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_shutdown_rtt, neighbor_shutdown_rtt_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer shutdown rtt (1-65535)$rtt [count (1-255)$cnt]",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Administratively shut down this neighbor\n"
	"Shutdown if round-trip-time is higher than expected\n"
	"Round-trip-time in milliseconds\n"
	"Specify the number of keepalives before shutdown\n"
	"The number of keepalives with higher RTT to shutdown\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/shutdown/rtt/threshold", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, rtt_str);
	XFREE(MTYPE_TMP, xpath_child);

	if (cnt_str) {
		xpath_child = asprintfrr(MTYPE_TMP, "%s/shutdown/rtt/count", xpath);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, cnt_str);
		XFREE(MTYPE_TMP, xpath_child);
	}
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

/* Destroys both 'rtt/threshold' and 'rtt/count' together, matching
 * legacy's no_neighbor_shutdown_rtt (bgp_vty.c, retired), which always
 * resets both peer->rtt_expected and peer->rtt_keepalive_conf regardless
 * of whether count was ever set independently.
 */
DEFPY_YANG(
	no_neighbor_shutdown_rtt, no_neighbor_shutdown_rtt_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer shutdown rtt [(1-65535) [count (1-255)]]",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Administratively shut down this neighbor\n"
	"Shutdown if round-trip-time is higher than expected\n"
	"Round-trip-time in milliseconds\n"
	"Specify the number of keepalives before shutdown\n"
	"The number of keepalives with higher RTT to shutdown\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/shutdown/rtt/threshold", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/shutdown/rtt/count", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_graceful_shutdown, neighbor_graceful_shutdown_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer graceful-shutdown",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Graceful shutdown\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/graceful-shutdown", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, no ? "false" : "true");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_aigp, neighbor_aigp_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer aigp",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Enable send and receive of the AIGP attribute per neighbor\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/aigp", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, no ? "false" : "true");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_oad, neighbor_oad_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer oad",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Set peering session type to EBGP-OAD\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/oad", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, no ? "false" : "true");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

/*
 * timers (+ connect, + delayopen), advertisement-interval (M4 batch B5):
 * numeric session-tuning leaves shared between neighbor/peer-group via the
 * neighbor-session-parameters grouping. Pure subcommands like B3/B4's, so
 * no legacy DEFUN retention (same rationale as
 * bgp_cli_peer_or_group_xpath()'s doc comment above).
 */

/* 'neighbor X timers (0-65535) (0-65535)' enqueues both leaves in one CLI
 * line, matching the joint keepalive+holdtime grammar (there is no way to
 * set one without the other); 'no neighbor X timers [K H]' destroys both
 * regardless of whether trailing values were given, matching legacy's
 * no_neighbor_timers DEFUN (the optional K/H tokens are accepted and
 * ignored, same as legacy).
 */
DEFPY_YANG(
	neighbor_timers, neighbor_timers_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer timers (0-65535)$keepalive (0-65535)$holdtime",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"BGP per neighbor timers\n"
	"Keepalive interval\n"
	"Holdtime\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/timers/keepalive", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, keepalive_str);
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/timers/holdtime", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, holdtime_str);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	no_neighbor_timers, no_neighbor_timers_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer timers [(0-65535) (0-65535)]",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"BGP per neighbor timers\n"
	"Keepalive interval\n"
	"Holdtime\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/timers/keepalive", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/timers/holdtime", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_timers_connect, neighbor_timers_connect_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer timers connect (1-65535)$connect",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"BGP per neighbor timers\n"
	"BGP connect timer\n"
	"Connect timer\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/timers/connect", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, connect_str);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	no_neighbor_timers_connect, no_neighbor_timers_connect_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer timers connect [(1-65535)]",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"BGP per neighbor timers\n"
	"BGP connect timer\n"
	"Connect timer\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/timers/connect", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_timers_delayopen, neighbor_timers_delayopen_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer timers delayopen (1-240)$delayopen",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"BGP per neighbor timers\n"
	"RFC 4271 DelayOpenTimer\n"
	"DelayOpenTime timer interval\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/timers/delayopen", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, delayopen_str);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

/* Legacy's no-form grammar oddly ranges its optional value token as
 * "(0-65535)" (no_neighbor_timers_delayopen DEFPY, bgp_vty.c, retired)
 * even though the set-form is "(1-240)" -- the value is ignored either
 * way (always a full unset), so the wider range is reproduced verbatim
 * for grammar/help-string fidelity without giving it any semantic
 * meaning here either.
 */
DEFPY_YANG(
	no_neighbor_timers_delayopen, no_neighbor_timers_delayopen_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer timers delayopen [(0-65535)]",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"BGP per neighbor timers\n"
	"RFC 4271 DelayOpenTimer\n"
	"DelayOpenTime timer interval\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/timers/delayopen", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_advertisement_interval, neighbor_advertisement_interval_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer advertisement-interval (0-600)$interval",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Minimum interval between sending BGP routing updates\n"
	"time in seconds\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/advertisement-interval", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, interval_str);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	no_neighbor_advertisement_interval, no_neighbor_advertisement_interval_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer advertisement-interval [(0-600)]",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Minimum interval between sending BGP routing updates\n"
	"time in seconds\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/advertisement-interval", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);
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

/* description/password/solo/port/source-interface/tcp-mss/passive (M4
 * batch B3): reproduces the corresponding slice of
 * bgp_config_write_peer_global()'s (bgp_vty.c, retired for these seven
 * leaves) per-peer block, in the same relative order, for one neighbor or
 * peer-group entry. None of these leaves fan out to group members in the
 * datastore (legacy has no fanout for description/port/source-interface
 * at all -- confirmed by direct inspection of
 * peer_group2peer_config_copy(), bgpd.c -- and password/solo/tcp-mss/
 * passive fan out only at the runtime peer-flag/flags_override level, not
 * by writing the member's own leaf), so a plain per-entry
 * yang_dnode_exists()/get_*() read on this dnode is exactly the
 * northbound mirror of legacy's peergroup_flag_check()-gated emission:
 * only the entry that owns its own explicit configuration ever has the
 * leaf present/non-default here.
 *
 * 'not_group_member' is true for a peer-group entry (never itself bound to
 * another group) and for a neighbor entry with no 'peer-group' leaf --
 * i.e. it is the northbound mirror of legacy's !peer_group_active(peer),
 * needed below for the 'timers connect'/'timers delayopen' SAVE_ idiom.
 */
static void bgp_cli_write_session_scalars(struct vty *vty, const struct lyd_node *dnode,
					  const char *addr, bool not_group_member)
{
	if (yang_dnode_exists(dnode, "description"))
		vty_out(vty, " neighbor %s description %s\n", addr,
			yang_dnode_get_string(dnode, "description"));

	if (yang_dnode_exists(dnode, "password"))
		vty_out(vty, " neighbor %s password %s\n", addr,
			yang_dnode_get_string(dnode, "password"));

	if (yang_dnode_exists(dnode, "solo") && yang_dnode_get_bool(dnode, "solo"))
		vty_out(vty, " neighbor %s solo\n", addr);

	if (yang_dnode_exists(dnode, "port"))
		vty_out(vty, " neighbor %s port %u\n", addr, yang_dnode_get_uint16(dnode, "port"));

	if (yang_dnode_exists(dnode, "source-interface"))
		vty_out(vty, " neighbor %s interface %s\n", addr,
			yang_dnode_get_string(dnode, "source-interface"));

	if (yang_dnode_exists(dnode, "tcp-mss"))
		vty_out(vty, " neighbor %s tcp-mss %u\n", addr,
			yang_dnode_get_uint16(dnode, "tcp-mss"));

	if (yang_dnode_exists(dnode, "passive") && yang_dnode_get_bool(dnode, "passive"))
		vty_out(vty, " neighbor %s passive\n", addr);

	/* shutdown (+ message, + rtt), graceful-shutdown, aigp, oad (M4
	 * batch B4): reproduces bgp_config_write_peer_global()'s (bgp_vty.c,
	 * retired for these leaves) shutdown-through-oad block, in the same
	 * relative order. 'message'/'rtt/count' are stored
	 * unconditionally in the datastore (see the northbound callbacks'
	 * comment, bgp_nb_instance_gr.c) but emission stays gated on their
	 * own governing presence exactly like legacy: 'enabled' gates the
	 * message line (peergroup_flag_check(peer, PEER_FLAG_SHUTDOWN) in
	 * legacy), while 'rtt/threshold's mere presence gates the rtt line
	 * (mirroring the wholly separate PEER_FLAG_RTT_SHUTDOWN) --
	 * reproducing legacy's "if (peer->tx_shutdown_message) ... else
	 * ..." branch and its unconditional "count %u" (falling back to the
	 * peer_new() default of 1 when 'rtt/count' itself is absent).
	 */
	if (yang_dnode_exists(dnode, "shutdown/enabled") &&
	    yang_dnode_get_bool(dnode, "shutdown/enabled")) {
		if (yang_dnode_exists(dnode, "shutdown/message"))
			vty_out(vty, " neighbor %s shutdown message %s\n", addr,
				yang_dnode_get_string(dnode, "shutdown/message"));
		else
			vty_out(vty, " neighbor %s shutdown\n", addr);
	}

	if (yang_dnode_exists(dnode, "shutdown/rtt/threshold"))
		vty_out(vty, " neighbor %s shutdown rtt %u count %u\n", addr,
			yang_dnode_get_uint16(dnode, "shutdown/rtt/threshold"),
			yang_dnode_exists(dnode, "shutdown/rtt/count")
				? yang_dnode_get_uint8(dnode, "shutdown/rtt/count")
				: 1);

	if (yang_dnode_exists(dnode, "aigp") && yang_dnode_get_bool(dnode, "aigp"))
		vty_out(vty, " neighbor %s aigp\n", addr);

	if (yang_dnode_exists(dnode, "graceful-shutdown") &&
	    yang_dnode_get_bool(dnode, "graceful-shutdown"))
		vty_out(vty, " neighbor %s graceful-shutdown\n", addr);

	if (yang_dnode_exists(dnode, "oad") && yang_dnode_get_bool(dnode, "oad"))
		vty_out(vty, " neighbor %s oad\n", addr);

	/* advertisement-interval, timers (+ connect, + delayopen) (M4 batch
	 * B5): reproduces bgp_config_write_peer_global()'s (bgp_vty.c,
	 * retired for these leaves) advertisement-interval-through-
	 * timers-delayopen block, in the same relative order.
	 *
	 * 'timers connect'/'timers delayopen' each carry a legacy special
	 * case: even when the leaf itself is absent (no explicit "neighbor X
	 * timers connect/delayopen" was ever configured for this entry),
	 * legacy still emits a synthetic line carrying the *default* value
	 * whenever that default no longer matches what a reload under this
	 * config's declared "frr version"/profile would reconstruct --
	 * otherwise the explicit value in effect right now would silently
	 * turn into a different one after a config save/reload cycle across
	 * a version or profile change ("there is no 'timers bgp connect'
	 * command, so we need to save this per-peer", per the retired
	 * comment). DFLT_BGP_CONNECT_RETRY/SAVE_BGP_CONNECT_RETRY
	 * (bgp_vty.h's FRR_CFG_DEFAULT_ULONG(BGP_CONNECT_RETRY, ...)) are
	 * global, not per-'struct bgp', so this reads them directly rather
	 * than through any per-instance/per-peer runtime state -- there is
	 * no YANG leaf modeling an instance-level 'default connect-retry'
	 * (M2 never added one), so bgp->default_connect_retry is always
	 * exactly DFLT_BGP_CONNECT_RETRY in the northbound-converted world,
	 * making this global comparison the exact equivalent of legacy's
	 * per-peer 'peer->bgp->default_connect_retry != SAVE_BGP_CONNECT_RETRY'
	 * check. delayopen has no FRR_CFG_DEFAULT_ULONG profile/version
	 * variant (BGP_DEFAULT_DELAYOPEN is a plain, non-switchable macro)
	 * and, likewise, no YANG-modeled instance-level default -- so
	 * bgp->default_delayopen is always exactly BGP_DEFAULT_DELAYOPEN
	 * here, meaning legacy's analogous
	 * 'peer->bgp->default_delayopen != BGP_DEFAULT_DELAYOPEN' check can
	 * never be true and that branch never fires; correctly reproduced
	 * by simply not implementing it (dead code preserved as a no-op,
	 * not a gap).
	 */
	if (yang_dnode_exists(dnode, "advertisement-interval"))
		vty_out(vty, " neighbor %s advertisement-interval %u\n", addr,
			yang_dnode_get_uint16(dnode, "advertisement-interval"));

	if (yang_dnode_exists(dnode, "timers/keepalive") &&
	    yang_dnode_exists(dnode, "timers/holdtime"))
		vty_out(vty, " neighbor %s timers %u %u\n", addr,
			yang_dnode_get_uint16(dnode, "timers/keepalive"),
			yang_dnode_get_uint16(dnode, "timers/holdtime"));

	if (yang_dnode_exists(dnode, "timers/connect"))
		vty_out(vty, " neighbor %s timers connect %u\n", addr,
			yang_dnode_get_uint16(dnode, "timers/connect"));
	else if (not_group_member && DFLT_BGP_CONNECT_RETRY != SAVE_BGP_CONNECT_RETRY)
		vty_out(vty, " neighbor %s timers connect %lu\n", addr, DFLT_BGP_CONNECT_RETRY);

	if (yang_dnode_exists(dnode, "timers/delayopen"))
		vty_out(vty, " neighbor %s timers delayopen %u\n", addr,
			yang_dnode_get_uint8(dnode, "timers/delayopen"));
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

	/* A peer-group entry is never itself bound to another peer-group
	 * (!peer_group_active(group->conf) is unconditionally true, see
	 * bgpd.h's peer_group_active()), so it always qualifies for the
	 * 'timers connect' SAVE_ idiom's not-a-group-member gate.
	 */
	bgp_cli_write_session_scalars(vty, dnode, name, true);
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

	/* has_pg mirrors legacy's !peer_group_active(peer): a neighbor bound
	 * to a peer-group inherits from it and never itself qualifies for
	 * the 'timers connect' SAVE_ idiom (see bgp_cli_write_session_scalars()).
	 */
	bgp_cli_write_session_scalars(vty, dnode, address, !has_pg);
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

	/* description, password, port, tcp-mss, source-interface, solo,
	 * passive (M4 batch B3). */
	install_element(BGP_NODE, &neighbor_description_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_description_cli_cmd);
	install_element(BGP_NODE, &neighbor_password_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_password_cli_cmd);
	install_element(BGP_NODE, &neighbor_solo_cli_cmd);
	install_element(BGP_NODE, &neighbor_port_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_port_cli_cmd);
	install_element(BGP_NODE, &neighbor_interface_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_interface_cli_cmd);
	install_element(BGP_NODE, &neighbor_tcp_mss_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_tcp_mss_cli_cmd);
	install_element(BGP_NODE, &neighbor_passive_cli_cmd);

	/* shutdown (+ message, + rtt), graceful-shutdown, aigp, oad (M4
	 * batch B4). */
	install_element(BGP_NODE, &neighbor_shutdown_cli_cmd);
	install_element(BGP_NODE, &neighbor_shutdown_message_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_shutdown_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_shutdown_message_cli_cmd);
	install_element(BGP_NODE, &neighbor_shutdown_rtt_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_shutdown_rtt_cli_cmd);
	install_element(BGP_NODE, &neighbor_graceful_shutdown_cli_cmd);
	install_element(BGP_NODE, &neighbor_aigp_cli_cmd);
	install_element(BGP_NODE, &neighbor_oad_cli_cmd);

	/* timers (+ connect, + delayopen), advertisement-interval (M4
	 * batch B5). */
	install_element(BGP_NODE, &neighbor_timers_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_timers_cli_cmd);
	install_element(BGP_NODE, &neighbor_timers_connect_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_timers_connect_cli_cmd);
	install_element(BGP_NODE, &neighbor_timers_delayopen_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_timers_delayopen_cli_cmd);
	install_element(BGP_NODE, &neighbor_advertisement_interval_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_advertisement_interval_cli_cmd);
}
