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
#include <errno.h>
#include <inttypes.h>
#include "command.h"
#include "northbound.h"
#include "northbound_cli.h"
#include "vty.h"
#include "vrf.h"
#include "asn.h"
#include "bfd.h"

#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_cli.h"
#include "bgpd/bgp_damp.h"
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

/* update-source, ip-transparent (M4 batch B7). */
DEFPY_YANG(
	neighbor_update_source, neighbor_update_source_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer update-source <A.B.C.D|X:X::X:X|WORD>$source",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Source of routing updates\n"
	"IPv4 address\n"
	"IPv6 address\n"
	"Interface name (requires zebra to be running)\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/update-source", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, source);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	no_neighbor_update_source, no_neighbor_update_source_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer update-source [<A.B.C.D|X:X::X:X|WORD>]",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Source of routing updates\n"
	"IPv4 address\n"
	"IPv6 address\n"
	"Interface name (requires zebra to be running)\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/update-source", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_ip_transparent, neighbor_ip_transparent_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer ip-transparent",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Enable IP_TRANSPARENT on the BGP TCP socket\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/ip-transparent", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, no ? "false" : "true");
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
 * capabilities container (M4 batch B8): dynamic, extended-nexthop,
 * software-version(+latest-encoding), link-local, fqdn -- Tier B, canonical
 * '<enabled|disabled>$mode' grammar (tiers.md) plus two CMD_ATTR_DEPRECATED
 * bare aliases reproducing legacy's only grammar exactly (bare positive ->
 * modify "true"; bare 'no' -> modify "false", NOT a destroy -- that's what
 * legacy actually persisted). dont-capability-negotiate, override-capability,
 * strict-capability-match -- Tier A, single combined '[no]' command like
 * B6's disable-connected-check. All nine shared between neighbor/peer-group
 * via bgp_cli_peer_or_group_xpath(), same as every leaf in this section.
 */
DEFPY_YANG(
	neighbor_capability_dynamic, neighbor_capability_dynamic_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer capability dynamic <enabled|disabled>$mode",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Advertise capability to the peer\n"
	"Advertise dynamic capability to this neighbor\n"
	"Enable dynamic capability\n"
	"Disable dynamic capability\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/capabilities/dynamic", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY,
			      strmatch(mode, "enabled") ? "true" : "false");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	no_neighbor_capability_dynamic, no_neighbor_capability_dynamic_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer capability dynamic <enabled|disabled>$mode",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Advertise capability to the peer\n"
	"Advertise dynamic capability to this neighbor\n"
	"Enable dynamic capability\n"
	"Disable dynamic capability\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/capabilities/dynamic", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_ATTR(
	neighbor_capability_dynamic_deprecated, neighbor_capability_dynamic_deprecated_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer capability dynamic",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Advertise capability to the peer\n"
	"Advertise dynamic capability to this neighbor\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/capabilities/dynamic", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "true");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_ATTR(
	no_neighbor_capability_dynamic_deprecated, no_neighbor_capability_dynamic_deprecated_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer capability dynamic",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Advertise capability to the peer\n"
	"Advertise dynamic capability to this neighbor\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/capabilities/dynamic", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "false");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_capability_enhe, neighbor_capability_enhe_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer capability extended-nexthop <enabled|disabled>$mode",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Advertise capability to the peer\n"
	"Advertise extended next-hop capability to the peer\n"
	"Enable extended next-hop capability\n"
	"Disable extended next-hop capability\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/capabilities/extended-nexthop", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY,
			      strmatch(mode, "enabled") ? "true" : "false");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	no_neighbor_capability_enhe, no_neighbor_capability_enhe_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer capability extended-nexthop <enabled|disabled>$mode",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Advertise capability to the peer\n"
	"Advertise extended next-hop capability to the peer\n"
	"Enable extended next-hop capability\n"
	"Disable extended next-hop capability\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/capabilities/extended-nexthop", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_ATTR(
	neighbor_capability_enhe_deprecated, neighbor_capability_enhe_deprecated_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer capability extended-nexthop",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Advertise capability to the peer\n"
	"Advertise extended next-hop capability to the peer\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/capabilities/extended-nexthop", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "true");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_ATTR(
	no_neighbor_capability_enhe_deprecated, no_neighbor_capability_enhe_deprecated_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer capability extended-nexthop",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Advertise capability to the peer\n"
	"Advertise extended next-hop capability to the peer\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/capabilities/extended-nexthop", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "false");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_capability_software_version, neighbor_capability_software_version_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer capability software-version <enabled|disabled>$mode",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Advertise capability to the peer\n"
	"Advertise Software Version capability to the peer\n"
	"Enable Software Version capability\n"
	"Disable Software Version capability\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/capabilities/software-version", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY,
			      strmatch(mode, "enabled") ? "true" : "false");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	no_neighbor_capability_software_version, no_neighbor_capability_software_version_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer capability software-version <enabled|disabled>$mode",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Advertise capability to the peer\n"
	"Advertise Software Version capability to the peer\n"
	"Enable Software Version capability\n"
	"Disable Software Version capability\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/capabilities/software-version", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_ATTR(
	neighbor_capability_software_version_deprecated,
	neighbor_capability_software_version_deprecated_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer capability software-version",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Advertise capability to the peer\n"
	"Advertise Software Version capability to the peer\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/capabilities/software-version", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "true");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_ATTR(
	no_neighbor_capability_software_version_deprecated,
	no_neighbor_capability_software_version_deprecated_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer capability software-version",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Advertise capability to the peer\n"
	"Advertise Software Version capability to the peer\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/capabilities/software-version", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "false");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_capability_software_version_latest_encoding,
	neighbor_capability_software_version_latest_encoding_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer capability software-version latest-encoding <enabled|disabled>$mode",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Advertise capability to the peer\n"
	"Advertise Software Version capability to the peer\n"
	"Use the latest-encoding defined in draft-abraitis-bgp-version-capability-15\n"
	"Enable latest-encoding\n"
	"Disable latest-encoding\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/capabilities/software-version-latest-encoding",
				 xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY,
			      strmatch(mode, "enabled") ? "true" : "false");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	no_neighbor_capability_software_version_latest_encoding,
	no_neighbor_capability_software_version_latest_encoding_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer capability software-version latest-encoding <enabled|disabled>$mode",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Advertise capability to the peer\n"
	"Advertise Software Version capability to the peer\n"
	"Use the latest-encoding defined in draft-abraitis-bgp-version-capability-15\n"
	"Enable latest-encoding\n"
	"Disable latest-encoding\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/capabilities/software-version-latest-encoding",
				 xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_ATTR(
	neighbor_capability_software_version_latest_encoding_deprecated,
	neighbor_capability_software_version_latest_encoding_deprecated_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer capability software-version latest-encoding",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Advertise capability to the peer\n"
	"Advertise Software Version capability to the peer\n"
	"Use the latest-encoding defined in draft-abraitis-bgp-version-capability-15\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/capabilities/software-version-latest-encoding",
				 xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "true");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_ATTR(
	no_neighbor_capability_software_version_latest_encoding_deprecated,
	no_neighbor_capability_software_version_latest_encoding_deprecated_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer capability software-version latest-encoding",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Advertise capability to the peer\n"
	"Advertise Software Version capability to the peer\n"
	"Use the latest-encoding defined in draft-abraitis-bgp-version-capability-15\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/capabilities/software-version-latest-encoding",
				 xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "false");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_capability_link_local, neighbor_capability_link_local_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer capability link-local <enabled|disabled>$mode",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Advertise capability to the peer\n"
	"Advertise Link-Local Next Hop capability to the peer\n"
	"Enable Link-Local Next Hop capability\n"
	"Disable Link-Local Next Hop capability\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/capabilities/link-local", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY,
			      strmatch(mode, "enabled") ? "true" : "false");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	no_neighbor_capability_link_local, no_neighbor_capability_link_local_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer capability link-local <enabled|disabled>$mode",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Advertise capability to the peer\n"
	"Advertise Link-Local Next Hop capability to the peer\n"
	"Enable Link-Local Next Hop capability\n"
	"Disable Link-Local Next Hop capability\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/capabilities/link-local", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_ATTR(
	neighbor_capability_link_local_deprecated, neighbor_capability_link_local_deprecated_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer capability link-local",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Advertise capability to the peer\n"
	"Advertise Link-Local Next Hop capability to the peer\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/capabilities/link-local", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "true");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_ATTR(
	no_neighbor_capability_link_local_deprecated,
	no_neighbor_capability_link_local_deprecated_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer capability link-local",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Advertise capability to the peer\n"
	"Advertise Link-Local Next Hop capability to the peer\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/capabilities/link-local", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "false");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_capability_fqdn, neighbor_capability_fqdn_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer capability fqdn <enabled|disabled>$mode",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Advertise capability to the peer\n"
	"Advertise fqdn capability to the peer\n"
	"Enable fqdn capability\n"
	"Disable fqdn capability\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/capabilities/fqdn", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY,
			      strmatch(mode, "enabled") ? "true" : "false");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	no_neighbor_capability_fqdn, no_neighbor_capability_fqdn_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer capability fqdn <enabled|disabled>$mode",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Advertise capability to the peer\n"
	"Advertise fqdn capability to the peer\n"
	"Enable fqdn capability\n"
	"Disable fqdn capability\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/capabilities/fqdn", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_ATTR(
	neighbor_capability_fqdn_deprecated, neighbor_capability_fqdn_deprecated_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer capability fqdn",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Advertise capability to the peer\n"
	"Advertise fqdn capability to the peer\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/capabilities/fqdn", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "true");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_ATTR(
	no_neighbor_capability_fqdn_deprecated, no_neighbor_capability_fqdn_deprecated_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer capability fqdn",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Advertise capability to the peer\n"
	"Advertise fqdn capability to the peer\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/capabilities/fqdn", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "false");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_dont_capability_negotiate, neighbor_dont_capability_negotiate_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer dont-capability-negotiate",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Do not perform capability negotiation\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/capabilities/dont-capability-negotiate", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, no ? "false" : "true");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_override_capability, neighbor_override_capability_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer override-capability",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Override capability negotiation result\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/capabilities/override-capability", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, no ? "false" : "true");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_strict_capability, neighbor_strict_capability_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer strict-capability-match",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Strict capability negotiation match\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/capabilities/strict-capability-match", xpath);
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
 * ebgp-multihop, ttl-security hops, disable-connected-check (M4 batch B6):
 * session-tuning leaves shared between neighbor/peer-group via the
 * neighbor-session-parameters grouping. Pure subcommands like B3/B4/B5's,
 * so no legacy DEFUN retention (same rationale as
 * bgp_cli_peer_or_group_xpath()'s doc comment above). ebgp-multihop and
 * ttl-security hops each collapse legacy's separate set/unset DEFUNs
 * (neighbor_ebgp_multihop_cmd/_ttl_cmd/no_neighbor_ebgp_multihop_cmd,
 * neighbor_ttl_security_cmd/no_neighbor_ttl_security_cmd, bgp_vty.c,
 * retired) into one '[no]'-prefixed grammar, same shape as B4/B5's
 * combined commands; disable-connected-check keeps legacy's
 * '<disable-connected-check|enforce-multihop>' keyword alternation
 * (neighbor_disable_connected_check_cmd/no_..., retired) unchanged.
 */

DEFPY_YANG(
	neighbor_ebgp_multihop, neighbor_ebgp_multihop_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer ebgp-multihop [(1-255)]$ttl",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Allow EBGP neighbors not on directly connected networks\n"
	"maximum hop count\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/ebgp-multihop", xpath);
	if (no)
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	else
		/* Bare 'ebgp-multihop' (no ttl_str) is legacy's MAXTTL (255)
		 * default -- the same value that makes the leaf render bare
		 * again on write (see bgp_cli_write_session_scalars() below).
		 */
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, ttl_str ? ttl_str : "255");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_ttl_security, neighbor_ttl_security_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer ttl-security hops (1-254)$hops",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"BGP ttl-security parameters\n"
	"Specify the maximum number of hops to the BGP peer\n"
	"Number of hops to BGP peer\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/ttl-security-hops", xpath);
	if (no)
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, hops_str);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_disable_connected_check, neighbor_disable_connected_check_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer <disable-connected-check|enforce-multihop>",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"one-hop away EBGP peer using loopback address\n"
	"Enforce EBGP neighbors perform multihop\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/disable-connected-check", xpath);
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
 * local-as (+ no-prepend, + replace-as, + dual-as) (M4 batch B9): shares
 * bgp_cli_peer_or_group_xpath() like B3/B4/B5/B6/B7's pure subcommands (no
 * legacy DEFUN retention -- same rationale as that helper's doc comment).
 * Legacy's three positive DEFUNs (neighbor_local_as/_no_prepend/
 * _no_prepend_replace_as, bgp_vty.c, retired) collapse into one
 * nested-optional grammar, the same shape already used for 'shutdown rtt
 * [(1-65535) [count (1-255)]]' (M4 batch B4): 'replace-as' is only
 * reachable after 'no-prepend', and 'dual-as' only after 'replace-as',
 * exactly mirroring which token combinations legacy registered a command
 * for.
 */
static void bgp_cli_enqueue_local_as(struct vty *vty, const char *base_xpath, const char *asnum_str,
				     bool no_prepend, bool replace_as, bool dual_as)
{
	char *xpath_child;

	/*
	 * Same value-pointer-lifetime discipline as bgp_cli_enqueue_remote_as()
	 * above: the asdot high/low buffers must outlive this helper's return
	 * (until the caller's deferred nb_cli_apply_changes()), so they use
	 * static storage rather than this frame's stack.
	 */
	if (strchr(asnum_str, '.')) {
		static char highbuf[8], lowbuf[8];
		as_t as = 0, high, low;

		asn_str2asn(asnum_str, &as);
		high = as >> 16;
		low = as & 0xffff;

		snprintf(highbuf, sizeof(highbuf), "%u", high);
		snprintf(lowbuf, sizeof(lowbuf), "%u", low);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/local-as/asdot/high", base_xpath);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, highbuf);
		XFREE(MTYPE_TMP, xpath_child);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/local-as/asdot/low", base_xpath);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, lowbuf);
		XFREE(MTYPE_TMP, xpath_child);
	} else {
		xpath_child = asprintfrr(MTYPE_TMP, "%s/local-as/plain", base_xpath);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, asnum_str);
		XFREE(MTYPE_TMP, xpath_child);
	}

	/*
	 * Legacy's positive DEFUNs always pass explicit 0/1 for all three
	 * modifiers (bgp_vty.c's neighbor_local_as/_no_prepend/
	 * _no_prepend_replace_as each hard-code the trailing
	 * peer_local_as_set() arguments), never leaving a previously
	 * configured modifier in place -- re-issuing a bare 'neighbor X
	 * local-as ASNUM' resets no-prepend/replace-as/dual-as back to false.
	 * Mirrored here by unconditionally enqueueing all three every time,
	 * matching the Tier A boolean convention used throughout this file
	 * (e.g. neighbor_oad_cli_cmd) of NB_OP_MODIFY "true"/"false" rather
	 * than destroy.
	 */
	xpath_child = asprintfrr(MTYPE_TMP, "%s/local-as/no-prepend", base_xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, no_prepend ? "true" : "false");
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/local-as/replace-as", base_xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, replace_as ? "true" : "false");
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/local-as/dual-as", base_xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, dual_as ? "true" : "false");
	XFREE(MTYPE_TMP, xpath_child);
}

DEFPY_YANG(
	neighbor_local_as, neighbor_local_as_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer local-as ASNUM$asnum [no-prepend$no_prepend [replace-as$replace_as [dual-as$dual_as]]]",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Specify a local-as number\n"
	"AS number expressed in dotted or plain format used as local AS\n"
	"Do not prepend local-as to updates from ebgp peers\n"
	"Do not prepend local-as to updates from ibgp peers\n"
	"Allow peering with a global AS number or local-as number\n")
{
	char *xpath;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	bgp_cli_enqueue_local_as(vty, xpath, asnum_str, !!no_prepend, !!replace_as, !!dual_as);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	no_neighbor_local_as, no_neighbor_local_as_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer local-as [ASNUM [no-prepend [replace-as] [dual-as]]]",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Specify a local-as number\n"
	"AS number expressed in dotted or plain format used as local AS\n"
	"Do not prepend local-as to updates from ebgp peers\n"
	"Do not prepend local-as to updates from ibgp peers\n"
	"Allow peering with a global AS number or local-as number\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	/* Trailing ASNUM/no-prepend/replace-as/dual-as tokens are accepted
	 * but ignored, exactly like legacy's no_neighbor_local_as() DEFUN
	 * (bgp_vty.c, retired): this always fully unsets local-as. */
	xpath_child = asprintfrr(MTYPE_TMP, "%s/local-as/plain", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/local-as/asdot", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/local-as/no-prepend", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "false");
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/local-as/replace-as", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "false");
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/local-as/dual-as", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "false");
	XFREE(MTYPE_TMP, xpath_child);

	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

/*
 * bfd container (M4 batch B10): shares bgp_cli_peer_or_group_xpath() like
 * the other pure subcommands in this section. Legacy's BFD commands lived
 * in bgpd/bgp_bfd.c (neighbor_bfd, neighbor_bfd_param, neighbor_bfd_strict,
 * neighbor_bfd_strict_hold_time, neighbor_bfd_check_controlplane_failure,
 * no_neighbor_bfd, neighbor_bfd_profile/no_neighbor_bfd_profile), all
 * retired. Their build split (HAVE_BFDD) is reproduced here: the inline
 * detect-multiplier/min-rx/min-tx form of 'neighbor X bfd' is a hidden
 * command with a separate BFD daemon present and a visible one without it,
 * and the 'bfd profile' commands exist only with a BFD daemon present --
 * matching bgp_bfd_init()'s conditional install_element()s exactly.
 *
 * 'neighbor X bfd', its inline-timer variant, 'bfd check-control-plane-
 * failure', and 'bfd strict hold-time N' each enable BFD (legacy's
 * bgp_{peer,group}_configure_bfd() marking bfd_config->manual), so they
 * co-enqueue bfd/enabled=true; the emission gate for the enable line is
 * exactly that leaf. 'bfd strict' alone does not (legacy's
 * neighbor_bfd_strict is a bare flag toggle) and only sets bfd/strict.
 */
static void bgp_cli_bfd_enqueue_disable(struct vty *vty, const char *base_xpath)
{
	char *xpath_child;

	/* 'no neighbor X bfd' frees the whole bfd_config in legacy
	 * (bgp_peer_remove_bfd()/bgp_group_remove_bfd(), resetting the timers,
	 * control-plane-failure bit, profile and strict hold-time back to
	 * their defaults) while leaving the PEER_FLAG_BFD_STRICT flag itself
	 * untouched -- reproduced here by resetting every bfd_config-data
	 * leaf to its default and leaving bfd/strict alone.
	 */
	xpath_child = asprintfrr(MTYPE_TMP, "%s/bfd/enabled", base_xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "false");
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/bfd/detect-multiplier", base_xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "3");
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/bfd/min-rx", base_xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "300");
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/bfd/min-tx", base_xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "300");
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/bfd/check-control-plane-failure", base_xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "false");
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/bfd/profile", base_xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/bfd/strict-hold-time", base_xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);
}

DEFPY_YANG(
	neighbor_bfd, neighbor_bfd_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer bfd",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Enables BFD support\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/bfd/enabled", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "true");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

/* Legacy hid this inline-timer form in builds with a separate BFD daemon
 * (neighbor_bfd_param's DEFUN_HIDDEN vs DEFUN split, bgpd/bgp_bfd.c). The
 * two full macro invocations below reproduce that, sharing one body -- the
 * CPP branch sits between complete DEFPY_YANG[_HIDDEN](...) headers so it
 * never splits a macro argument list (which clippy cannot parse).
 */
#if HAVE_BFDD > 0
DEFPY_YANG_HIDDEN(
	neighbor_bfd_param, neighbor_bfd_param_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer bfd (2-255)$multiplier (50-60000)$rx (50-60000)$tx",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Enables BFD support\n"
	"Detect Multiplier\n"
	"Required min receive interval\n"
	"Desired min transmit interval\n")
#else
DEFPY_YANG(
	neighbor_bfd_param, neighbor_bfd_param_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer bfd (2-255)$multiplier (50-60000)$rx (50-60000)$tx",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Enables BFD support\n"
	"Detect Multiplier\n"
	"Required min receive interval\n"
	"Desired min transmit interval\n")
#endif
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/bfd/enabled", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "true");
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/bfd/detect-multiplier", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, multiplier_str);
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/bfd/min-rx", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, rx_str);
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/bfd/min-tx", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, tx_str);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

#if HAVE_BFDD > 0
DEFPY_YANG(
	no_neighbor_bfd, no_neighbor_bfd_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer bfd",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Disables BFD support\n")
#else
DEFPY_YANG(
	no_neighbor_bfd, no_neighbor_bfd_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer bfd [(2-255) (50-60000) (50-60000)]",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Disables BFD support\n"
	"Detect Multiplier\n"
	"Required min receive interval\n"
	"Desired min transmit interval\n")
#endif
{
	char *xpath;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	bgp_cli_bfd_enqueue_disable(vty, xpath);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_bfd_check_controlplane_failure, neighbor_bfd_check_controlplane_failure_cli_cmd,
	"[no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer bfd check-control-plane-failure",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"BFD support\n"
	"Link dataplane status with BGP controlplane\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	if (!no) {
		xpath_child = asprintfrr(MTYPE_TMP, "%s/bfd/enabled", xpath);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "true");
		XFREE(MTYPE_TMP, xpath_child);
	}

	xpath_child = asprintfrr(MTYPE_TMP, "%s/bfd/check-control-plane-failure", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, no ? "false" : "true");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_bfd_strict, neighbor_bfd_strict_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer bfd strict",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"BFD support\n"
	"Strict mode\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/bfd/strict", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, no ? "false" : "true");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_bfd_strict_hold_time, neighbor_bfd_strict_hold_time_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer bfd strict hold-time ![(1-4294967295)$hold_time]",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"BFD support\n"
	"Strict mode\n"
	"BFD Hold time in seconds\n"
	"Seconds to wait before declaring BFD session down\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	if (no) {
		xpath_child = asprintfrr(MTYPE_TMP, "%s/bfd/strict", xpath);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "false");
		XFREE(MTYPE_TMP, xpath_child);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/bfd/strict-hold-time", xpath);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
		XFREE(MTYPE_TMP, xpath_child);
	} else {
		xpath_child = asprintfrr(MTYPE_TMP, "%s/bfd/enabled", xpath);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "true");
		XFREE(MTYPE_TMP, xpath_child);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/bfd/strict", xpath);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "true");
		XFREE(MTYPE_TMP, xpath_child);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/bfd/strict-hold-time", xpath);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, hold_time_str);
		XFREE(MTYPE_TMP, xpath_child);
	}
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

#if HAVE_BFDD > 0
DEFPY_YANG(
	neighbor_bfd_profile, neighbor_bfd_profile_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer bfd profile BFDPROF$profile",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"BFD integration\n"
	BFD_PROFILE_STR
	BFD_PROFILE_NAME_STR)
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/bfd/enabled", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "true");
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/bfd/profile", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, profile);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	no_neighbor_bfd_profile, no_neighbor_bfd_profile_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer bfd profile [BFDPROF]",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"BFD integration\n"
	BFD_PROFILE_STR
	BFD_PROFILE_NAME_STR)
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/bfd/profile", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}
#endif /* HAVE_BFDD */

/*
 * graceful-restart-mode (M4 batch B11): shares bgp_cli_peer_or_group_xpath()
 * like B3/B4/B5/B6/B7/B9/B10's pure subcommands (no legacy DEFUN retention).
 * Legacy's six DEFUNs (bgp_neighbor_graceful_restart_set/
 * no_bgp_neighbor_graceful_restart/bgp_neighbor_graceful_restart_helper_set/
 * no_bgp_neighbor_graceful_restart_helper/
 * bgp_neighbor_graceful_restart_disable_set/
 * no_bgp_neighbor_graceful_restart_disable, bgp_vty.c, retired) collapse
 * into three MODIFY/DESTROY pairs on one enum leaf, same shape as B13's
 * instance-level 'bgp graceful-restart'/'bgp graceful-restart-disable' mode
 * commands (bgp_cli_instance.c). All trailing tokens on the 'no' forms are
 * irrelevant (DESTROY always fully unsets, matching legacy's own three 'no'
 * DEFUNs, none of which take an argument); only the base command word
 * (graceful-restart/-helper/-disable) distinguishes the three DESTROY call
 * sites here, and all three enqueue the identical DESTROY -- the actual
 * "which of the three 'no' forms was issued" distinction is irrelevant at
 * the northbound layer too, since instance_neighbor_graceful_restart_mode_destroy()/
 * instance_peer_group_graceful_restart_mode_destroy() (bgp_nb_instance_gr.c)
 * read the *old* value to decide which underlying command to replay, not
 * which 'no' spelling was used -- exactly mirroring legacy's FSM, where
 * e.g. 'no neighbor X graceful-restart-helper' while X is actually in
 * restarter mode is a documented no-op (NO_PEER_HELPER_CMD only has a
 * transition defined out of PEER_HELPER mode).
 *
 * The "Graceful restart configuration changed, reset this peer to take
 * effect" message accompanies only the bare graceful-restart and
 * graceful-restart-helper forms in legacy (never graceful-restart-disable),
 * gated there on BGP_GR_SUCCESS; reproduced here unconditionally, same
 * precedent as the tcp-mss session-reset warning (M4 batch B3) -- the CLI
 * layer has no visibility into the northbound APPLY's per-transition FSM
 * result. See bgp_nb_instance_gr.c's callback comment for why no actual
 * extra reset call is needed: bgp_neighbor_graceful_restart() already
 * performs one as a side effect of a real transition.
 */
DEFPY_YANG(
	neighbor_graceful_restart, neighbor_graceful_restart_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer graceful-restart",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	GR_NEIGHBOR_CMD)
{
	char *xpath, *xpath_child;
	int ret;

	vty_out(vty, "Graceful restart configuration changed, reset this peer to take effect\n");

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/graceful-restart-mode", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "restarter");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	no_neighbor_graceful_restart, no_neighbor_graceful_restart_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer graceful-restart",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	NO_GR_NEIGHBOR_CMD)
{
	char *xpath, *xpath_child;
	int ret;

	vty_out(vty, "Graceful restart configuration changed, reset this peer to take effect\n");

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/graceful-restart-mode", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_graceful_restart_helper, neighbor_graceful_restart_helper_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer graceful-restart-helper",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	GR_NEIGHBOR_HELPER_CMD)
{
	char *xpath, *xpath_child;
	int ret;

	vty_out(vty, "Graceful restart configuration changed, reset this peer to take effect\n");

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/graceful-restart-mode", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "helper");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	no_neighbor_graceful_restart_helper, no_neighbor_graceful_restart_helper_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer graceful-restart-helper",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	NO_GR_NEIGHBOR_HELPER_CMD)
{
	char *xpath, *xpath_child;
	int ret;

	vty_out(vty, "Graceful restart configuration changed, reset this peer to take effect\n");

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/graceful-restart-mode", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_graceful_restart_disable, neighbor_graceful_restart_disable_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer graceful-restart-disable",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	GR_NEIGHBOR_DISABLE_CMD)
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/graceful-restart-mode", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "disable");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	no_neighbor_graceful_restart_disable, no_neighbor_graceful_restart_disable_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer graceful-restart-disable",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	NO_GR_NEIGHBOR_DISABLE_CMD)
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/graceful-restart-mode", xpath);
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

/* rpki-strict, sender-as-path-loop-detection, send-nexthop-characteristics,
 * disable-link-bw-encoding-ieee, extended-link-bandwidth, extended-optional-
 * parameters (M4 batch B13): the remaining plain Tier A session-level flags
 * shared between neighbor/peer-group. Pure subcommands like B3/B4/B5/B6/
 * B7/B9/B10's (no legacy DEFUN retention, same rationale as
 * bgp_cli_peer_or_group_xpath()'s doc comment above); each collapses its
 * legacy DEFUN(s) (which/whether a 'no' twin exists in legacy varies leaf
 * by leaf, but all six are the same "no$no" Tier A modify-only shape here,
 * matching passive/disable-connected-check) into one MODIFY-to-"true"/
 * "false" DEFPY_YANG.
 */
DEFPY_YANG(
	neighbor_rpki_strict, neighbor_rpki_strict_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer rpki strict",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"RPKI configuration\n"
	"Strict mode\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/rpki-strict", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, no ? "false" : "true");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_aspath_loop_detection, neighbor_aspath_loop_detection_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer sender-as-path-loop-detection",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Detect AS loops before sending to neighbor\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/sender-as-path-loop-detection", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, no ? "false" : "true");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

/* 'neighbor X path-attribute discard (1-255)...' (M4 batch B14): reproduces
 * neighbor_path_attribute_discard_cmd (bgp_vty.c, retired) -- one
 * nb_cli_enqueue_change(CREATE) per attribute number on the line, all
 * applied together in a single commit (leaf-list entries, additive; see
 * the northbound callbacks' doc comment, bgp_nb_neighbor.c, for why the
 * legacy _vty() wrapper's whole-array "clear then set" replace semantics
 * is deliberately not replicated here).
 */
DEFPY_YANG(
	neighbor_path_attribute_discard, neighbor_path_attribute_discard_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer path-attribute discard (1-255)...",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Manipulate path attributes from incoming UPDATE messages\n"
	"Drop specified attributes from incoming UPDATE messages\n"
	"Attribute number\n")
{
	char *xpath, *xpath_child;
	int idx = 0;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	argv_find(argv, argc, "(1-255)", &idx);
	for (; idx < argc; idx++) {
		xpath_child = asprintfrr(MTYPE_TMP, "%s/path-attribute-discard[.='%s']", xpath,
					 argv[idx]->arg);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_CREATE, NULL);
		XFREE(MTYPE_TMP, xpath_child);
	}
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

/* 'no neighbor X path-attribute discard [(1-255)]' (M4 batch B14):
 * reproduces no_neighbor_path_attribute_discard_cmd (bgp_vty.c, retired)
 * byte-for-byte, including its asymmetry with the 'no' form below -- this
 * grammar takes at most *one* attribute number (destroying just that
 * entry), while an absent number destroys the whole leaf-list, matching
 * legacy's "no args -> flush all" branch in bgp_path_attribute_discard_vty().
 */
DEFPY_YANG(
	no_neighbor_path_attribute_discard, no_neighbor_path_attribute_discard_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer path-attribute discard [(1-255)]$attr_num",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Manipulate path attributes from incoming UPDATE messages\n"
	"Drop specified attributes from incoming UPDATE messages\n"
	"Attribute number\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	if (attr_num_str)
		xpath_child = asprintfrr(MTYPE_TMP, "%s/path-attribute-discard[.='%s']", xpath,
					 attr_num_str);
	else
		xpath_child = asprintfrr(MTYPE_TMP, "%s/path-attribute-discard", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

/* 'neighbor X path-attribute treat-as-withdraw (1-255)...' (M4 batch B14):
 * treat-as-withdraw's positive-form sibling of discard above, same
 * per-entry CREATE loop.
 */
DEFPY_YANG(
	neighbor_path_attribute_treat_as_withdraw, neighbor_path_attribute_treat_as_withdraw_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer path-attribute treat-as-withdraw (1-255)...",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Manipulate path attributes from incoming UPDATE messages\n"
	"Treat-as-withdraw any incoming BGP UPDATE messages that contain the specified attribute\n"
	"Attribute number\n")
{
	char *xpath, *xpath_child;
	int idx = 0;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	argv_find(argv, argc, "(1-255)", &idx);
	for (; idx < argc; idx++) {
		xpath_child = asprintfrr(MTYPE_TMP, "%s/path-attribute-treat-as-withdraw[.='%s']",
					 xpath, argv[idx]->arg);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_CREATE, NULL);
		XFREE(MTYPE_TMP, xpath_child);
	}
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

/* 'no neighbor X path-attribute treat-as-withdraw (1-255)...' (M4 batch
 * B14): reproduces no_neighbor_path_attribute_treat_as_withdraw_cmd
 * (bgp_vty.c, retired) byte-for-byte -- unlike discard's 'no' form above,
 * legacy's grammar here requires at least one attribute number (no '[...]'
 * around the range, confirmed by direct inspection of bgp_vty.c); there is
 * no legacy CLI path that ever flushes the whole treat-as-withdraw
 * leaf-list in one command (an asymmetry with discard, not a mistake in
 * this conversion).
 */
DEFPY_YANG(
	no_neighbor_path_attribute_treat_as_withdraw,
	no_neighbor_path_attribute_treat_as_withdraw_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer path-attribute treat-as-withdraw (1-255)...",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Manipulate path attributes from incoming UPDATE messages\n"
	"Treat-as-withdraw any incoming BGP UPDATE messages that contain the specified attribute\n"
	"Attribute number\n")
{
	char *xpath, *xpath_child;
	int idx = 0;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	argv_find(argv, argc, "(1-255)", &idx);
	for (; idx < argc; idx++) {
		xpath_child = asprintfrr(MTYPE_TMP, "%s/path-attribute-treat-as-withdraw[.='%s']",
					 xpath, argv[idx]->arg);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
		XFREE(MTYPE_TMP, xpath_child);
	}
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_nhc_attribute, neighbor_nhc_attribute_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer send-nexthop-characteristics",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Send BGP Next Hop Dependent Characteristics Attribute\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/send-nexthop-characteristics", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, no ? "false" : "true");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_disable_link_bw_encoding_ieee, neighbor_disable_link_bw_encoding_ieee_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer disable-link-bw-encoding-ieee",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Disable IEEE floating-point encoding for extended community bandwidth\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/disable-link-bw-encoding-ieee", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, no ? "false" : "true");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_extended_link_bw, neighbor_extended_link_bw_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer extended-link-bandwidth",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Send Extended (64-bit) version of encoding for Link-Bandwidth\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/extended-link-bandwidth", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, no ? "false" : "true");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_extended_optional_parameters, neighbor_extended_optional_parameters_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer extended-optional-parameters",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Force the extended optional parameters format for OPEN messages\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/extended-optional-parameters", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, no ? "false" : "true");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
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
struct bgp_cli_path_attribute_collect_ctx {
	bool present[256];
};

static int bgp_cli_path_attribute_collect_cb(const struct lyd_node *dnode, void *arg)
{
	struct bgp_cli_path_attribute_collect_ctx *ctx = arg;

	ctx->present[yang_dnode_get_uint8(dnode, NULL)] = true;

	return YANG_ITER_CONTINUE;
}

/* Builds the space-separated attribute-number list legacy's
 * bgp_path_attribute_discard()/bgp_path_attribute_treat_as_withdraw()
 * (bgpd.c, retired) produce for config-write -- in ascending numeric order
 * regardless of the leaf-list's own (implementation-defined, "ordered-by
 * system") storage/iteration order, so this stays byte-identical to
 * legacy's own "for (i = 1; i <= BGP_ATTR_MAX; i++)" scan. Returns false
 * (nothing to print) when the leaf-list is empty, matching legacy's bool
 * return.
 */
static bool bgp_cli_path_attribute_list(const struct lyd_node *dnode, const char *leaf_list,
					char *buf, size_t buflen)
{
	struct bgp_cli_path_attribute_collect_ctx ctx = { 0 };
	bool any = false;
	unsigned int i;

	yang_dnode_iterate(bgp_cli_path_attribute_collect_cb, &ctx, dnode, "./%s", leaf_list);

	buf[0] = '\0';
	for (i = 1; i <= 255; i++) {
		if (!ctx.present[i])
			continue;

		snprintf(buf + strlen(buf), buflen - strlen(buf), "%s%u",
			 strlen(buf) > 0 ? " " : "", i);
		any = true;
	}

	return any;
}

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

	/* bfd (+ inline timers, check-control-plane-failure, profile, strict,
	 * strict hold-time) (M4 batch B10): reproduces bgp_bfd_peer_config_write()
	 * (bgpd/bgp_bfd.c, retired). The enable line is gated on this entry's
	 * own bfd/enabled leaf -- the northbound mirror of legacy's
	 * '(!group && bfd_config->manual) || group' gate (bfd_config->manual
	 * being the explicit-configured marker, set true by every enabling
	 * command; a peer-group's own conf always renders it). The bare form
	 * carries the inline detect-multiplier/min-rx/min-tx triple only in
	 * builds without a separate BFD daemon -- the one HAVE_BFDD split in
	 * this function, matching the legacy config-writer's own #if exactly
	 * (the build-conditional belongs here in the C writer, never in the
	 * YANG, which models every leaf unconditionally). profile/check-
	 * control-plane-failure/strict lines are each gated on their own leaf,
	 * as in legacy; strict renders bare unless its hold-time diverges from
	 * the default, exactly like legacy's hold_time != BFD_DEF_STRICT_HOLD_TIME
	 * branch.
	 */
	if (yang_dnode_get_bool(dnode, "bfd/enabled")) {
#if HAVE_BFDD > 0
		vty_out(vty, " neighbor %s bfd\n", addr);
#else
		vty_out(vty, " neighbor %s bfd %u %u %u\n", addr,
			yang_dnode_get_uint8(dnode, "bfd/detect-multiplier"),
			yang_dnode_get_uint32(dnode, "bfd/min-rx"),
			yang_dnode_get_uint32(dnode, "bfd/min-tx"));
#endif /* HAVE_BFDD */
	}

	if (yang_dnode_exists(dnode, "bfd/profile"))
		vty_out(vty, " neighbor %s bfd profile %s\n", addr,
			yang_dnode_get_string(dnode, "bfd/profile"));

	if (yang_dnode_get_bool(dnode, "bfd/check-control-plane-failure"))
		vty_out(vty, " neighbor %s bfd check-control-plane-failure\n", addr);

	if (yang_dnode_get_bool(dnode, "bfd/strict")) {
		uint32_t hold_time = yang_dnode_exists(dnode, "bfd/strict-hold-time")
					     ? yang_dnode_get_uint32(dnode, "bfd/strict-hold-time")
					     : BFD_DEF_STRICT_HOLD_TIME;

		if (hold_time != BFD_DEF_STRICT_HOLD_TIME)
			vty_out(vty, " neighbor %s bfd strict hold-time %u\n", addr, hold_time);
		else
			vty_out(vty, " neighbor %s bfd strict\n", addr);
	}

	/* ebgp-multihop (M4 batch B6): reproduces bgp_config_write_peer_global()'s
	 * (bgp_vty.c, retired) ebgp-multihop block, gated purely on this entry's
	 * own leaf presence -- the northbound mirror of legacy's
	 * '!peer_group_active(peer) || CHECK_FLAG(peer->flags,
	 * PEER_FLAG_EBGP_MULTIHOP)' ownership check (PEER_FLAG_EBGP_MULTIHOP is
	 * always mirrored into flags_override, bgpd.c's peer_cfg_ttl_set()), same
	 * "presence on this dnode is exactly legacy's ownership flag" principle
	 * already used for description/password/etc. above. 255 (MAXTTL) is the
	 * bare 'ebgp-multihop' form; any other value carries the explicit hop
	 * count.
	 */
	if (yang_dnode_exists(dnode, "ebgp-multihop")) {
		uint8_t ttl = yang_dnode_get_uint8(dnode, "ebgp-multihop");

		if (ttl != MAXTTL)
			vty_out(vty, " neighbor %s ebgp-multihop %u\n", addr, ttl);
		else
			vty_out(vty, " neighbor %s ebgp-multihop\n", addr);
	}

	if (yang_dnode_exists(dnode, "aigp") && yang_dnode_get_bool(dnode, "aigp"))
		vty_out(vty, " neighbor %s aigp\n", addr);

	if (yang_dnode_exists(dnode, "graceful-shutdown") &&
	    yang_dnode_get_bool(dnode, "graceful-shutdown"))
		vty_out(vty, " neighbor %s graceful-shutdown\n", addr);

	if (yang_dnode_exists(dnode, "oad") && yang_dnode_get_bool(dnode, "oad"))
		vty_out(vty, " neighbor %s oad\n", addr);

	/* ttl-security hops, disable-connected-check (M4 batch B6):
	 * reproduces bgp_config_write_peer_global()'s (bgp_vty.c, retired)
	 * ttl-security-hops-through-disable-connected-check block.
	 * ttl-security-hops is gated on this entry's own leaf presence rather
	 * than legacy's '!peer_group_active(peer) || g_peer->gtsm_hops !=
	 * peer->gtsm_hops' value comparison: gtsm_hops has no ownership flag
	 * of its own in legacy (unlike ebgp-multihop's PEER_FLAG_EBGP_MULTIHOP),
	 * so that comparison is itself only a best-effort proxy for ownership,
	 * and can under-suppress a member whose explicit hop count happens to
	 * numerically match its group's -- the same value-comparison edge case
	 * already documented (and deliberately not replicated) for remote-as in
	 * neighbor_cli_write() above. Leaf presence is the exact ownership
	 * invariant the legacy check was approximating.
	 */
	if (yang_dnode_exists(dnode, "ttl-security-hops"))
		vty_out(vty, " neighbor %s ttl-security hops %u\n", addr,
			yang_dnode_get_uint8(dnode, "ttl-security-hops"));

	if (yang_dnode_exists(dnode, "disable-connected-check") &&
	    yang_dnode_get_bool(dnode, "disable-connected-check"))
		vty_out(vty, " neighbor %s disable-connected-check\n", addr);

	/* local-as (+ no-prepend, + replace-as, + dual-as) (M4 batch B9):
	 * reproduces bgp_config_write_peer_global()'s (bgp_vty.c, retired)
	 * local-as block, gated on this entry's own local-as/plain-or-asdot
	 * presence -- the same "presence is exactly legacy's ownership
	 * flag" principle used throughout this function -- rather than
	 * legacy's peergroup_flag_check(peer, PEER_FLAG_LOCAL_AS) runtime
	 * check. Renders the canonical plain/asdot notation reconstructed
	 * from the stored structured value, the same convention already
	 * used for the instance-level autonomous-system and confederation
	 * identifier leaves, rather than preserving peer->change_local_as_pretty's
	 * literal typed string.
	 */
	if (yang_dnode_exists(dnode, "local-as/plain") ||
	    yang_dnode_exists(dnode, "local-as/asdot")) {
		if (yang_dnode_exists(dnode, "local-as/plain"))
			vty_out(vty, " neighbor %s local-as %u", addr,
				yang_dnode_get_uint32(dnode, "local-as/plain"));
		else
			vty_out(vty, " neighbor %s local-as %u.%u", addr,
				yang_dnode_get_uint16(dnode, "local-as/asdot/high"),
				yang_dnode_get_uint16(dnode, "local-as/asdot/low"));

		if (yang_dnode_exists(dnode, "local-as/no-prepend") &&
		    yang_dnode_get_bool(dnode, "local-as/no-prepend"))
			vty_out(vty, " no-prepend");
		if (yang_dnode_exists(dnode, "local-as/replace-as") &&
		    yang_dnode_get_bool(dnode, "local-as/replace-as"))
			vty_out(vty, " replace-as");
		if (yang_dnode_exists(dnode, "local-as/dual-as") &&
		    yang_dnode_get_bool(dnode, "local-as/dual-as"))
			vty_out(vty, " dual-as");
		vty_out(vty, "\n");
	}

	/* update-source, ip-transparent (M4 batch B7): reproduces
	 * bgp_config_write_peer_global()'s (bgp_vty.c, retired for these
	 * two leaves) update-source-through-ip-transparent block, in the
	 * same relative order (right before the still-legacy enforce-
	 * first-as/BGP-LS block, which sit in between in bgp_vty.c but are
	 * unconverted and thus not reproduced here). Gated on this entry's
	 * own leaf presence, the same "presence is exactly legacy's
	 * ownership flag" principle used throughout this function --
	 * update-source's union value renders identically via its string
	 * form regardless of which union branch (address vs interface
	 * name) matched, so a plain %s suffices where legacy needed a
	 * peer->update_source vs. peer->update_if branch.
	 */
	if (yang_dnode_exists(dnode, "update-source"))
		vty_out(vty, " neighbor %s update-source %s\n", addr,
			yang_dnode_get_string(dnode, "update-source"));

	if (yang_dnode_exists(dnode, "ip-transparent") &&
	    yang_dnode_get_bool(dnode, "ip-transparent"))
		vty_out(vty, " neighbor %s ip-transparent\n", addr);

	/* capabilities container (M4 batch B8): reproduces
	 * bgp_config_write_peer_global()'s (bgp_vty.c, retired) capability-
	 * dynamic-through-strict-capability-match block, skipping rpki-strict
	 * (unconverted, stays legacy, B13) which sits between the software-
	 * version-latest-encoding and link-local lines there. Gated on this
	 * entry's own leaf presence for all six Tier B leaves -- the same
	 * "presence is exactly legacy's ownership flag" principle used
	 * throughout this function -- rather than legacy's various value-
	 * comparison approximations (fqdn's inverted comparison never
	 * renders an explicit re-enable to the default; link-local's extra
	 * conf_if special case), deliberately not replicated for the same
	 * reason ttl-security-hops' (M4 batch B6) wasn't.
	 */
	if (yang_dnode_exists(dnode, "capabilities/dynamic"))
		vty_out(vty, " neighbor %s capability dynamic %s\n", addr,
			yang_dnode_get_bool(dnode, "capabilities/dynamic") ? "enabled"
									   : "disabled");

	if (yang_dnode_exists(dnode, "capabilities/extended-nexthop"))
		vty_out(vty, " neighbor %s capability extended-nexthop %s\n", addr,
			yang_dnode_get_bool(dnode, "capabilities/extended-nexthop") ? "enabled"
										    : "disabled");

	if (yang_dnode_exists(dnode, "capabilities/software-version"))
		vty_out(vty, " neighbor %s capability software-version %s\n", addr,
			yang_dnode_get_bool(dnode, "capabilities/software-version") ? "enabled"
										    : "disabled");

	if (yang_dnode_exists(dnode, "capabilities/software-version-latest-encoding"))
		vty_out(vty, " neighbor %s capability software-version latest-encoding %s\n", addr,
			yang_dnode_get_bool(dnode, "capabilities/software-version-latest-encoding")
				? "enabled"
				: "disabled");

	if (yang_dnode_exists(dnode, "capabilities/link-local"))
		vty_out(vty, " neighbor %s capability link-local %s\n", addr,
			yang_dnode_get_bool(dnode, "capabilities/link-local") ? "enabled"
									      : "disabled");

	if (yang_dnode_exists(dnode, "capabilities/fqdn"))
		vty_out(vty, " neighbor %s capability fqdn %s\n", addr,
			yang_dnode_get_bool(dnode, "capabilities/fqdn") ? "enabled" : "disabled");

	if (yang_dnode_exists(dnode, "capabilities/dont-capability-negotiate") &&
	    yang_dnode_get_bool(dnode, "capabilities/dont-capability-negotiate"))
		vty_out(vty, " neighbor %s dont-capability-negotiate\n", addr);

	if (yang_dnode_exists(dnode, "capabilities/override-capability") &&
	    yang_dnode_get_bool(dnode, "capabilities/override-capability"))
		vty_out(vty, " neighbor %s override-capability\n", addr);

	if (yang_dnode_exists(dnode, "capabilities/strict-capability-match") &&
	    yang_dnode_get_bool(dnode, "capabilities/strict-capability-match"))
		vty_out(vty, " neighbor %s strict-capability-match\n", addr);

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

	/* graceful-restart-mode (M4 batch B11): reproduces
	 * bgp_config_write_peer_global()'s (bgp_vty.c, retired) per-neighbor
	 * graceful-restart block. Presence-based like every Tier B leaf in
	 * this function -- only present when this exact entry's own
	 * graceful-restart/-helper/-disable command was issued -- rather than
	 * legacy's peer->peer_gr_new_status_flag runtime read, which can
	 * diverge from this entry's own stored command after a later
	 * peer-group-level fanout (see bgp_nb_instance_gr.c's callback
	 * comment).
	 */
	if (yang_dnode_exists(dnode, "graceful-restart-mode")) {
		const char *mode = yang_dnode_get_string(dnode, "graceful-restart-mode");

		if (strmatch(mode, "restarter"))
			vty_out(vty, " neighbor %s graceful-restart\n", addr);
		else if (strmatch(mode, "helper"))
			vty_out(vty, " neighbor %s graceful-restart-helper\n", addr);
		else
			vty_out(vty, " neighbor %s graceful-restart-disable\n", addr);
	}

	/* local-role (+ strict-mode) (M4 batch B12): reproduces
	 * bgp_config_write_peer_global()'s (bgp_vty.c, retired) role block.
	 * Gated on 'local-role/role's own presence (no YANG default, unlike
	 * strict-mode) -- the same "presence is exactly legacy's ownership
	 * flag" principle used throughout this function, replacing legacy's
	 * peergroup_flag_check(peer, PEER_FLAG_ROLE) && local_role !=
	 * ROLE_UNDEFINED value-comparison pair. The YANG enum string already
	 * matches the CLI keyword directly, so no bgp_get_name_by_role()
	 * round-trip is needed.
	 */
	if (yang_dnode_exists(dnode, "local-role/role"))
		vty_out(vty, " neighbor %s local-role %s%s\n", addr,
			yang_dnode_get_string(dnode, "local-role/role"),
			yang_dnode_get_bool(dnode, "local-role/strict-mode") ? " strict-mode" : "");

	/* enforce-first-as (M4 batch B12): reproduces
	 * bgp_config_write_peer_global()'s (bgp_vty.c, retired) enforce-first-as
	 * block. Tier B, gated on this entry's own leaf presence like every
	 * other Tier B leaf in this function, replacing legacy's
	 * peergroup_flag_check(peer, PEER_FLAG_ENFORCE_FIRST_AS) plus its
	 * bgp->flags-derived polarity inversion for display.
	 */
	if (yang_dnode_exists(dnode, "enforce-first-as"))
		vty_out(vty, " neighbor %s enforce-first-as %s\n", addr,
			yang_dnode_get_bool(dnode, "enforce-first-as") ? "enabled" : "disabled");

	/* rpki-strict, sender-as-path-loop-detection, send-nexthop-
	 * characteristics, disable-link-bw-encoding-ieee, extended-link-
	 * bandwidth, extended-optional-parameters (M4 batch B13): reproduces
	 * bgp_config_write_peer_global()'s (bgp_vty.c, retired for these six
	 * leaves) disable-link-bw-encoding-ieee-through-send-nexthop-
	 * characteristics lines (physically split across that function by
	 * the path-attribute discard/treat-as-withdraw block, B14 below,
	 * which sits in between rpki-strict/sender-as-path-loop-detection
	 * and send-nexthop-characteristics there). Tier A, gated on this
	 * entry's own leaf presence like every other Tier A boolean in this
	 * function, replacing legacy's peergroup_flag_check() reads.
	 */
	if (yang_dnode_exists(dnode, "disable-link-bw-encoding-ieee") &&
	    yang_dnode_get_bool(dnode, "disable-link-bw-encoding-ieee"))
		vty_out(vty, " neighbor %s disable-link-bw-encoding-ieee\n", addr);

	if (yang_dnode_exists(dnode, "extended-link-bandwidth") &&
	    yang_dnode_get_bool(dnode, "extended-link-bandwidth"))
		vty_out(vty, " neighbor %s extended-link-bandwidth\n", addr);

	if (yang_dnode_exists(dnode, "extended-optional-parameters") &&
	    yang_dnode_get_bool(dnode, "extended-optional-parameters"))
		vty_out(vty, " neighbor %s extended-optional-parameters\n", addr);

	if (yang_dnode_exists(dnode, "rpki-strict") && yang_dnode_get_bool(dnode, "rpki-strict"))
		vty_out(vty, " neighbor %s rpki strict\n", addr);

	if (yang_dnode_exists(dnode, "sender-as-path-loop-detection") &&
	    yang_dnode_get_bool(dnode, "sender-as-path-loop-detection"))
		vty_out(vty, " neighbor %s sender-as-path-loop-detection\n", addr);

	/* path-attribute discard / treat-as-withdraw (M4 batch B14):
	 * reproduces bgp_config_write_peer_global()'s (bgp_vty.c, retired)
	 * path-attribute discard/treat-as-withdraw block, in the same
	 * relative position. One line per non-empty leaf-list, attribute
	 * numbers in ascending order (see bgp_cli_path_attribute_list()).
	 */
	{
		char attrs[BUFSIZ];

		if (bgp_cli_path_attribute_list(dnode, "path-attribute-discard", attrs,
						sizeof(attrs)))
			vty_out(vty, " neighbor %s path-attribute discard %s\n", addr, attrs);

		if (bgp_cli_path_attribute_list(dnode, "path-attribute-treat-as-withdraw", attrs,
						sizeof(attrs)))
			vty_out(vty, " neighbor %s path-attribute treat-as-withdraw %s\n", addr,
				attrs);
	}

	if (yang_dnode_exists(dnode, "send-nexthop-characteristics") &&
	    yang_dnode_get_bool(dnode, "send-nexthop-characteristics"))
		vty_out(vty, " neighbor %s send-nexthop-characteristics\n", addr);
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

/*
 * 'neighbor X local-role <role> [strict-mode]' / 'no neighbor X local-role
 * <role> [strict-mode]' (RFC 9234, M4 batch B12): shared between neighbor/
 * peer-group via bgp_cli_peer_or_group_xpath() like every leaf in this
 * file. The bare and strict-mode variants enqueue an explicit MODIFY on
 * the sibling 'strict-mode' leaf alongside 'role' -- strict-mode has a YANG
 * default and so is modify-only (no .destroy), the same convention as
 * aigp/oad's bare '[no]' grammar above -- rather than leaving it untouched,
 * reproducing peer_role_set()'s own unconditional strict_mode overwrite on
 * any role change (bgpd.c, see bgp_nb_neighbor_role_apply()'s doc comment,
 * bgp_nb_util.c). The 'no' form's role DESTROY and strict-mode MODIFY
 * "false" together reproduce peer_role_unset()'s full reset, the same
 * composite-destroy-across-siblings idiom already used for
 * 'shutdown [message]' (M4 batch B4).
 */
DEFPY_YANG(
	neighbor_role, neighbor_role_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer local-role <provider|rs-server|rs-client|customer|peer>$role",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Set session role\n"
	ROLE_STR)
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/local-role/role", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, role);
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/local-role/strict-mode", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "false");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_role_strict, neighbor_role_strict_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer local-role <provider|rs-server|rs-client|customer|peer>$role strict-mode",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Set session role\n"
	ROLE_STR
	"Use additional restriction on peer\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/local-role/role", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, role);
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/local-role/strict-mode", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "true");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	no_neighbor_role, no_neighbor_role_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer local-role <provider|rs-server|rs-client|customer|peer> [strict-mode]",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Set session role\n"
	ROLE_STR
	"Use additional restriction on peer\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/local-role/role", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/local-role/strict-mode", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "false");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

/*
 * 'neighbor X enforce-first-as <enabled|disabled>' (M4 batch B12): Tier B,
 * canonical '<enabled|disabled>$mode' grammar plus two CMD_ATTR_DEPRECATED
 * bare aliases, the same shape as B8's capabilities container leaves (bare
 * positive -> modify "true"; bare 'no' -> modify "false", not a destroy --
 * that's what legacy actually persisted). Inventory section 1.12 confirmed
 * this leaf shares B8's "profile-dependent instance default seeded onto
 * peers" shape rather than needing a bespoke inheritance path -- see
 * instance_neighbor_enforce_first_as_modify()'s doc comment
 * (bgp_nb_neighbor.c).
 */
DEFPY_YANG(
	neighbor_enforce_first_as, neighbor_enforce_first_as_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer enforce-first-as <enabled|disabled>$mode",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Enforce the first AS for EBGP routes\n"
	"Enable enforce-first-as\n"
	"Disable enforce-first-as\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/enforce-first-as", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY,
			      strmatch(mode, "enabled") ? "true" : "false");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	no_neighbor_enforce_first_as, no_neighbor_enforce_first_as_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer enforce-first-as <enabled|disabled>$mode",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Enforce the first AS for EBGP routes\n"
	"Enable enforce-first-as\n"
	"Disable enforce-first-as\n")
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/enforce-first-as", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_ATTR(
	neighbor_enforce_first_as_deprecated, neighbor_enforce_first_as_deprecated_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer enforce-first-as",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Enforce the first AS for EBGP routes\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/enforce-first-as", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "true");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_ATTR(
	no_neighbor_enforce_first_as_deprecated, no_neighbor_enforce_first_as_deprecated_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer enforce-first-as",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Enforce the first AS for EBGP routes\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED)
{
	char *xpath, *xpath_child;
	int ret;

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/enforce-first-as", xpath);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "false");
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

/*
 * M5 batch B1: per-address-family 'neighbor X activate' / 'no neighbor X
 * activate', shared between neighbor and peer-group via
 * bgp_cli_peer_or_group_xpath() like every command in this file. Installed
 * in the nine proteus address-family sub-nodes (BGP_IPV4_NODE ...
 * BGP_EVPN_NODE); the target AF is read from vty->node via
 * bgp_afi_safi_container_name() (bgp_cli_instance.c, M5 B0), so one command
 * definition covers all nine families. flowspec/unreachability/link-state
 * keep the legacy neighbor_activate DEFUN (bgp_vty.c) -- proteus models no
 * per-AF surface for them.
 *
 * 'neighbor X activate' -> activate=true, 'no neighbor X activate' ->
 * activate=false (both MODIFY: legacy 'no activate' calls peer_deactivate(),
 * an explicit deactivation, not a revert to the default). An unset leaf means
 * "follow the per-AF default activation" (bgp_nb_af_activate_default(),
 * bgp_nb_util.c).
 */
static int bgp_cli_neighbor_activate(struct vty *vty, const char *peer, const char *value)
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath, *xpath_child;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/activate", xpath, container);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, value);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_activate, neighbor_activate_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer activate",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Enable the Address Family for this Neighbor\n")
{
	return bgp_cli_neighbor_activate(vty, peer, "true");
}

DEFPY_YANG(
	no_neighbor_activate, no_neighbor_activate_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer activate",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Enable the Address Family for this Neighbor\n")
{
	return bgp_cli_neighbor_activate(vty, peer, "false");
}

/* Shared activate emitter for both neighbor and peer-group afi-safis/<af>/
 * activate. Reproduces bgp_config_write_peer_af()'s (bgp_vty.c) two-space
 * '  neighbor <addr> activate' / '  no neighbor <addr> activate' inside the
 * address-family block opened by afi_safi_cli_write() (M5 B0). The stored
 * value is authoritative: true -> activate, false -> no activate; a peer or
 * group that follows its default activation has no leaf and emits nothing.
 * The display token is the neighbor address key (an IP or an interface name,
 * matching legacy's conf_if/host) or the peer-group name. */
void neighbor_af_activate_cli_write(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults)
{
	const struct lyd_node *nbr = yang_dnode_get_parent(dnode, "neighbor");
	const char *addr;

	if (nbr)
		addr = yang_dnode_get_string(nbr, "address");
	else
		addr = yang_dnode_get_string(yang_dnode_get_parent(dnode, "peer-group"), "name");

	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "  neighbor %s activate\n", addr);
	else
		vty_out(vty, "  no neighbor %s activate\n", addr);
}

/*
 * M5 batch B2: shared per-AF policy-attachment CLI (route-map/prefix-list/
 * filter-list/distribute-list in|out, unsuppress-map), neighbor +
 * peer-group, all nine proteus AFs -- reusing B1's xpath-building pattern
 * (container from vty->node via bgp_afi_safi_container_name(), peer/group
 * xpath from bgp_cli_peer_or_group_xpath()). These are the 'filters'
 * container leaves under afi-safis/<af> (proteus-bgp.yang
 * neighbor-af-filters-{ipv4,ipv6,evpn}/-common), plain string policy
 * NAMES -- no M3 route-map dependency.
 *
 * Unlike activate, 'no neighbor X <cmd> ...' is a leaf DESTROY, not a
 * MODIFY-to-false: these have no explicit-false state, matching legacy's
 * peer_*_unset() (bgpd.c), which fully clears the filter slot (or
 * restores peer-group inheritance) rather than writing a sentinel.
 * Legacy's 'no' forms require the same WORD/direction tokens as the 'do'
 * form for grammar symmetry but never use the value (see e.g.
 * no_neighbor_route_map, bgp_vty.c); this DEFPY set keeps that shape.
 */
static int bgp_cli_neighbor_af_filter_modify(struct vty *vty, const char *peer, const char *leaf,
					     const char *value)
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath, *xpath_child;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/filters/%s", xpath, container, leaf);
	if (value)
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, value);
	else
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

/* Directional families (route-map, prefix-list, filter-list,
 * distribute-list): the yang leaf name is '<cmd>-in'/'<cmd>-out', which is
 * also the legacy CLI keyword plus direction -- build it from the two. */
static int bgp_cli_neighbor_af_filter_dir_modify(struct vty *vty, const char *peer, const char *cmd,
						 const char *direction, const char *value)
{
	char leaf[64];

	snprintf(leaf, sizeof(leaf), "%s-%s", cmd, direction);

	return bgp_cli_neighbor_af_filter_modify(vty, peer, leaf, value);
}

DEFPY_YANG(
	neighbor_route_map, neighbor_route_map_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer route-map WORD$name_str <in|out>$direction",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Apply route map to neighbor\n"
	"Name of route map\n"
	"Apply map to incoming routes\n"
	"Apply map to outbound routes\n")
{
	return bgp_cli_neighbor_af_filter_dir_modify(vty, peer, "route-map", direction, name_str);
}

DEFPY_YANG(
	no_neighbor_route_map, no_neighbor_route_map_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer route-map WORD <in|out>$direction",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Apply route map to neighbor\n"
	"Name of route map\n"
	"Apply map to incoming routes\n"
	"Apply map to outbound routes\n")
{
	return bgp_cli_neighbor_af_filter_dir_modify(vty, peer, "route-map", direction, NULL);
}

DEFPY_YANG(
	neighbor_prefix_list, neighbor_prefix_list_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer prefix-list WORD$name_str <in|out>$direction",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Filter updates to/from this neighbor\n"
	"Name of a prefix list\n"
	"Filter incoming updates\n"
	"Filter outgoing updates\n")
{
	return bgp_cli_neighbor_af_filter_dir_modify(vty, peer, "prefix-list", direction, name_str);
}

DEFPY_YANG(
	no_neighbor_prefix_list, no_neighbor_prefix_list_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer prefix-list WORD <in|out>$direction",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Filter updates to/from this neighbor\n"
	"Name of a prefix list\n"
	"Filter incoming updates\n"
	"Filter outgoing updates\n")
{
	return bgp_cli_neighbor_af_filter_dir_modify(vty, peer, "prefix-list", direction, NULL);
}

DEFPY_YANG(
	neighbor_filter_list, neighbor_filter_list_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer filter-list WORD$name_str <in|out>$direction",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Establish BGP filters\n"
	"AS path access-list name\n"
	"Filter incoming routes\n"
	"Filter outgoing routes\n")
{
	return bgp_cli_neighbor_af_filter_dir_modify(vty, peer, "filter-list", direction, name_str);
}

DEFPY_YANG(
	no_neighbor_filter_list, no_neighbor_filter_list_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer filter-list WORD <in|out>$direction",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Establish BGP filters\n"
	"AS path access-list name\n"
	"Filter incoming routes\n"
	"Filter outgoing routes\n")
{
	return bgp_cli_neighbor_af_filter_dir_modify(vty, peer, "filter-list", direction, NULL);
}

DEFPY_YANG(
	neighbor_distribute_list, neighbor_distribute_list_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer distribute-list WORD$name_str <in|out>$direction",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Filter updates to/from this neighbor\n"
	"IP Access-list name\n"
	"Filter incoming updates\n"
	"Filter outgoing updates\n")
{
	return bgp_cli_neighbor_af_filter_dir_modify(vty, peer, "distribute-list", direction,
						     name_str);
}

DEFPY_YANG(
	no_neighbor_distribute_list, no_neighbor_distribute_list_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer distribute-list WORD <in|out>$direction",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Filter updates to/from this neighbor\n"
	"IP Access-list name\n"
	"Filter incoming updates\n"
	"Filter outgoing updates\n")
{
	return bgp_cli_neighbor_af_filter_dir_modify(vty, peer, "distribute-list", direction, NULL);
}

DEFPY_YANG(
	neighbor_unsuppress_map, neighbor_unsuppress_map_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer unsuppress-map WORD$name_str",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Route-map to selectively unsuppress suppressed routes\n"
	"Name of route map\n")
{
	return bgp_cli_neighbor_af_filter_modify(vty, peer, "unsuppress-map", name_str);
}

DEFPY_YANG(
	no_neighbor_unsuppress_map, no_neighbor_unsuppress_map_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer unsuppress-map WORD",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Route-map to selectively unsuppress suppressed routes\n"
	"Name of route map\n")
{
	return bgp_cli_neighbor_af_filter_modify(vty, peer, "unsuppress-map", NULL);
}

/* Shared filters-leaf emitter for the four directional families
 * (route-map/prefix-list/filter-list/distribute-list, in|out), both
 * neighbor and peer-group. The yang leaf name IS the legacy CLI keyword
 * plus direction ('route-map-in' -> 'route-map' + 'in'), so split on the
 * last hyphen and reproduce bgp_config_write_filter()'s (bgp_vty.c)
 * two-space '  neighbor <addr> <cmd> <name> <in|out>' line. */
void neighbor_af_filter_dir_cli_write(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	const struct lyd_node *nbr = yang_dnode_get_parent(dnode, "neighbor");
	const char *addr;
	const char *leaf = dnode->schema->name;
	const char *dash = strrchr(leaf, '-');
	int cmd_len = (int)(dash - leaf);

	if (nbr)
		addr = yang_dnode_get_string(nbr, "address");
	else
		addr = yang_dnode_get_string(yang_dnode_get_parent(dnode, "peer-group"), "name");

	vty_out(vty, "  neighbor %s %.*s %s %s\n", addr, cmd_len, leaf,
		yang_dnode_get_string(dnode, NULL), dash + 1);
}

/* Shared unsuppress-map emitter (no direction), both neighbor and
 * peer-group. */
void neighbor_af_unsuppress_map_cli_write(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	const struct lyd_node *nbr = yang_dnode_get_parent(dnode, "neighbor");
	const char *addr;

	if (nbr)
		addr = yang_dnode_get_string(nbr, "address");
	else
		addr = yang_dnode_get_string(yang_dnode_get_parent(dnode, "peer-group"), "name");

	vty_out(vty, "  neighbor %s unsuppress-map %s\n", addr, yang_dnode_get_string(dnode, NULL));
}

/*
 * M5 batch B3: per-AF conditional-advertisement (advertise-map) + site-of-
 * origin (soo), neighbor + peer-group -- reusing B1/B2's xpath-building
 * pattern (container from vty->node via bgp_afi_safi_container_name(), peer/
 * group xpath from bgp_cli_peer_or_group_xpath()).
 *
 * advertise-map is installed only on the eight proteus AFs the legacy
 * neighbor_advertise_map DEFPY reached (ipv4/ipv6 {unicast,multicast,
 * labeled-unicast,vpn}; never l2vpn evpn -- see bgp_cli_neighbor_init()).
 * soo is installed on all nine (legacy neighbor_soo_cmd included
 * BGP_EVPN_NODE).
 */
static int bgp_cli_neighbor_advertise_map(struct vty *vty, const char *peer,
					  const char *advertise_str, const char *exist,
					  const char *condition_str, bool no)
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath, *xpath_base, *xpath_child;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_base = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/filters/conditional-advertisement",
				xpath, container);
	XFREE(MTYPE_TMP, xpath);

	if (no) {
		/* Trailing advertise-map/exist-map/condition-map tokens are
		 * accepted but never inspected, exactly like legacy's
		 * no-form (the bracketed '[no$no]' single-DEFPY grammar
		 * shares argv slots with the positive form): destroy the
		 * whole non-presence container at once, same pattern as 'no
		 * neighbor X local-as ...' destroying 'local-as/asdot'.
		 */
		nb_cli_enqueue_change(vty, xpath_base, NB_OP_DESTROY, NULL);
	} else {
		bool exist_flag = !strcmp(exist, "exist-map");

		xpath_child = asprintfrr(MTYPE_TMP, "%s/advertise-map", xpath_base);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, advertise_str);
		XFREE(MTYPE_TMP, xpath_child);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/condition", xpath_base);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY,
				      exist_flag ? "exist" : "non-exist");
		XFREE(MTYPE_TMP, xpath_child);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/condition-map", xpath_base);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, condition_str);
		XFREE(MTYPE_TMP, xpath_child);
	}
	XFREE(MTYPE_TMP, xpath_base);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_advertise_map, neighbor_advertise_map_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer advertise-map RMAP_NAME$advertise_str <exist-map|non-exist-map>$exist RMAP_NAME$condition_str",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Route-map to conditionally advertise routes\n"
	"Name of advertise map\n"
	"Advertise routes only if prefixes in exist-map are installed in BGP table\n"
	"Advertise routes only if prefixes in non-exist-map are not installed in BGP table\n"
	"Name of the exist or non exist map\n")
{
	return bgp_cli_neighbor_advertise_map(vty, peer, advertise_str, exist, condition_str, !!no);
}

/* Shared conditional-advertisement emitter, both neighbor and peer-group.
 * dnode is the container's condition-map leaf -- the one registration point
 * in bgp_cli_common.c's node table for all three leaves, since the CLI
 * always sets/destroys them together as a unit. Reproduces
 * bgp_config_write_filter()'s (bgp_vty.c) two-space '  neighbor <addr>
 * advertise-map <name> <exist-map|non-exist-map> <name>' line, always in
 * the OUT direction like legacy. */
void neighbor_af_advertise_map_cli_write(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	const struct lyd_node *cond_adv = yang_dnode_get_parent(dnode, "conditional-advertisement");
	const struct lyd_node *nbr = yang_dnode_get_parent(dnode, "neighbor");
	const char *addr;
	bool exist;

	if (nbr)
		addr = yang_dnode_get_string(nbr, "address");
	else
		addr = yang_dnode_get_string(yang_dnode_get_parent(dnode, "peer-group"), "name");

	exist = strmatch(yang_dnode_get_string(cond_adv, "condition"), "exist");

	vty_out(vty, "  neighbor %s advertise-map %s %s %s\n", addr,
		yang_dnode_get_string(cond_adv, "advertise-map"),
		exist ? "exist-map" : "non-exist-map",
		yang_dnode_get_string(cond_adv, "condition-map"));
}

/*
 * soo (site-of-origin): proteus-bgp models it as a YANG 'choice' -- as2/
 * as4/ipv4, the same three RFC 4360 subtype 0x03 encodings
 * bgp_ecommunity.c's ecommunity_gettoken() distinguishes for the legacy
 * 'neighbor X soo ASN:NN_OR_IP-ADDRESS:NN' token -- under a presence
 * container, rather than the single opaque string the legacy grammar
 * accepts. bgp_ecommunity.c is bgpd-only (bgpd/subdir.am; not among
 * mgmtd/subdir.am's sources), so this mgmtd-side CLI can't call
 * ecommunity_str2com() to validate/decode the token; bgp_cli_soo_parse()
 * below is a small independent re-implementation of just its AS-vs-IP
 * branch (SITE_ORIGIN is already the known type here, so the rt/soo/color
 * keyword branch never triggers), producing the case plus the two typed
 * leaves' canonical string values directly. The northbound APPLY side
 * (bgp_nb_util.c, in bgpd) re-derives the same struct ecommunity straight
 * from those already-typed YANG leaves, no string re-parsing there.
 */
enum bgp_cli_soo_case { BGP_CLI_SOO_AS2, BGP_CLI_SOO_AS4, BGP_CLI_SOO_IPV4 };

static bool bgp_cli_soo_parse(const char *token, enum bgp_cli_soo_case *soo_case,
			      char *global_admin_buf, size_t global_admin_buf_len,
			      char *local_admin_buf, size_t local_admin_buf_len)
{
	char prefix[INET_ADDRSTRLEN];
	struct in_addr ip;
	const char *colon;
	char *endptr;
	unsigned long val;
	as_t as;

	colon = strrchr(token, ':');
	if (!colon || colon == token || (size_t)(colon - token) >= sizeof(prefix))
		return false;

	memcpy(prefix, token, (size_t)(colon - token));
	prefix[colon - token] = '\0';

	errno = 0;
	val = strtoul(colon + 1, &endptr, 10);
	if (*endptr != '\0' || errno || val > UINT32_MAX)
		return false;

	if (inet_pton(AF_INET, prefix, &ip) == 1) {
		if (val > UINT16_MAX)
			return false;
		*soo_case = BGP_CLI_SOO_IPV4;
		snprintf(global_admin_buf, global_admin_buf_len, "%s", prefix);
		snprintf(local_admin_buf, local_admin_buf_len, "%lu", val);
		return true;
	}

	if (!asn_str2asn(prefix, &as))
		return false;

	*soo_case = (as > UINT16_MAX) ? BGP_CLI_SOO_AS4 : BGP_CLI_SOO_AS2;
	if (*soo_case == BGP_CLI_SOO_AS4 && val > UINT16_MAX)
		return false;

	snprintf(global_admin_buf, global_admin_buf_len, "%u", as);
	snprintf(local_admin_buf, local_admin_buf_len, "%lu", val);

	return true;
}

static int bgp_cli_neighbor_soo(struct vty *vty, const char *peer, const char *soo_token)
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	enum bgp_cli_soo_case soo_case;
	char global_admin[INET_ADDRSTRLEN], local_admin[12];
	const char *case_name;
	char *xpath, *xpath_child;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (!bgp_cli_soo_parse(soo_token, &soo_case, global_admin, sizeof(global_admin),
			       local_admin, sizeof(local_admin))) {
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

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/soo/%s/global-admin", xpath,
				 container, case_name);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, global_admin);
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/soo/%s/local-admin", xpath, container,
				 case_name);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, local_admin);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_soo, neighbor_soo_cli_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$peer soo ASN:NN_OR_IP-ADDRESS:NN$soo",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Set the Site-of-Origin (SoO) extended community\n"
	"VPN extended community\n")
{
	return bgp_cli_neighbor_soo(vty, peer, soo);
}

DEFPY_YANG(
	no_neighbor_soo, no_neighbor_soo_cli_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$peer soo [ASN:NN_OR_IP-ADDRESS:NN]",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Set the Site-of-Origin (SoO) extended community\n"
	"VPN extended community\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath, *xpath_child;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	/* Trailing SoO token is accepted but ignored, exactly like legacy's
	 * no_neighbor_soo DEFPY (bgp_vty.c, retired): this always fully
	 * unsets soo, destroying the whole presence container at once.
	 */
	xpath_child = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/soo", xpath, container);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

/* Shared soo emitter, both neighbor and peer-group. dnode is any one of the
 * three cases' local-admin leaf (bgp_cli_common.c registers all three --
 * only whichever case is actually configured ever exists in the datastore,
 * so exactly one registration fires per neighbor/group). Reproduces
 * bgp_config_write_peer_af()'s (bgp_vty.c) two-space '  neighbor <addr> soo
 * <ASN|IP>:<NN>' line, in the same textual form
 * ecommunity_ecom2str(ECOMMUNITY_FORMAT_ROUTE_MAP) legacy printed (no
 * 'RT:'/'SoO:' prefix). */
void neighbor_af_soo_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const struct lyd_node *soo = yang_dnode_get_parent(dnode, "soo");
	const struct lyd_node *nbr = yang_dnode_get_parent(dnode, "neighbor");
	const char *addr;
	const char *case_name;

	if (nbr)
		addr = yang_dnode_get_string(nbr, "address");
	else
		addr = yang_dnode_get_string(yang_dnode_get_parent(dnode, "peer-group"), "name");

	if (yang_dnode_exists(soo, "as2"))
		case_name = "as2";
	else if (yang_dnode_exists(soo, "as4"))
		case_name = "as4";
	else if (yang_dnode_exists(soo, "ipv4"))
		case_name = "ipv4";
	else
		return;

	vty_out(vty, "  neighbor %s soo %s:%s\n", addr,
		yang_dnode_get_string(soo, "%s/global-admin", case_name),
		yang_dnode_get_string(soo, "%s/local-admin", case_name));
}

/*
 * M5 batch B4: plain per-AF PEER_FLAG_* booleans (neighbor + peer-group, all
 * nine proteus AFs where legacy reached them). Every leaf here is `type
 * boolean; default "false";` (bgpd-no-line-yang-modeling-guidance.md's
 * plain-flag category -- no inheritance tri-state), so every DEFPY below
 * always issues a MODIFY (never a DESTROY, matching bgp_nb_util.c's
 * bgp_nb_{neighbor,peer_group}_af_flag_modify(), the only apply-side
 * callback wired up for these xpaths) -- 'no ...' writes an explicit
 * "false", the same shape as instance-scope plain flags like
 * neighbor_passive above. bgp_cli_neighbor_af_flag_modify() is this batch's
 * xpath-building helper, the B1 bgp_cli_neighbor_activate() template
 * parameterized by leaf name instead of hardcoding "activate".
 *
 * CLI install sets below intentionally do NOT match uniformly across all
 * nine AFs: each mirrors exactly the per-AF install_element() calls the
 * retired legacy DEFUN had (as-override never reached l2vpn evpn;
 * nexthop-local-unchanged only ever reached ipv6-unicast; accept-own only
 * vpnv4/vpnv6) -- while the northbound apply side (bgp_nb_util.c,
 * bgp_nb_neighbor_afi_*.c/bgp_nb_peer_group_afi_*.c) is wired up uniformly
 * across all nine, exactly like B2/B3's policy attachments. Where the
 * retired DEFUN kept a hidden BGP_NODE alias (or, for next-hop-self force,
 * a hidden 'all' alias reachable inside every AF node too) that alias stays
 * native and is left installed below, per the existing B1-B3 precedent.
 */
static int bgp_cli_neighbor_af_flag_modify(struct vty *vty, const char *peer, const char *leaf,
					   const char *value)
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath, *xpath_child;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/%s", xpath, container, leaf);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, value);
	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

/* Shared neighbor-or-peer-group display name for the standalone plain-flag
 * emitters below: the address for a neighbor-scope dnode, the peer-group
 * name otherwise -- the same "nbr ? ... : ..." idiom every other cli_write
 * function in this file repeats individually (e.g.
 * neighbor_af_activate_cli_write() above). */
static const char *bgp_cli_neighbor_or_group_name(const struct lyd_node *dnode)
{
	const struct lyd_node *nbr = yang_dnode_get_parent(dnode, "neighbor");

	if (nbr)
		return yang_dnode_get_string(nbr, "address");

	return yang_dnode_get_string(yang_dnode_get_parent(dnode, "peer-group"), "name");
}

DEFPY_YANG(
	neighbor_route_reflector_client, neighbor_route_reflector_client_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer route-reflector-client",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Configure a neighbor as Route Reflector client\n")
{
	return bgp_cli_neighbor_af_flag_modify(vty, peer, "route-reflector-client",
					       no ? "false" : "true");
}

void neighbor_af_route_reflector_client_cli_write(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "  neighbor %s route-reflector-client\n",
			bgp_cli_neighbor_or_group_name(dnode));
}

DEFPY_YANG(
	neighbor_route_server_client, neighbor_route_server_client_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer route-server-client",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Configure a neighbor as Route Server client\n")
{
	return bgp_cli_neighbor_af_flag_modify(vty, peer, "route-server-client",
					       no ? "false" : "true");
}

void neighbor_af_route_server_client_cli_write(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "  neighbor %s route-server-client\n",
			bgp_cli_neighbor_or_group_name(dnode));
}

DEFPY_YANG(
	neighbor_as_override, neighbor_as_override_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer as-override",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Override ASNs in outbound updates if aspath equals remote-as\n")
{
	return bgp_cli_neighbor_af_flag_modify(vty, peer, "as-override", no ? "false" : "true");
}

void neighbor_af_as_override_cli_write(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "  neighbor %s as-override\n", bgp_cli_neighbor_or_group_name(dnode));
}

/* 'neighbor X next-hop-self [force]' / 'no neighbor X next-hop-self
 * [force]': one grammar, two independent leaves -- legacy's
 * neighbor_nexthop_self_force_cmd only ever touches
 * PEER_FLAG_FORCE_NEXTHOP_SELF, never PEER_FLAG_NEXTHOP_SELF, and vice
 * versa for the bare form (bgp_vty.c, retired), so the [force] token
 * selects which single leaf this command modifies rather than setting both.
 */
DEFPY_YANG(
	neighbor_nexthop_self, neighbor_nexthop_self_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer next-hop-self [force]$force",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Disable the next hop calculation for this neighbor\n"
	"Set the next hop to self for reflected routes\n")
{
	return bgp_cli_neighbor_af_flag_modify(vty, peer,
					       force ? "next-hop-self/force"
						     : "next-hop-self/enabled",
					       no ? "false" : "true");
}

void neighbor_af_next_hop_self_enabled_cli_write(struct vty *vty, const struct lyd_node *dnode,
						 bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "  neighbor %s next-hop-self\n",
			bgp_cli_neighbor_or_group_name(dnode));
}

void neighbor_af_next_hop_self_force_cli_write(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "  neighbor %s next-hop-self force\n",
			bgp_cli_neighbor_or_group_name(dnode));
}

/* 'neighbor X nexthop-local unchanged': legacy only ever installed this on
 * BGP_IPV6_NODE (ipv6-unicast) -- no hidden BGP_NODE alias, no other AF, no
 * flowspec. Kept to that single AF here too. */
DEFPY_YANG(
	neighbor_nexthop_local_unchanged, neighbor_nexthop_local_unchanged_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer nexthop-local unchanged",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Configure treatment of outgoing link-local nexthop attribute\n"
	"Leave link-local nexthop unchanged for this peer\n")
{
	return bgp_cli_neighbor_af_flag_modify(vty, peer, "nexthop-local-unchanged",
					       no ? "false" : "true");
}

void neighbor_af_nexthop_local_unchanged_cli_write(struct vty *vty, const struct lyd_node *dnode,
						    bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "  neighbor %s nexthop-local unchanged\n",
			bgp_cli_neighbor_or_group_name(dnode));
}

DEFPY_YANG(
	neighbor_soft_reconfiguration, neighbor_soft_reconfiguration_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer soft-reconfiguration inbound",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Per neighbor soft reconfiguration\n"
	"Allow inbound soft reconfiguration for this neighbor\n")
{
	return bgp_cli_neighbor_af_flag_modify(vty, peer, "soft-reconfiguration-inbound",
					       no ? "false" : "true");
}

void neighbor_af_soft_reconfiguration_inbound_cli_write(struct vty *vty,
							 const struct lyd_node *dnode,
							 bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "  neighbor %s soft-reconfiguration inbound\n",
			bgp_cli_neighbor_or_group_name(dnode));
}

/* 'neighbor X accept-own': legacy installed this only on BGP_VPNV4_NODE and
 * BGP_VPNV6_NODE (neighbor_accept_own_cmd, bgp_vty.c, retired) -- no hidden
 * BGP_NODE alias. */
DEFPY_YANG(
	neighbor_accept_own, neighbor_accept_own_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer accept-own",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Enable handling of self-originated VPN routes containing ACCEPT_OWN community\n")
{
	return bgp_cli_neighbor_af_flag_modify(vty, peer, "accept-own", no ? "false" : "true");
}

void neighbor_af_accept_own_cli_write(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "  neighbor %s accept-own\n", bgp_cli_neighbor_or_group_name(dnode));
}

/*
 * 'neighbor X attribute-unchanged [{as-path|next-hop|med}]' /
 * 'no neighbor X attribute-unchanged [{as-path|next-hop|med}]'
 * (neighbor_attr_unchanged/no_neighbor_attr_unchanged, bgp_vty.c, retired).
 * Three independent boolean leaves, but legacy's grammar has asymmetric
 * "bare vs. selective" semantics that don't reduce to three independent
 * per-leaf MODIFYs:
 *  - bare positive ('attribute-unchanged', no sub-tokens) sets all three;
 *  - selective positive ('attribute-unchanged as-path') REPLACES the whole
 *    triple: the named leaves go true, the unnamed ones go false (legacy
 *    unsets whichever of next-hop/med isn't named, even if it was
 *    previously set -- see neighbor_attr_unchanged(), bgp_vty.c);
 *  - bare negative ('no attribute-unchanged') clears all three;
 *  - selective negative ('no ... as-path') clears only the named leaves and
 *    leaves the rest untouched.
 * All three leaves are always written together in one commit (three
 * MODIFYs batched under one nb_cli_apply_changes()), matching B3's
 * conditional-advertisement precedent for a CLI grammar that doesn't map
 * 1:1 onto independent leaf writes.
 */
static void bgp_cli_attribute_unchanged_enqueue(struct vty *vty, const char *xpath,
						const char *container, const char *leaf, bool val)
{
	char *xpath_child = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/attribute-unchanged/%s", xpath,
				       container, leaf);

	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, val ? "true" : "false");
	XFREE(MTYPE_TMP, xpath_child);
}

DEFPY_YANG(
	neighbor_attribute_unchanged, neighbor_attribute_unchanged_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer attribute-unchanged"
	" [{as-path$aspath|next-hop$nexthop|med$med}]",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"BGP attribute is propagated unchanged to this neighbor\n"
	"As-path attribute\n"
	"Nexthop attribute\n"
	"Med attribute\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	bool has_aspath = !!aspath, has_nexthop = !!nexthop, has_med = !!med;
	bool any = has_aspath || has_nexthop || has_med;
	bool bare_value = !no;
	char *xpath;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	if (no && any) {
		/* selective negative: clear only the named leaves */
		if (has_aspath)
			bgp_cli_attribute_unchanged_enqueue(vty, xpath, container, "as-path",
							    false);
		if (has_nexthop)
			bgp_cli_attribute_unchanged_enqueue(vty, xpath, container, "next-hop",
							    false);
		if (has_med)
			bgp_cli_attribute_unchanged_enqueue(vty, xpath, container, "med", false);
	} else {
		/* bare (either polarity): all three to bare_value. selective
		 * positive: named leaves true, unnamed false (replace). */
		bgp_cli_attribute_unchanged_enqueue(vty, xpath, container, "as-path",
						    any ? has_aspath : bare_value);
		bgp_cli_attribute_unchanged_enqueue(vty, xpath, container, "next-hop",
						    any ? has_nexthop : bare_value);
		bgp_cli_attribute_unchanged_enqueue(vty, xpath, container, "med",
						    any ? has_med : bare_value);
	}

	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

/* Shared attribute-unchanged emitter, both neighbor and peer-group.
 * Registered on the CONTAINER xpath (bgp_cli_common.c), not on the three
 * leaves individually: the three sub-flags are independent (any subset may
 * be true), so no single leaf's presence is guaranteed whenever the line
 * needs printing -- e.g. only 'med' set means the 'as-path'/'next-hop'
 * leaves are still at their default and never walked on their own.
 * Reproduces bgp_config_write_peer_af()'s (bgp_vty.c) exact token order and
 * spacing: "  neighbor <addr> attribute-unchanged[ as-path][ next-hop][
 * med]\n", omitted entirely when all three are false. */
void neighbor_af_attribute_unchanged_cli_write(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults)
{
	bool aspath = yang_dnode_exists(dnode, "as-path") && yang_dnode_get_bool(dnode, "as-path");
	bool nexthop = yang_dnode_exists(dnode, "next-hop") &&
		       yang_dnode_get_bool(dnode, "next-hop");
	bool med = yang_dnode_exists(dnode, "med") && yang_dnode_get_bool(dnode, "med");

	if (!aspath && !nexthop && !med)
		return;

	vty_out(vty, "  neighbor %s attribute-unchanged%s%s%s\n",
		bgp_cli_neighbor_or_group_name(dnode), aspath ? " as-path" : "",
		nexthop ? " next-hop" : "", med ? " med" : "");
}

/*
 * M5 batch B5: per-AF send-community (standard/extended/large tri-state +
 * extended-rpki) + remove-private-as (enum) + capability orf prefix-list
 * (enum), neighbor + peer-group, all nine proteus AFs where the retired
 * legacy DEFUNs reached them.
 *
 * send-community: legacy's bare 'neighbor X send-community'/'no ...' DEFUN
 * pair only ever touches the 'standard' leaf; the typed
 * 'send-community <both|all|extended|standard|large>' pair touches a
 * subset -- both -> standard+extended (NOT large, matching legacy's own
 * asymmetric "both" naming), all/default -> all three. Every touched leaf
 * gets its own batched MODIFY, matching B4's attribute-unchanged precedent
 * for a legacy grammar that sets several leaves per invocation. extended
 * rpki keeps its own separate legacy grammar ('send-community extended
 * rpki', neighbor_ecommunity_rpki_cmd, bgp_vty.c) and is a plain Tier-A
 * default-false flag, so it reuses bgp_cli_neighbor_af_flag_modify()
 * directly (B4's helper) rather than the send-community-specific enqueue
 * below.
 */
static void bgp_cli_send_community_enqueue(struct vty *vty, const char *xpath,
					    const char *container, const char *leaf, bool val)
{
	char *xpath_child = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/send-community/%s", xpath,
				       container, leaf);

	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, val ? "true" : "false");
	XFREE(MTYPE_TMP, xpath_child);
}

DEFPY_YANG(
	neighbor_send_community, neighbor_send_community_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer send-community",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Send Community attribute to this neighbor\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	bgp_cli_send_community_enqueue(vty, xpath, container, "standard", no ? false : true);

	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_send_community_type, neighbor_send_community_type_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer send-community"
	" <both|all|extended|standard|large>$type",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Send Community attribute to this neighbor\n"
	"Send Standard and Extended Community attributes\n"
	"Send Standard, Large and Extended Community attributes\n"
	"Send Extended Community attributes\n"
	"Send Standard Community attributes\n"
	"Send Large Community attributes\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	bool val = no ? false : true;
	char *xpath;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	if (strmatch(type, "standard")) {
		bgp_cli_send_community_enqueue(vty, xpath, container, "standard", val);
	} else if (strmatch(type, "extended")) {
		bgp_cli_send_community_enqueue(vty, xpath, container, "extended", val);
	} else if (strmatch(type, "large")) {
		bgp_cli_send_community_enqueue(vty, xpath, container, "large", val);
	} else if (strmatch(type, "both")) {
		bgp_cli_send_community_enqueue(vty, xpath, container, "standard", val);
		bgp_cli_send_community_enqueue(vty, xpath, container, "extended", val);
	} else {
		/* "all" */
		bgp_cli_send_community_enqueue(vty, xpath, container, "standard", val);
		bgp_cli_send_community_enqueue(vty, xpath, container, "extended", val);
		bgp_cli_send_community_enqueue(vty, xpath, container, "large", val);
	}

	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_ecommunity_rpki, neighbor_ecommunity_rpki_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer send-community extended rpki",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Send Community attribute to this neighbor\n"
	"Send Extended Community attributes\n"
	"Send RPKI Extended Community attributes\n")
{
	return bgp_cli_neighbor_af_flag_modify(vty, peer, "send-community/extended-rpki",
					       no ? "false" : "true");
}

/* Shared per-AF send-community emitter (neighbor + peer-group), registered
 * on the CONTAINER xpath, not the leaves individually: legacy's negative
 * forms (bgp_config_write_peer_af(), bgp_vty.c) are only meaningful
 * evaluated jointly (the combined "no ... send-community all" line when
 * standard/extended/large are all explicitly off), and the extended-rpki
 * line is legacy-nested inside the "not all three off" branch -- reproduced
 * byte-for-byte, quirk included, the same "reread the whole container"
 * discipline as B4's attribute-unchanged. standard/extended/large have no
 * YANG default (tri-state: absent means "send", matching the compiled-in
 * default), so each is only inspected when explicitly present; extended-rpki
 * carries a YANG default of false and so is always safe to read directly.
 */
void neighbor_af_send_community_cli_write(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	const char *name = bgp_cli_neighbor_or_group_name(dnode);
	bool std_off = yang_dnode_exists(dnode, "standard") &&
		       !yang_dnode_get_bool(dnode, "standard");
	bool ext_off = yang_dnode_exists(dnode, "extended") &&
		       !yang_dnode_get_bool(dnode, "extended");
	bool lrg_off = yang_dnode_exists(dnode, "large") && !yang_dnode_get_bool(dnode, "large");

	if (std_off && ext_off && lrg_off) {
		vty_out(vty, "  no neighbor %s send-community all\n", name);
		return;
	}

	if (std_off)
		vty_out(vty, "  no neighbor %s send-community\n", name);
	if (ext_off)
		vty_out(vty, "  no neighbor %s send-community extended\n", name);
	if (lrg_off)
		vty_out(vty, "  no neighbor %s send-community large\n", name);

	if (yang_dnode_get_bool(dnode, "extended-rpki"))
		vty_out(vty, "  neighbor %s send-community extended rpki\n", name);
}

/*
 * remove-private-as: proteus-bgp.yang's `remove-private-as` leaf is a
 * four-way enumeration (basic/all/replace-as/all-replace-as) replacing
 * legacy's four independent DEFUN/no-DEFUN pairs
 * (neighbor_remove_private_as[_all][_replace_as], bgp_vty.c, retired).
 * Unified into a single DEFPY with two optional trailing tokens; the
 * negative form's trailing [all]/[replace-AS] tokens are accepted but
 * ignored (like B3's advertise-map/soo negative forms) since the enum leaf
 * has exactly one "off" state -- any 'no ... remove-private-AS ...' spelling
 * destroys it.
 */
DEFPY_YANG(
	neighbor_remove_private_as, neighbor_remove_private_as_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer remove-private-AS"
	" [all$all] [replace-AS$replace]",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Remove private ASNs in outbound updates\n"
	"Apply to all AS numbers\n"
	"Replace private ASNs with our ASN in outbound updates\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath, *xpath_child;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/remove-private-as", xpath, container);

	if (no) {
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	} else {
		const char *value;

		if (all && replace)
			value = "all-replace-as";
		else if (replace)
			value = "replace-as";
		else if (all)
			value = "all";
		else
			value = "basic";

		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, value);
	}

	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

static const struct {
	const char *value;
	const char *text;
} bgp_cli_remove_private_as_text[] = {
	{ "basic", "remove-private-AS" },
	{ "all", "remove-private-AS all" },
	{ "replace-as", "remove-private-AS replace-AS" },
	{ "all-replace-as", "remove-private-AS all replace-AS" },
};

void neighbor_af_remove_private_as_cli_write(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults)
{
	const char *value = yang_dnode_get_string(dnode, NULL);
	unsigned int i;

	for (i = 0; i < array_size(bgp_cli_remove_private_as_text); i++) {
		if (strmatch(value, bgp_cli_remove_private_as_text[i].value)) {
			vty_out(vty, "  neighbor %s %s\n", bgp_cli_neighbor_or_group_name(dnode),
				bgp_cli_remove_private_as_text[i].text);
			return;
		}
	}
}

/*
 * capability orf prefix-list: proteus-bgp.yang's `orf-prefix-list` leaf is a
 * three-way enumeration (send/receive/both) whose values already spell the
 * legacy <send|receive|both> tokens directly, replacing legacy's
 * neighbor_capability_orf_prefix/no_... DEFUN pair (bgp_vty.c, retired).
 * The negative form's trailing token is likewise accepted but ignored,
 * always destroying the enum leaf -- same reasoning as remove-private-as
 * above.
 */
DEFPY_YANG(
	neighbor_capability_orf_prefix, neighbor_capability_orf_prefix_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer capability orf prefix-list"
	" <both|send|receive>$type",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Advertise capability to the peer\n"
	"Advertise ORF capability to the peer\n"
	"Advertise prefixlist ORF capability to this neighbor\n"
	"Capability to SEND and RECEIVE the ORF to/from this neighbor\n"
	"Capability to RECEIVE the ORF from this neighbor\n"
	"Capability to SEND the ORF to this neighbor\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath, *xpath_child;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/orf-prefix-list", xpath, container);

	if (no)
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, type);

	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

void neighbor_af_orf_prefix_list_cli_write(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	vty_out(vty, "  neighbor %s capability orf prefix-list %s\n",
		bgp_cli_neighbor_or_group_name(dnode), yang_dnode_get_string(dnode, NULL));
}

/*
 * M5 batch B6: per-AF default-originate + maximum-prefix (+opts) +
 * maximum-prefix-out + allowas-in + weight, neighbor + peer-group --
 * reusing B1/B2's xpath-building pattern (container from vty->node via
 * bgp_afi_safi_container_name(), peer/group xpath from
 * bgp_cli_peer_or_group_xpath()).
 *
 * default-originate is installed only on the six proteus AFs the legacy
 * neighbor_default_originate[_rmap] DEFUNs reached (ipv4/ipv6
 * {unicast,multicast,labeled-unicast}; never vpn or l2vpn evpn -- see
 * bgp_cli_neighbor_init()); maximum-prefix-out and weight on the eight the
 * legacy DEFUNs reached (adding vpn, never l2vpn evpn); maximum-prefix and
 * allowas-in on all nine (legacy reached BGP_EVPN_NODE for both). Every
 * legacy DEFUN/DEFPY stays defined -- their BGP_NODE hidden aliases (and,
 * for maximum-prefix/allowas-in, the still-native BGP_IPV4U_NODE/
 * BGP_IPV6U_NODE unreachability installs; for maximum-prefix-out, the bare
 * non-hidden BGP_NODE install operating on the default ipv4-unicast AF)
 * keep them reachable -- only the per-AF install_element() calls for the
 * nodes converted here are removed.
 */

/*
 * default-originate: legacy's bare 'default-originate' (no route-map)
 * explicitly clears any previously configured route-map
 * (peer_default_originate_set()'s '!rmap' branch), so the positive form
 * here always issues both leaves -- MODIFY enabled=true and either MODIFY
 * or DESTROY route-map depending on whether RMAP_NAME was given. The
 * negative form destroys the whole non-presence container in one shot,
 * same pattern as B3's 'no neighbor X advertise-map ...'.
 */
DEFPY_YANG(
	neighbor_default_originate, neighbor_default_originate_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer default-originate [route-map RMAP_NAME$rmap_name]",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Originate default route to this neighbor\n"
	"Route-map to specify criteria to originate default\n"
	"route-map name\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath, *xpath_base, *xpath_child;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_base = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/default-originate", xpath, container);
	XFREE(MTYPE_TMP, xpath);

	if (no) {
		nb_cli_enqueue_change(vty, xpath_base, NB_OP_DESTROY, NULL);
	} else {
		xpath_child = asprintfrr(MTYPE_TMP, "%s/enabled", xpath_base);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "true");
		XFREE(MTYPE_TMP, xpath_child);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/route-map", xpath_base);
		if (rmap_name)
			nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, rmap_name);
		else
			nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
		XFREE(MTYPE_TMP, xpath_child);
	}
	XFREE(MTYPE_TMP, xpath_base);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

/* Registered on the container xpath (dnode is the 'default-originate'
 * container itself), same idiom as B5's send-community: the legacy
 * bgp_config_write_peer_af() line combines 'enabled' and 'route-map' on one
 * line, so both leaves are read directly off dnode rather than
 * independently. */
void neighbor_af_default_originate_cli_write(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, "enabled"))
		return;

	vty_out(vty, "  neighbor %s default-originate", bgp_cli_neighbor_or_group_name(dnode));
	if (yang_dnode_exists(dnode, "route-map"))
		vty_out(vty, " route-map %s", yang_dnode_get_string(dnode, "route-map"));
	vty_out(vty, "\n");
}

/*
 * maximum-prefix: collapses legacy's six neighbor_maximum_prefix[_threshold]
 * [_warning][_restart] DEFUN combinations plus no_neighbor_maximum_prefix
 * into one DEFPY -- a superset grammar (threshold/restart/warning-only/
 * force freely combinable) rather than legacy's exact enumerated set,
 * matching B5's collapsing philosophy. The positive form always issues
 * every leaf explicitly (MODIFY the given value, or DESTROY the ranged
 * leaves threshold/restart-interval when omitted, matching
 * peer_maximum_prefix_set_vty()'s own "always rewrite all five fields from
 * scratch" behavior -- a bare re-run of 'maximum-prefix N' after a previous
 * 'maximum-prefix N 50 restart 5' really does clear threshold/restart, not
 * just leave them alone). The negative form destroys the whole container in
 * one shot, same as default-originate above.
 */
DEFPY_YANG(
	neighbor_maximum_prefix, neighbor_maximum_prefix_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer maximum-prefix"
	" [(1-4294967295)$max [(1-100)$threshold]] [restart (1-65535)$restart] [warning-only$warning] [force$force]",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Maximum number of prefixes to accept from this peer\n"
	"maximum no. of prefix limit\n"
	"Threshold value (%) at which to generate a warning msg\n"
	"Restart bgp connection after limit is exceeded\n"
	"Restart interval in minutes\n"
	"Only give warning message when limit is exceeded\n"
	"Force checking all received routes not only accepted\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath, *xpath_base, *xpath_child;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_base = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/maximum-prefix", xpath, container);
	XFREE(MTYPE_TMP, xpath);

	if (no) {
		nb_cli_enqueue_change(vty, xpath_base, NB_OP_DESTROY, NULL);
		XFREE(MTYPE_TMP, xpath_base);
		ret = nb_cli_apply_changes(vty, NULL);
		return ret;
	}

	if (!max_str) {
		vty_out(vty, "%% Must specify a prefix count\n");
		XFREE(MTYPE_TMP, xpath_base);
		return CMD_WARNING;
	}

	xpath_child = asprintfrr(MTYPE_TMP, "%s/count", xpath_base);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, max_str);
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/threshold", xpath_base);
	if (threshold_str)
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, threshold_str);
	else
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/warning-only", xpath_base);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, warning ? "true" : "false");
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/restart-interval", xpath_base);
	if (restart_str)
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, restart_str);
	else
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/force", xpath_base);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, force ? "true" : "false");
	XFREE(MTYPE_TMP, xpath_child);

	XFREE(MTYPE_TMP, xpath_base);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

/* Registered on the container xpath, reproducing
 * bgp_config_write_peer_af()'s single incrementally-built
 * '  neighbor <addr> maximum-prefix <count> [<threshold>] [warning-only]
 * [restart <n>] [force]\n' line. */
void neighbor_af_maximum_prefix_cli_write(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	if (!yang_dnode_exists(dnode, "count"))
		return;

	vty_out(vty, "  neighbor %s maximum-prefix %u", bgp_cli_neighbor_or_group_name(dnode),
		yang_dnode_get_uint32(dnode, "count"));

	if (yang_dnode_exists(dnode, "threshold"))
		vty_out(vty, " %u", yang_dnode_get_uint8(dnode, "threshold"));
	if (yang_dnode_get_bool(dnode, "warning-only"))
		vty_out(vty, " warning-only");
	if (yang_dnode_exists(dnode, "restart-interval"))
		vty_out(vty, " restart %u", yang_dnode_get_uint16(dnode, "restart-interval"));
	if (yang_dnode_get_bool(dnode, "force"))
		vty_out(vty, " force");

	vty_out(vty, "\n");
}

/* maximum-prefix-out: plain independent leaf, collapsing legacy's
 * neighbor_maximum_prefix_out/no_... DEFUN pair. */
DEFPY_YANG(
	neighbor_maximum_prefix_out, neighbor_maximum_prefix_out_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer maximum-prefix-out [(1-4294967295)$max]",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Maximum number of prefixes to be sent to this peer\n"
	"Maximum no. of prefix limit\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath, *xpath_child;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/maximum-prefix-out", xpath, container);
	XFREE(MTYPE_TMP, xpath);

	if (no) {
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	} else {
		if (!max_str) {
			vty_out(vty, "%% Must specify a prefix count\n");
			XFREE(MTYPE_TMP, xpath_child);
			return CMD_WARNING;
		}
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, max_str);
	}
	XFREE(MTYPE_TMP, xpath_child);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

void neighbor_af_maximum_prefix_out_cli_write(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults)
{
	vty_out(vty, "  neighbor %s maximum-prefix-out %u\n", bgp_cli_neighbor_or_group_name(dnode),
		yang_dnode_get_uint32(dnode, NULL));
}

/*
 * allowas-in: collapses legacy's neighbor_allowas_in/no_... DEFPY pair.
 * peer_allowas_in_set()'s allow_num argument folds 'origin' (0), an
 * explicit count or -- like legacy's bare 'allowas-in' -- the implicit
 * default of 3 (BGP_ALLOWAS_IN_DEFAULT), so the positive form always
 * issues 'enabled=true' plus a definitive MODIFY-or-DESTROY for each of
 * 'origin'/'count'/'route-map', mirroring maximum-prefix's "always rewrite
 * every leaf from scratch" discipline. The negative form destroys the
 * whole container in one shot.
 */
DEFPY_YANG(
	neighbor_allowas_in, neighbor_allowas_in_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer allowas-in"
	" [route-map RMAP_NAME$rmap_name] [<(1-10)$allow_num|origin$origin_kw>]",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Accept as-path with my AS present in it\n"
	"Filter routes using route-map\n"
	"Name of route-map\n"
	"Number of occurrences of AS number\n"
	"Only accept my AS in the as-path if the route was originated in my AS\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath, *xpath_base, *xpath_child;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_base = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/allowas-in", xpath, container);
	XFREE(MTYPE_TMP, xpath);

	if (no) {
		nb_cli_enqueue_change(vty, xpath_base, NB_OP_DESTROY, NULL);
		XFREE(MTYPE_TMP, xpath_base);
		ret = nb_cli_apply_changes(vty, NULL);
		return ret;
	}

	xpath_child = asprintfrr(MTYPE_TMP, "%s/enabled", xpath_base);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "true");
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/origin", xpath_base);
	nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, origin_kw ? "true" : "false");
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/count", xpath_base);
	if (!origin_kw && allow_num_str)
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, allow_num_str);
	else
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);

	xpath_child = asprintfrr(MTYPE_TMP, "%s/route-map", xpath_base);
	if (rmap_name)
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, rmap_name);
	else
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath_child);

	XFREE(MTYPE_TMP, xpath_base);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

/* Registered on the container xpath, reproducing
 * bgp_config_write_peer_af()'s four-branch allowas-in line (route-map
 * present/absent x origin/explicit-count/implicit-default). */
void neighbor_af_allowas_in_cli_write(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	const char *name = bgp_cli_neighbor_or_group_name(dnode);
	bool origin;
	const char *rmap;

	if (!yang_dnode_get_bool(dnode, "enabled"))
		return;

	origin = yang_dnode_get_bool(dnode, "origin");
	rmap = yang_dnode_exists(dnode, "route-map") ? yang_dnode_get_string(dnode, "route-map")
						     : NULL;

	if (rmap) {
		if (origin)
			vty_out(vty, "  neighbor %s allowas-in route-map %s origin\n", name, rmap);
		else if (!yang_dnode_exists(dnode, "count"))
			vty_out(vty, "  neighbor %s allowas-in route-map %s\n", name, rmap);
		else
			vty_out(vty, "  neighbor %s allowas-in route-map %s %u\n", name, rmap,
				yang_dnode_get_uint8(dnode, "count"));
	} else {
		if (origin)
			vty_out(vty, "  neighbor %s allowas-in origin\n", name);
		else if (!yang_dnode_exists(dnode, "count"))
			vty_out(vty, "  neighbor %s allowas-in\n", name);
		else
			vty_out(vty, "  neighbor %s allowas-in %u\n", name,
				yang_dnode_get_uint8(dnode, "count"));
	}
}

/* weight: plain independent leaf, collapsing legacy's neighbor_weight/
 * no_... DEFUN pair. */
DEFPY_YANG(
	neighbor_weight, neighbor_weight_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer weight [(0-65535)$weight]",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Set default weight for routes from this neighbor\n"
	"default weight\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath, *xpath_child;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/weight", xpath, container);
	XFREE(MTYPE_TMP, xpath);

	if (no) {
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	} else {
		if (!weight_str) {
			vty_out(vty, "%% Must specify weight\n");
			XFREE(MTYPE_TMP, xpath_child);
			return CMD_WARNING;
		}
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, weight_str);
	}
	XFREE(MTYPE_TMP, xpath_child);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

void neighbor_af_weight_cli_write(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults)
{
	vty_out(vty, "  neighbor %s weight %u\n", bgp_cli_neighbor_or_group_name(dnode),
		yang_dnode_get_uint16(dnode, NULL));
}

/*
 * M5 batch B7: per-AF addpath tx/tx-best-selected/disable-rx/rx-paths-limit,
 * neighbor + peer-group -- reusing B1's xpath-building pattern (container
 * from vty->node via bgp_afi_safi_container_name(), peer/group xpath from
 * bgp_cli_peer_or_group_xpath()).
 *
 * Legacy installed all five DEFUN/DEFPY pairs
 * (neighbor_addpath_tx_all_paths, neighbor_addpath_tx_best_selected_paths,
 * neighbor_addpath_tx_bestpath_per_as, neighbor_disable_addpath_rx,
 * neighbor_addpath_paths_limit, bgp_vty.c) on the same uniform nine-AF set
 * (ipv4/ipv6 {unicast,multicast,labeled-unicast,vpn} and l2vpn evpn), unlike
 * B6's per-family asymmetric reach -- so every install set below matches
 * exactly. tx-all-paths and tx-bestpath-per-as keep their hidden BGP_NODE
 * aliases native (untouched); tx-best-selected and disable-addpath-rx had no
 * such alias and no bare BGP_NODE install, so once every per-AF
 * install_element() is removed for them here their legacy DEFUN/DEFPY bodies
 * become entirely unreachable and are deleted outright, unlike B6's
 * "every DEFUN body stays defined since something keeps it reachable"
 * precedent -- there is nothing left keeping these two reachable.
 * rx-paths-limit's bare non-hidden BGP_NODE install (operating on the
 * default ipv4-unicast AF, same as maximum-prefix-out's B6 precedent) stays
 * native.
 */

/*
 * addpath-tx-all-paths / addpath-tx-bestpath-per-AS: two of legacy's three
 * mutually-exclusive tx variants, each a bare keyword with no argument.
 * Legacy's negative forms additionally guarded on the peer's *current*
 * addpath_type before allowing the destroy ("%% Peer not currently
 * configured to transmit ..."); dropped here since the enum-typed YANG leaf
 * has exactly one "off" state regardless of which variant set it, the same
 * simplification B5 made for remove-private-as/orf-prefix-list's negative
 * forms.
 */
DEFPY_YANG(
	neighbor_addpath_tx_all_paths, neighbor_addpath_tx_all_paths_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer addpath-tx-all-paths",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Use addpath to advertise all paths to a neighbor\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath, *xpath_child;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/addpath/tx", xpath, container);

	if (no)
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "all-paths");

	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(
	neighbor_addpath_tx_bestpath_per_as, neighbor_addpath_tx_bestpath_per_as_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer addpath-tx-bestpath-per-AS",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Use addpath to advertise the bestpath per each neighboring AS\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath, *xpath_child;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/addpath/tx", xpath, container);

	if (no)
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "best-per-as");

	XFREE(MTYPE_TMP, xpath_child);
	XFREE(MTYPE_TMP, xpath);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

/*
 * addpath-tx-best-selected (1-6): the positive form sets both 'tx' and
 * 'tx-best-selected' together (paths is mandatory in the legacy grammar);
 * the negative form's optional trailing count is accepted but ignored,
 * destroying only 'tx-best-selected' -- not 'tx' -- reproducing legacy's own
 * quirk (no_neighbor_addpath_tx_best_selected_paths, bgp_vty.c, kept type
 * BGP_ADDPATH_BEST_SELECTED and merely zeroed the path count) without any
 * special-casing: bgp_nb_af_addpath_tx_apply() (bgp_nb_util.c) always
 * rereads 'tx' fresh, so leaving it untouched here naturally preserves it.
 */
DEFPY_YANG(
	neighbor_addpath_tx_best_selected_paths, neighbor_addpath_tx_best_selected_paths_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer addpath-tx-best-selected [(1-6)]$paths",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Use addpath to advertise best selected paths to a neighbor\n"
	"The number of best paths\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath, *xpath_base, *xpath_child;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_base = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/addpath", xpath, container);
	XFREE(MTYPE_TMP, xpath);

	if (no) {
		xpath_child = asprintfrr(MTYPE_TMP, "%s/tx-best-selected", xpath_base);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
		XFREE(MTYPE_TMP, xpath_child);
	} else {
		if (!paths_str) {
			vty_out(vty, "%% Must specify the number of best paths\n");
			XFREE(MTYPE_TMP, xpath_base);
			return CMD_WARNING;
		}

		xpath_child = asprintfrr(MTYPE_TMP, "%s/tx", xpath_base);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, "best-selected");
		XFREE(MTYPE_TMP, xpath_child);

		xpath_child = asprintfrr(MTYPE_TMP, "%s/tx-best-selected", xpath_base);
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, paths_str);
		XFREE(MTYPE_TMP, xpath_child);
	}
	XFREE(MTYPE_TMP, xpath_base);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

/* Registered on the 'addpath' container xpath: 'tx'/'tx-best-selected' are
 * always emitted together on one line, the same shape as
 * bgp_config_write_peer_af()'s legacy switch (bgp_vty.c). */
void neighbor_af_addpath_tx_cli_write(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	const char *name = bgp_cli_neighbor_or_group_name(dnode);
	const char *tx;

	if (!yang_dnode_exists(dnode, "tx"))
		return;

	tx = yang_dnode_get_string(dnode, "tx");

	if (strmatch(tx, "all-paths"))
		vty_out(vty, "  neighbor %s addpath-tx-all-paths\n", name);
	else if (strmatch(tx, "best-per-as"))
		vty_out(vty, "  neighbor %s addpath-tx-bestpath-per-AS\n", name);
	else if (strmatch(tx, "best-selected") && yang_dnode_exists(dnode, "tx-best-selected"))
		vty_out(vty, "  neighbor %s addpath-tx-best-selected %u\n", name,
			yang_dnode_get_uint8(dnode, "tx-best-selected"));
}

/* disable-addpath-rx: Tier A boolean flag, reusing bgp_cli_neighbor_af_flag_modify(). */
DEFPY_YANG(
	neighbor_disable_addpath_rx, neighbor_disable_addpath_rx_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer disable-addpath-rx",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Do not accept additional paths\n")
{
	return bgp_cli_neighbor_af_flag_modify(vty, peer, "addpath/disable-rx",
					       no ? "false" : "true");
}

void neighbor_af_addpath_disable_rx_cli_write(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "  neighbor %s disable-addpath-rx\n",
			bgp_cli_neighbor_or_group_name(dnode));
}

/*
 * addpath-rx-paths-limit (1-65535): plain independent leaf, collapsing
 * legacy's neighbor_addpath_paths_limit/no_... DEFPY pair.
 */
DEFPY_YANG(
	neighbor_addpath_paths_limit, neighbor_addpath_paths_limit_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer addpath-rx-paths-limit [(1-65535)]$paths_limit",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Paths Limit for Addpath to receive from the peer\n"
	"Maximum number of paths\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath, *xpath_child;
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_child = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/addpath/rx-paths-limit", xpath,
				 container);
	XFREE(MTYPE_TMP, xpath);

	if (no) {
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_DESTROY, NULL);
	} else {
		if (!paths_limit_str) {
			vty_out(vty, "%% Must specify the paths limit\n");
			XFREE(MTYPE_TMP, xpath_child);
			return CMD_WARNING;
		}
		nb_cli_enqueue_change(vty, xpath_child, NB_OP_MODIFY, paths_limit_str);
	}
	XFREE(MTYPE_TMP, xpath_child);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

void neighbor_af_addpath_rx_paths_limit_cli_write(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults)
{
	vty_out(vty, "  neighbor %s addpath-rx-paths-limit %u\n",
		bgp_cli_neighbor_or_group_name(dnode), yang_dnode_get_uint16(dnode, NULL));
}

/*
 * neighbor X dampening [(1-45) [(1-20000) (1-20000) (1-255)]] / no ... :
 * collapses legacy's neighbor_damp/no_neighbor_damp DEFPY pair (bgp_vty.c,
 * retained for the still-native BGP_NODE hidden alias only -- legacy
 * installed this pair on BGP_NODE plus the six ipv4/ipv6
 * {unicast,multicast,labeled-unicast} nodes, never vpnv4/vpnv6/l2vpn-evpn,
 * matching B6's weight precedent for asymmetric install reach). The
 * positive form always issues a concrete MODIFY of 'enabled' plus all four
 * number leaves -- reproducing legacy's own default-filling ('dampening'
 * bare -> DEFAULT_HALF_LIFE/_REUSE/_SUPPRESS/half*4; 'dampening H' -> given
 * half-life, defaults for the rest, both computed here exactly as legacy's
 * own DEFUN body did) -- never a partial update, the same "always rewrite
 * from scratch" idiom B6 established for maximum-prefix. The negative form
 * destroys the whole container in one shot, same as B6's maximum-prefix
 * teardown.
 */
DEFPY_YANG(
	neighbor_damp, neighbor_damp_cli_cmd,
	"[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer dampening"
	" [(1-45)$half [(1-20000)$reuse (1-20000)$suppress (1-255)$max]]",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Enable neighbor route-flap dampening\n"
	"Half-life time for the penalty\n"
	"Value to start reusing a route\n"
	"Value to start suppressing a route\n"
	"Maximum duration to suppress a stable route\n")
{
	const char *container = bgp_afi_safi_container_name(vty->node);
	char *xpath, *xpath_base, *xpath_child;
	char half_buf[24], reuse_buf[24], suppress_buf[24], max_buf[24];
	int ret;

	if (!container) {
		vty_out(vty, "%% address-family not modeled in proteus-bgp\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	xpath = bgp_cli_peer_or_group_xpath(vty, peer);
	if (!xpath)
		return CMD_WARNING_CONFIG_FAILED;

	xpath_base = asprintfrr(MTYPE_TMP, "%s/afi-safis/%s/dampening", xpath, container);
	XFREE(MTYPE_TMP, xpath);

	if (no) {
		nb_cli_enqueue_change(vty, xpath_base, NB_OP_DESTROY, NULL);
		XFREE(MTYPE_TMP, xpath_base);
		ret = nb_cli_apply_changes(vty, NULL);
		return ret;
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

/* Registered on the container xpath, reproducing
 * bgp_config_write_peer_damp()'s three-way rendering: bare 'dampening' when
 * every number matches the legacy defaults, 'dampening <half>' when only
 * half-life differs, else the full four-number form. */
void neighbor_af_dampening_cli_write(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults)
{
	const char *name = bgp_cli_neighbor_or_group_name(dnode);
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
		vty_out(vty, "  neighbor %s dampening\n", name);
	else if (reuse == DEFAULT_REUSE && suppress == DEFAULT_SUPPRESS && max == half * 4)
		vty_out(vty, "  neighbor %s dampening %" PRId64 "\n", name, half);
	else
		vty_out(vty, "  neighbor %s dampening %" PRId64 " %" PRId64 " %" PRId64 " %" PRId64
			     "\n",
			name, half, reuse, suppress, max);
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

	/* ebgp-multihop, ttl-security hops, disable-connected-check (M4
	 * batch B6). */
	install_element(BGP_NODE, &neighbor_ebgp_multihop_cli_cmd);
	install_element(BGP_NODE, &neighbor_ttl_security_cli_cmd);
	install_element(BGP_NODE, &neighbor_disable_connected_check_cli_cmd);

	/* update-source, ip-transparent (M4 batch B7). */
	install_element(BGP_NODE, &neighbor_update_source_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_update_source_cli_cmd);
	install_element(BGP_NODE, &neighbor_ip_transparent_cli_cmd);

	/* local-as (+ no-prepend, + replace-as, + dual-as) (M4 batch B9). */
	install_element(BGP_NODE, &neighbor_local_as_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_local_as_cli_cmd);

	/* bfd container (M4 batch B10). */
	install_element(BGP_NODE, &neighbor_bfd_cli_cmd);
	install_element(BGP_NODE, &neighbor_bfd_param_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_bfd_cli_cmd);
	install_element(BGP_NODE, &neighbor_bfd_check_controlplane_failure_cli_cmd);
	install_element(BGP_NODE, &neighbor_bfd_strict_cli_cmd);
	install_element(BGP_NODE, &neighbor_bfd_strict_hold_time_cli_cmd);
#if HAVE_BFDD > 0
	install_element(BGP_NODE, &neighbor_bfd_profile_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_bfd_profile_cli_cmd);
#endif /* HAVE_BFDD */

	/* graceful-restart-mode (M4 batch B11). */
	install_element(BGP_NODE, &neighbor_graceful_restart_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_graceful_restart_cli_cmd);
	install_element(BGP_NODE, &neighbor_graceful_restart_helper_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_graceful_restart_helper_cli_cmd);
	install_element(BGP_NODE, &neighbor_graceful_restart_disable_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_graceful_restart_disable_cli_cmd);

	/* capabilities container (M4 batch B8). */
	install_element(BGP_NODE, &neighbor_capability_dynamic_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_capability_dynamic_cli_cmd);
	install_element(BGP_NODE, &neighbor_capability_dynamic_deprecated_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_capability_dynamic_deprecated_cli_cmd);
	install_element(BGP_NODE, &neighbor_capability_enhe_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_capability_enhe_cli_cmd);
	install_element(BGP_NODE, &neighbor_capability_enhe_deprecated_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_capability_enhe_deprecated_cli_cmd);
	install_element(BGP_NODE, &neighbor_capability_software_version_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_capability_software_version_cli_cmd);
	install_element(BGP_NODE, &neighbor_capability_software_version_deprecated_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_capability_software_version_deprecated_cli_cmd);
	install_element(BGP_NODE, &neighbor_capability_software_version_latest_encoding_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_capability_software_version_latest_encoding_cli_cmd);
	install_element(BGP_NODE,
			&neighbor_capability_software_version_latest_encoding_deprecated_cli_cmd);
	install_element(BGP_NODE,
			&no_neighbor_capability_software_version_latest_encoding_deprecated_cli_cmd);
	install_element(BGP_NODE, &neighbor_capability_link_local_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_capability_link_local_cli_cmd);
	install_element(BGP_NODE, &neighbor_capability_link_local_deprecated_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_capability_link_local_deprecated_cli_cmd);
	install_element(BGP_NODE, &neighbor_capability_fqdn_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_capability_fqdn_cli_cmd);
	install_element(BGP_NODE, &neighbor_capability_fqdn_deprecated_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_capability_fqdn_deprecated_cli_cmd);
	install_element(BGP_NODE, &neighbor_dont_capability_negotiate_cli_cmd);
	install_element(BGP_NODE, &neighbor_override_capability_cli_cmd);
	install_element(BGP_NODE, &neighbor_strict_capability_cli_cmd);

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

	/* local-role (+ strict-mode), enforce-first-as (M4 batch B12). */
	install_element(BGP_NODE, &neighbor_role_cli_cmd);
	install_element(BGP_NODE, &neighbor_role_strict_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_role_cli_cmd);
	install_element(BGP_NODE, &neighbor_enforce_first_as_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_enforce_first_as_cli_cmd);
	install_element(BGP_NODE, &neighbor_enforce_first_as_deprecated_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_enforce_first_as_deprecated_cli_cmd);

	/* rpki-strict, sender-as-path-loop-detection, send-nexthop-
	 * characteristics, disable-link-bw-encoding-ieee, extended-link-
	 * bandwidth, extended-optional-parameters (M4 batch B13). */
	install_element(BGP_NODE, &neighbor_rpki_strict_cli_cmd);
	install_element(BGP_NODE, &neighbor_aspath_loop_detection_cli_cmd);

	/* "neighbor path-attribute discard"/"neighbor path-attribute
	 * treat-as-withdraw" commands (M4 batch B14). */
	install_element(BGP_NODE, &neighbor_path_attribute_discard_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_path_attribute_discard_cli_cmd);
	install_element(BGP_NODE, &neighbor_path_attribute_treat_as_withdraw_cli_cmd);
	install_element(BGP_NODE, &no_neighbor_path_attribute_treat_as_withdraw_cli_cmd);

	install_element(BGP_NODE, &neighbor_nhc_attribute_cli_cmd);
	install_element(BGP_NODE, &neighbor_disable_link_bw_encoding_ieee_cli_cmd);
	install_element(BGP_NODE, &neighbor_extended_link_bw_cli_cmd);
	install_element(BGP_NODE, &neighbor_extended_optional_parameters_cli_cmd);

	/* per-AF 'neighbor X activate' in the nine proteus address-family
	 * sub-nodes (M5 batch B1). install_element() needs a compile-time-
	 * constant node, so each is spelled out (as with exit-address-family
	 * in bgp_cli_instance.c). */
	install_element(BGP_IPV4_NODE, &neighbor_activate_cli_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_activate_cli_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_activate_cli_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_activate_cli_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_activate_cli_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_activate_cli_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_activate_cli_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_activate_cli_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_activate_cli_cmd);

	install_element(BGP_IPV4_NODE, &no_neighbor_activate_cli_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_activate_cli_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_activate_cli_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_activate_cli_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_activate_cli_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_activate_cli_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_activate_cli_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_activate_cli_cmd);
	install_element(BGP_EVPN_NODE, &no_neighbor_activate_cli_cmd);

	/* per-AF policy attachments (route-map/prefix-list/filter-list/
	 * distribute-list in|out, unsuppress-map) in the proteus
	 * address-family sub-nodes (M5 batch B2). route-map also installs in
	 * BGP_EVPN_NODE, matching the legacy install set (bgp_vty.c); the
	 * other four families never had an l2vpn-evpn command, so they don't
	 * either. */
	install_element(BGP_IPV4_NODE, &neighbor_route_map_cli_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_route_map_cli_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_route_map_cli_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_route_map_cli_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_route_map_cli_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_route_map_cli_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_route_map_cli_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_route_map_cli_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_route_map_cli_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_route_map_cli_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_route_map_cli_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_route_map_cli_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_route_map_cli_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_route_map_cli_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_route_map_cli_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_route_map_cli_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_route_map_cli_cmd);
	install_element(BGP_EVPN_NODE, &no_neighbor_route_map_cli_cmd);

	install_element(BGP_IPV4_NODE, &neighbor_prefix_list_cli_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_prefix_list_cli_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_prefix_list_cli_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_prefix_list_cli_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_prefix_list_cli_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_prefix_list_cli_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_prefix_list_cli_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_prefix_list_cli_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_prefix_list_cli_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_prefix_list_cli_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_prefix_list_cli_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_prefix_list_cli_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_prefix_list_cli_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_prefix_list_cli_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_prefix_list_cli_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_prefix_list_cli_cmd);

	install_element(BGP_IPV4_NODE, &neighbor_filter_list_cli_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_filter_list_cli_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_filter_list_cli_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_filter_list_cli_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_filter_list_cli_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_filter_list_cli_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_filter_list_cli_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_filter_list_cli_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_filter_list_cli_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_filter_list_cli_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_filter_list_cli_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_filter_list_cli_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_filter_list_cli_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_filter_list_cli_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_filter_list_cli_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_filter_list_cli_cmd);

	install_element(BGP_IPV4_NODE, &neighbor_distribute_list_cli_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_distribute_list_cli_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_distribute_list_cli_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_distribute_list_cli_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_distribute_list_cli_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_distribute_list_cli_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_distribute_list_cli_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_distribute_list_cli_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_distribute_list_cli_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_distribute_list_cli_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_distribute_list_cli_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_distribute_list_cli_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_distribute_list_cli_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_distribute_list_cli_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_distribute_list_cli_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_distribute_list_cli_cmd);

	install_element(BGP_IPV4_NODE, &neighbor_unsuppress_map_cli_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_unsuppress_map_cli_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_unsuppress_map_cli_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_unsuppress_map_cli_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_unsuppress_map_cli_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_unsuppress_map_cli_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_unsuppress_map_cli_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_unsuppress_map_cli_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_unsuppress_map_cli_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_unsuppress_map_cli_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_unsuppress_map_cli_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_unsuppress_map_cli_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_unsuppress_map_cli_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_unsuppress_map_cli_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_unsuppress_map_cli_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_unsuppress_map_cli_cmd);

	/* per-AF conditional-advertisement (advertise-map) and site-of-origin
	 * (soo), neighbor + peer-group (M5 batch B3). advertise-map matches
	 * legacy's eight-AF install set (never l2vpn evpn); soo matches
	 * legacy's nine-AF set (including BGP_EVPN_NODE). */
	install_element(BGP_IPV4_NODE, &neighbor_advertise_map_cli_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_advertise_map_cli_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_advertise_map_cli_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_advertise_map_cli_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_advertise_map_cli_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_advertise_map_cli_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_advertise_map_cli_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_advertise_map_cli_cmd);

	install_element(BGP_IPV4_NODE, &neighbor_soo_cli_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_soo_cli_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_soo_cli_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_soo_cli_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_soo_cli_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_soo_cli_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_soo_cli_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_soo_cli_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_soo_cli_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_soo_cli_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_soo_cli_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_soo_cli_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_soo_cli_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_soo_cli_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_soo_cli_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_soo_cli_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_soo_cli_cmd);
	install_element(BGP_EVPN_NODE, &no_neighbor_soo_cli_cmd);

	/* per-AF plain PEER_FLAG_* booleans, neighbor + peer-group (M5 batch
	 * B4). Each install set matches the retired legacy DEFUN's per-AF
	 * install_element() calls exactly; where legacy kept a hidden
	 * BGP_NODE alias (or, for next-hop-self, a hidden 'all' alias
	 * reachable inside every AF node), that alias is left native and
	 * untouched in bgp_vty.c. */
	install_element(BGP_IPV4_NODE, &neighbor_route_reflector_client_cli_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_route_reflector_client_cli_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_route_reflector_client_cli_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_route_reflector_client_cli_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_route_reflector_client_cli_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_route_reflector_client_cli_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_route_reflector_client_cli_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_route_reflector_client_cli_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_route_reflector_client_cli_cmd);

	install_element(BGP_IPV4_NODE, &neighbor_route_server_client_cli_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_route_server_client_cli_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_route_server_client_cli_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_route_server_client_cli_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_route_server_client_cli_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_route_server_client_cli_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_route_server_client_cli_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_route_server_client_cli_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_route_server_client_cli_cmd);

	/* as-override: legacy never reached BGP_EVPN_NODE. */
	install_element(BGP_IPV4_NODE, &neighbor_as_override_cli_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_as_override_cli_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_as_override_cli_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_as_override_cli_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_as_override_cli_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_as_override_cli_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_as_override_cli_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_as_override_cli_cmd);

	install_element(BGP_IPV4_NODE, &neighbor_nexthop_self_cli_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_nexthop_self_cli_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_nexthop_self_cli_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_nexthop_self_cli_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_nexthop_self_cli_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_nexthop_self_cli_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_nexthop_self_cli_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_nexthop_self_cli_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_nexthop_self_cli_cmd);

	/* nexthop-local unchanged: legacy only ever reached BGP_IPV6_NODE. */
	install_element(BGP_IPV6_NODE, &neighbor_nexthop_local_unchanged_cli_cmd);

	install_element(BGP_IPV4_NODE, &neighbor_soft_reconfiguration_cli_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_soft_reconfiguration_cli_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_soft_reconfiguration_cli_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_soft_reconfiguration_cli_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_soft_reconfiguration_cli_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_soft_reconfiguration_cli_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_soft_reconfiguration_cli_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_soft_reconfiguration_cli_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_soft_reconfiguration_cli_cmd);

	/* accept-own: legacy only ever reached BGP_VPNV4_NODE/BGP_VPNV6_NODE. */
	install_element(BGP_VPNV4_NODE, &neighbor_accept_own_cli_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_accept_own_cli_cmd);

	install_element(BGP_IPV4_NODE, &neighbor_attribute_unchanged_cli_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_attribute_unchanged_cli_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_attribute_unchanged_cli_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_attribute_unchanged_cli_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_attribute_unchanged_cli_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_attribute_unchanged_cli_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_attribute_unchanged_cli_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_attribute_unchanged_cli_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_attribute_unchanged_cli_cmd);

	/* send-community (+ type + extended rpki) + remove-private-as +
	 * capability orf prefix-list, neighbor + peer-group (M5 batch B5).
	 * Install sets match the retired legacy DEFUNs' per-AF
	 * install_element() calls exactly (none of the four ever reached
	 * BGP_EVPN_NODE; orf additionally never reached the two VPN nodes) --
	 * the corresponding hidden BGP_NODE aliases (bare BGP_NODE for
	 * extended rpki) are left native and untouched in bgp_vty.c. */
	install_element(BGP_IPV4_NODE, &neighbor_send_community_cli_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_send_community_cli_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_send_community_cli_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_send_community_cli_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_send_community_cli_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_send_community_cli_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_send_community_cli_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_send_community_cli_cmd);

	install_element(BGP_IPV4_NODE, &neighbor_send_community_type_cli_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_send_community_type_cli_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_send_community_type_cli_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_send_community_type_cli_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_send_community_type_cli_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_send_community_type_cli_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_send_community_type_cli_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_send_community_type_cli_cmd);

	install_element(BGP_IPV4_NODE, &neighbor_ecommunity_rpki_cli_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_ecommunity_rpki_cli_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_ecommunity_rpki_cli_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_ecommunity_rpki_cli_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_ecommunity_rpki_cli_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_ecommunity_rpki_cli_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_ecommunity_rpki_cli_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_ecommunity_rpki_cli_cmd);

	install_element(BGP_IPV4_NODE, &neighbor_remove_private_as_cli_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_remove_private_as_cli_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_remove_private_as_cli_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_remove_private_as_cli_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_remove_private_as_cli_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_remove_private_as_cli_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_remove_private_as_cli_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_remove_private_as_cli_cmd);

	/* capability orf prefix-list: legacy never reached the VPN nodes. */
	install_element(BGP_IPV4_NODE, &neighbor_capability_orf_prefix_cli_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_capability_orf_prefix_cli_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_capability_orf_prefix_cli_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_capability_orf_prefix_cli_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_capability_orf_prefix_cli_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_capability_orf_prefix_cli_cmd);

	/* default-originate + maximum-prefix (+opts) + maximum-prefix-out +
	 * allowas-in + weight, neighbor + peer-group (M5 batch B6). Install
	 * sets match the retired legacy DEFUNs' per-AF install_element()
	 * calls exactly. */

	/* default-originate: legacy never reached vpn or l2vpn evpn. */
	install_element(BGP_IPV4_NODE, &neighbor_default_originate_cli_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_default_originate_cli_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_default_originate_cli_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_default_originate_cli_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_default_originate_cli_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_default_originate_cli_cmd);

	/* maximum-prefix: legacy reached all nine proteus AFs (including
	 * BGP_EVPN_NODE); still native for the unmodeled unreachability
	 * BGP_IPV4U_NODE/BGP_IPV6U_NODE. */
	install_element(BGP_IPV4_NODE, &neighbor_maximum_prefix_cli_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_maximum_prefix_cli_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_maximum_prefix_cli_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_maximum_prefix_cli_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_maximum_prefix_cli_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_maximum_prefix_cli_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_maximum_prefix_cli_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_maximum_prefix_cli_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_maximum_prefix_cli_cmd);

	/* maximum-prefix-out: legacy never reached l2vpn evpn; still native
	 * for the unmodeled unreachability nodes and the bare BGP_NODE
	 * install (no hidden alias for this one -- the retired DEFUN's own
	 * plain BGP_NODE install operated directly on the default
	 * ipv4-unicast AF). */
	install_element(BGP_IPV4_NODE, &neighbor_maximum_prefix_out_cli_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_maximum_prefix_out_cli_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_maximum_prefix_out_cli_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_maximum_prefix_out_cli_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_maximum_prefix_out_cli_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_maximum_prefix_out_cli_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_maximum_prefix_out_cli_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_maximum_prefix_out_cli_cmd);

	/* allowas-in: legacy reached all nine proteus AFs (including
	 * BGP_EVPN_NODE). */
	install_element(BGP_IPV4_NODE, &neighbor_allowas_in_cli_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_allowas_in_cli_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_allowas_in_cli_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_allowas_in_cli_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_allowas_in_cli_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_allowas_in_cli_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_allowas_in_cli_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_allowas_in_cli_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_allowas_in_cli_cmd);

	/* weight: legacy never reached l2vpn evpn. */
	install_element(BGP_IPV4_NODE, &neighbor_weight_cli_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_weight_cli_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_weight_cli_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_weight_cli_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_weight_cli_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_weight_cli_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_weight_cli_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_weight_cli_cmd);

	/* addpath tx/tx-best-selected/disable-rx/rx-paths-limit, neighbor +
	 * peer-group (M5 batch B7): legacy reached all nine proteus AFs
	 * uniformly for every one of the five commands. */
	install_element(BGP_IPV4_NODE, &neighbor_addpath_tx_all_paths_cli_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_addpath_tx_all_paths_cli_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_addpath_tx_all_paths_cli_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_addpath_tx_all_paths_cli_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_addpath_tx_all_paths_cli_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_addpath_tx_all_paths_cli_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_addpath_tx_all_paths_cli_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_addpath_tx_all_paths_cli_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_addpath_tx_all_paths_cli_cmd);

	install_element(BGP_IPV4_NODE, &neighbor_addpath_tx_bestpath_per_as_cli_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_addpath_tx_bestpath_per_as_cli_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_addpath_tx_bestpath_per_as_cli_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_addpath_tx_bestpath_per_as_cli_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_addpath_tx_bestpath_per_as_cli_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_addpath_tx_bestpath_per_as_cli_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_addpath_tx_bestpath_per_as_cli_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_addpath_tx_bestpath_per_as_cli_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_addpath_tx_bestpath_per_as_cli_cmd);

	install_element(BGP_IPV4_NODE, &neighbor_addpath_tx_best_selected_paths_cli_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_addpath_tx_best_selected_paths_cli_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_addpath_tx_best_selected_paths_cli_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_addpath_tx_best_selected_paths_cli_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_addpath_tx_best_selected_paths_cli_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_addpath_tx_best_selected_paths_cli_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_addpath_tx_best_selected_paths_cli_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_addpath_tx_best_selected_paths_cli_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_addpath_tx_best_selected_paths_cli_cmd);

	install_element(BGP_IPV4_NODE, &neighbor_disable_addpath_rx_cli_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_disable_addpath_rx_cli_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_disable_addpath_rx_cli_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_disable_addpath_rx_cli_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_disable_addpath_rx_cli_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_disable_addpath_rx_cli_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_disable_addpath_rx_cli_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_disable_addpath_rx_cli_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_disable_addpath_rx_cli_cmd);

	install_element(BGP_IPV4_NODE, &neighbor_addpath_paths_limit_cli_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_addpath_paths_limit_cli_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_addpath_paths_limit_cli_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_addpath_paths_limit_cli_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_addpath_paths_limit_cli_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_addpath_paths_limit_cli_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_addpath_paths_limit_cli_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_addpath_paths_limit_cli_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_addpath_paths_limit_cli_cmd);

	/* per-neighbor dampening (M5 batch B8): legacy reached only the six
	 * ipv4/ipv6 {unicast,multicast,labeled-unicast} nodes (plus the
	 * hidden BGP_NODE alias, which bgp_afi_safi_container_name() cannot
	 * map to a proteus container and is intentionally left
	 * unconverted), never vpnv4/vpnv6/l2vpn-evpn. */
	install_element(BGP_IPV4_NODE, &neighbor_damp_cli_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_damp_cli_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_damp_cli_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_damp_cli_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_damp_cli_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_damp_cli_cmd);
}
