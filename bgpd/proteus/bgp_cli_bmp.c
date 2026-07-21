// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Robin Christ, partimus GmbH */
/* BMP CLI (DEFPYs + northbound cli_show callbacks) for the
 * proteus-bgp-bmp module, compiled into mgmtd alongside its bgp_cli_*
 * siblings (TODO #31 batch B2, replacing bgpd/bgp_bmp.c's config
 * DEFPYs). The grammar is byte-identical to the plugin's.
 *
 * The 'bmp targets' node entry does a real CREATE of the targets list
 * entry (the M6 vni / M8.5 srv6 NOSH pattern), so a bare targets group
 * survives a configuration write like it always did; the BMP_NODE
 * commands then work with relative xpaths against the pushed entry.
 */
#include <zebra.h>

#include "command.h"
#include "northbound.h"
#include "northbound_cli.h"
#include "vty.h"
#include "vrf.h"

#include "bgpd/bgp_cli.h"
#include "bgpd/proteus/bgp_cli_local.h"
#include "bgpd/proteus/bgp_cli_bmp_clippy.c"

#define BMP_STR "BGP Monitoring Protocol\n"

/* mgmtd-side parallel cmd_node (mgmtd renders via cli_show, so no
 * config_write). */
static struct cmd_node bmp_cmd_node = {
	.name = "bmp",
	.node = BMP_NODE,
	.parent_node = BGP_NODE,
	.prompt = "%s(config-bgp-bmp)# ",
};

DEFPY_YANG_NOSH(bmp_targets_main,
      bmp_targets_cmd,
      "bmp targets BMPTARGETS",
      BMP_STR
      "Create BMP target group\n"
      "Name of the BMP target group\n")
{
	char xpath[XPATH_MAXLEN];
	int rv;

	snprintf(xpath, sizeof(xpath), "%s/proteus-bgp-bmp:bmp/targets[name='%s']", VTY_CURR_XPATH,
		 bmptargets);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	rv = nb_cli_apply_changes(vty, NULL);
	if (rv == CMD_SUCCESS)
		VTY_PUSH_XPATH(BMP_NODE, xpath);

	return rv;
}

DEFPY_YANG(no_bmp_targets_main,
      no_bmp_targets_cmd,
      "no bmp targets BMPTARGETS",
      NO_STR
      BMP_STR
      "Delete BMP target group\n"
      "Name of the BMP target group\n")
{
	char xpath[XPATH_MAXLEN];

	if (!yang_dnode_existsf(vty->candidate_config->dnode,
				"%s/proteus-bgp-bmp:bmp/targets[name='%s']", VTY_CURR_XPATH,
				bmptargets)) {
		vty_out(vty, "%% BMP target group not found\n");
		return CMD_WARNING;
	}

	snprintf(xpath, sizeof(xpath), "./proteus-bgp-bmp:bmp/targets[name='%s']", bmptargets);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

/* Importing the enclosing instance itself is rejected like it always
 * was; note the historical quirk that this only ever caught non-default
 * instances (the default instance could always 'import' itself by the
 * name 'default', a no-op at runtime), reproduced as-is. */
DEFPY_YANG(bmp_import_vrf,
      bmp_import_vrf_cmd,
      "[no] bmp import-vrf-view VRFNAME$vrfname",
      NO_STR
      BMP_STR
      "Import BMP information from another VRF\n"
      "Specify the VRF or view instance name\n")
{
	char xpath[XPATH_MAXLEN];
	const struct lyd_node *targets_dnode;
	const char *instance_vrf;

	targets_dnode = yang_dnode_get(vty->candidate_config->dnode, VTY_CURR_XPATH);
	if (!targets_dnode) {
		vty_out(vty, "%% Failed to get targets dnode in candidate db\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	instance_vrf = yang_dnode_get_string(targets_dnode, "../../vrf");
	if (!strmatch(instance_vrf, VRF_DEFAULT_NAME) && strmatch(vrfname, instance_vrf)) {
		vty_out(vty, "%% BMP target, can not import our own BGP instance\n");
		return CMD_WARNING;
	}

	if (no && !yang_dnode_existsf(vty->candidate_config->dnode, "%s/import-vrf-view[.='%s']",
				      VTY_CURR_XPATH, vrfname)) {
		vty_out(vty, "%% BMP imported BGP instance not found\n");
		return CMD_WARNING;
	}

	snprintf(xpath, sizeof(xpath), "./import-vrf-view[.='%s']", vrfname);
	nb_cli_enqueue_change(vty, xpath, no ? NB_OP_DESTROY : NB_OP_CREATE, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bmp_listener_main,
      bmp_listener_cmd,
      "bmp listener <X:X::X:X|A.B.C.D> port (1-65535)",
      BMP_STR
      "Listen for inbound BMP connections\n"
      "IPv6 address to listen on\n"
      "IPv4 address to listen on\n"
      "TCP Port number\n"
      "TCP Port number\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "./listener[address='%s'][port='%" PRId64 "']",
		 listener_str, port);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_bmp_listener_main,
      no_bmp_listener_cmd,
      "no bmp listener <X:X::X:X|A.B.C.D> port (1-65535)",
      NO_STR
      BMP_STR
      "Create BMP listener\n"
      "IPv6 address to listen on\n"
      "IPv4 address to listen on\n"
      "TCP Port number\n"
      "TCP Port number\n")
{
	char xpath[XPATH_MAXLEN];

	if (!yang_dnode_existsf(vty->candidate_config->dnode,
				"%s/listener[address='%s'][port='%" PRId64 "']", VTY_CURR_XPATH,
				listener_str, port)) {
		vty_out(vty, "%% BMP listener not found\n");
		return CMD_WARNING;
	}

	snprintf(xpath, sizeof(xpath), "./listener[address='%s'][port='%" PRId64 "']",
		 listener_str, port);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

/* Positive form: an omitted min-retry/max-retry/source-interface keeps a
 * previously configured value, like the legacy command did. The no-form
 * destroys the keyed entry regardless of the optional tail (the legacy
 * command additionally required the source-interface to match; dropped
 * as a deliberate simplification of the keyed datastore semantics). */
DEFPY_YANG(bmp_connect,
      bmp_connect_cmd,
      "[no] bmp connect HOSTNAME port (1-65535) {min-retry (100-86400000)|max-retry (100-86400000)} [source-interface <WORD$srcif>]",
      NO_STR
      BMP_STR
      "Actively establish connection to monitoring station\n"
      "Monitoring station hostname or address\n"
      "TCP port\n"
      "TCP port\n"
      "Minimum connection retry interval\n"
      "Minimum connection retry interval (milliseconds)\n"
      "Maximum connection retry interval\n"
      "Maximum connection retry interval (milliseconds)\n"
      "Source interface to use\n"
      "Define an interface\n")
{
	char xpath[XPATH_MAXLEN];

	if (no) {
		if (!yang_dnode_existsf(vty->candidate_config->dnode,
					"%s/connect[hostname='%s'][port='%" PRId64 "']",
					VTY_CURR_XPATH, hostname, port)) {
			vty_out(vty, "%% No such active connection found\n");
			return CMD_WARNING;
		}

		snprintf(xpath, sizeof(xpath), "./connect[hostname='%s'][port='%" PRId64 "']",
			 hostname, port);
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

		return nb_cli_apply_changes(vty, NULL);
	}

	snprintf(xpath, sizeof(xpath), "./connect[hostname='%s'][port='%" PRId64 "']", hostname,
		 port);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	if (min_retry_str) {
		snprintf(xpath, sizeof(xpath),
			 "./connect[hostname='%s'][port='%" PRId64 "']/min-retry", hostname, port);
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, min_retry_str);
	}
	if (max_retry_str) {
		snprintf(xpath, sizeof(xpath),
			 "./connect[hostname='%s'][port='%" PRId64 "']/max-retry", hostname, port);
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, max_retry_str);
	}
	if (srcif) {
		snprintf(xpath, sizeof(xpath),
			 "./connect[hostname='%s'][port='%" PRId64 "']/source-interface", hostname,
			 port);
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, srcif);
	}

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bmp_acl,
      bmp_acl_cmd,
      "[no] <ip|ipv6>$af access-list ACCESSLIST_NAME$access_list",
      NO_STR
      IP_STR
      IPV6_STR
      "Access list to restrict BMP sessions\n"
      "Access list name\n")
{
	const char *leaf = strmatch(af, "ipv6") ? "./ipv6-access-list" : "./ipv4-access-list";

	nb_cli_enqueue_change(vty, leaf, no ? NB_OP_DESTROY : NB_OP_MODIFY,
			      no ? NULL : access_list);

	return nb_cli_apply_changes(vty, NULL);
}

/* Bare 'bmp stats' restores the default interval, like the legacy
 * command; the emission always re-states the interval. */
DEFPY_YANG(bmp_stats_cfg,
      bmp_stats_cmd,
      "[no] bmp stats [interval (100-86400000)]",
      NO_STR
      BMP_STR
      "Send BMP statistics messages\n"
      "Specify BMP stats interval\n"
      "Interval (milliseconds) to send BMP Stats in\n")
{
	if (no) {
		nb_cli_enqueue_change(vty, "./stats", NB_OP_DESTROY, NULL);
		return nb_cli_apply_changes(vty, NULL);
	}

	nb_cli_enqueue_change(vty, "./stats", NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, "./stats/interval", interval_str ? NB_OP_MODIFY : NB_OP_DESTROY,
			      interval_str);

	return nb_cli_apply_changes(vty, NULL);
}

/* Tier A default-on boolean: the positive form destroys the leaf back to
 * its true default, the no-form persists an explicit 'false' that emits
 * the legacy 'no bmp stats send-experimental' line. */
DEFPY_YANG(bmp_stats_send_experimental,
      bmp_stats_send_experimental_cmd,
      "[no] bmp stats send-experimental",
      NO_STR
      BMP_STR
      "Send BMP statistics messages\n"
      "Send experimental BMP stats [65531-65534]\n")
{
	nb_cli_enqueue_change(vty, "./stats-send-experimental", no ? NB_OP_MODIFY : NB_OP_DESTROY,
			      no ? "false" : NULL);

	return nb_cli_apply_changes(vty, NULL);
}

static const char *bmp_monitor_policy_leaf(const char *policy)
{
	if (strmatch(policy, "pre-policy"))
		return "rib-in-pre-policy";
	if (strmatch(policy, "post-policy"))
		return "rib-in-post-policy";
	return "loc-rib";
}

DEFPY_YANG(bmp_monitor_cfg, bmp_monitor_cmd,
      "[no] bmp monitor <ipv4|ipv6|l2vpn>$afi_token <unicast|multicast|evpn|vpn>$safi_token <pre-policy|post-policy|loc-rib>$policy",
      NO_STR BMP_STR
      "Send BMP route monitoring messages\n" BGP_AF_STR BGP_AF_STR BGP_AF_STR
	      BGP_AF_STR BGP_AF_STR BGP_AF_STR BGP_AF_STR
      "Send state before policy and filter processing\n"
      "Send state with policy and filters applied\n"
      "Send state after decision process is applied\n")
{
	char xpath[XPATH_MAXLEN];
	const char *leaf = bmp_monitor_policy_leaf(policy);

	if (no) {
		bool others = false;
		const char *other;
		const char *leaves[] = { "rib-in-pre-policy", "rib-in-post-policy", "loc-rib" };

		/* Unsetting a view point that was never set is accepted
		 * as a no-op, like it always was; unsetting the last set
		 * view point removes the whole monitor entry so it does
		 * not linger in the configuration. */
		if (!yang_dnode_existsf(vty->candidate_config->dnode,
					"%s/monitor[afi-safi='%s-%s']", VTY_CURR_XPATH, afi_token,
					safi_token))
			return CMD_SUCCESS;

		for (size_t i = 0; i < array_size(leaves); i++) {
			other = leaves[i];
			if (strmatch(other, leaf))
				continue;
			if (yang_dnode_get_bool(vty->candidate_config->dnode,
						"%s/monitor[afi-safi='%s-%s']/%s", VTY_CURR_XPATH,
						afi_token, safi_token, other))
				others = true;
		}

		if (others) {
			snprintf(xpath, sizeof(xpath), "./monitor[afi-safi='%s-%s']/%s", afi_token,
				 safi_token, leaf);
			nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
		} else {
			snprintf(xpath, sizeof(xpath), "./monitor[afi-safi='%s-%s']", afi_token,
				 safi_token);
			nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
		}

		return nb_cli_apply_changes(vty, NULL);
	}

	snprintf(xpath, sizeof(xpath), "./monitor[afi-safi='%s-%s']", afi_token, safi_token);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath, sizeof(xpath), "./monitor[afi-safi='%s-%s']/%s", afi_token, safi_token,
		 leaf);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, "true");

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bmp_mirror_cfg,
      bmp_mirror_cmd,
      "[no] bmp mirror",
      NO_STR
      BMP_STR
      "Send BMP route mirroring messages\n")
{
	nb_cli_enqueue_change(vty, "./mirror", no ? NB_OP_DESTROY : NB_OP_MODIFY,
			      no ? NULL : "true");

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bmp_mirror_limit_cfg,
      bmp_mirror_limit_cmd,
      "bmp mirror buffer-limit (0-4294967294)",
      BMP_STR
      "Route Mirroring settings\n"
      "Configure maximum memory used for buffered mirroring messages\n"
      "Limit in bytes\n")
{
	nb_cli_enqueue_change(vty, "./proteus-bgp-bmp:bmp/mirror-buffer-limit", NB_OP_MODIFY,
			      buffer_limit_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_bmp_mirror_limit_cfg,
      no_bmp_mirror_limit_cmd,
      "no bmp mirror buffer-limit [(0-4294967294)]",
      NO_STR
      BMP_STR
      "Route Mirroring settings\n"
      "Configure maximum memory used for buffered mirroring messages\n"
      "Limit in bytes\n")
{
	nb_cli_enqueue_change(vty, "./proteus-bgp-bmp:bmp/mirror-buffer-limit", NB_OP_DESTROY,
			      NULL);

	return nb_cli_apply_changes(vty, NULL);
}

/* Emitters, byte-identical to the pre-conversion bmp_config_write
 * including the ' !' separator lines and the historical three-space
 * indent of the listener line. The container sits on proteus-bgp's
 * instance as an augment, so the block renders at the end of the
 * 'router bgp' block, where the legacy hook emitted it too. */
static void bmp_mirror_buffer_limit_cli_write(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults)
{
	vty_out(vty, " !\n bmp mirror buffer-limit %s\n", yang_dnode_get_string(dnode, NULL));
}

static void bmp_targets_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " !\n bmp targets %s\n", yang_dnode_get_string(dnode, "name"));
}

static void bmp_targets_cli_write_end(struct vty *vty, const struct lyd_node *dnode)
{
	vty_out(vty, " exit\n");
}

static void bmp_targets_ipv6_access_list_cli_write(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults)
{
	vty_out(vty, "  ipv6 access-list %s\n", yang_dnode_get_string(dnode, NULL));
}

static void bmp_targets_ipv4_access_list_cli_write(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults)
{
	vty_out(vty, "  ip access-list %s\n", yang_dnode_get_string(dnode, NULL));
}

static void bmp_targets_stats_send_experimental_cli_write(struct vty *vty,
							  const struct lyd_node *dnode,
							  bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "  no bmp stats send-experimental\n");
}

static void bmp_targets_stats_cli_write(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults)
{
	/* 'bmp stats' always re-emits in interval form, like legacy. */
	vty_out(vty, "  bmp stats interval %s\n", yang_dnode_get_string(dnode, "interval"));
}

static void bmp_targets_mirror_cli_write(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "  bmp mirror\n");
}

static void bmp_targets_monitor_cli_write(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	/* The afi-safi value is '<afi> <safi>' with the dash swapped for
	 * the command's token separator. */
	const char *afi_safi = yang_dnode_get_string(dnode, "afi-safi");
	const char *safi_str = strchr(afi_safi, '-') + 1;
	char afi_str[16];

	strlcpy(afi_str, afi_safi, sizeof(afi_str));
	afi_str[safi_str - afi_safi - 1] = '\0';

	if (yang_dnode_get_bool(dnode, "rib-in-pre-policy"))
		vty_out(vty, "  bmp monitor %s %s pre-policy\n", afi_str, safi_str);
	if (yang_dnode_get_bool(dnode, "rib-in-post-policy"))
		vty_out(vty, "  bmp monitor %s %s post-policy\n", afi_str, safi_str);
	if (yang_dnode_get_bool(dnode, "loc-rib"))
		vty_out(vty, "  bmp monitor %s %s loc-rib\n", afi_str, safi_str);
}

static void bmp_targets_import_vrf_view_cli_write(struct vty *vty, const struct lyd_node *dnode,
						  bool show_defaults)
{
	vty_out(vty, "  bmp import-vrf-view %s\n", yang_dnode_get_string(dnode, NULL));
}

static void bmp_targets_listener_cli_write(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	/* The three-space indent is a historical quirk, kept as-is. */
	vty_out(vty, "   bmp listener %s port %s\n", yang_dnode_get_string(dnode, "address"),
		yang_dnode_get_string(dnode, "port"));
}

static void bmp_targets_connect_cli_write(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	vty_out(vty, "  bmp connect %s port %s min-retry %s max-retry %s",
		yang_dnode_get_string(dnode, "hostname"), yang_dnode_get_string(dnode, "port"),
		yang_dnode_get_string(dnode, "min-retry"),
		yang_dnode_get_string(dnode, "max-retry"));

	if (yang_dnode_exists(dnode, "source-interface"))
		vty_out(vty, " source-interface %s\n",
			yang_dnode_get_string(dnode, "source-interface"));
	else
		vty_out(vty, "\n");
}

/* clang-format off */
const struct frr_yang_module_info proteus_bgp_bmp_cli_info = {
	.name = "proteus-bgp-bmp",
	.ignore_cfg_cbs = true,
	.nodes = {
		{
			.xpath = "/proteus-bgp:instance/proteus-bgp-bmp:bmp/mirror-buffer-limit",
			.cbs = {
				.cli_show = bmp_mirror_buffer_limit_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/proteus-bgp-bmp:bmp/targets",
			.cbs = {
				.cli_show = bmp_targets_cli_write,
				.cli_show_end = bmp_targets_cli_write_end,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/proteus-bgp-bmp:bmp/targets/ipv6-access-list",
			.cbs = {
				.cli_show = bmp_targets_ipv6_access_list_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/proteus-bgp-bmp:bmp/targets/ipv4-access-list",
			.cbs = {
				.cli_show = bmp_targets_ipv4_access_list_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/proteus-bgp-bmp:bmp/targets/stats-send-experimental",
			.cbs = {
				.cli_show = bmp_targets_stats_send_experimental_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/proteus-bgp-bmp:bmp/targets/stats",
			.cbs = {
				.cli_show = bmp_targets_stats_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/proteus-bgp-bmp:bmp/targets/mirror",
			.cbs = {
				.cli_show = bmp_targets_mirror_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/proteus-bgp-bmp:bmp/targets/monitor",
			.cbs = {
				.cli_show = bmp_targets_monitor_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/proteus-bgp-bmp:bmp/targets/import-vrf-view",
			.cbs = {
				.cli_show = bmp_targets_import_vrf_view_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/proteus-bgp-bmp:bmp/targets/listener",
			.cbs = {
				.cli_show = bmp_targets_listener_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/proteus-bgp-bmp:bmp/targets/connect",
			.cbs = {
				.cli_show = bmp_targets_connect_cli_write,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
/* clang-format on */

void bgp_cli_bmp_init(void)
{
	install_node(&bmp_cmd_node);
	install_default(BMP_NODE);

	install_element(BGP_NODE, &bmp_targets_cmd);
	install_element(BGP_NODE, &no_bmp_targets_cmd);

	install_element(BMP_NODE, &bmp_listener_cmd);
	install_element(BMP_NODE, &no_bmp_listener_cmd);
	install_element(BMP_NODE, &bmp_connect_cmd);
	install_element(BMP_NODE, &bmp_acl_cmd);
	install_element(BMP_NODE, &bmp_stats_send_experimental_cmd);
	install_element(BMP_NODE, &bmp_stats_cmd);
	install_element(BMP_NODE, &bmp_monitor_cmd);
	install_element(BMP_NODE, &bmp_mirror_cmd);
	install_element(BMP_NODE, &bmp_import_vrf_cmd);

	install_element(BGP_NODE, &bmp_mirror_limit_cmd);
	install_element(BGP_NODE, &no_bmp_mirror_limit_cmd);
}
