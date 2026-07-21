// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Robin Christ, partimus GmbH */
/* RPKI CLI (DEFPYs + northbound cli_show callbacks) for the
 * proteus-bgp-rpki module, compiled into mgmtd alongside its bgp_cli_*
 * siblings (TODO #31 batch B1, replacing bgpd/bgp_rpki.c's config
 * DEFUNs). The grammar - including the historical underscore keywords
 * polling_period / retry_interval / expire_interval - is byte-identical
 * to the plugin's.
 *
 * The 'rpki' node entry does a real CREATE of the instance list entry
 * (the M6 vni / M8.5 srv6 NOSH pattern); at VRF_NODE the instance key is
 * the enclosing vrf's name from the pushed frr-vrf xpath. An instance
 * with no caches and default timers emits nothing (vty_frame
 * suppression), so a bare 'rpki' entry does not survive a config write -
 * same as the pre-conversion emission.
 */
#include <zebra.h>

#include "command.h"
#include "northbound.h"
#include "northbound_cli.h"
#include "vty.h"
#include "vrf.h"

#include "bgpd/bgp_cli.h"
#include "bgpd/proteus/bgp_cli_local.h"
#include "bgpd/proteus/bgp_cli_rpki_clippy.c"

#define RPKI_OUTPUT_STRING "Control rpki specific settings\n"

/* mgmtd-side parallel cmd_nodes (mgmtd renders via cli_show, so no
 * config_write). */
static struct cmd_node rpki_cmd_node = {
	.name = "rpki",
	.node = RPKI_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-rpki)# ",
};

static struct cmd_node rpki_vrf_cmd_node = {
	.name = "rpki",
	.node = RPKI_VRF_NODE,
	.parent_node = VRF_NODE,
	.prompt = "%s(config-vrf-rpki)# ",
};

/* Instance xpath for the scope the command runs in: the default VRF at
 * CONFIG_NODE/RPKI_NODE, the enclosing vrf's name at
 * VRF_NODE/RPKI_VRF_NODE (its frr-vrf list entry is the pushed xpath). */
static int rpki_instance_xpath(struct vty *vty, char *xpath, size_t len)
{
	const char *vrfname = VRF_DEFAULT_NAME;

	if (vty->node == VRF_NODE || vty->node == RPKI_VRF_NODE) {
		const struct lyd_node *vrf_dnode;

		vrf_dnode = yang_dnode_get(vty->candidate_config->dnode, VTY_CURR_XPATH);
		if (!vrf_dnode) {
			vty_out(vty, "%% Failed to get vrf dnode in candidate db\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		vrfname = yang_dnode_get_string(vrf_dnode, "name");
	}

	snprintf(xpath, len, "/proteus-bgp-rpki:rpki/instance[vrf='%s']", vrfname);
	return CMD_SUCCESS;
}

DEFPY_YANG_NOSH (rpki,
		 rpki_cli_cmd,
		 "rpki",
		 "Enable rpki and enter rpki configuration mode\n")
{
	char xpath[XPATH_MAXLEN];
	int node = vty->node == VRF_NODE ? RPKI_VRF_NODE : RPKI_NODE;
	int rv;

	rv = rpki_instance_xpath(vty, xpath, sizeof(xpath));
	if (rv != CMD_SUCCESS)
		return rv;

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	rv = nb_cli_apply_changes(vty, NULL);
	if (rv == CMD_SUCCESS)
		VTY_PUSH_XPATH(node, xpath);

	return rv;
}

DEFPY_YANG (no_rpki,
	    no_rpki_cli_cmd,
	    "no rpki",
	    NO_STR
	    "Enable rpki and enter rpki configuration mode\n")
{
	char xpath[XPATH_MAXLEN];
	int rv;

	rv = rpki_instance_xpath(vty, xpath, sizeof(xpath));
	if (rv != CMD_SUCCESS)
		return rv;

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (rpki_polling_period,
	    rpki_polling_period_cli_cmd,
	    "rpki polling_period (1-86400)$pp",
	    RPKI_OUTPUT_STRING
	    "Set polling period\n"
	    "Polling period value\n")
{
	nb_cli_enqueue_change(vty, "./polling-period", NB_OP_MODIFY, pp_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (no_rpki_polling_period,
	    no_rpki_polling_period_cli_cmd,
	    "no rpki polling_period [(1-86400)]",
	    NO_STR
	    RPKI_OUTPUT_STRING
	    "Set polling period back to default\n"
	    "Polling period value\n")
{
	nb_cli_enqueue_change(vty, "./polling-period", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (rpki_expire_interval,
	    rpki_expire_interval_cli_cmd,
	    "rpki expire_interval (600-172800)$tmp",
	    RPKI_OUTPUT_STRING
	    "Set expire interval\n"
	    "Expire interval value\n")
{
	nb_cli_enqueue_change(vty, "./expire-interval", NB_OP_MODIFY, tmp_str);
	return nb_cli_apply_changes(vty, NULL);
}

/* Deliberate divergence: the pre-conversion no-form restored twice the
 * current polling period instead of the documented default; here the
 * leaf destroy restores the schema default (7200). */
DEFPY_YANG (no_rpki_expire_interval,
	    no_rpki_expire_interval_cli_cmd,
	    "no rpki expire_interval [(600-172800)]",
	    NO_STR
	    RPKI_OUTPUT_STRING
	    "Set expire interval back to default\n"
	    "Expire interval value\n")
{
	nb_cli_enqueue_change(vty, "./expire-interval", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (rpki_retry_interval,
	    rpki_retry_interval_cli_cmd,
	    "rpki retry_interval (1-7200)$tmp",
	    RPKI_OUTPUT_STRING
	    "Set retry interval\n"
	    "retry interval value\n")
{
	nb_cli_enqueue_change(vty, "./retry-interval", NB_OP_MODIFY, tmp_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (no_rpki_retry_interval,
	    no_rpki_retry_interval_cli_cmd,
	    "no rpki retry_interval [(1-7200)]",
	    NO_STR
	    RPKI_OUTPUT_STRING
	    "Set retry interval back to default\n"
	    "retry interval value\n")
{
	nb_cli_enqueue_change(vty, "./retry-interval", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/* Re-entering a preference with a different endpoint or transport
 * replaces that cache (datastore modify semantics; the pre-conversion
 * CLI rejected a duplicate preference interactively). Enqueuing a child
 * of one transport case automatically drops the other case's nodes. */
DEFPY_YANG (rpki_cache_tcp,
	    rpki_cache_tcp_cli_cmd,
	    "rpki cache tcp <A.B.C.D|WORD>$cache TCPPORT [source <A.B.C.D>$bindaddr] preference (1-255)",
	    RPKI_OUTPUT_STRING
	    "Install a cache server to current group\n"
	    "Use TCP\n"
	    "IP address of cache server\n"
	    "Hostname of cache server\n"
	    "TCP port number\n"
	    "Configure source IP address of RPKI connection\n"
	    "Define a Source IP Address\n"
	    "Preference of the cache server\n"
	    "Preference value\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "./cache[preference='%" PRId64 "']", preference);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath, sizeof(xpath), "./cache[preference='%" PRId64 "']/tcp/host", preference);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, cache);

	snprintf(xpath, sizeof(xpath), "./cache[preference='%" PRId64 "']/tcp/port", preference);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, tcpport);

	snprintf(xpath, sizeof(xpath), "./cache[preference='%" PRId64 "']/tcp/source", preference);
	nb_cli_enqueue_change(vty, xpath, bindaddr_str ? NB_OP_MODIFY : NB_OP_DESTROY,
			      bindaddr_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (rpki_cache_ssh,
	    rpki_cache_ssh_cli_cmd,
	    "rpki cache ssh <A.B.C.D|WORD>$cache (1-65535)$sshport SSH_UNAME SSH_PRIVKEY [KNOWN_HOSTS_PATH] [source <A.B.C.D>$bindaddr] preference (1-255)",
	    RPKI_OUTPUT_STRING
	    "Install a cache server to current group\n"
	    "Use SSH\n"
	    "IP address of cache server\n"
	    "Hostname of cache server\n"
	    "SSH port number\n"
	    "SSH user name\n"
	    "Path to own SSH private key\n"
	    "Path to the known hosts file\n"
	    "Configure source IP address of RPKI connection\n"
	    "Define a Source IP Address\n"
	    "Preference of the cache server\n"
	    "Preference value\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "./cache[preference='%" PRId64 "']", preference);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath, sizeof(xpath), "./cache[preference='%" PRId64 "']/ssh/host", preference);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, cache);

	snprintf(xpath, sizeof(xpath), "./cache[preference='%" PRId64 "']/ssh/port", preference);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, sshport_str);

	snprintf(xpath, sizeof(xpath), "./cache[preference='%" PRId64 "']/ssh/user", preference);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, ssh_uname);

	snprintf(xpath, sizeof(xpath), "./cache[preference='%" PRId64 "']/ssh/private-key",
		 preference);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, ssh_privkey);

	snprintf(xpath, sizeof(xpath), "./cache[preference='%" PRId64 "']/ssh/known-hosts",
		 preference);
	nb_cli_enqueue_change(vty, xpath, known_hosts_path ? NB_OP_MODIFY : NB_OP_DESTROY,
			      known_hosts_path);

	snprintf(xpath, sizeof(xpath), "./cache[preference='%" PRId64 "']/ssh/source", preference);
	nb_cli_enqueue_change(vty, xpath, bindaddr_str ? NB_OP_MODIFY : NB_OP_DESTROY,
			      bindaddr_str);

	return nb_cli_apply_changes(vty, NULL);
}

/* Like the pre-conversion command, only the preference identifies the
 * cache to delete; the other tokens are accepted and ignored. */
DEFPY_YANG (no_rpki_cache,
	    no_rpki_cache_cli_cmd,
	    "no rpki cache <tcp|ssh> <A.B.C.D|WORD> <TCPPORT|(1-65535)$sshport SSH_UNAME SSH_PRIVKEY [KNOWN_HOSTS_PATH]> [source <A.B.C.D>$bindaddr] preference (1-255)",
	    NO_STR
	    RPKI_OUTPUT_STRING
	    "Install a cache server to current group\n"
	    "Use TCP\n"
	    "Use SSH\n"
	    "IP address of cache server\n"
	    "Hostname of cache server\n"
	    "TCP port number\n"
	    "SSH port number\n"
	    "SSH user name\n"
	    "Path to own SSH private key\n"
	    "Path to the known hosts file\n"
	    "Configure source IP address of RPKI connection\n"
	    "Define a Source IP Address\n"
	    "Preference of the cache server\n"
	    "Preference value\n")
{
	char xpath[XPATH_MAXLEN];

	if (!yang_dnode_existsf(vty->candidate_config->dnode, "%s/cache[preference='%" PRId64 "']",
				VTY_CURR_XPATH, preference)) {
		vty_out(vty, "Could not find cache with preference %" PRId64 "\n", preference);
		return CMD_WARNING;
	}

	snprintf(xpath, sizeof(xpath), "./cache[preference='%" PRId64 "']", preference);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

/* Emitters, byte-identical to the pre-conversion per-vrf write-out. The
 * default VRF's block sits at the top configuration level framed by '!'
 * lines; a non-default vrf's instance reopens its vrf block
 * ('vrf NAME' ... 'exit-vrf'), which parses identically to the legacy
 * inline placement. vty_frame suppresses an instance whose children are
 * all at implicit defaults, reproducing the legacy all-default-block
 * suppression. */
static bool rpki_instance_is_default_vrf(const struct lyd_node *dnode)
{
	return strmatch(yang_dnode_get_string(dnode, "vrf"), VRF_DEFAULT_NAME);
}

/* Child-line separator: legacy indented instance children one space
 * deeper than the enclosing block ('' at top level, ' ' inside a vrf). */
static const char *rpki_cli_sep(const struct lyd_node *dnode)
{
	return rpki_instance_is_default_vrf(yang_dnode_get_parent(dnode, "instance")) ? "" : " ";
}

static void rpki_instance_cli_write(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults)
{
	if (rpki_instance_is_default_vrf(dnode))
		vty_frame(vty, "!\nrpki\n");
	else
		vty_frame(vty, "vrf %s\n rpki\n", yang_dnode_get_string(dnode, "vrf"));
}

static void rpki_instance_cli_write_end(struct vty *vty, const struct lyd_node *dnode)
{
	if (rpki_instance_is_default_vrf(dnode))
		vty_endframe(vty, "exit\n!\n");
	else
		vty_endframe(vty, " exit\nexit-vrf\n!\n");
}

static void rpki_instance_polling_period_cli_write(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults)
{
	vty_out(vty, "%s rpki polling_period %s\n", rpki_cli_sep(dnode),
		yang_dnode_get_string(dnode, NULL));
}

static void rpki_instance_retry_interval_cli_write(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults)
{
	vty_out(vty, "%s rpki retry_interval %s\n", rpki_cli_sep(dnode),
		yang_dnode_get_string(dnode, NULL));
}

static void rpki_instance_expire_interval_cli_write(struct vty *vty, const struct lyd_node *dnode,
						    bool show_defaults)
{
	vty_out(vty, "%s rpki expire_interval %s\n", rpki_cli_sep(dnode),
		yang_dnode_get_string(dnode, NULL));
}

static void rpki_instance_cache_cli_write(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	const char *sep = rpki_cli_sep(dnode);

	if (yang_dnode_exists(dnode, "tcp")) {
		vty_out(vty, "%s rpki cache tcp %s %s ", sep,
			yang_dnode_get_string(dnode, "tcp/host"),
			yang_dnode_get_string(dnode, "tcp/port"));
		if (yang_dnode_exists(dnode, "tcp/source"))
			vty_out(vty, "source %s ", yang_dnode_get_string(dnode, "tcp/source"));
	} else {
		/* Legacy printed an empty token for an absent known-hosts
		 * path, leaving a double space; kept byte-identical. */
		vty_out(vty, "%s rpki cache ssh %s %s %s %s %s ", sep,
			yang_dnode_get_string(dnode, "ssh/host"),
			yang_dnode_get_string(dnode, "ssh/port"),
			yang_dnode_get_string(dnode, "ssh/user"),
			yang_dnode_get_string(dnode, "ssh/private-key"),
			yang_dnode_exists(dnode, "ssh/known-hosts")
				? yang_dnode_get_string(dnode, "ssh/known-hosts")
				: "");
		if (yang_dnode_exists(dnode, "ssh/source"))
			vty_out(vty, "source %s ", yang_dnode_get_string(dnode, "ssh/source"));
	}

	vty_out(vty, "preference %s\n", yang_dnode_get_string(dnode, "preference"));
}

/* clang-format off */
const struct frr_yang_module_info proteus_bgp_rpki_cli_info = {
	.name = "proteus-bgp-rpki",
	.ignore_cfg_cbs = true,
	.nodes = {
		{
			.xpath = "/proteus-bgp-rpki:rpki/instance",
			.cbs = {
				.cli_show = rpki_instance_cli_write,
				.cli_show_end = rpki_instance_cli_write_end,
			}
		},
		{
			.xpath = "/proteus-bgp-rpki:rpki/instance/polling-period",
			.cbs = {
				.cli_show = rpki_instance_polling_period_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp-rpki:rpki/instance/retry-interval",
			.cbs = {
				.cli_show = rpki_instance_retry_interval_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp-rpki:rpki/instance/expire-interval",
			.cbs = {
				.cli_show = rpki_instance_expire_interval_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp-rpki:rpki/instance/cache",
			.cbs = {
				.cli_show = rpki_instance_cache_cli_write,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
/* clang-format on */

void bgp_cli_rpki_init(void)
{
	install_node(&rpki_cmd_node);
	install_default(RPKI_NODE);
	install_node(&rpki_vrf_cmd_node);
	install_default(RPKI_VRF_NODE);

	install_element(CONFIG_NODE, &rpki_cli_cmd);
	install_element(CONFIG_NODE, &no_rpki_cli_cmd);
	install_element(VRF_NODE, &rpki_cli_cmd);
	install_element(VRF_NODE, &no_rpki_cli_cmd);

	install_element(RPKI_NODE, &rpki_polling_period_cli_cmd);
	install_element(RPKI_NODE, &no_rpki_polling_period_cli_cmd);
	install_element(RPKI_NODE, &rpki_expire_interval_cli_cmd);
	install_element(RPKI_NODE, &no_rpki_expire_interval_cli_cmd);
	install_element(RPKI_NODE, &rpki_retry_interval_cli_cmd);
	install_element(RPKI_NODE, &no_rpki_retry_interval_cli_cmd);
	install_element(RPKI_NODE, &rpki_cache_tcp_cli_cmd);
	install_element(RPKI_NODE, &rpki_cache_ssh_cli_cmd);
	install_element(RPKI_NODE, &no_rpki_cache_cli_cmd);

	install_element(RPKI_VRF_NODE, &rpki_polling_period_cli_cmd);
	install_element(RPKI_VRF_NODE, &no_rpki_polling_period_cli_cmd);
	install_element(RPKI_VRF_NODE, &rpki_expire_interval_cli_cmd);
	install_element(RPKI_VRF_NODE, &no_rpki_expire_interval_cli_cmd);
	install_element(RPKI_VRF_NODE, &rpki_retry_interval_cli_cmd);
	install_element(RPKI_VRF_NODE, &no_rpki_retry_interval_cli_cmd);
	install_element(RPKI_VRF_NODE, &rpki_cache_tcp_cli_cmd);
	install_element(RPKI_VRF_NODE, &rpki_cache_ssh_cli_cmd);
	install_element(RPKI_VRF_NODE, &no_rpki_cache_cli_cmd);
}
