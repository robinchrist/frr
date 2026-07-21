// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Robin Christ, partimus GmbH */
/* Northbound apply callbacks for the proteus-bgp-rpki module (TODO #31
 * batch B1), registered by the proteus_bgp_rpki_info table in
 * bgpd/bgp_nb.c. Compiled unconditionally into bgpd; the runtime lives in
 * the dlopen'd bgpd_rpki plugin, which subscribes to the two hooks
 * declared in bgp_rpki.h at module load.
 *
 * Convergence model: one instance (= one VRF's cache group + timers) is
 * converged atomically through the instance list entry's apply_finish,
 * which fires once per commit with the instance from the NEW tree,
 * rereads the complete desired state into a plain C struct
 * (struct bgp_rpki_config) and hands it to the bgp_rpki_config_apply
 * hook; the plugin diffs its runtime against it. The per-leaf callbacks
 * below therefore accept every event and do nothing. The instance
 * entry's destroy fires the bgp_rpki_config_destroy hook (stop + free,
 * the legacy 'no rpki' teardown); northbound skips a destroyed entry's
 * own apply_finish, so 'no rpki' cannot transiently re-apply.
 *
 * When bgpd runs without '-M bgpd_rpki' the hooks have no listeners:
 * apply/destroy degrade to a warning and the config stays stored but
 * inactive. VALIDATE never rejects for plugin absence - a reject would
 * fail the whole startup init-push and drop the entire bgp config.
 */
#include <zebra.h>

#include "northbound.h"
#include "vrf.h"

#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_nb.h"
#include "bgpd/bgp_rpki.h"

DEFINE_HOOK(bgp_rpki_config_apply, (const char *vrfname, const struct bgp_rpki_config *cfg),
	    (vrfname, cfg));
DEFINE_HOOK(bgp_rpki_config_destroy, (const char *vrfname), (vrfname));

/* The hooks take NULL for the default VRF (the plugin's internal
 * convention); the datastore key is the literal VRF name. */
static const char *rpki_instance_vrfname(const struct lyd_node *dnode)
{
	const char *vrf = yang_dnode_get_string(dnode, "vrf");

	if (strmatch(vrf, VRF_DEFAULT_NAME))
		return NULL;
	return vrf;
}

static void rpki_plugin_absent_warn(void)
{
	flog_warn(EC_BGP_RPKI_PLUGIN_ABSENT,
		  "rpki configuration present but bgpd was started without -M bgpd_rpki; config accepted but inactive");
}

/*
 * XPath: /proteus-bgp-rpki:rpki/instance
 */
int rpki_instance_create(struct nb_cb_create_args *args)
{
	/* No-op: the instance's apply_finish does the work, see above. */
	return NB_OK;
}

int rpki_instance_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if (!hook_have_hooks(bgp_rpki_config_destroy)) {
		rpki_plugin_absent_warn();
		return NB_OK;
	}

	hook_call(bgp_rpki_config_destroy, rpki_instance_vrfname(args->dnode));

	return NB_OK;
}

void rpki_instance_apply_finish(struct nb_cb_apply_finish_args *args)
{
	struct bgp_rpki_config cfg = {};
	struct bgp_rpki_cache_config *caches = NULL;
	const struct lyd_node *cache_dnode;
	uint32_t count;
	size_t i = 0;

	if (!hook_have_hooks(bgp_rpki_config_apply)) {
		rpki_plugin_absent_warn();
		return;
	}

	cfg.polling_period = yang_dnode_get_uint32(args->dnode, "polling-period");
	cfg.expire_interval = yang_dnode_get_uint32(args->dnode, "expire-interval");
	cfg.retry_interval = yang_dnode_get_uint16(args->dnode, "retry-interval");

	count = yang_dnode_count(args->dnode, "cache");
	if (count)
		caches = XCALLOC(MTYPE_TMP, count * sizeof(*caches));

	LY_LIST_FOR (lyd_child(args->dnode), cache_dnode) {
		struct bgp_rpki_cache_config *cache;

		if (!strmatch(cache_dnode->schema->name, "cache"))
			continue;

		cache = &caches[i++];
		cache->preference = yang_dnode_get_uint8(cache_dnode, "preference");
		if (yang_dnode_exists(cache_dnode, "tcp")) {
			cache->is_ssh = false;
			cache->host = yang_dnode_get_string(cache_dnode, "tcp/host");
			cache->tcp_port = yang_dnode_get_string(cache_dnode, "tcp/port");
			if (yang_dnode_exists(cache_dnode, "tcp/source"))
				cache->source = yang_dnode_get_string(cache_dnode, "tcp/source");
		} else {
			cache->is_ssh = true;
			cache->host = yang_dnode_get_string(cache_dnode, "ssh/host");
			cache->ssh_port = yang_dnode_get_uint16(cache_dnode, "ssh/port");
			cache->ssh_user = yang_dnode_get_string(cache_dnode, "ssh/user");
			cache->ssh_privkey = yang_dnode_get_string(cache_dnode, "ssh/private-key");
			if (yang_dnode_exists(cache_dnode, "ssh/known-hosts"))
				cache->ssh_known_hosts = yang_dnode_get_string(cache_dnode,
									       "ssh/known-hosts");
			if (yang_dnode_exists(cache_dnode, "ssh/source"))
				cache->source = yang_dnode_get_string(cache_dnode, "ssh/source");
		}
	}

	cfg.cache_count = i;
	cfg.caches = caches;

	hook_call(bgp_rpki_config_apply, rpki_instance_vrfname(args->dnode), &cfg);

	XFREE(MTYPE_TMP, caches);
}

/*
 * XPath: /proteus-bgp-rpki:rpki/instance/polling-period
 */
int rpki_instance_polling_period_modify(struct nb_cb_modify_args *args)
{
	/* No-op: the instance's apply_finish does the work, see above. */
	return NB_OK;
}

int rpki_instance_polling_period_destroy(struct nb_cb_destroy_args *args)
{
	/* No-op: the instance's apply_finish does the work, see above. */
	return NB_OK;
}

/*
 * XPath: /proteus-bgp-rpki:rpki/instance/retry-interval
 */
int rpki_instance_retry_interval_modify(struct nb_cb_modify_args *args)
{
	/* No-op: the instance's apply_finish does the work, see above. */
	return NB_OK;
}

int rpki_instance_retry_interval_destroy(struct nb_cb_destroy_args *args)
{
	/* No-op: the instance's apply_finish does the work, see above. */
	return NB_OK;
}

/*
 * XPath: /proteus-bgp-rpki:rpki/instance/expire-interval
 */
int rpki_instance_expire_interval_modify(struct nb_cb_modify_args *args)
{
	uint32_t expire, polling;

	if (args->event != NB_EV_VALIDATE)
		return NB_OK;

	/* Legacy cross-check, reproduced exactly: only an EXPLICITLY
	 * configured expire interval is checked against the (candidate)
	 * polling period; the defaults are never cross-checked, so a
	 * polling period larger than the default expire interval stays
	 * accepted, as it always was. */
	if (yang_dnode_is_default(args->dnode, NULL))
		return NB_OK;

	expire = yang_dnode_get_uint32(args->dnode, NULL);
	polling = yang_dnode_get_uint32(args->dnode, "../polling-period");
	if (expire < polling) {
		snprintf(args->errmsg, args->errmsg_len,
			 "Expiry interval must be polling period or larger");
		return NB_ERR_VALIDATION;
	}

	return NB_OK;
}

int rpki_instance_expire_interval_destroy(struct nb_cb_destroy_args *args)
{
	/* No-op: the instance's apply_finish does the work, see above. */
	return NB_OK;
}

/*
 * XPath: /proteus-bgp-rpki:rpki/instance/cache
 */
int rpki_instance_cache_create(struct nb_cb_create_args *args)
{
	/* No-op: the instance's apply_finish does the work, see above. */
	return NB_OK;
}

int rpki_instance_cache_destroy(struct nb_cb_destroy_args *args)
{
	/* No-op: the enclosing instance's apply_finish converges the
	 * surviving cache set, see above. */
	return NB_OK;
}

/*
 * XPath: /proteus-bgp-rpki:rpki/instance/cache/tcp
 */
int rpki_instance_cache_tcp_create(struct nb_cb_create_args *args)
{
	/* No-op: the instance's apply_finish does the work, see above. */
	return NB_OK;
}

int rpki_instance_cache_tcp_destroy(struct nb_cb_destroy_args *args)
{
	/* No-op: the instance's apply_finish does the work, see above. */
	return NB_OK;
}

/*
 * XPath: /proteus-bgp-rpki:rpki/instance/cache/tcp/host
 */
int rpki_instance_cache_tcp_host_modify(struct nb_cb_modify_args *args)
{
	/* No-op: the instance's apply_finish does the work, see above. */
	return NB_OK;
}

/*
 * XPath: /proteus-bgp-rpki:rpki/instance/cache/tcp/port
 */
int rpki_instance_cache_tcp_port_modify(struct nb_cb_modify_args *args)
{
	/* No-op: the instance's apply_finish does the work, see above. */
	return NB_OK;
}

/*
 * XPath: /proteus-bgp-rpki:rpki/instance/cache/tcp/source
 */
int rpki_instance_cache_tcp_source_modify(struct nb_cb_modify_args *args)
{
	/* No-op: the instance's apply_finish does the work, see above. */
	return NB_OK;
}

int rpki_instance_cache_tcp_source_destroy(struct nb_cb_destroy_args *args)
{
	/* No-op: the instance's apply_finish does the work, see above. */
	return NB_OK;
}

/*
 * XPath: /proteus-bgp-rpki:rpki/instance/cache/ssh
 */
int rpki_instance_cache_ssh_create(struct nb_cb_create_args *args)
{
	/* No-op: the instance's apply_finish does the work, see above. */
	return NB_OK;
}

int rpki_instance_cache_ssh_destroy(struct nb_cb_destroy_args *args)
{
	/* No-op: the instance's apply_finish does the work, see above. */
	return NB_OK;
}

/*
 * XPath: /proteus-bgp-rpki:rpki/instance/cache/ssh/host
 */
int rpki_instance_cache_ssh_host_modify(struct nb_cb_modify_args *args)
{
	/* No-op: the instance's apply_finish does the work, see above. */
	return NB_OK;
}

/*
 * XPath: /proteus-bgp-rpki:rpki/instance/cache/ssh/port
 */
int rpki_instance_cache_ssh_port_modify(struct nb_cb_modify_args *args)
{
	/* No-op: the instance's apply_finish does the work, see above. */
	return NB_OK;
}

/*
 * XPath: /proteus-bgp-rpki:rpki/instance/cache/ssh/user
 */
int rpki_instance_cache_ssh_user_modify(struct nb_cb_modify_args *args)
{
	/* No-op: the instance's apply_finish does the work, see above. */
	return NB_OK;
}

/*
 * XPath: /proteus-bgp-rpki:rpki/instance/cache/ssh/private-key
 */
int rpki_instance_cache_ssh_private_key_modify(struct nb_cb_modify_args *args)
{
	/* No-op: the instance's apply_finish does the work, see above. */
	return NB_OK;
}

/*
 * XPath: /proteus-bgp-rpki:rpki/instance/cache/ssh/known-hosts
 */
int rpki_instance_cache_ssh_known_hosts_modify(struct nb_cb_modify_args *args)
{
	/* No-op: the instance's apply_finish does the work, see above. */
	return NB_OK;
}

int rpki_instance_cache_ssh_known_hosts_destroy(struct nb_cb_destroy_args *args)
{
	/* No-op: the instance's apply_finish does the work, see above. */
	return NB_OK;
}

/*
 * XPath: /proteus-bgp-rpki:rpki/instance/cache/ssh/source
 */
int rpki_instance_cache_ssh_source_modify(struct nb_cb_modify_args *args)
{
	/* No-op: the instance's apply_finish does the work, see above. */
	return NB_OK;
}

int rpki_instance_cache_ssh_source_destroy(struct nb_cb_destroy_args *args)
{
	/* No-op: the instance's apply_finish does the work, see above. */
	return NB_OK;
}
