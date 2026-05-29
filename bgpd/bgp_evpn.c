// SPDX-License-Identifier: GPL-2.0-or-later
/* Ethernet-VPN Packet and vty Processing File
 * Copyright (C) 2016 6WIND
 * Copyright (C) 2017 Cumulus Networks, Inc.
 */

#include <zebra.h>

#include "command.h"
#include "filter.h"
#include "prefix.h"
#include "log.h"
#include "memory.h"
#include "stream.h"
#include "hash.h"
#include "jhash.h"
#include "zclient.h"

#include "lib/printfrr.h"

#include "bgpd/bgp_attr_evpn.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_label.h"
#include "bgpd/bgp_evpn.h"
#include "bgpd/bgp_evpn_private.h"
#include "bgpd/bgp_evpn_mh.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_encap_types.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_addpath.h"
#include "bgpd/bgp_mac.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_nht.h"
#include "bgpd/bgp_trace.h"
#include "bgpd/bgp_mpath.h"
#include "bgpd/bgp_packet.h"

/*
 * Definitions and external declarations.
 */
DEFINE_QOBJ_TYPE(bgp_evpn_evi);
DEFINE_QOBJ_TYPE(bgp_evpn_es);

DEFINE_MTYPE_STATIC(BGPD, BGP_EVPN_RT_CONFIG, "BGP EVPN Route Target Config");
DEFINE_MTYPE_STATIC(BGPD, BGP_EVPN_INFO, "BGP EVPN instance information");
DEFINE_MTYPE_STATIC(BGPD, BGP_EVPN_CFGD_RT, "BGP EVPN Configured Route Target");
DEFINE_MTYPE_STATIC(BGPD, BGP_EVPN_EFFECTIVE_WILDCARD_RT, "BGP EVPN Effective Wildcard Route Target");
DEFINE_MTYPE_STATIC(BGPD, BGP_EVPN_EFFECTIVE_FQ_RT, "BGP EVPN Effective Fully Qualified Route Target");

DEFINE_MTYPE_STATIC(BGPD, BGP_EVPN_VRF_WILDCARD_IRT_NODE, "BGP EVPN VRF Wildcard Import RT hash table node");
DEFINE_MTYPE_STATIC(BGPD, BGP_EVPN_VRF_FQ_IRT_NODE, "BGP EVPN VRF fully qualified Import RT hash table node");
DEFINE_MTYPE_STATIC(BGPD, BGP_EVPN_VRF_MAPPED_BGP_INSTANCE, "BGP EVPN BGP instance to VRF Import RT Node Mapping");

DEFINE_MTYPE_STATIC(BGPD, BGP_EVPN_EVI_WILDCARD_IRT_NODE, "BGP EVPN EVI Wildcard Import RT hash table node");
DEFINE_MTYPE_STATIC(BGPD, BGP_EVPN_EVI_FQ_IRT_NODE, "BGP EVPN EVI fully qualified Import RT hash table node");
DEFINE_MTYPE_STATIC(BGPD, BGP_EVPN_EVI_MAPPED_EVI, "BGP EVPN EVI to EVI Import RT Node Mapping");

/*
 * Static function declarations
 */
static void bgp_evpn_remote_ip_hash_init(struct bgp_evpn_evi *evpn);
static void bgp_evpn_remote_ip_hash_destroy(struct bgp_evpn_evi *evpn);
static void bgp_evpn_remote_ip_hash_add(struct bgp_evpn_evi *evi,
					struct bgp_path_info *pi);
static void bgp_evpn_remote_ip_hash_del(struct bgp_evpn_evi *evi,
					struct bgp_path_info *pi);
static void bgp_evpn_remote_ip_hash_iterate(struct bgp_evpn_evi *evi,
					    void (*func)(struct hash_bucket *,
							 void *),
					    void *arg);
static void bgp_evpn_link_to_vni_svi_hash(struct bgp *bgp, struct bgp_evpn_evi *evi);
static void bgp_evpn_unlink_from_vni_svi_hash(struct bgp *bgp,
					      struct bgp_evpn_evi *evi);
static unsigned int vni_svi_hash_key_make(const void *p);
static bool vni_svi_hash_cmp(const void *p1, const void *p2);
static void bgp_evpn_remote_ip_process_nexthops(struct bgp_evpn_evi *evi,
						struct ipaddr *addr,
						bool resolve);
static void bgp_evpn_remote_ip_hash_link_nexthop(struct hash_bucket *bucket,
						 void *args);
static void bgp_evpn_remote_ip_hash_unlink_nexthop(struct hash_bucket *bucket,
						   void *args);
static struct ipaddr zero_vtep_ip = {
	.ipa_type = IPADDR_V4,
	.ip = {
		._v4_addr = {0},
	}
};

static uint32_t bgp_evpn_addpath_id_for_path(const struct bgp *bgp, const struct bgp_path_info *pi,
					     afi_t afi);

static const char *vxlan_flood_control_str(enum vxlan_flood_control flood_ctrl)
{
	switch (flood_ctrl) {
	case VXLAN_FLOOD_HEAD_END_REPL:
		return "Flooding";
	case VXLAN_FLOOD_DISABLED:
		return "Disabled";
	case VXLAN_FLOOD_PIM_SM:
		return "PIM-SM";
	case VXLAN_FLOOD_INHERIT_GLOBAL:
		return "Inherit Global";
	default:
		return "unknown";
	}
}

/*
 * Private functions.
 */

/*
 * Make vni hash key.
 */
static unsigned int vni_hash_key_make(const void *p)
{
	const struct bgp_evpn_evi *evi = p;
	return (jhash_1word(evi->vni, 0));
}

/*
 * Comparison function for vni hash
 */
static bool vni_hash_cmp(const void *p1, const void *p2)
{
	const struct bgp_evpn_evi *evi1 = p1;
	const struct bgp_evpn_evi *evi2 = p2;

	return evi1->vni == evi2->vni;
}

int vni_list_cmp(void *p1, void *p2)
{
	const struct bgp_evpn_evi *evi1 = p1;
	const struct bgp_evpn_evi *evi2 = p2;

	return evi1->vni - evi2->vni;
}

/* Roughly grouped route target functionality follows */

/* allocate new user configured route target bgp_evpn_cfgd_rt */
static struct bgp_evpn_cfgd_rt* bgp_evpn_cfgd_rt_new(void)
{
	struct bgp_evpn_cfgd_rt *cfgd_rt;

	cfgd_rt = XCALLOC(MTYPE_BGP_EVPN_CFGD_RT, sizeof(struct bgp_evpn_cfgd_rt));

	return cfgd_rt;
}

/* free user configured route target bgp_evpn_cfgd_rt */
static void bgp_evpn_cfgd_rt_free(struct bgp_evpn_cfgd_rt *cfgd_rt)
{
	if (!cfgd_rt)
		return;

	XFREE(MTYPE_BGP_EVPN_CFGD_RT, cfgd_rt);
}

/*
 * Convert a single-entry ecommunity to a newly allocated bgp_evpn_cfgd_rt.
 * is_wildcard must be set when the original RT string used '*' as the global
 * admin (the caller replaces '*' with '0' before parsing, so the ecommunity
 * itself carries AS=0 and is indistinguishable from a real AS=0 RT).
 * Returns NULL on any validation failure.
 */
struct bgp_evpn_cfgd_rt *bgp_evpn_cfgd_rt_from_ecom(const struct ecommunity *ecom,
						     bool is_wildcard)
{
	/* The ecommunity comes from the VTY, which gets each RT as a separate argument*/
	if (!ecom || ecom->size != 1 || ecom->unit_size != ECOMMUNITY_SIZE)
		return NULL;

	const uint8_t* ecom_val = ecom->val;
	const uint8_t type = ecom_val[0];
	const uint8_t subtype = ecom_val[1];

	if (subtype != ECOMMUNITY_ROUTE_TARGET)
		return NULL;

	if (is_wildcard) {
		/* Wildcard parsing uses AS0 -> should always be AS2 type RT */
		if(type != ECOMMUNITY_ENCODE_AS)
			return NULL;

		struct bgp_evpn_cfgd_rt *cfgd_rt = bgp_evpn_cfgd_rt_new();

		cfgd_rt->type = BGP_EVPN_CFGD_RT_TYPE_WILDCARD;

		ptr_get_be32(ecom_val + 4, &cfgd_rt->payload.wildcard_rt.local_admin);

		return cfgd_rt;
	} else {
		struct bgp_evpn_cfgd_rt *cfgd_rt;

		switch (type) {
		case ECOMMUNITY_ENCODE_AS: /* 0x00 */
			cfgd_rt = bgp_evpn_cfgd_rt_new();
			cfgd_rt->type = BGP_EVPN_CFGD_RT_TYPE_AS2;
			ptr_get_be16(ecom_val + 2, &cfgd_rt->payload.as2_rt.as);
			ptr_get_be32(ecom_val + 4, &cfgd_rt->payload.as2_rt.local_admin);

			return cfgd_rt;
		case ECOMMUNITY_ENCODE_IP: /* 0x01 */
			cfgd_rt = bgp_evpn_cfgd_rt_new();
			cfgd_rt->type = BGP_EVPN_CFGD_RT_TYPE_IP4;
			memcpy(&cfgd_rt->payload.ip4_rt.ip, ecom_val + 2, sizeof(struct in_addr));
			ptr_get_be16(ecom_val + 6, &cfgd_rt->payload.ip4_rt.local_admin);
			
			return cfgd_rt;
		case ECOMMUNITY_ENCODE_AS4: /* 0x02 */
			cfgd_rt = bgp_evpn_cfgd_rt_new();
			cfgd_rt->type = BGP_EVPN_CFGD_RT_TYPE_AS4;
			ptr_get_be32(ecom_val + 2, &cfgd_rt->payload.as4_rt.as);
			ptr_get_be16(ecom_val + 6, &cfgd_rt->payload.as4_rt.local_admin);

			return cfgd_rt;
		default:
			return NULL;
		}
	}
}

/*
 * Comparison function for user configured route targets bgp_evpn_cfgd_rt_cmp
 * Uses standard convention: returns 0 if equal, < 0 if rt1 < rt2, > 0 if rt1 > rt2
 * Sort order is defined as follows:
 * 1) by type, in order of enum bgp_evpn_cfgd_rt_type (wildcard < AS2 < IP4 < AS4)
 * 2) by specific value:
 * 2a) Wildcard RTs are sorted by local admin value (ascending)
 * 2b) AS2 RTs are sorted by AS number first (ascending), then by local admin (ascending)
 * 2c) IP4 RTs are sorted by IP address first (ascending), then by local admin (ascending)
 * 2d) AS4 RTs are sorted by AS number first (ascending), then by local admin (ascending)
 * 2e) Invalid type fallback: memcmp of payload (should not happen, as only valid types should be constructed, but just in case)
 */
int bgp_evpn_cfgd_rt_cmp(const struct bgp_evpn_cfgd_rt *rt1, const struct bgp_evpn_cfgd_rt *rt2) {

	if (rt1->type != rt2->type)
		/* Sort type as defined in enum bgp_evpn_cfgd_rt_type: Wildcard, AS2, IP4, AS4 */
		return rt1->type < rt2->type ? -1 : 1;

	switch (rt1->type) {
		case BGP_EVPN_CFGD_RT_TYPE_WILDCARD:
			if(rt1->payload.wildcard_rt.local_admin != rt2->payload.wildcard_rt.local_admin)
				/* Sort ascending by local admin */
				return rt1->payload.wildcard_rt.local_admin < rt2->payload.wildcard_rt.local_admin ? -1 : 1;

			return 0; /* wildcard RTs are identical if local admin is identical, as there is no global admin field */

		case BGP_EVPN_CFGD_RT_TYPE_AS2:
			if (rt1->payload.as2_rt.as != rt2->payload.as2_rt.as)
				/* Sort ascending by AS number */
				return rt1->payload.as2_rt.as < rt2->payload.as2_rt.as ? -1 : 1;

			if(rt1->payload.as2_rt.local_admin != rt2->payload.as2_rt.local_admin)
				/* Then sort ascending by local admin */
				return rt1->payload.as2_rt.local_admin < rt2->payload.as2_rt.local_admin ? -1 : 1;

			/* identical */
			return 0;

		case BGP_EVPN_CFGD_RT_TYPE_IP4:
			if (rt1->payload.ip4_rt.ip.s_addr != rt2->payload.ip4_rt.ip.s_addr)
				/* Sort ascending by IP Address number */
				return (ntohl(rt1->payload.ip4_rt.ip.s_addr) < ntohl(rt2->payload.ip4_rt.ip.s_addr)) ? -1 : 1;

			if(rt1->payload.ip4_rt.local_admin != rt2->payload.ip4_rt.local_admin)
				/* Then sort ascending by local admin */
				return rt1->payload.ip4_rt.local_admin < rt2->payload.ip4_rt.local_admin ? -1 : 1;

			/* identical */
			return 0;

		case BGP_EVPN_CFGD_RT_TYPE_AS4:
			if (rt1->payload.as4_rt.as != rt2->payload.as4_rt.as)
				/* Sort ascending by AS number */
				return (rt1->payload.as4_rt.as < rt2->payload.as4_rt.as) ? -1 : 1;

			if (rt1->payload.as4_rt.local_admin != rt2->payload.as4_rt.local_admin)
				/* Then sort ascending by local admin */
				return (rt1->payload.as4_rt.local_admin < rt2->payload.as4_rt.local_admin) ? -1 : 1;

			/* Identical */
			return 0;

		default:
			/* Unknown - should not happen! Still try to get away with a somehow sensible fallback */
			return memcmp(&rt1->payload, &rt2->payload, sizeof(rt1->payload));
	}
}

int bgp_evpn_effective_wildcard_rt_cmp(const struct bgp_evpn_effective_wildcard_rt *rt1, const struct bgp_evpn_effective_wildcard_rt *rt2) {
	if(rt1->local_admin_nbo != rt2->local_admin_nbo)
		/* Sort ascending by local admin */
		return rt1->local_admin_nbo < rt2->local_admin_nbo ? -1 : 1;

	return 0; /* wildcard RTs are identical if local admin is identical, as there is no global admin field */
}

int bgp_evpn_effective_fq_rt_cmp(const struct bgp_evpn_effective_fq_rt *rt1, const struct bgp_evpn_effective_fq_rt *rt2) {
	uint8_t rt1_type = rt1->ecom_val.val[0];
	uint8_t rt2_type = rt2->ecom_val.val[0];

	/* subtype should always be 0x02...*/
	uint8_t rt1_subtype = rt1->ecom_val.val[1];
	uint8_t rt2_subtype = rt2->ecom_val.val[1];

	/* Sort by subtype first, just in case...*/
	if(rt1_subtype != rt2_subtype)
		/* Sort by subtype - should not really happen as only 0x02 is valid for EVPN RTs, but just in case */
		return rt1_subtype < rt2_subtype ? -1 : 1;

	if(rt1_type != rt2_type)
		/* Sort AS before IP4 before AS4 ecom type */
		return rt1_type < rt2_type ? -1 : 1;

	switch(rt1_type) {
		case ECOMMUNITY_ENCODE_AS: { /* 0x00 */
			uint16_t rt1_as;
			uint16_t rt2_as;
			ptr_get_be16(rt1->ecom_val.val + 2, &rt1_as);
			ptr_get_be16(rt2->ecom_val.val + 2, &rt2_as);

			if(rt1_as != rt2_as)
				/* Sort ascending by AS number */
				return rt1_as < rt2_as ? -1 : 1;

			uint32_t rt1_local_admin;
			uint32_t rt2_local_admin;
			ptr_get_be32(rt1->ecom_val.val + 4, &rt1_local_admin);
			ptr_get_be32(rt2->ecom_val.val + 4, &rt2_local_admin);

			if(rt1_local_admin != rt2_local_admin)
				/* Then sort ascending by local admin */
				return rt1_local_admin < rt2_local_admin ? -1 : 1;

			/* identical */
			return 0;
		}
		case ECOMMUNITY_ENCODE_IP: {/* 0x01 */

			/* IP4 RTs are sorted by IP address first (ascending), then by local admin (ascending) */
			int ip_cmp = memcmp(rt1->ecom_val.val + 2, rt2->ecom_val.val + 2, sizeof(struct in_addr));
			if(ip_cmp != 0) {
				return ip_cmp;
			}

			uint16_t rt1_local_admin;
			uint16_t rt2_local_admin;
			ptr_get_be16(rt1->ecom_val.val + 6, &rt1_local_admin);
			ptr_get_be16(rt2->ecom_val.val + 6, &rt2_local_admin);
			if(rt1_local_admin != rt2_local_admin)
				/* Then sort ascending by local admin */
				return rt1_local_admin < rt2_local_admin ? -1 : 1;
			

			return 0;
		}
		case ECOMMUNITY_ENCODE_AS4: { /* 0x02 */
			uint32_t rt1_as;
			uint32_t rt2_as;
			ptr_get_be32(rt1->ecom_val.val + 2, &rt1_as);
			ptr_get_be32(rt2->ecom_val.val + 2, &rt2_as);

			if(rt1_as != rt2_as)
				/* Sort ascending by AS number */
				return rt1_as < rt2_as ? -1 : 1;

			uint16_t rt1_local_admin;
			uint16_t rt2_local_admin;
			ptr_get_be16(rt1->ecom_val.val + 4, &rt1_local_admin);
			ptr_get_be16(rt2->ecom_val.val + 4, &rt2_local_admin);

			if(rt1_local_admin != rt2_local_admin)
				/* Then sort ascending by local admin */
				return rt1_local_admin < rt2_local_admin ? -1 : 1;

			/* identical */
			return 0;
		}
		default:
			/* Unknown - should not happen! Still try to get away with a somehow sensible fallback */
			return memcmp(&rt1->ecom_val.val, &rt2->ecom_val.val, sizeof(rt1->ecom_val.val));
	}
}

/* init wrapper struct */
static struct bgp_evpn_rt_config* bgp_evpn_rt_config_new(void) {

	struct bgp_evpn_rt_config* config = XCALLOC(MTYPE_BGP_EVPN_RT_CONFIG, sizeof(struct bgp_evpn_rt_config));

	bgp_evpn_cfgd_rt_slu_init(&config->cfgd_both);
	bgp_evpn_cfgd_rt_slu_init(&config->cfgd_import);
	bgp_evpn_cfgd_rt_slu_init(&config->cfgd_export);

	return config;
}

/* free wrapper struct */
static void bgp_evpn_rt_config_free(struct bgp_evpn_rt_config* config) {
	struct bgp_evpn_cfgd_rt* item;

	if (!config)
		return;

	while ((item = bgp_evpn_cfgd_rt_slu_pop(&config->cfgd_both)))
    	bgp_evpn_cfgd_rt_free(item);

	bgp_evpn_cfgd_rt_slu_fini(&config->cfgd_both);


	while ((item = bgp_evpn_cfgd_rt_slu_pop(&config->cfgd_import)))
    	bgp_evpn_cfgd_rt_free(item);

	bgp_evpn_cfgd_rt_slu_fini(&config->cfgd_import);


	while ((item = bgp_evpn_cfgd_rt_slu_pop(&config->cfgd_export)))
    	bgp_evpn_cfgd_rt_free(item);

	bgp_evpn_cfgd_rt_slu_fini(&config->cfgd_export);

	XFREE(MTYPE_BGP_EVPN_RT_CONFIG, config);
}

static struct bgp_evpn_effective_wildcard_rt* bgp_evpn_effective_wildcard_rt_new(uint32_t local_admin_nbo) {
	struct bgp_evpn_effective_wildcard_rt* eff_rt = XCALLOC(MTYPE_BGP_EVPN_EFFECTIVE_WILDCARD_RT, sizeof(struct bgp_evpn_effective_wildcard_rt));

	eff_rt->local_admin_nbo = local_admin_nbo;

	return eff_rt;
}
static void bgp_evpn_effective_wildcard_rt_free(struct bgp_evpn_effective_wildcard_rt* eff_rt) {
	if (!eff_rt)
		return;

	XFREE(MTYPE_BGP_EVPN_EFFECTIVE_WILDCARD_RT, eff_rt);
}

static struct bgp_evpn_effective_fq_rt* bgp_evpn_effective_fq_rt_new(struct ecommunity_val ecom_val) {
	struct bgp_evpn_effective_fq_rt* eff_rt = XCALLOC(MTYPE_BGP_EVPN_EFFECTIVE_FQ_RT, sizeof(struct bgp_evpn_effective_fq_rt));

	memcpy(&eff_rt->ecom_val, &ecom_val, sizeof(struct ecommunity_val));

	return eff_rt;
}
static void bgp_evpn_effective_fq_rt_free(struct bgp_evpn_effective_fq_rt* eff_rt) {
	if (!eff_rt)
		return;

	XFREE(MTYPE_BGP_EVPN_EFFECTIVE_FQ_RT, eff_rt);
}

/*
 * FRR automatic route target generation for VRFs and EVIs:
 * For VRFs, <VNI> is the L3VNI assigned to the VRF
 * For EVIs, <VNI> is the L2VNI assigned to the EVI
 * 
 * Export RT: <lower 2 byte of AS>:<VNI>
 * Import RT: *:<VNI> - this is a wildcard RT!
 *
 * Wildcard RT: Will match any RT with the correct local admin (typically encoded VNI)
 * Wildcard RTs are primarily useful in modern datacenter EVPN-VXLAN deployments which are typically eBGP
 * Every leaf has a different AS - so configuring import RTs would be very tedious and a long list
 * and by default we wouldn't import any other leaf's RTs
 *
 * RFC8365 Compatible: Some remnant from the past? Totally not RFC8365 compliant, but only "compatible"
 * Apparently, some users require the "automatic" bit set in the RT / VNI, so this is what we do
 */

/* Common function to generate import auto RT for VRF and EVIs, see above for details
 * Import Auto RTs are always wildcard at the moment - should we generate other kinds of import RTs
 * we'll have to adjust fhe function signature and return a union or split the function and have the caller
 * call all of them
 */
static struct bgp_evpn_effective_wildcard_rt* _bgp_evpn_derive_import_auto_rt_common(vni_t vni, bool rfc8365_compatible) {

	if(rfc8365_compatible) {
		/* Set the "automatic" bit in the local admin field of the RT, see docs above why */
		SET_FLAG(vni, BGP_EVPN_RT_RFC8365_A_BIT);
	}

	/* Need to convert to network byte order to match ecommunity_val */
	uint32_t local_admin_nbo = htonl(vni);

	return bgp_evpn_effective_wildcard_rt_new(local_admin_nbo);
}
/* Common function to generate export auto RT for VRF and EVIs, see above for details */
static struct bgp_evpn_effective_fq_rt* _bgp_evpn_derive_export_auto_rt_common(as_t as, vni_t vni, bool rfc8365_compatible) {

	struct ecommunity_val eval;

	if(rfc8365_compatible) {
		/* Set the "automatic" bit in the local admin field of the RT, see docs above why */
		SET_FLAG(vni, BGP_EVPN_RT_RFC8365_A_BIT);
	}

	/*
	 * BGP EVPN Route Targets are transitive extended communities
	 * We only use the LAST two bytes of the AS
	 * This allows for somehow sensible operation in AS4 environments where AS numbers
	 * are often within the same 2-byte "prefix" due to ASdot notation
	 * (-> less likely route target AS "overlap")
	 */
	encode_route_target_as((as & 0x0000FFFF), vni, &eval, true);


	return bgp_evpn_effective_fq_rt_new(eval);
}

/*
 * Function does not check whether auto RT generation should actually be done
 * caller needs to check this and only call if auto RTs should actually be generated!
 */
static struct bgp_evpn_effective_fq_rt* bgp_evpn_vrf_derive_export_auto_rt(const struct bgp *bgp_vrf) {
	return _bgp_evpn_derive_export_auto_rt_common(bgp_vrf->as, bgp_vrf->l3vni, bgp_vrf->evpn_autort_rfc8365_compatible);
}

/*
 * Function does not check whether auto RT generation should actually be done
 * caller needs to check this and only call if auto RTs should actually be generated!
 */
static struct bgp_evpn_effective_wildcard_rt* bgp_evpn_vrf_derive_import_auto_rt(const struct bgp *bgp_vrf) {
	return _bgp_evpn_derive_import_auto_rt_common(bgp_vrf->l3vni, bgp_vrf->evpn_autort_rfc8365_compatible);
}


/*
 * Function does not check whether auto RT generation should actually be done
 * caller needs to check this and only call if auto RTs should actually be generated!
 */
static struct bgp_evpn_effective_fq_rt* bgp_evpn_evi_derive_export_auto_rt(const struct bgp *parent_vrf, const struct bgp_evpn_evi *evi) {
	return _bgp_evpn_derive_export_auto_rt_common(parent_vrf->as, evi->vni, parent_vrf->evpn_autort_rfc8365_compatible);
}

/*
 * Function does not check whether auto RT generation should actually be done
 * caller needs to check this and only call if auto RTs should actually be generated!
 */
static struct bgp_evpn_effective_wildcard_rt* bgp_evpn_evi_derive_import_auto_rt(const struct bgp *parent_vrf, const struct bgp_evpn_evi *evi) {
	return _bgp_evpn_derive_import_auto_rt_common(evi->vni, parent_vrf->evpn_autort_rfc8365_compatible);
}


/* Common function used for both VRFs and EVIs, returns whether Auto RT should be generated
 * - If user Auto RT config exists, that takes precedence (explicit request / explicit disable)
 *   - "both" takes precedence over import/export specific config - however, if both is set, import/export
 *      should not be set! So this precedence should never be relevant
 * 
 * - If no user auto rt config exists, implicit auto RT generation kicks in ONLY if NO user configured RTs exist
 */
static bool _bgp_evpn_should_generate_autort_common(
	enum bgp_evpn_autort_cfgd autort_cfg_both, /* autort cfg for "both" */
	enum bgp_evpn_autort_cfgd direction_autort_cfg, /* autort cfg for import or export */
	struct bgp_evpn_cfgd_rt_slu_head *both_cfgd_rt_list, /* list of configured RTs for "both" */
	struct bgp_evpn_cfgd_rt_slu_head *direction_cfgd_rt_list /* list of configured RTs for import or export */
	) {

	/* First process the "both" config */
	/* "both" config takes precedence - conflicting "import"/"export" config should not even exist then */

	/* If auto RT generation is disabled, then we should not generate auto RTs in any case */
	if (autort_cfg_both == BGP_EVPN_AUTORT_DISABLE_CFGD)
		return false;

	/* autort_cfgd_both config can now only be NOT_CFGD or AUTO_CFGD */
	if(autort_cfg_both == BGP_EVPN_AUTORT_AUTO_CFGD)
		return true; /* User has explicitly requested auto RT generation */

	/* autort_cfgd_both == NOT_CFGD */


	/* Now process the "import" or "export" config */

	if(direction_autort_cfg == BGP_EVPN_AUTORT_DISABLE_CFGD)
		return false; /* User has explicitly requested to disable auto RT generation in import/export specific config */

	if(direction_autort_cfg == BGP_EVPN_AUTORT_AUTO_CFGD)
		return true; /* User has explicitly requested auto RT generation in import/export specific config */

	/* autort_cfgd_[import/export] == NOT_CFGD */

	/* Now determine whether implicit auto RT generation should kick in */
	/* Only generate the implicit auto RT if user has not configured ANY import/export (+both because that also affects import/export) RT */
	if(bgp_evpn_cfgd_rt_slu_count(both_cfgd_rt_list) == 0 && bgp_evpn_cfgd_rt_slu_count(direction_cfgd_rt_list) == 0)
		return true;

	return false;
}

static bool _bgp_evpn_vrf_should_generate_autort(const struct bgp *bgp_vrf, bool is_import) {

	struct bgp_evpn_rt_config* rt_config;

	/* The relevant autort cfg, either import or export */
	enum bgp_evpn_autort_cfgd direction_autort_cfg;
	struct bgp_evpn_cfgd_rt_slu_head *direction_cfgd_rt_list;

	if(!bgp_vrf)
		return false; /* shouldn't happen, but be defensive */

	if(!bgp_vrf->vrf_route_target_config)
		return false; /* also shouldn't happen, but be defensive */

	rt_config = bgp_vrf->vrf_route_target_config;

	if(is_import) {
		direction_autort_cfg = rt_config->autort_cfgd_import;
		direction_cfgd_rt_list = &rt_config->cfgd_import;
	} else {
		direction_autort_cfg = rt_config->autort_cfgd_export;
		direction_cfgd_rt_list = &rt_config->cfgd_export;
	}

	/* Auto RT generation only supported when VNI is configured */
	if (!is_l3vni_cfgd(bgp_vrf))
		return false;

	return _bgp_evpn_should_generate_autort_common(
		rt_config->autort_cfgd_both,
		direction_autort_cfg,
		&rt_config->cfgd_both,
		direction_cfgd_rt_list
	);
}

static bool bgp_evpn_vrf_should_generate_import_autort(const struct bgp *bgp_vrf) {
	return _bgp_evpn_vrf_should_generate_autort(bgp_vrf, false);
}
static bool bgp_evpn_vrf_should_generate_export_autort(const struct bgp *bgp_vrf) {
	return _bgp_evpn_vrf_should_generate_autort(bgp_vrf, true);
}

static bool _bgp_evpn_evi_should_generate_autort(const struct bgp_evpn_evi *evi, bool is_import) {

	struct bgp_evpn_rt_config* rt_config;

	/* The relevant autort cfg, either import or export */
	enum bgp_evpn_autort_cfgd direction_autort_cfg;
	struct bgp_evpn_cfgd_rt_slu_head *direction_cfgd_rt_list;

	if(!evi)
		return false; /* shouldn't happen, but be defensive */

	if(!evi->evi_rt_config)
		return false; /* also shouldn't happen, but be defensive */

	rt_config = evi->evi_rt_config;

	if(is_import) {
		direction_autort_cfg = rt_config->autort_cfgd_import;
		direction_cfgd_rt_list = &rt_config->cfgd_import;
	} else {
		direction_autort_cfg = rt_config->autort_cfgd_export;
		direction_cfgd_rt_list = &rt_config->cfgd_export;
	}

	/* Auto RT generation only supported when VNI is configured */
	if(!is_vni_configured(evi))
		return false;

	return _bgp_evpn_should_generate_autort_common(
		rt_config->autort_cfgd_both,
		direction_autort_cfg,
		&rt_config->cfgd_both,
		direction_cfgd_rt_list
	);
}

static bool bgp_evpn_evi_should_generate_import_autort(const struct bgp_evpn_evi *evi) {
	return _bgp_evpn_evi_should_generate_autort(evi, false);
}
static bool bgp_evpn_evi_should_generate_export_autort(const struct bgp_evpn_evi *evi) {
	return _bgp_evpn_evi_should_generate_autort(evi, true);
}


/*
 * Returns the local admin in network byte order from a route target ecommunity value
 * Maybe return unexpected values for route targets that are not AS, AS4 or IP!
 * Assumes caller does validation!
 */
static inline uint32_t bgp_evpn_rt_eval_get_local_admin_nbo(struct ecommunity_val eval)
{
	uint8_t type = eval.val[0];
	/* subtype = eval.val[1] -> should be 0x02*/
	struct ecommunity_val eval_tmp = eval;

	/* local admin is in the last 4 bytes for AS, last 2 bytes for AS4 and IP */
	if(type != ECOMMUNITY_ENCODE_AS) {
		eval_tmp.val[4] = 0;
		eval_tmp.val[5] = 0;
	}
	uint32_t local_admin_val_nbo;
	memcpy(&local_admin_val_nbo, &eval_tmp.val[4], sizeof(local_admin_val_nbo));

	return local_admin_val_nbo;
}

/* convert a configured fully qualified RT to a fully qualified effective RT
 * must ONLY be called for fully qualified RTs! Wildcard RTs have a separate function
 */
static struct bgp_evpn_effective_fq_rt* bgp_evpn_effective_fq_rt_from_cfgd_rt_new(const struct bgp_evpn_cfgd_rt* cfgd_rt) {

	if(!cfgd_rt)
		return NULL;

	if(cfgd_rt->type == BGP_EVPN_CFGD_RT_TYPE_WILDCARD) {
		/* This function should only be called for fully qualified RTs, wildcard RTs should be converted to effective wildcard RTs instead */
		return NULL;
	}

	/* BGP Route Targets are transitive communities */
	struct ecommunity_val eval;

	if(cfgd_rt->type == BGP_EVPN_CFGD_RT_TYPE_AS2) {
		encode_route_target_as(cfgd_rt->payload.as2_rt.as, cfgd_rt->payload.as2_rt.local_admin, &eval, true);

	} else if(cfgd_rt->type == BGP_EVPN_CFGD_RT_TYPE_AS4) {
		encode_route_target_as4(cfgd_rt->payload.as4_rt.as, cfgd_rt->payload.as4_rt.local_admin, &eval, true);

	} else if(cfgd_rt->type == BGP_EVPN_CFGD_RT_TYPE_IP4) {
		encode_route_target_ip(&cfgd_rt->payload.ip4_rt.ip, cfgd_rt->payload.ip4_rt.local_admin, &eval, true);

	} else {
		return NULL; /* unknown / unsupported RT type */
	}

	return bgp_evpn_effective_fq_rt_new(eval);
}

/* Helper function for updating effective route targets for both VRF and EVI
 * Converts a configured RT into an effective RT and pushes it into the relevant list (fully qualified / wildcard)
 * may be called with the list pointers being NULL, will simply not insert then 
 */
static int bgp_evpn_push_effective_rt_common(
	const struct bgp_evpn_cfgd_rt * cfgd_rt,
	struct bgp_evpn_effective_wildcard_rt_slu_head* wildcard_list,
	struct bgp_evpn_effective_fq_rt_slu_head* fq_list
) {

	if(cfgd_rt->type == BGP_EVPN_CFGD_RT_TYPE_WILDCARD) {
		if(!wildcard_list)
			return -1; /* Supposed to push a wildcard RT but have no list to push it to... */

		/* Need to convert to network byte order to match ecommunity_val */
		uint32_t local_admin_nbo = htonl(cfgd_rt->payload.wildcard_rt.local_admin);

		struct bgp_evpn_effective_wildcard_rt *wildcard_rt = bgp_evpn_effective_wildcard_rt_new(local_admin_nbo);

		if(!wildcard_rt)
			return -1; /* shouldn't happen */

		if(!bgp_evpn_effective_wildcard_rt_slu_add(wildcard_list, wildcard_rt)) {
			bgp_evpn_effective_wildcard_rt_free(wildcard_rt);
			return -1; /* insertion failure */
		}
	} else {
		/* Fully qualified / non-wildcard RT */
		if(!fq_list)
			return -1; /* Supposed to push a fully qualified RT but have no list to push it to... */

		struct bgp_evpn_effective_fq_rt* fq_rt = bgp_evpn_effective_fq_rt_from_cfgd_rt_new(cfgd_rt);

		if(!fq_rt)
			return -1; /* shouldn't happen - malformed config? */

		if(!bgp_evpn_effective_fq_rt_slu_add(fq_list, fq_rt)) {
			bgp_evpn_effective_fq_rt_free(fq_rt);
			return -1; /* insertion failure - duplicate route target in config?? */
		}
	}

	return 0;
}

static void bgp_evpn_vrf_regenerate_effective_import_rts(struct bgp *bgp_vrf) {

	struct bgp_evpn_effective_wildcard_rt* eff_w_item;
	struct bgp_evpn_effective_fq_rt* eff_fq_item;
	struct bgp_evpn_cfgd_rt* cfgd_item;

	if(!bgp_vrf)
		return; /* shouldn't happen! */
	if(!bgp_vrf->vrf_route_target_config)
		return; /* also shouldn't happen, but be defensive */

	/* Clear the existing lists */
	while ((eff_w_item = bgp_evpn_effective_wildcard_rt_slu_pop(&bgp_vrf->effective_wildcard_import_rts)))
		bgp_evpn_effective_wildcard_rt_free(eff_w_item);

	while ((eff_fq_item = bgp_evpn_effective_fq_rt_slu_pop(&bgp_vrf->effective_fq_import_rts)))
		bgp_evpn_effective_fq_rt_free(eff_fq_item);

	/* Start with the auto RT */
	bool should_generate_auto_rt = bgp_evpn_vrf_should_generate_import_autort(bgp_vrf);
	if(should_generate_auto_rt) {

		eff_w_item = bgp_evpn_vrf_derive_import_auto_rt(bgp_vrf);

		if(eff_w_item) /* eff_w_item should never be NULL... */
			/* Insert should always succeed, list is empty */
			bgp_evpn_effective_wildcard_rt_slu_add(&bgp_vrf->effective_wildcard_import_rts, eff_w_item);
	}

	/* Now add the user configured RTs */

	/* Begin with the both RTs */
	frr_each(bgp_evpn_cfgd_rt_slu, &bgp_vrf->vrf_route_target_config->cfgd_both, cfgd_item) {
		/* Return code ignored for now, maybe add some logging in the future? */
		bgp_evpn_push_effective_rt_common(
			cfgd_item,
			&bgp_vrf->effective_wildcard_import_rts,
			&bgp_vrf->effective_fq_import_rts
		);
	}

	/* Now the import specific RTs */
	frr_each(bgp_evpn_cfgd_rt_slu, &bgp_vrf->vrf_route_target_config->cfgd_import, cfgd_item) {
		/* Return code ignored for now, maybe add some logging in the future? */
		bgp_evpn_push_effective_rt_common(
			cfgd_item,
			&bgp_vrf->effective_wildcard_import_rts,
			&bgp_vrf->effective_fq_import_rts
		);
	}
}

static void bgp_evpn_vrf_regenerate_effective_export_rts(struct bgp *bgp_vrf) {

	struct bgp_evpn_effective_fq_rt* eff_fq_item;
	struct bgp_evpn_cfgd_rt* cfgd_item;

	if(!bgp_vrf)
		return; /* shouldn't happen! */
	if(!bgp_vrf->vrf_route_target_config)
		return; /* also shouldn't happen, but be defensive */

	/* Clear the existing lists */
	while ((eff_fq_item = bgp_evpn_effective_fq_rt_slu_pop(&bgp_vrf->effective_fq_export_rts)))
		bgp_evpn_effective_fq_rt_free(eff_fq_item);

	/* Start with the auto RT */
	bool should_generate_auto_rt = bgp_evpn_vrf_should_generate_export_autort(bgp_vrf);
	if(should_generate_auto_rt) {

		eff_fq_item = bgp_evpn_vrf_derive_export_auto_rt(bgp_vrf);

		if(eff_fq_item) /* eff_fq_item should never be NULL... */
			/* Insert should always succeed, list is empty */
			bgp_evpn_effective_fq_rt_slu_add(&bgp_vrf->effective_fq_export_rts, eff_fq_item);
	}

	/* Now add the user configured RTs */

	/* Begin with the both RTs */
	frr_each(bgp_evpn_cfgd_rt_slu, &bgp_vrf->vrf_route_target_config->cfgd_both, cfgd_item) {
		/* Return code ignored for now, maybe add some logging in the future? */
		bgp_evpn_push_effective_rt_common(
			cfgd_item,
			NULL, /* export RTs cannot be wildcard, so no need to push to wildcard list */
			&bgp_vrf->effective_fq_export_rts
		);
	}

	/* Now the import specific RTs */
	frr_each(bgp_evpn_cfgd_rt_slu, &bgp_vrf->vrf_route_target_config->cfgd_export, cfgd_item) {
		/* Return code ignored for now, maybe add some logging in the future? */
		bgp_evpn_push_effective_rt_common(
			cfgd_item,
			NULL, /* export RTs cannot be wildcard, so no need to push to wildcard list */
			&bgp_vrf->effective_fq_export_rts
		);
	}
}

static void bgp_evpn_evi_regenerate_effective_import_rts(struct bgp* parent_vrf, struct bgp_evpn_evi *evi) {

	struct bgp_evpn_effective_wildcard_rt* eff_w_item;
	struct bgp_evpn_effective_fq_rt* eff_fq_item;
	struct bgp_evpn_cfgd_rt* cfgd_item;

	if(!parent_vrf)
		return; /* shouldn't happen */
	if(!evi)
		return; /* shouldn't happen! */
	if(!evi->evi_rt_config)
		return; /* also shouldn't happen, but be defensive */

	/* Clear the existing lists */
	while ((eff_w_item = bgp_evpn_effective_wildcard_rt_slu_pop(&evi->effective_wildcard_import_rts)))
		bgp_evpn_effective_wildcard_rt_free(eff_w_item);

	while ((eff_fq_item = bgp_evpn_effective_fq_rt_slu_pop(&evi->effective_fq_import_rts)))
		bgp_evpn_effective_fq_rt_free(eff_fq_item);

	/* Start with the auto RT */
	bool should_generate_auto_rt = bgp_evpn_evi_should_generate_import_autort(evi);
	if(should_generate_auto_rt) {

		eff_w_item = bgp_evpn_evi_derive_import_auto_rt(parent_vrf, evi);

		if(eff_w_item) /* eff_w_item should never be NULL... */
			/* Insert should always succeed, list is empty */
			bgp_evpn_effective_wildcard_rt_slu_add(&evi->effective_wildcard_import_rts, eff_w_item);
	}

	/* Now add the user configured RTs */

	/* Begin with the both RTs */
	frr_each(bgp_evpn_cfgd_rt_slu, &evi->evi_rt_config->cfgd_both, cfgd_item) {
		/* Return code ignored for now, maybe add some logging in the future? */
		bgp_evpn_push_effective_rt_common(
			cfgd_item,
			&evi->effective_wildcard_import_rts,
			&evi->effective_fq_import_rts
		);
	}

	/* Now the import specific RTs */
	frr_each(bgp_evpn_cfgd_rt_slu, &evi->evi_rt_config->cfgd_import, cfgd_item) {
		/* Return code ignored for now, maybe add some logging in the future? */
		bgp_evpn_push_effective_rt_common(
			cfgd_item,
			&evi->effective_wildcard_import_rts,
			&evi->effective_fq_import_rts
		);
	}
}

static void bgp_evpn_evi_regenerate_effective_export_rts(struct bgp* parent_vrf, struct bgp_evpn_evi *evi) {

	struct bgp_evpn_effective_fq_rt* eff_fq_item;
	struct bgp_evpn_cfgd_rt* cfgd_item;

	if(!parent_vrf)
		return; /* shouldn't happen */
	if(!evi)
		return; /* shouldn't happen! */
	if(!evi->evi_rt_config)
		return; /* also shouldn't happen, but be defensive */

	/* Clear the existing lists */
	while ((eff_fq_item = bgp_evpn_effective_fq_rt_slu_pop(&evi->effective_fq_export_rts)))
		bgp_evpn_effective_fq_rt_free(eff_fq_item);

	/* Start with the auto RT */
	bool should_generate_auto_rt = bgp_evpn_evi_should_generate_export_autort(evi);
	if(should_generate_auto_rt) {

		eff_fq_item = bgp_evpn_evi_derive_export_auto_rt(parent_vrf, evi);

		if(eff_fq_item) /* eff_fq_item should never be NULL... */
			/* Insert should always succeed, list is empty */
			bgp_evpn_effective_fq_rt_slu_add(&evi->effective_fq_export_rts, eff_fq_item);
	}

	/* Now add the user configured RTs */

	/* Begin with the both RTs */
	frr_each(bgp_evpn_cfgd_rt_slu, &evi->evi_rt_config->cfgd_both, cfgd_item) {
		/* Return code ignored for now, maybe add some logging in the future? */
		bgp_evpn_push_effective_rt_common(
			cfgd_item,
			NULL, /* export RTs cannot be wildcard, so no need to push to wildcard list */
			&evi->effective_fq_export_rts
		);
	}

	/* Now the import specific RTs */
	frr_each(bgp_evpn_cfgd_rt_slu, &evi->evi_rt_config->cfgd_export, cfgd_item) {
		/* Return code ignored for now, maybe add some logging in the future? */
		bgp_evpn_push_effective_rt_common(
			cfgd_item,
			NULL, /* export RTs cannot be wildcard, so no need to push to wildcard list */
			&evi->effective_fq_export_rts
		);
	}
}



static void bgp_evpn_format_wildcard_rt(char *buf, size_t buflen,
					uint32_t local_admin)
{
	snprintf(buf, buflen, "*:%u", local_admin);
}

static void bgp_evpn_format_as2_rt(char *buf, size_t buflen,
				   uint16_t as, uint32_t local_admin)
{
	snprintf(buf, buflen, "%u:%u", as, local_admin);
}

static void bgp_evpn_format_ip4_rt(char *buf, size_t buflen,
				   struct in_addr ip, uint16_t local_admin)
{
	snprintfrr(buf, buflen, "%pI4:%u", &ip, local_admin);
}

static void bgp_evpn_format_as4_rt(char *buf, size_t buflen,
				   uint32_t as, uint16_t local_admin)
{
	snprintf(buf, buflen, "%u:%u", as, local_admin);
}

/* For displaying irt nodes */
void bgp_evpn_format_wildcard_rt_local_admin(char *buf, size_t buflen,
					     uint32_t local_admin_nbo)
{
	bgp_evpn_format_wildcard_rt(buf, buflen, ntohl(local_admin_nbo));
}

/* For displaying irt nodes */
void bgp_evpn_format_fq_rt_ecom_val(char *buf, size_t buflen,
				    struct ecommunity_val eval)
{
	uint8_t subtype = eval.val[1];

	if (subtype != ECOMMUNITY_ROUTE_TARGET) {
		snprintf(buf, buflen, "(Invalid RT, wrong subtype)");
		return;
	}

	/* The ptr_get_beXX convert network byte order / big endian to host byte order */
	switch (eval.val[0]) {
	case ECOMMUNITY_ENCODE_AS: {
		uint16_t as2;
		uint32_t local_admin_val;
		ptr_get_be16(eval.val + 2, &as2);
		ptr_get_be32(eval.val + 4, &local_admin_val);
		bgp_evpn_format_as2_rt(buf, buflen, as2, local_admin_val);
		break;
	}
	case ECOMMUNITY_ENCODE_AS4: {
		uint32_t as4;
		uint16_t local_admin_val;
		ptr_get_be32(eval.val + 2, &as4);
		ptr_get_be16(eval.val + 6, &local_admin_val);
		bgp_evpn_format_as4_rt(buf, buflen, as4, local_admin_val);
		break;
	}
	case ECOMMUNITY_ENCODE_IP: {
		struct in_addr ip;
		uint16_t local_admin_val;
		memcpy(&ip, eval.val + 2, 4);
		ptr_get_be16(eval.val + 6, &local_admin_val);
		bgp_evpn_format_ip4_rt(buf, buflen, ip, local_admin_val);
		break;
	}
	default:
		snprintf(buf, buflen, "(Invalid RT, wrong type)");
		break;
	}
}

void bgp_evpn_format_cfgd_rt(char *buf, size_t buflen,
			      const struct bgp_evpn_cfgd_rt *cfgd_rt)
{
	switch (cfgd_rt->type) {
	case BGP_EVPN_CFGD_RT_TYPE_WILDCARD:
		bgp_evpn_format_wildcard_rt(buf, buflen,
					    cfgd_rt->payload.wildcard_rt.local_admin);
		break;
	case BGP_EVPN_CFGD_RT_TYPE_AS2:
		bgp_evpn_format_as2_rt(buf, buflen,
				       cfgd_rt->payload.as2_rt.as,
				       cfgd_rt->payload.as2_rt.local_admin);
		break;
	case BGP_EVPN_CFGD_RT_TYPE_IP4:
		bgp_evpn_format_ip4_rt(buf, buflen,
				       cfgd_rt->payload.ip4_rt.ip,
				       cfgd_rt->payload.ip4_rt.local_admin);
		break;
	case BGP_EVPN_CFGD_RT_TYPE_AS4:
		bgp_evpn_format_as4_rt(buf, buflen,
				       cfgd_rt->payload.as4_rt.as,
				       cfgd_rt->payload.as4_rt.local_admin);
		break;
	default:
		snprintf(buf, buflen, "(Invalid RT, unknown type)");
		break;
	}
}

/*
 * Hash key function for fully qualified VRF import route target hashmap node.
 * Does not hash values, only key (ecommunity value!)
 */
uint32_t vrf_fq_irt_node_hash_key(const struct vrf_fq_irt_node *irt)
{
	return jhash(irt->rt.val, ECOMMUNITY_SIZE, 0x46515254);
}

/*
 * Key Comparison function for fully qualified VRF import route target hashmap node
 * Does NOT compare values, only key (ecommunity value!)
 */
int vrf_fq_irt_node_hash_cmp(const struct vrf_fq_irt_node *a, const struct vrf_fq_irt_node *b)
{
	return memcmp(a->rt.val, b->rt.val, ECOMMUNITY_SIZE);
}

/*
 * Function to lookup a fully qualified Import RT node - used to map a RT to set of
 * VRFs importing routes with that RT.
 */
static struct vrf_fq_irt_node *lookup_vrf_fq_irt_node_by_ecom_val(struct ecommunity_val rt_val)
{
	struct bgp *bgp_evpn_mi = NULL;
	struct vrf_fq_irt_node tmp;

	bgp_evpn_mi = bgp_get_evpn_master_instance();
	if (!bgp_evpn_mi) {
		flog_err(
			EC_BGP_NO_DFLT,
			"vrf fq import rt lookup - evpn instance not created yet");
		return NULL;
	}

	memset(&tmp, 0, sizeof(tmp));
	memcpy(&tmp.rt, &rt_val, sizeof(tmp.rt));

	return vrf_fq_irt_nodes_find(&bgp_evpn_mi->evpn_master_instance_info.vrf_fq_irt_nodes, &tmp);
}


/*
 * Hash key function for wildcard VRF import route target hashmap node.
 * Does not hash values, only key (local_admin value!)
 */
uint32_t vrf_wildcard_irt_node_hash_key(const struct vrf_wildcard_irt_node *irt)
{
	return jhash_1word(irt->local_admin_nbo, 0x57435254);
}

/*
 * Key Comparison function for wildcard VRF import route target hashmap node
 * Does NOT compare values, only key (local_admin value!)
 */
int vrf_wildcard_irt_node_hash_cmp(const struct vrf_wildcard_irt_node *a, const struct vrf_wildcard_irt_node *b)
{
	return memcmp(&a->local_admin_nbo, &b->local_admin_nbo, sizeof(a->local_admin_nbo));
}

/*
 * Function to lookup a wildcard qualified Import RT node by route target ecommunity value
 * will return NULL if route target is not of type AS, AS4 or IP
 */
static struct vrf_wildcard_irt_node *lookup_vrf_wildcard_irt_node_by_ecom_val(struct ecommunity_val eval)
{
	struct bgp *bgp_evpn_mi = NULL;
	struct vrf_wildcard_irt_node tmp;

	bgp_evpn_mi = bgp_get_evpn_master_instance();
	if (!bgp_evpn_mi) {
		flog_err(
			EC_BGP_NO_DFLT,
			"vrf wildcard import rt lookup - evpn instance not created yet");
		return NULL;
	}

	/* Wildcard RTs were only built with AS, AS4 and IP4 support in mind - filter other types! */
	uint8_t type = eval.val[0];
	if(!(type == ECOMMUNITY_ENCODE_AS ||
			type == ECOMMUNITY_ENCODE_AS4 ||
			type == ECOMMUNITY_ENCODE_IP)) {
		return NULL;
	}

	/* Extract local admin value, then perform actual lookup */
	uint32_t local_admin_val = bgp_evpn_rt_eval_get_local_admin_nbo(eval);

	memset(&tmp, 0, sizeof(tmp));
	memcpy(&tmp.local_admin_nbo, &local_admin_val, sizeof(tmp.local_admin_nbo));

	return vrf_wildcard_irt_nodes_find(&bgp_evpn_mi->evpn_master_instance_info.vrf_wildcard_irt_nodes, &tmp);
}

static struct vrf_mapped_bgp_instance *vrf_mapped_bgp_instance_new(struct bgp *bgp_vrf)
{
	struct vrf_mapped_bgp_instance *item;

	item = XCALLOC(MTYPE_BGP_EVPN_VRF_MAPPED_BGP_INSTANCE, sizeof(*item));
	item->bgp = bgp_vrf;
	return item;
}

static void vrf_mapped_bgp_instance_free(struct vrf_mapped_bgp_instance *item)
{
	XFREE(MTYPE_BGP_EVPN_VRF_MAPPED_BGP_INSTANCE, item);
}

static struct vrf_fq_irt_node *vrf_fq_irt_node_new(struct ecommunity_val rt)
{
	struct vrf_fq_irt_node *node;

	node = XCALLOC(MTYPE_BGP_EVPN_VRF_FQ_IRT_NODE, sizeof(*node));
	memcpy(&node->rt, &rt, sizeof(node->rt));

	vrf_mapped_bgp_instance_slu_init(&node->vrfs);

	return node;
}

static void vrf_fq_irt_node_free(struct vrf_fq_irt_node *node)
{
	struct vrf_mapped_bgp_instance *item;

	while ((item = vrf_mapped_bgp_instance_slu_pop(&node->vrfs)))
		vrf_mapped_bgp_instance_free(item);
	vrf_mapped_bgp_instance_slu_fini(&node->vrfs);

	XFREE(MTYPE_BGP_EVPN_VRF_FQ_IRT_NODE, node);
}

static struct vrf_wildcard_irt_node *vrf_wildcard_irt_node_new(uint32_t local_admin_nbo)
{
	struct vrf_wildcard_irt_node *node;

	node = XCALLOC(MTYPE_BGP_EVPN_VRF_WILDCARD_IRT_NODE, sizeof(*node));
	node->local_admin_nbo = local_admin_nbo;

	vrf_mapped_bgp_instance_slu_init(&node->vrfs);

	return node;
}

static void vrf_wildcard_irt_node_free(struct vrf_wildcard_irt_node *node)
{
	struct vrf_mapped_bgp_instance *item;

	while ((item = vrf_mapped_bgp_instance_slu_pop(&node->vrfs)))
		vrf_mapped_bgp_instance_free(item);
	vrf_mapped_bgp_instance_slu_fini(&node->vrfs);

	XFREE(MTYPE_BGP_EVPN_VRF_WILDCARD_IRT_NODE, node);
}



/*
 * Hash key function for fully qualified EVI import route target hashmap node.
 * Does not hash values, only key (ecommunity value!)
 */
uint32_t evi_fq_irt_node_hash_key(const struct evi_fq_irt_node *irt)
{
	return jhash(irt->rt.val, ECOMMUNITY_SIZE, 0x46515254);
}

/*
 * Key Comparison function for fully qualified EVI import route target hashmap node
 * Does NOT compare values, only key (ecommunity value!)
 */
int evi_fq_irt_node_hash_cmp(const struct evi_fq_irt_node *a, const struct evi_fq_irt_node *b)
{
	return memcmp(a->rt.val, b->rt.val, ECOMMUNITY_SIZE);
}

/*
 * Function to lookup a fully qualified Import RT node - used to map a RT to set of
 * EVIs importing routes with that RT.
 */
static struct evi_fq_irt_node *lookup_evi_fq_irt_node_by_ecom_val(struct ecommunity_val rt_val)
{
	struct bgp *bgp_evpn_mi = NULL;
	struct evi_fq_irt_node tmp;

	bgp_evpn_mi = bgp_get_evpn_master_instance();
	if (!bgp_evpn_mi) {
		flog_err(
			EC_BGP_NO_DFLT,
			"evi fq import rt lookup - evpn instance not created yet");
		return NULL;
	}

	memset(&tmp, 0, sizeof(tmp));
	memcpy(&tmp.rt, &rt_val, sizeof(tmp.rt));

	return evi_fq_irt_nodes_find(&bgp_evpn_mi->evpn_master_instance_info.evi_fq_irt_nodes, &tmp);
}


/*
 * Hash key function for wildcard EVI import route target hashmap node.
 * Does not hash values, only key (local_admin value!)
 */
uint32_t evi_wildcard_irt_node_hash_key(const struct evi_wildcard_irt_node *irt)
{
	return jhash_1word(irt->local_admin_nbo, 0x57435254);
}

/*
 * Key Comparison function for wildcard EVI import route target hashmap node
 * Does NOT compare values, only key (local_admin value!)
 */
int evi_wildcard_irt_node_hash_cmp(const struct evi_wildcard_irt_node *a, const struct evi_wildcard_irt_node *b)
{
	return memcmp(&a->local_admin_nbo, &b->local_admin_nbo, sizeof(a->local_admin_nbo));
}

/*
 * Function to lookup a wildcard qualified Import RT node by route target ecommunity value
 * will return NULL if route target is not of type AS, AS4 or IP
 */
static struct evi_wildcard_irt_node *lookup_evi_wildcard_irt_node_by_ecom_val(struct ecommunity_val eval)
{
	struct bgp *bgp_evpn_mi = NULL;
	struct evi_wildcard_irt_node tmp;

	bgp_evpn_mi = bgp_get_evpn_master_instance();
	if (!bgp_evpn_mi) {
		flog_err(
			EC_BGP_NO_DFLT,
			"evi wildcard import rt lookup - evpn instance not created yet");
		return NULL;
	}

	/* Wildcard RTs were only built with AS, AS4 and IP4 support in mind - filter other types! */
	uint8_t type = eval.val[0];
	if(!(type == ECOMMUNITY_ENCODE_AS ||
			type == ECOMMUNITY_ENCODE_AS4 ||
			type == ECOMMUNITY_ENCODE_IP)) {
		return NULL;
	}

	/* Extract local admin value, then perform actual lookup */
	uint32_t local_admin_val = bgp_evpn_rt_eval_get_local_admin_nbo(eval);

	memset(&tmp, 0, sizeof(tmp));
	memcpy(&tmp.local_admin_nbo, &local_admin_val, sizeof(tmp.local_admin_nbo));

	return evi_wildcard_irt_nodes_find(&bgp_evpn_mi->evpn_master_instance_info.evi_wildcard_irt_nodes, &tmp);
}

static struct evi_mapped_evi *evi_mapped_evi_new(struct bgp_evpn_evi *evi)
{
	struct evi_mapped_evi *item;

	item = XCALLOC(MTYPE_BGP_EVPN_EVI_MAPPED_EVI, sizeof(*item));
	item->evi = evi;
	return item;
}

static void evi_mapped_evi_free(struct evi_mapped_evi *item)
{
	XFREE(MTYPE_BGP_EVPN_EVI_MAPPED_EVI, item);
}

static struct evi_fq_irt_node *evi_fq_irt_node_new(struct ecommunity_val rt)
{
	struct evi_fq_irt_node *node;

	node = XCALLOC(MTYPE_BGP_EVPN_EVI_FQ_IRT_NODE, sizeof(*node));
	memcpy(&node->rt, &rt, sizeof(node->rt));

	evi_mapped_evi_slu_init(&node->evis);

	return node;
}

static void evi_fq_irt_node_free(struct evi_fq_irt_node *node)
{
	struct evi_mapped_evi *item;

	while ((item = evi_mapped_evi_slu_pop(&node->evis)))
		evi_mapped_evi_free(item);
	evi_mapped_evi_slu_fini(&node->evis);

	XFREE(MTYPE_BGP_EVPN_EVI_FQ_IRT_NODE, node);
}

static struct evi_wildcard_irt_node *evi_wildcard_irt_node_new(uint32_t local_admin_nbo)
{
	struct evi_wildcard_irt_node *node;

	node = XCALLOC(MTYPE_BGP_EVPN_EVI_WILDCARD_IRT_NODE, sizeof(*node));
	node->local_admin_nbo = local_admin_nbo;

	evi_mapped_evi_slu_init(&node->evis);

	return node;
}

static void evi_wildcard_irt_node_free(struct evi_wildcard_irt_node *node)
{
	struct evi_mapped_evi *item;

	while ((item = evi_mapped_evi_slu_pop(&node->evis)))
		evi_mapped_evi_free(item);
	evi_mapped_evi_slu_fini(&node->evis);

	XFREE(MTYPE_BGP_EVPN_EVI_WILDCARD_IRT_NODE, node);
}




/*
 * Hash key function for import route target.
 */
uint32_t evi_irt_node_hash_key(const struct evi_irt_node *irt)
{
	uint32_t hashval = jhash_1word(irt->is_wildcard, 0xdeadbeef);
	return jhash(irt->rt.val, 8, hashval);
}

/*
 * Comparison function for evi_irt_node hash(-map)
 * Does NOT compare values, only key (is_wildcard + RT value)
 */
int evi_irt_node_hash_cmp(const struct evi_irt_node *a,
			  const struct evi_irt_node *b)
{
	/* Sort Wildcard RTs first */
	if(a->is_wildcard != b->is_wildcard)
		return a->is_wildcard ? -1 : 1;

	return memcmp(a->rt.val, b->rt.val, ECOMMUNITY_SIZE);
}

/*
 * Legacy!
 * Create a new import_rt
 */
static struct evi_irt_node *evi_irt_node_new(struct bgp *bgp,
						 struct ecommunity_val rt, bool is_wildcard)
{
	struct evi_irt_node *irt;

	irt = XCALLOC(MTYPE_BGP_EVPN_EVI_IRT_NODE, sizeof(struct evi_irt_node));

	irt->is_wildcard = is_wildcard;
	irt->rt = rt;
	irt->evis = list_new();

	/* Add to typesafe hash */
	evi_irt_nodes_add(&bgp->evpn_master_instance_info.evi_irt_nodes, irt);

	return irt;
}

/*
 * Legacy!
 * Free the import rt node
 */
static void evi_irt_node_free(struct bgp *bgp, struct evi_irt_node *irt)
{
	evi_irt_nodes_del(&bgp->evpn_master_instance_info.evi_irt_nodes, irt);
	/* No need to free the EVIs themselves, they are held in vnihash */
	list_delete(&irt->evis);
	XFREE(MTYPE_BGP_EVPN_EVI_IRT_NODE, irt);
}

/*
 * Legacy!
 * Function to lookup Import RT node - used to map a RT to set of
 * VNIs importing routes with that RT.
 */
static struct evi_irt_node *lookup_evi_irt_node(struct bgp *bgp,
						struct ecommunity_val *rt)
{
	struct evi_irt_node tmp;

	memset(&tmp, 0, sizeof(tmp));
	memcpy(&tmp.rt, rt, ECOMMUNITY_SIZE);
	return evi_irt_nodes_find(&bgp->evpn_master_instance_info.evi_irt_nodes, &tmp);
}

/*
 * Legacy!
 * Is specified VNI present on the RT's list of "importing" VNIs?
 */
static int is_evi_present_in_evi_irt_node(struct evi_irt_node *irt_node, struct bgp_evpn_evi *evi)
{
	struct listnode *node, *nnode;
	struct bgp_evpn_evi *tmp_evi;

	for (ALL_LIST_ELEMENTS(irt_node->evis, node, nnode, tmp_evi)) {
		if (tmp_evi == evi)
			return 1;
	}

	return 0;
}

/*
 * Mask off global-admin field of specified extended community (RT),
 * just retain the local-admin field.
 */
static inline void mask_ecom_global_admin(struct ecommunity_val *dst,
					  const struct ecommunity_val *src)
{
	uint8_t type;

	type = src->val[0];
	dst->val[0] = 0;
	if (type == ECOMMUNITY_ENCODE_AS) {
		dst->val[2] = dst->val[3] = 0;
	} else if (type == ECOMMUNITY_ENCODE_AS4
		   || type == ECOMMUNITY_ENCODE_IP) {
		dst->val[2] = dst->val[3] = 0;
		dst->val[4] = dst->val[5] = 0;
	}
}

/*
 * Compare Route Targets.
 */
int bgp_evpn_route_target_ecom_cmp(struct ecommunity *ecom1,
			      struct ecommunity *ecom2)
{
	if (ecom1 && !ecom2)
		return -1;

	if (!ecom1 && ecom2)
		return 1;

	if (!ecom1 && !ecom2)
		return 0;

	if (ecom1->str && !ecom2->str)
		return -1;

	if (!ecom1->str && ecom2->str)
		return 1;

	if (!ecom1->str && !ecom2->str)
		return 0;

	return strcmp(ecom1->str, ecom2->str);
}

void bgp_evpn_xxport_delete_ecomm(void *val)
{
	struct ecommunity *ecomm = val;
	ecommunity_free(&ecomm);
}



/* Legacy!
 * Map one RT to specified VNI.
 */
static void bgp_evpn_evi_map_to_evi_irt_nodes(struct bgp *bgp, struct bgp_evpn_evi *evi,
			  struct ecommunity_val *eval)
{
	struct evi_irt_node *irt;
	struct ecommunity_val eval_tmp;

	/* If using "automatic" RT, we only care about the local-admin
	 * sub-field.
	 * This is to facilitate using VNI as the RT for EBGP peering too.
	 */
	bool rt_is_wildcard = !is_import_rt_configured(evi);
	memcpy(&eval_tmp, eval, ECOMMUNITY_SIZE);
	if (rt_is_wildcard)
		mask_ecom_global_admin(&eval_tmp, eval);

	irt = lookup_evi_irt_node(bgp, &eval_tmp);
	if (irt && is_evi_present_in_evi_irt_node(irt, evi))
		/* Already mapped. */
		return;

	if (!irt)
		irt = evi_irt_node_new(bgp, eval_tmp, rt_is_wildcard);

	/* Add VNI to the hash list for this RT. */
	listnode_add(irt->evis, evi);
}

/* Legacy!
 * Unmap specified VNI from specified RT. If there are no other
 * VNIs for this RT, then the RT hash is deleted.
 */
static void bgp_evpn_evi_unmap_from_evi_irt_nodes(struct bgp *bgp, struct bgp_evpn_evi *evi,
			      struct evi_irt_node *irt)
{
	/* Delete VNI from hash list for this RT. */
	listnode_delete(irt->evis, evi);
	if (!listnode_head(irt->evis)) {
		evi_irt_node_free(bgp, irt);
	}
}

/* Legacy!
 * Create RT extended community automatically from passed information:
 * of the form AS:VNI.
 * NOTE: We use only the lower 16 bits of the AS. This is sufficient as
 * the need is to get a RT value that will be unique across different
 * VNIs but the same across routers (in the same AS) for a particular
 * VNI.
 */
static void bgp_evpn_evi_form_auto_rt(struct bgp *bgp, vni_t vni, struct list *rtl)
{
	struct ecommunity_val eval;
	struct ecommunity *ecomadd;
	struct ecommunity *ecom;
	bool ecom_found = false;
	struct listnode *node;

	if (bgp->evpn_autort_rfc8365_compatible)
		SET_FLAG(vni, BGP_EVPN_RT_RFC8365_A_BIT);
	encode_route_target_as((bgp->as & 0xFFFF), vni, &eval, true);

	ecomadd = ecommunity_new();
	ecommunity_add_val(ecomadd, &eval, false, false);

	for (ALL_LIST_ELEMENTS_RO(rtl, node, ecom))
		if (ecommunity_cmp(ecomadd, ecom)) {
			ecom_found = true;
			break;
		}

	if (!ecom_found)
		listnode_add_sort(rtl, ecomadd);
	else
		ecommunity_free(&ecomadd);
}

/* Call this when you've done modifications that could potentially influence the effective Import Route Targets
 * e.g. VNI change (different Auto RT), new "import" RT added / removed, new "both" RT added / removed, etc..
 */
void bgp_evpn_vrf_handle_import_rt_change(struct bgp *bgp_vrf)
{
	if(bgp_get_evpn_master_instance() == NULL)
		return; /* EVPN not even activated? Why are we even being called? */

	/* Before we can update / regenerate the effective RTs, we need to perform the teardown
	 * which uses the effective RTs to determine which routes must be deleted
	 */
	bgp_evpn_vrf_teardown_import(bgp_vrf);

	/* Now we can regenerate the effective RTs based on the new config */
	bgp_evpn_vrf_regenerate_effective_import_rts(bgp_vrf);

	/* Setup the Import again, now with the new effective RTs */
	bgp_evpn_vrf_setup_import(bgp_vrf);
}

/* Call this when you've done modifications that could potentially influence the effective Export Route Targets
 * e.g. VNI change (different Auto RT), new "export" RT added / removed, new "both" RT added / removed, etc..
 */
void bgp_evpn_vrf_handle_export_rt_change(struct bgp *bgp_vrf)
{
	struct bgp *bgp_evpn_mi = NULL;
	struct listnode *node = NULL;
	struct bgp_evpn_evi *evi = NULL;

	bgp_evpn_mi = bgp_get_evpn_master_instance();
	if (!bgp_evpn_mi)
		return; /* EVPN not even activated? Why are we even being called? */

	/* Update the Export RTs in any case - the regenerate function might decide to not generate any new RTs
	 * depending on the L3VNIs state and only clear the existing ones.
	 */
	bgp_evpn_vrf_regenerate_effective_export_rts(bgp_vrf);

	/* If the L3VNI is not yet active, do not advertise routes
	 * because we could never process received traffic or might not even have a VNI we could set as
	 * MPLS Label 2 / L3VNI in the routes
	 * Note that we might want to change this in the future e.g. for DCI applications where we are not involved
	 * in the data plane but still want to announce some modified routes on behalf of others
	 */
	if (!is_l3vni_live(bgp_vrf))
		return;

	/* update all type-5 routes
	 * We don't need to teardown / withdraw routes, because the routes themself (or rather the part that is
	 * part of the route key, i.e. what determines whether two routes are the same) will be identical, only
	 * the export RTs aka some extended communities change (which are not part of the route key),
	 * so existing routes will simply be overriden!
	 */
	bgp_evpn_vrf_update_advertise_originated_type_5_routes(bgp_vrf);

	/*
	 * for all EVIs attached to this VRF, update all type-2 routes
	 * because they carry the export route-targets of the VRF they belong to and of the EVI itselfs
	 */
	for (ALL_LIST_ELEMENTS_RO(bgp_vrf->l2vnis, node, evi))
		bgp_evpn_evi_update_all_type2_routes(bgp_evpn_mi, evi);
}

/* Legacy!
 * Handle autort change for a given VNI.
 */
static void bgp_evpn_evi_update_autorts(struct hash_bucket *bucket, struct bgp *bgp)
{
	struct bgp_evpn_evi *evi = bucket->data;

	if (!is_import_rt_configured(evi)) {
		if (is_evi_live(evi))
			bgp_evpn_evi_uninstall_routes(bgp, evi);
		bgp_evpn_unmap_vni_from_its_rts(bgp, evi);
		list_delete_all_node(evi->evi_import_rtl);
		legacy_bgp_evpn_evi_derive_import_auto_rt(bgp, evi);
		if (is_evi_live(evi))
			bgp_evpn_evi_install_routes(bgp, evi);
	}
	if (!is_export_rt_configured(evi)) {
		list_delete_all_node(evi->evi_export_rtl);
		legacy_bgp_evpn_evi_derive_export_auto_rt(bgp, evi);
		if (is_evi_live(evi))
			bgp_evpn_evi_handle_export_rt_change(bgp, evi);
	}
}

/*
 * Change the auto RT "algorithm" / algorithm option, takes care of both VRFs and EVIs
 */
void bgp_evpn_configure_evpn_autort_rfc8365_compatible(struct bgp *bgp_vrf, bool evpn_autort_rfc8365_compatible)
{
	struct bgp *bgp_evpn_mi = bgp_get_evpn_master_instance();
	assert(bgp_evpn_mi); /* This function should only be called after EVPN instance is created */

	if(bgp_vrf->evpn_autort_rfc8365_compatible == evpn_autort_rfc8365_compatible)
		return; /* No change */

	/* The VRF Route Target should be updated BEFORE updating the EVIs
	 * because the EVIs use their own RTs AND possibly the VRF RTs!
	*/
	/* Only trigger the update logic if Auto RT is actually being used */
	if(bgp_evpn_vrf_should_generate_import_autort(bgp_vrf))
		bgp_evpn_vrf_handle_import_rt_change(bgp_vrf);

	if(bgp_evpn_vrf_should_generate_export_autort(bgp_vrf))
		bgp_evpn_vrf_handle_export_rt_change(bgp_vrf);

	hash_iterate(bgp_vrf->evpn_master_instance_info.vnihash,
		     (void (*)(struct hash_bucket *,
			       void*))bgp_evpn_evi_update_autorts,
		     bgp_vrf);
}



/*
 * Map the effective import RTs of a VRF to the vrf_irt_nodes lookup tables.
 * The mapping is used during route import (bgp_evpn_vrf_check_route_matches_import_rts).
 */
void bgp_evpn_vrf_map_to_vrf_irt_nodes(struct bgp *bgp_vrf)
{
	struct bgp *bgp_evpn_mi;
	struct bgp_evpn_effective_wildcard_rt *eff_w;
	struct bgp_evpn_effective_fq_rt *eff_fq;

	bgp_evpn_mi = bgp_get_evpn_master_instance();
	if (!bgp_evpn_mi) {
		flog_err(EC_BGP_NO_DFLT,
			 "vrf map to irt nodes - evpn instance not created yet");
		return;
	}

	frr_each (bgp_evpn_effective_wildcard_rt_slu, &bgp_vrf->effective_wildcard_import_rts, eff_w) {

		struct vrf_wildcard_irt_node tmp_lookup_node;
		struct vrf_wildcard_irt_node *irt;
		struct vrf_mapped_bgp_instance *vrf_item;

		memset(&tmp_lookup_node, 0, sizeof(tmp_lookup_node));
		tmp_lookup_node.local_admin_nbo = eff_w->local_admin_nbo;

		irt = vrf_wildcard_irt_nodes_find(&bgp_evpn_mi->evpn_master_instance_info.vrf_wildcard_irt_nodes,&tmp_lookup_node);
		/* Create the node if it doesn't exist */
		if (!irt) {
			irt = vrf_wildcard_irt_node_new(eff_w->local_admin_nbo);
			vrf_wildcard_irt_nodes_add(&bgp_evpn_mi->evpn_master_instance_info.vrf_wildcard_irt_nodes,irt);
		}


		vrf_item = vrf_mapped_bgp_instance_new(bgp_vrf);
		/* Skip the extra "is already present" check - try to insert right away
		 * and if it fails, it means it's already present and we can just free the newly allocated item
		 */
		if(vrf_mapped_bgp_instance_slu_add(&irt->vrfs, vrf_item) != NULL)
			/* Already mapped, free the newly allocated item */
			vrf_mapped_bgp_instance_free(vrf_item);
	}

	frr_each (bgp_evpn_effective_fq_rt_slu,&bgp_vrf->effective_fq_import_rts, eff_fq) {
		struct vrf_fq_irt_node tmp_lookup_node;
		struct vrf_fq_irt_node *irt;
		struct vrf_mapped_bgp_instance *vrf_item;

		memset(&tmp_lookup_node, 0, sizeof(tmp_lookup_node));
		memcpy(&tmp_lookup_node.rt, &eff_fq->ecom_val, sizeof(tmp_lookup_node.rt));

		irt = vrf_fq_irt_nodes_find(&bgp_evpn_mi->evpn_master_instance_info.vrf_fq_irt_nodes,&tmp_lookup_node);
		/* Create the node if it doesn't exist */
		if (!irt) {
			irt = vrf_fq_irt_node_new(eff_fq->ecom_val);
			vrf_fq_irt_nodes_add(&bgp_evpn_mi->evpn_master_instance_info.vrf_fq_irt_nodes,irt);
		}

		vrf_item = vrf_mapped_bgp_instance_new(bgp_vrf);

		/* Skip the extra "is already present" check - try to insert right away
		 * and if it fails, it means it's already present and we can just free the newly allocated item
		 */
		if(vrf_mapped_bgp_instance_slu_add(&irt->vrfs, vrf_item) != NULL)
			/* Already mapped, free the newly allocated item */
			vrf_mapped_bgp_instance_free(vrf_item);
		
	}
}

/*
 * Unmap the VRF from all vrf_irt_nodes corresponding to its effective import RTs.
 * Deletes IRT nodes that become empty.
 */
void bgp_evpn_vrf_unmap_from_vrf_irt_nodes(struct bgp *bgp_vrf)
{
	struct bgp *bgp_evpn_mi;
	struct bgp_evpn_effective_wildcard_rt *eff_w;
	struct bgp_evpn_effective_fq_rt *eff_fq;

	bgp_evpn_mi = bgp_get_evpn_master_instance();
	if (!bgp_evpn_mi) {
		flog_err(EC_BGP_NO_DFLT,
			 "vrf unmap from irt nodes - evpn instance not created yet");
		return;
	}

	frr_each (bgp_evpn_effective_wildcard_rt_slu,&bgp_vrf->effective_wildcard_import_rts, eff_w) {
		struct vrf_wildcard_irt_node tmp_lookup_node;
		struct vrf_wildcard_irt_node *irt;
		struct vrf_mapped_bgp_instance tmp_vrf;
		struct vrf_mapped_bgp_instance *vrf_item;

		memset(&tmp_lookup_node, 0, sizeof(tmp_lookup_node));
		tmp_lookup_node.local_admin_nbo = eff_w->local_admin_nbo;

		irt = vrf_wildcard_irt_nodes_find(&bgp_evpn_mi->evpn_master_instance_info.vrf_wildcard_irt_nodes,&tmp_lookup_node);
		if (!irt)
			continue; /* Node does not exist, nothing to do */

		tmp_vrf.bgp = bgp_vrf;
		vrf_item = vrf_mapped_bgp_instance_slu_find(&irt->vrfs, &tmp_vrf);
		if (!vrf_item)
			continue; /* VRF not mapped to this IRT node*/

		vrf_mapped_bgp_instance_slu_del(&irt->vrfs, vrf_item);
		vrf_mapped_bgp_instance_free(vrf_item);

		/* if the node doesn't hold any other mapped VRFs, delete it */
		if (vrf_mapped_bgp_instance_slu_count(&irt->vrfs) == 0) {
			vrf_wildcard_irt_nodes_del(&bgp_evpn_mi->evpn_master_instance_info.vrf_wildcard_irt_nodes,irt);
			vrf_wildcard_irt_node_free(irt);
		}
	}

	frr_each (bgp_evpn_effective_fq_rt_slu,&bgp_vrf->effective_fq_import_rts, eff_fq) {
		struct vrf_fq_irt_node tmp_lookup_node;
		struct vrf_fq_irt_node *irt;
		struct vrf_mapped_bgp_instance tmp_vrf;
		struct vrf_mapped_bgp_instance *vrf_item;

		memset(&tmp_lookup_node, 0, sizeof(tmp_lookup_node));
		memcpy(&tmp_lookup_node.rt, &eff_fq->ecom_val, sizeof(tmp_lookup_node.rt));

		irt = vrf_fq_irt_nodes_find(&bgp_evpn_mi->evpn_master_instance_info.vrf_fq_irt_nodes,&tmp_lookup_node);
		if (!irt)
			continue; /* Node does not exist, nothing to do */

		tmp_vrf.bgp = bgp_vrf;
		vrf_item = vrf_mapped_bgp_instance_slu_find(&irt->vrfs, &tmp_vrf);
		if (!vrf_item)
			continue; /* VRF not mapped to this IRT node*/

		vrf_mapped_bgp_instance_slu_del(&irt->vrfs, vrf_item);
		vrf_mapped_bgp_instance_free(vrf_item);

		/* if the node doesn't hold any other mapped VRFs, delete it */
		if (vrf_mapped_bgp_instance_slu_count(&irt->vrfs) == 0) {
			vrf_fq_irt_nodes_del(&bgp_evpn_mi->evpn_master_instance_info.vrf_fq_irt_nodes,irt);
			vrf_fq_irt_node_free(irt);
		}
	}
}

/*
 * Map the RTs (configured or automatically derived) of a VNI to the VNI.
 * The mapping will be used during route processing.
 */
void bgp_evpn_map_vni_to_its_rts(struct bgp *bgp, struct bgp_evpn_evi *evi)
{
	uint32_t i;
	struct ecommunity_val *eval;
	struct listnode *node, *nnode;
	struct ecommunity *ecom;

	for (ALL_LIST_ELEMENTS(evi->evi_import_rtl, node, nnode, ecom)) {
		for (i = 0; i < ecom->size; i++) {
			eval = (struct ecommunity_val *)(ecom->val
							 + (i
							    * ECOMMUNITY_SIZE));
			bgp_evpn_evi_map_to_evi_irt_nodes(bgp, evi, eval);
		}
	}
}

/*
 * Unmap the RTs (configured or automatically derived) of a VNI from the VNI.
 */
void bgp_evpn_unmap_vni_from_its_rts(struct bgp *bgp, struct bgp_evpn_evi *evi)
{
	uint32_t i;
	struct ecommunity_val *eval;
	struct listnode *node, *nnode;
	struct ecommunity *ecom;

	for (ALL_LIST_ELEMENTS(evi->evi_import_rtl, node, nnode, ecom)) {
		for (i = 0; i < ecom->size; i++) {
			struct evi_irt_node *irt;
			struct ecommunity_val eval_tmp;

			eval = (struct ecommunity_val *)(ecom->val
							 + (i
							    * ECOMMUNITY_SIZE));
			/* If using "automatic" RT, we only care about the
			 * local-admin sub-field.
			 * This is to facilitate using VNI as the RT for EBGP
			 * peering too.
			 */
			memcpy(&eval_tmp, eval, ECOMMUNITY_SIZE);
			if (!is_import_rt_configured(evi))
				mask_ecom_global_admin(&eval_tmp, eval);

			irt = lookup_evi_irt_node(bgp, &eval_tmp);
			if (irt)
				bgp_evpn_evi_unmap_from_evi_irt_nodes(bgp, evi, irt);
		}
	}
}

/*
 * Derive Import RT automatically for VNI and map VNI to RT.
 * The mapping will be used during route processing.
 */
void legacy_bgp_evpn_evi_derive_import_auto_rt(struct bgp *bgp, struct bgp_evpn_evi *evi)
{
	bgp_evpn_evi_form_auto_rt(bgp, evi->vni, evi->evi_import_rtl);
	UNSET_FLAG(evi->flags, EVI_FLAG_IMPRT_CFGD);

	/* Map RT to VNI */
	bgp_evpn_map_vni_to_its_rts(bgp, evi);
}

/*
 * Derive Export RT automatically for VNI.
 */
void legacy_bgp_evpn_evi_derive_export_auto_rt(struct bgp *bgp, struct bgp_evpn_evi *evi)
{
	bgp_evpn_evi_form_auto_rt(bgp, evi->vni, evi->evi_export_rtl);
	UNSET_FLAG(evi->flags, EVI_FLAG_EXPRT_CFGD);
}

static void bgp_evpn_rt_list_remove_by_ecom(struct list *rt_list, struct ecommunity *ecomdel)
{
	struct listnode *node = NULL, *nnode = NULL, *node_to_del = NULL;
	struct ecommunity *ecom = NULL;

	for (ALL_LIST_ELEMENTS(rt_list, node, nnode, ecom)) {
		if (ecommunity_match(ecom, ecomdel)) {
			ecommunity_free(&ecom);
			node_to_del = node;
			break;
		}
	}

	if (node_to_del)
		list_delete_node(rt_list, node_to_del);
}

void bgp_evpn_evi_delete_auto_rt(struct bgp *bgp, vni_t vni, struct list *rtl)
{
	struct ecommunity *ecom_auto;
	struct ecommunity_val eval;

	if (bgp->evpn_autort_rfc8365_compatible)
		SET_FLAG(vni, BGP_EVPN_RT_RFC8365_A_BIT);

	encode_route_target_as((bgp->as & 0xFFFF), vni, &eval, true);

	ecom_auto = ecommunity_new();
	ecommunity_add_val(ecom_auto, &eval, false, false);

	bgp_evpn_rt_list_remove_by_ecom(rtl, ecom_auto);

	ecommunity_free(&ecom_auto);
}

/*
 * Map the VRF to the applicable vrf_irt_nodes and then import / install
 * all applicable routes
 * You should be able to call this function multiple times without issues
 * (just no guarantee that the results or the routing tables makes sense then :) )
 * Sorry, I couldn't find a nicer name for this function
 */
void bgp_evpn_vrf_setup_import(struct bgp *bgp_vrf)
{

	/*
	 * First setup the mapping to vrf_irt_nodes (which is the actual data
	 * structure used in the import process, specifically by bgp_evpn_vrf_check_route_matches_import_rts)
	 * THEN import / install routes.
	 */
	/*if (is_l3vni_live(bgp_vrf)) {*/
		bgp_evpn_vrf_map_to_vrf_irt_nodes(bgp_vrf);
		bgp_evpn_vrf_install_global_routes(bgp_vrf);
	/*}*/
}

/*
 * Uninstall all routes from the VRF and then
 * unmap the VRF from all vrf_irt_nodes corresponding to the VRF RTs
 * !! Call BEFORE you modify the effective import route targets!!
 * Sorry, I couldn't find a nicer name for this function
 */
void bgp_evpn_vrf_teardown_import(struct bgp *bgp_vrf)
{
	/*
	 * First uninstall the routes (this process uses vrf_irt_nodes
	 * specifically in bgp_evpn_vrf_check_route_matches_import_rts)
	 * THEN destroy the mapping to the vrf_irt_nodes
	 */
	/* uninstall routes from vrf */
	/*if (is_l3vni_live(bgp_vrf))*/
		bgp_evpn_vrf_uninstall_global_routes(bgp_vrf);

	/* Cleanup the RT to VRF mapping in any case for robustness */
	bgp_evpn_vrf_unmap_from_vrf_irt_nodes(bgp_vrf);
}

/* Unified function for configuring manual route targets, meant to be called by VTY
 * Will call the appropriate bgp_evpn_vrf_handle_..._rt_change functions
 *
 * For direction "both", it will err if the route target already exists in "both"
 * and if not, it will override / remove any import / export statements with the same route target if present
 * !!!General rule: "both" cannot coexist with "import" or "export" statements for the same route target!!!
 *
 * For direction "import" or "export", it will err if the route target already exists as "both"
 * or explicitly configured with the respective direction
 * will NOT split up "both" statements into "import" an "export" - there is no real use case for that
 * and if the user REALLY wants that, they have to do "no both" and then import + export..
 *
 * Note that there is NO auto merge of "import" + "export" to "both"!
 * "both" is only placed in the config if function is called with direction "both"!
 *
 * Note that this function does NOT optimize the path when an implicit RT is active and the
 * user configures this RT manually - full change handling logic will be called!
 *
 * Takes ownership of cfgd_rt and will always free, even in case of error
 */
int bgp_evpn_vrf_configure_rt_manual(struct bgp *bgp_vrf,
				     enum bgp_evpn_rt_direction direction,
				     struct bgp_evpn_cfgd_rt *cfgd_rt)
{
	bool import_changed = false;
	bool export_changed = false;

	/* This logic could perhaps be simplified once insert hints for sorted lists exist?
	 * because we always need to check whether the RT already exists in the "both" list, but
	 * in the "both" case we also need to insert and I don't want "check if exists" + "insert"
	 * With insert hint we could perhaps try to find (check whether exists) and reuse that?
	 */

	/* Wildcard import route targets are not allowed for export -> deny export and both -> only allow import! */
	if(cfgd_rt->type == BGP_EVPN_CFGD_RT_TYPE_WILDCARD && direction != BGP_EVPN_RT_DIRECTION_IMPORT)  {
		bgp_evpn_cfgd_rt_free(cfgd_rt);
		return -1;
	}

	/* "both" overrides any existing "import" or "export" statements - we don't want those to coexist
	 * because that just doesn't make sense and can make the config difficult to understand
	 */
	if (direction == BGP_EVPN_RT_DIRECTION_BOTH) {
		/* Safe the extra "does exist" step, insert right away - if it fails, it was already present */
		if (bgp_evpn_cfgd_rt_slu_add(&bgp_vrf->vrf_route_target_config->cfgd_both,cfgd_rt) != NULL) {
			bgp_evpn_cfgd_rt_free(cfgd_rt);
			return -1; /* Already present as "both" -> abort */
		}
		/* Assume both changed, may be set to false in next step */
		import_changed = true;
		export_changed = true;

		/* "both" cannot coexist with import or export - delete those if exists */
		struct bgp_evpn_cfgd_rt * found_rt;

		found_rt = bgp_evpn_cfgd_rt_slu_find(&bgp_vrf->vrf_route_target_config->cfgd_import, cfgd_rt);
		if (found_rt) {
			import_changed = false; /* RT was already in import -> no change -> no need to trigger update */
			bgp_evpn_cfgd_rt_slu_del(&bgp_vrf->vrf_route_target_config->cfgd_import,found_rt);
			bgp_evpn_cfgd_rt_free(found_rt);
		}

		found_rt = bgp_evpn_cfgd_rt_slu_find(&bgp_vrf->vrf_route_target_config->cfgd_export,cfgd_rt);
		if (found_rt) {
			export_changed = false; /* RT was already in export -> no change -> no need to trigger update */
			bgp_evpn_cfgd_rt_slu_del(&bgp_vrf->vrf_route_target_config->cfgd_export,found_rt);
			bgp_evpn_cfgd_rt_free(found_rt);
		}
	} else {
		/* Branch for import or export - the logic is pretty much identical, just on different lists */
		struct bgp_evpn_cfgd_rt_slu_head* relevant_list;
		bool* relevant_changed_flag;
		if (direction == BGP_EVPN_RT_DIRECTION_IMPORT) {
			relevant_list = &bgp_vrf->vrf_route_target_config->cfgd_import;
			relevant_changed_flag = &import_changed;
		} else { /* BGP_EVPN_RT_DIRECTION_EXPORT */
			relevant_list = &bgp_vrf->vrf_route_target_config->cfgd_export;
			relevant_changed_flag = &export_changed;
		}

		/* Check whether the route target already exists in the "both" list, if yes, abort */
		if(bgp_evpn_cfgd_rt_slu_find(&bgp_vrf->vrf_route_target_config->cfgd_both, cfgd_rt)) {
			bgp_evpn_cfgd_rt_free(cfgd_rt);
			return -1; /* RT already exists as "both", abort */
		}

		/* Skip the extra "does exist" / ..._find step and insert into the relevant list right away
		 * if a duplicate exists, the _add function will fail and return non-null
		 */
		if (bgp_evpn_cfgd_rt_slu_add(relevant_list, cfgd_rt) != NULL) {
			bgp_evpn_cfgd_rt_free(cfgd_rt);
			return -1; /* RT already exists in relevant list, abort */
		}

		*relevant_changed_flag = true; /* RT was newly added to relevant list -> change happened -> need to trigger update */
	}

	/* Trigger update logic if necessary */
	if(import_changed)
		bgp_evpn_vrf_handle_import_rt_change(bgp_vrf);
	if(export_changed)
		bgp_evpn_vrf_handle_export_rt_change(bgp_vrf);

	return 0;
}

/* Unified function for de-configuring manual route targets, meant to be called by VTY
 * Will call the appropriate bgp_evpn_vrf_handle_..._rt_change functions
 *
 * For direction "both", it will err if the route target does not exist in "both"
 *
 * For direction "import" or "export", a "both" statement will be split up into "import" and "export"
 * if the route target exists as "both" and the user tries to deconfigure it as "import" or "export"
 * Function will err if it exists neither as "both" nor in the relevant direction list
 *
 * Note that this function does NOT optimize the path when an explicit RT is active, the user
 * deconfigures it and the implicit RT with the same value kicks in - full change handling logic will be called!
 *
 * Takes ownership of cfgd_rt and will always free, even in case of error
 */
int bgp_evpn_vrf_unconfigure_rt_manual(struct bgp *bgp_vrf,
				       enum bgp_evpn_rt_direction direction,
				       struct bgp_evpn_cfgd_rt *to_delete)
{
	bool import_changed = false;
	bool export_changed = false;

	/* No need to check for "Wildcard only for direction import" here
	 * The user shouldn't be able to configure wildcard RTs for any other direction than import in the first place
	 * so it's only in our interest to let them remove anything that shouldn't have been configured anyway
	 */

	if (direction == BGP_EVPN_RT_DIRECTION_BOTH) {
		/* Check if the route target exists in the "both" configuration */
		struct bgp_evpn_cfgd_rt* found_rt;
		found_rt = bgp_evpn_cfgd_rt_slu_find(&bgp_vrf->vrf_route_target_config->cfgd_both, to_delete);
		bgp_evpn_cfgd_rt_free(to_delete);

		if(!found_rt) {
			return -1; /* RT doesn't exist as "both", nothing to unconfigure */
		}

		/* Remove from "both" list */
		bgp_evpn_cfgd_rt_slu_del(&bgp_vrf->vrf_route_target_config->cfgd_both, found_rt);
		bgp_evpn_cfgd_rt_free(found_rt);

		import_changed = true;
		export_changed = true;
	} else {
		/* Branch for import or export - the logic is pretty much identical, just on different lists */
		struct bgp_evpn_cfgd_rt_slu_head* relevant_list;
		struct bgp_evpn_cfgd_rt_slu_head* other_list;
		bool* relevant_changed_flag;

		if (direction == BGP_EVPN_RT_DIRECTION_IMPORT) {
			relevant_list = &bgp_vrf->vrf_route_target_config->cfgd_import;
			other_list = &bgp_vrf->vrf_route_target_config->cfgd_export;
			relevant_changed_flag = &import_changed;
		} else { /* BGP_EVPN_RT_DIRECTION_EXPORT */
			relevant_list = &bgp_vrf->vrf_route_target_config->cfgd_export;
			other_list = &bgp_vrf->vrf_route_target_config->cfgd_import;
			relevant_changed_flag = &export_changed;
		}

		/* Note that if one branch is hit, the other one should NOT be hit - but we perform both checks for robustness */

		/* Check if the route target exists in the "both" configuration
		 * (shouldn't be configured as "import" or "export" in that case!)
		 * if yes: split up the "both" statement
		 */
		struct bgp_evpn_cfgd_rt* found_rt;
		found_rt = bgp_evpn_cfgd_rt_slu_find(&bgp_vrf->vrf_route_target_config->cfgd_both, to_delete);
		if(found_rt) {
			/* Route-Target to deconfigure is configured as "both" -> Split it up */
			*relevant_changed_flag = true;

			/* Extract / Remove from "both" list */
			bgp_evpn_cfgd_rt_slu_del(&bgp_vrf->vrf_route_target_config->cfgd_both, found_rt);
			/* And move the node into the other list */
			bgp_evpn_cfgd_rt_slu_add(other_list, found_rt);
		}

		/* Check if RT exists in the relevant list ("both" shouldn't be configured in that case!) */
		found_rt = bgp_evpn_cfgd_rt_slu_find(relevant_list, to_delete);
		if(found_rt) {
			/* Route-Target to deconfigure is configured in relevant list */
			*relevant_changed_flag = true;

			/* Simply delete it */
			bgp_evpn_cfgd_rt_slu_del(relevant_list, found_rt);
			bgp_evpn_cfgd_rt_free(found_rt);
		}
		bgp_evpn_cfgd_rt_free(to_delete);

		if(!*relevant_changed_flag) {
			return -1; /* RT doesn't exist, nothing to unconfigure */
		}
	}

	if(import_changed)
		bgp_evpn_vrf_handle_import_rt_change(bgp_vrf);
	if(export_changed)
		bgp_evpn_vrf_handle_export_rt_change(bgp_vrf);

	return 0;
}

/* Unified configure / unconfigure auto-RT, meant to be called by VTY
 * Note that for auto-RTs we don't have an "unconfigure" function, because auto-RT is an enum
 * For VTY "no route-target <both/import/export> auto", call this function with "BGP_EVPN_AUTORT_NOT_CFGD"
 *
 * The behaviour is pretty much the same as for manual RTs:
 *  - Call with dir both and cfg != BGP_EVPN_AUTORT_NOT_CFGD will override both "import" and "export" and cannot coexist with them.
 *  - Call with dir both and cfg == BGP_EVPN_AUTORT_NOT_CFGD will only work if "both" != BGP_EVPN_AUTORT_NOT_CFGD!
 *  - Call with dir import/export and cfg != BGP_EVPN_AUTORT_NOT_CFGD will override the respective direction and split up "both"
 *  - Call with dir import/export and cfg == BGP_EVPN_AUTORT_NOT_CFGD will override the respective direction and split up "both"
 *
 * This function should implicitly optimize the case when implicit RT is active and the user explicitly requests auto RT generation
 * or auto RT is not active and user requests explicitly auto rt disable
 */
int bgp_evpn_vrf_configure_auto_rt(struct bgp *bgp_vrf,
				   enum bgp_evpn_rt_direction direction,
				   enum bgp_evpn_autort_cfgd cfg)
{
	bool import_auto_rt_active_before = bgp_evpn_vrf_should_generate_import_autort(bgp_vrf);
	bool export_auto_rt_active_before = bgp_evpn_vrf_should_generate_export_autort(bgp_vrf);

	if (direction == BGP_EVPN_RT_DIRECTION_BOTH) {
		if(cfg == bgp_vrf->vrf_route_target_config->autort_cfgd_both)
			return -1; /* No config change, abort */

		/* don't bother with "change detection" / "do we have to call bgp_evpn_vrf_handle_<import/export>_rt_change"
		 * here, that logic would become a bit tricky and lengthy (particular with implicit auto RT...)
		 * we rely on bgp_evpn_vrf_should_generate_<import/export>_autort
		 * if that changed after we changed the config, we need to call the change handlers
		 */

		/* regardless of "both" new value, both import and export will be set to BGP_EVPN_AUTORT_NOT_CFGD
		 * either both was != BGP_EVPN_AUTORT_NOT_CFGD -> import and export (should be) NOT_CFGD -> no change
		 * or both was == BGP_EVPN_AUTORT_NOT_CFGD -> import and export should be removed because "both" cannot coexist with "import" or "export"
		 */
		bgp_vrf->vrf_route_target_config->autort_cfgd_import = BGP_EVPN_AUTORT_NOT_CFGD;
		bgp_vrf->vrf_route_target_config->autort_cfgd_export = BGP_EVPN_AUTORT_NOT_CFGD;

		bgp_vrf->vrf_route_target_config->autort_cfgd_both = cfg;

	} else {
		/* simplify the logic by just looking at the current effective state - if the effective state changes,
		 * we are good, otherwise err out because there is no actual change
		 */
		enum bgp_evpn_autort_cfgd* relevant_cfgd_var;
		enum bgp_evpn_autort_cfgd* other_cfgd_var;
		if(direction == BGP_EVPN_RT_DIRECTION_IMPORT) {
			relevant_cfgd_var = &bgp_vrf->vrf_route_target_config->autort_cfgd_import;
			other_cfgd_var = &bgp_vrf->vrf_route_target_config->autort_cfgd_export;
		} else { /* BGP_EVPN_RT_DIRECTION_EXPORT */
			relevant_cfgd_var = &bgp_vrf->vrf_route_target_config->autort_cfgd_export;
			other_cfgd_var = &bgp_vrf->vrf_route_target_config->autort_cfgd_import;
		}
		enum bgp_evpn_autort_cfgd current_effective_state;
		/* if "both" is configured, it takes precedence (in that case, import and export should both be NOT_CFGD!)*/
		if(bgp_vrf->vrf_route_target_config->autort_cfgd_both != BGP_EVPN_AUTORT_NOT_CFGD) {
			current_effective_state = bgp_vrf->vrf_route_target_config->autort_cfgd_both;
		} else {
			current_effective_state = *relevant_cfgd_var; /* both is not configured -> use the specific direction */
		}

		if(cfg == current_effective_state)
			return -1; /* No config change, abort */

		/* split up both if it's configured */
		if(bgp_vrf->vrf_route_target_config->autort_cfgd_both != BGP_EVPN_AUTORT_NOT_CFGD) {
			*other_cfgd_var = bgp_vrf->vrf_route_target_config->autort_cfgd_both;
			bgp_vrf->vrf_route_target_config->autort_cfgd_both = BGP_EVPN_AUTORT_NOT_CFGD;
		}
		/* both is always NOT_CFGD now */
		*relevant_cfgd_var = cfg;
	}
	bool import_rt_active_after = bgp_evpn_vrf_should_generate_import_autort(bgp_vrf);
	bool export_rt_active_after = bgp_evpn_vrf_should_generate_export_autort(bgp_vrf);

	if(import_auto_rt_active_before != import_rt_active_after)
		bgp_evpn_vrf_handle_import_rt_change(bgp_vrf);
	if(export_auto_rt_active_before != export_rt_active_after)
		bgp_evpn_vrf_handle_export_rt_change(bgp_vrf);

	return 0;
}

int bgp_evpn_vrf_configure_both_rt_manual(struct bgp *bgp_vrf, struct bgp_evpn_cfgd_rt* cfgd_rt)
{
	return bgp_evpn_vrf_configure_rt_manual(bgp_vrf, BGP_EVPN_RT_DIRECTION_BOTH, cfgd_rt);
}
int bgp_evpn_vrf_configure_both_auto_rt(struct bgp *bgp_vrf, enum bgp_evpn_autort_cfgd cfg)
{
	return bgp_evpn_vrf_configure_auto_rt(bgp_vrf, BGP_EVPN_RT_DIRECTION_BOTH, cfg);
}

int bgp_evpn_vrf_configure_import_rt_manual(struct bgp *bgp_vrf, struct bgp_evpn_cfgd_rt* cfgd_rt)
{
	return bgp_evpn_vrf_configure_rt_manual(bgp_vrf, BGP_EVPN_RT_DIRECTION_IMPORT, cfgd_rt);
}
int bgp_evpn_vrf_configure_import_auto_rt(struct bgp *bgp_vrf, enum bgp_evpn_autort_cfgd cfg)
{
	return bgp_evpn_vrf_configure_auto_rt(bgp_vrf, BGP_EVPN_RT_DIRECTION_IMPORT, cfg);
}

int bgp_evpn_vrf_configure_export_rt_manual(struct bgp *bgp_vrf, struct bgp_evpn_cfgd_rt* cfgd_rt)
{
	return bgp_evpn_vrf_configure_rt_manual(bgp_vrf, BGP_EVPN_RT_DIRECTION_EXPORT, cfgd_rt);
}

int bgp_evpn_vrf_configure_export_auto_rt(struct bgp *bgp_vrf, enum bgp_evpn_autort_cfgd cfg)
{
	return bgp_evpn_vrf_configure_auto_rt(bgp_vrf, BGP_EVPN_RT_DIRECTION_EXPORT, cfg);
}

int bgp_evpn_vrf_unconfigure_both_rt_manual(struct bgp *bgp_vrf, struct bgp_evpn_cfgd_rt* to_delete)
{
	return bgp_evpn_vrf_unconfigure_rt_manual(bgp_vrf, BGP_EVPN_RT_DIRECTION_BOTH, to_delete);
}

int bgp_evpn_vrf_unconfigure_import_rt_manual(struct bgp *bgp_vrf, struct bgp_evpn_cfgd_rt* to_delete)
{
	return bgp_evpn_vrf_unconfigure_rt_manual(bgp_vrf, BGP_EVPN_RT_DIRECTION_IMPORT, to_delete);
}

int bgp_evpn_vrf_unconfigure_export_rt_manual(struct bgp *bgp_vrf, struct bgp_evpn_cfgd_rt* to_delete)
{
	return bgp_evpn_vrf_unconfigure_rt_manual(bgp_vrf, BGP_EVPN_RT_DIRECTION_EXPORT, to_delete);
}






/* Flag if the route is injectable into EVPN.
 * This would be following category:
 * Non-imported route,
 * Non-EVPN imported route,
 */
bool is_route_injectable_into_evpn_non_supp(struct bgp_path_info *pi)
{
	struct bgp_path_info *parent_pi;
	struct bgp_table *table;
	struct bgp_dest *dest;

	if (pi->sub_type != BGP_ROUTE_IMPORTED || !pi->extra ||
	    !pi->extra->vrfleak || !pi->extra->vrfleak->parent)
		return true;

        parent_pi = (struct bgp_path_info *)pi->extra->vrfleak->parent;
        dest = parent_pi->net;
        if (!dest)
		return true;
        table = bgp_dest_table(dest);
        if (table &&
            table->afi == AFI_L2VPN &&
            table->safi == SAFI_EVPN)
                return false;

        return true;
}

/* Flag if the route is injectable into EVPN.
 * This would be following category:
 * Non-imported route,
 * Non-EVPN imported route,
 * Non Aggregate suppressed route.
 */
bool is_route_injectable_into_evpn(struct bgp_path_info *pi)
{
	/* do not import aggr suppressed routes */
	if (bgp_path_suppressed(pi)) {
		frrtrace(2, frr_bgp, evpn_ignore_suppress_route, pi->net, pi->peer);
		return false;
	}

	return is_route_injectable_into_evpn_non_supp(pi);
}


static void bgp_evpn_get_rmac_nexthop(struct bgp_evpn_evi *evi,
				      const struct prefix_evpn *p,
				      struct attr *attr, uint8_t flags)
{
	struct bgp *bgp_vrf = evi->bgp_vrf;

	memset(&attr->rmac, 0, sizeof(struct ethaddr));
	if (!bgp_vrf)
		return;

	if (p->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE)
		return;

	/* Copy sys (pip) RMAC and PIP IP as nexthop
	 * in case of route is self MAC-IP,
	 * advertise-pip and advertise-svi-ip features
	 * are enabled.
	 * Otherwise, for all host MAC-IP route's
	 * copy anycast RMAC.
	 */
	if (CHECK_FLAG(flags, BGP_EVPN_MACIP_TYPE_SVI_IP)
	    && bgp_vrf->evpn_info->advertise_pip &&
	    bgp_vrf->evpn_info->is_anycast_mac) {
		/* copy sys rmac */
		memcpy(&attr->rmac, &bgp_vrf->evpn_info->pip_rmac,
		       ETH_ALEN);
		attr->nexthop = bgp_vrf->evpn_info->pip_ip.ipaddr_v4;
		attr->mp_nexthop_global_in = bgp_vrf->evpn_info->pip_ip.ipaddr_v4;
	} else
		memcpy(&attr->rmac, &bgp_vrf->rmac, ETH_ALEN);
}

/*
 * Derive RD and RT for a VNI automatically. Invoked at the time of
 * creation of a VNI.
 */
static void bgp_evpn_evi_derive_rd_rt(struct bgp *bgp, struct bgp_evpn_evi *evi)
{
	bgp_evpn_evi_derive_auto_rd(bgp, evi);
	legacy_bgp_evpn_evi_derive_import_auto_rt(bgp, evi);
	legacy_bgp_evpn_evi_derive_export_auto_rt(bgp, evi);
}

/*
 * Convert nexthop (remote VTEP IP) into an IPv6 address.
 */
static void evpn_convert_nexthop_to_ipv6(struct attr *attr)
{
	if (BGP_ATTR_NEXTHOP_AFI_IP6(attr))
		return;
	ipv4_to_ipv4_mapped_ipv6(&attr->mp_nexthop_global, attr->nexthop);
	attr->mp_nexthop_len = IPV6_MAX_BYTELEN;
}

/*
 * Wrapper for node get in global table.
 */
struct bgp_dest *bgp_evpn_global_node_get(struct bgp_table *table, afi_t afi,
					  safi_t safi,
					  const struct prefix_evpn *evp,
					  struct prefix_rd *prd,
					  const struct bgp_path_info *local_pi)
{
	struct prefix_evpn global_p = {};

	if (evp->prefix.route_type == BGP_EVPN_AD_ROUTE) {
		/* prefix in the global table doesn't include the VTEP-IP so
		 * we need to create a different copy of the prefix
		 */
		evpn_type1_prefix_global_copy(&global_p, evp);
		evp = &global_p;
	} else if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE &&
		   local_pi) {
		/*
		 * prefix in the global table needs MAC/IP, ensure they are
		 * present, using one's from local table's path_info.
		 */
		if (is_evpn_prefix_ipaddr_none(evp)) {
			/* VNI MAC -> Global */
			evpn_type2_prefix_global_copy(
				&global_p, evp, NULL /* mac */,
				evpn_type2_path_info_get_ip(local_pi));
		} else {
			/* VNI IP -> Global */
			evpn_type2_prefix_global_copy(
				&global_p, evp,
				evpn_type2_path_info_get_mac(local_pi),
				NULL /* ip */);
		}

		evp = &global_p;
	}
	return bgp_afi_node_get(table, afi, safi, (struct prefix *)evp, prd);
}

/*
 * Wrapper for node lookup in global table.
 */
struct bgp_dest *bgp_evpn_global_node_lookup(
	struct bgp_table *table, safi_t safi, const struct prefix_evpn *evp,
	struct prefix_rd *prd, const struct bgp_path_info *local_pi)
{
	struct prefix_evpn global_p = {};

	if (evp->prefix.route_type == BGP_EVPN_AD_ROUTE) {
		/* prefix in the global table doesn't include the VTEP-IP so
		 * we need to create a different copy of the prefix
		 */
		evpn_type1_prefix_global_copy(&global_p, evp);
		evp = &global_p;
	} else if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE &&
		   local_pi) {
		/*
		 * prefix in the global table needs MAC/IP, ensure they are
		 * present, using one's from local table's path_info.
		 */
		if (is_evpn_prefix_ipaddr_none(evp)) {
			/* VNI MAC -> Global */
			evpn_type2_prefix_global_copy(
				&global_p, evp, NULL /* mac */,
				evpn_type2_path_info_get_ip(local_pi));
		} else {
			/* VNI IP -> Global */
			evpn_type2_prefix_global_copy(
				&global_p, evp,
				evpn_type2_path_info_get_mac(local_pi),
				NULL /* ip */);
		}

		evp = &global_p;
	}
	return bgp_safi_node_lookup(table, safi, (struct prefix *)evp, prd);
}

/*
 * Wrapper for node get in VNI IP table.
 */
struct bgp_dest *bgp_evpn_vni_ip_node_get(struct bgp_table *const table,
					  const struct prefix_evpn *evp,
					  const struct bgp_path_info *parent_pi)
{
	struct prefix_evpn vni_p = {};

	if (evp->prefix.route_type == BGP_EVPN_AD_ROUTE && parent_pi) {
		/* prefix in the global table doesn't include the VTEP-IP so
		 * we need to create a different copy for the VNI
		 */
		evpn_type1_prefix_vni_ip_copy(&vni_p, evp, parent_pi->attr);
		evp = &vni_p;
	} else if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) {
		/* Only MAC-IP should go into this table, not mac-only */
		assert(is_evpn_prefix_ipaddr_none(evp) == false);

		/*
		 * prefix in the vni IP table doesn't include MAC so
		 * we need to create a different copy of the prefix.
		 */
		evpn_type2_prefix_vni_ip_copy(&vni_p, evp);
		evp = &vni_p;
	}
	return bgp_node_get(table, (struct prefix *)evp);
}

/*
 * Wrapper for node lookup in VNI IP table.
 */
struct bgp_dest *
bgp_evpn_vni_ip_node_lookup(const struct bgp_table *const table,
			    const struct prefix_evpn *evp,
			    const struct bgp_path_info *parent_pi)
{
	struct prefix_evpn vni_p = {};

	if (evp->prefix.route_type == BGP_EVPN_AD_ROUTE && parent_pi) {
		/* prefix in the global table doesn't include the VTEP-IP so
		 * we need to create a different copy for the VNI
		 */
		evpn_type1_prefix_vni_ip_copy(&vni_p, evp, parent_pi->attr);
		evp = &vni_p;
	} else if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) {
		/* Only MAC-IP should go into this table, not mac-only */
		assert(is_evpn_prefix_ipaddr_none(evp) == false);

		/*
		 * prefix in the vni IP table doesn't include MAC so
		 * we need to create a different copy of the prefix.
		 */
		evpn_type2_prefix_vni_ip_copy(&vni_p, evp);
		evp = &vni_p;
	}
	return bgp_node_lookup(table, (struct prefix *)evp);
}

/*
 * Wrapper for node get in VNI MAC table.
 */
struct bgp_dest *
bgp_evpn_vni_mac_node_get(struct bgp_table *const table,
			  const struct prefix_evpn *evp,
			  const struct bgp_path_info *parent_pi)
{
	struct prefix_evpn vni_p = {};

	/* Only type-2 should ever go into this table */
	assert(evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE);

	/*
	 * prefix in the vni MAC table doesn't include IP so
	 * we need to create a different copy of the prefix.
	 */
	evpn_type2_prefix_vni_mac_copy(&vni_p, evp);
	evp = &vni_p;
	return bgp_node_get(table, (struct prefix *)evp);
}

/*
 * Wrapper for node lookup in VNI MAC table.
 */
struct bgp_dest *
bgp_evpn_vni_mac_node_lookup(const struct bgp_table *const table,
			     const struct prefix_evpn *evp,
			     const struct bgp_path_info *parent_pi)
{
	struct prefix_evpn vni_p = {};

	/* Only type-2 should ever go into this table */
	assert(evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE);

	/*
	 * prefix in the vni MAC table doesn't include IP so
	 * we need to create a different copy of the prefix.
	 */
	evpn_type2_prefix_vni_mac_copy(&vni_p, evp);
	evp = &vni_p;
	return bgp_node_lookup(table, (struct prefix *)evp);
}

/*
 * Wrapper for node get in both VNI tables.
 */
struct bgp_dest *bgp_evpn_vni_node_get(struct bgp_evpn_evi *evi,
				       const struct prefix_evpn *p,
				       const struct bgp_path_info *parent_pi)
{
	if ((p->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) &&
	    (is_evpn_prefix_ipaddr_none(p) == true))
		return bgp_evpn_vni_mac_node_get(evi->mac_table, p, parent_pi);

	return bgp_evpn_vni_ip_node_get(evi->ip_table, p, parent_pi);
}

/*
 * Wrapper for node lookup in both VNI tables.
 */
struct bgp_dest *bgp_evpn_vni_node_lookup(const struct bgp_evpn_evi *evi,
					  const struct prefix_evpn *p,
					  const struct bgp_path_info *parent_pi)
{
	if ((p->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) &&
	    (is_evpn_prefix_ipaddr_none(p) == true))
		return bgp_evpn_vni_mac_node_lookup(evi->mac_table, p,
						    parent_pi);

	return bgp_evpn_vni_ip_node_lookup(evi->ip_table, p, parent_pi);
}

/*
 * Add (update) or delete MACIP from zebra.
 */
static enum zclient_send_status bgp_zebra_send_remote_macip(
	struct bgp *bgp, struct bgp_evpn_evi *evi, const struct prefix_evpn *p,
	const struct ethaddr *mac, struct ipaddr *remote_vtep_ip, int add,
	uint8_t flags, uint32_t seq, esi_t *esi)
{
	struct stream *s;
	uint16_t ipa_len;
	static struct ipaddr zero_remote_vtep_ip = { .ipa_type = IPADDR_V4, .ipaddr_v4 = { INADDR_ANY } };
	bool esi_valid;

	/* Check socket. */
	if (!bgp_zclient || bgp_zclient->sock < 0) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("%s: No zclient or zclient->sock exists",
				   __func__);
		return ZCLIENT_SEND_SUCCESS;
	}

	/* Don't try to register if Zebra doesn't know of this instance. */
	if (!IS_BGP_INST_KNOWN_TO_ZEBRA(bgp)) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug(
				"%s: No zebra instance to talk to, not installing remote macip",
				__func__);
		return ZCLIENT_SEND_SUCCESS;
	}

	if (!esi)
		esi = zero_esi;
	s = bgp_zclient->obuf;
	stream_reset(s);

	zclient_create_header(
		s, add ? ZEBRA_REMOTE_MACIP_ADD : ZEBRA_REMOTE_MACIP_DEL,
		bgp->vrf_id);
	stream_putl(s, evi ? evi->vni : 0);

	if (mac) /* Mac Addr */
		stream_put(s, &mac->octet, ETH_ALEN);
	else
		stream_put(s, &p->prefix.macip_addr.mac.octet, ETH_ALEN);

	/* IP address length and IP address, if any. */
	if (is_evpn_prefix_ipaddr_none(p))
		stream_putw(s, 0);
	else {
		ipa_len = is_evpn_prefix_ipaddr_v4(p) ? IPV4_MAX_BYTELEN
						      : IPV6_MAX_BYTELEN;
		stream_putw(s, ipa_len);
		stream_put(s, &p->prefix.macip_addr.ip.ip.addr, ipa_len);
	}
	/* If the ESI is valid that becomes the nexthop; tape out the
	 * VTEP-IP for that case
	 */
	if (bgp_evpn_is_esi_valid(esi)) {
		esi_valid = true;
		stream_put_ipaddr(s, &zero_remote_vtep_ip);
	} else {
		esi_valid = false;
		stream_put_ipaddr(s, remote_vtep_ip);
	}

	/* TX flags - MAC sticky status and/or gateway mac */
	/* Also TX the sequence number of the best route. */
	if (add) {
		stream_putc(s, flags);
		stream_putl(s, seq);
		stream_put(s, esi, sizeof(esi_t));
	}

	stream_putw_at(s, 0, stream_get_endp(s));

	if (bgp_debug_zebra(NULL)) {
		char esi_buf[ESI_STR_LEN];

		if (esi_valid)
			esi_to_str(esi, esi_buf, sizeof(esi_buf));
		else
			snprintf(esi_buf, sizeof(esi_buf), "-");
		zlog_debug(
			"Tx %s MACIP, VNI %u MAC %pEA IP %pIA flags 0x%x seq %u remote VTEP %pIA esi %s",
			add ? "ADD" : "DEL", (evi ? evi->vni : 0),
			(mac ? mac : &p->prefix.macip_addr.mac),
			&p->prefix.macip_addr.ip, flags, seq, remote_vtep_ip,
			esi_buf);
	}

	frrtrace(5, frr_bgp, evpn_mac_ip_zsend, add, evi, p, remote_vtep_ip,
		 esi);

	return zclient_send_message(bgp_zclient);
}

/*
 * Add (update) or delete remote VTEP from zebra.
 */
static enum zclient_send_status
bgp_zebra_send_remote_vtep(struct bgp *bgp, struct bgp_evpn_evi *evi,
			   const struct prefix_evpn *p, int flood_control,
			   int add)
{
	struct stream *s;

	/* Check socket. */
	if (!bgp_zclient || bgp_zclient->sock < 0) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("%s: No zclient or zclient->sock exists",
				   __func__);
		return ZCLIENT_SEND_SUCCESS;
	}

	/* Don't try to register if Zebra doesn't know of this instance. */
	if (!IS_BGP_INST_KNOWN_TO_ZEBRA(bgp)) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug(
				"%s: No zebra instance to talk to, not installing remote vtep",
				__func__);
		return ZCLIENT_SEND_SUCCESS;
	}

	s = bgp_zclient->obuf;
	stream_reset(s);

	zclient_create_header(
		s, add ? ZEBRA_REMOTE_VTEP_ADD : ZEBRA_REMOTE_VTEP_DEL,
		bgp->vrf_id);
	stream_putl(s, evi ? evi->vni : 0);
	stream_put_ipaddr(s, &p->prefix.imet_addr.ip);
	stream_putl(s, flood_control);

	stream_putw_at(s, 0, stream_get_endp(s));

	if (bgp_debug_zebra(NULL))
		zlog_debug("Tx %s Remote VTEP, VNI %u (flood control %d) remote VTEP %pIA",
			   add ? "ADD" : "DEL", (evi ? evi->vni : 0), flood_control,
			   &p->prefix.imet_addr.ip);

	frrtrace(3, frr_bgp, evpn_bum_vtep_zsend, add, evi, p);

	return zclient_send_message(bgp_zclient);
}

/*
 * Build extended communities for EVPN prefix route (Route Type 5).
 */
static void bgp_evpn_build_route_type_5_extcomm(struct bgp *bgp_vrf,
					   struct attr *attr)
{
	struct ecommunity* ecom_merge;
	struct ecommunity_val eval_encap;
	struct ecommunity_val eval_rmac;
	bgp_encap_types tnl_type;
	struct bgp_evpn_effective_fq_rt *effective_rt;
	struct ecommunity *old_ecom;

	/* Previously this function used ecommunity_merge, which is unchecked (no "unique" / "overwrite" flags)
	 * and just merges.
	 * It has mostly been converted to ecommunity_append_val_unchecked for
	 * slightly simpler code (avoid lots of struct ecommunity which all only have
	 * one value..)
	 */

	old_ecom = bgp_attr_get_ecommunity(attr);

	/* Why do we have to dup here? */
	if (old_ecom) {
		ecom_merge = ecommunity_dup(old_ecom);

		if (!old_ecom->refcnt)
			ecommunity_free(&old_ecom);
	} else {
		ecom_merge = ecommunity_new();
	}

	/* Add Encap */
	tnl_type = BGP_ENCAP_TYPE_VXLAN;
	encode_encap_extcomm(tnl_type, &eval_encap);

	/* Previous version of this code used ecom_merge which is also unchecked... */
	ecommunity_append_val_unchecked(ecom_merge, &eval_encap);
	attr->encap_tunneltype = tnl_type;

	/* Add the export RTs for VRF */
	frr_each(bgp_evpn_effective_fq_rt_slu, &bgp_vrf->effective_fq_export_rts, effective_rt)
		ecommunity_append_val_unchecked(ecom_merge, &effective_rt->ecom_val);

	/* override the router mac extended community */
	if (!is_zero_mac(&attr->rmac)) {
		encode_rmac_extcomm(&eval_rmac, &attr->rmac);
		ecommunity_add_val(ecom_merge, &eval_rmac,
				   true, true);
	}

	/* Finally, add the communities to the route */
	bgp_attr_set_ecommunity(attr, ecom_merge);
}

/*
 * Build extended communities for EVPN route types 2 and 3.
 * The layer-2 RT and ENCAP extended communities are applicable for all routes.
 * The default gateway extended community and MAC mobility (sticky) extended
 * community are added as needed based on passed settings - only for type-2
 * routes. Likewise, the layer-3 RT and Router MAC extended communities are
 * added, if present, based on passed settings - only for non-link-local
 * type-2 routes.
 *
 * Overrides attr->ecommunity!
 */
static void bgp_evpn_build_route_type_2_3_extcomm(struct bgp_evpn_evi *evi, struct attr *attr,
				     bool add_l3_ecomm,
				     struct ecommunity *macvrf_soo)
{
	struct ecommunity* ecom_merge;
	struct ecommunity_val eval_encap;
	struct ecommunity_val eval_sticky;
	struct ecommunity_val eval_default_gw;
	struct ecommunity_val eval_rmac;
	struct ecommunity_val eval_na;
	bool proxy;

	bgp_encap_types tnl_type;
	struct bgp_evpn_effective_fq_rt *effective_rt;
	uint32_t seqnum;
	struct bgp_evpn_effective_fq_rt_slu_head *vrf_export_rts = NULL;

	ecom_merge = ecommunity_new();

	/* Previously this function used ecommunity_merge a lot, which is unchecked
	 * and just merges.
	 * It has mostly been converted to ecommunity_append_val_unchecked for
	 * slightly simpler code (avoid lots of struct ecommunity which all only have
	 * one value..)
	 */

	/* Add Encap */
	tnl_type = BGP_ENCAP_TYPE_VXLAN;
	encode_encap_extcomm(tnl_type, &eval_encap);

	ecommunity_append_val_unchecked(ecom_merge, &eval_encap);
	attr->encap_tunneltype = tnl_type;

	/* Add the EVI's export RTs */
	frr_each (bgp_evpn_effective_fq_rt_slu, &evi->effective_fq_export_rts, effective_rt)
		ecommunity_append_val_unchecked(ecom_merge, &effective_rt->ecom_val);

	/* Add the export RTs for L3VNI if told to - caller determines when this should
	 * be done. This is typically determined by bgp_evpn_route_add_l3_attrs_ok which
	 * returns false for Type-3 (IMET) routes or ipv6 link local type 2 routes.
	 */
	if (add_l3_ecomm) {
		vrf_export_rts = bgp_evpn_evi_get_vrf_export_rts(evi);
		if (vrf_export_rts) {
			frr_each (bgp_evpn_effective_fq_rt_slu, vrf_export_rts, effective_rt)
				ecommunity_append_val_unchecked(ecom_merge, &effective_rt->ecom_val);
		}
	}

	/* Add MAC mobility (sticky) if needed. */
	if (CHECK_FLAG(attr->evpn_flags, ATTR_EVPN_FLAG_STICKY)) {
		seqnum = 0;
		encode_mac_mobility_extcomm(1, seqnum, &eval_sticky);
		ecommunity_append_val_unchecked(ecom_merge, &eval_sticky);
	}

	/* Add RMAC, if told to. */
	if (add_l3_ecomm) {
		encode_rmac_extcomm(&eval_rmac, &attr->rmac);
		ecommunity_append_val_unchecked(ecom_merge, &eval_rmac);
	}

	/* Add Default Gateway Extended Community, if needed. */
	if (CHECK_FLAG(attr->evpn_flags, ATTR_EVPN_FLAG_DEFAULT_GW)) {
		encode_default_gw_extcomm(&eval_default_gw);
		ecommunity_append_val_unchecked(ecom_merge, &eval_default_gw);
	}

	/* Add RFC 9047 ARP/ND Extended Community if needed */
	proxy = !!(attr->es_flags & ATTR_ES_PROXY_ADVERT);
	if (CHECK_FLAG(attr->evpn_flags, ATTR_EVPN_FLAG_ROUTER) || proxy) {
		encode_na_flag_extcomm(&eval_na,
				       CHECK_FLAG(attr->evpn_flags,
						  ATTR_EVPN_FLAG_ROUTER),
				       proxy);

		ecommunity_append_val_unchecked(ecom_merge, &eval_na);
	}

	/* Add MAC-VRF SoO, if configured */
	if (macvrf_soo)
		/* This might break sorting introduced by ecommunity_add_val... */
		ecommunity_merge(ecom_merge, macvrf_soo);

	/* Finally, add the communities to the route */
	bgp_attr_set_ecommunity(attr, ecom_merge);
}

/*
 * Add MAC mobility extended community to attribute.
 */
static void add_mac_mobility_to_attr(uint32_t seq_num, struct attr *attr)
{
	struct ecommunity ecom_tmp;
	struct ecommunity_val eval;
	uint8_t *ecom_val_ptr;
	uint32_t i;
	uint8_t *pnt;
	int type = 0;
	int sub_type = 0;
	struct ecommunity *ecomm = bgp_attr_get_ecommunity(attr);

	/* Build MM */
	encode_mac_mobility_extcomm(0, seq_num, &eval);

	/* Find current MM ecommunity */
	ecom_val_ptr = NULL;

	if (ecomm) {
		for (i = 0; i < ecomm->size; i++) {
			pnt = ecomm->val + (i * ecomm->unit_size);
			type = *pnt++;
			sub_type = *pnt++;

			if (type == ECOMMUNITY_ENCODE_EVPN
			    && sub_type
				       == ECOMMUNITY_EVPN_SUBTYPE_MACMOBILITY) {
				ecom_val_ptr =
					(ecomm->val + (i * ecomm->unit_size));
				break;
			}
		}
	}

	/* Update the existing MM ecommunity */
	if (ecom_val_ptr) {
		memcpy(ecom_val_ptr, eval.val, sizeof(char) * ecomm->unit_size);
	}
	/* Add MM to existing */
	else {
		memset(&ecom_tmp, 0, sizeof(ecom_tmp));
		ecom_tmp.size = 1;
		ecom_tmp.unit_size = ECOMMUNITY_SIZE;
		ecom_tmp.val = (uint8_t *)eval.val;

		if (ecomm)
			bgp_attr_set_ecommunity(
				attr, ecommunity_merge(ecomm, &ecom_tmp));
		else
			bgp_attr_set_ecommunity(attr,
						ecommunity_dup(&ecom_tmp));
	}
}

/* Install EVPN route into zebra. */
enum zclient_send_status evpn_zebra_install(struct bgp *bgp, struct bgp_evpn_evi *evi,
					    const struct prefix_evpn *p,
					    struct bgp_path_info *pi)
{
	uint8_t flags;
	int flood_control = VXLAN_FLOOD_DISABLED;
	uint32_t seq;
	enum zclient_send_status ret = ZCLIENT_SEND_SUCCESS;
	struct ipaddr vtep_ip = { .ipa_type = IPADDR_V4, .ipaddr_v4 = { INADDR_ANY } };

	if (p->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) {
		flags = 0;

		if (pi->sub_type == BGP_ROUTE_IMPORTED) {
			if (CHECK_FLAG(pi->attr->evpn_flags,
				       ATTR_EVPN_FLAG_STICKY))
				SET_FLAG(flags, ZEBRA_MACIP_TYPE_STICKY);
			if (CHECK_FLAG(pi->attr->evpn_flags,
				       ATTR_EVPN_FLAG_DEFAULT_GW))
				SET_FLAG(flags, ZEBRA_MACIP_TYPE_GW);
			if (is_evpn_prefix_ipaddr_v6(p) &&
			    CHECK_FLAG(pi->attr->evpn_flags,
				       ATTR_EVPN_FLAG_ROUTER))
				SET_FLAG(flags, ZEBRA_MACIP_TYPE_ROUTER_FLAG);

			seq = mac_mobility_seqnum(pi->attr);
			/* If local ES notify zebra that this is a sync path.
			 * ES is non-local while in LACP Bypass.
			 */
			if (bgp_evpn_attr_is_local_es(pi->attr)) {
				SET_FLAG(flags, ZEBRA_MACIP_TYPE_SYNC_PATH);
				if (bgp_evpn_attr_is_proxy(pi->attr))
					SET_FLAG(flags,
						ZEBRA_MACIP_TYPE_PROXY_ADVERT);
			}
		} else {
			if (!bgp_evpn_attr_is_sync(pi->attr))
				return 0;

			/* If local ES notify zebra that this is a sync path.
			 * ES is non-local while in LACP Bypass.
			 */
			if (bgp_evpn_attr_is_local_es(pi->attr)) {
				/* if a local path is being turned around and
				 * sent to zebra it is because it is a sync path
				 * on a local ES
				 */
				SET_FLAG(flags, ZEBRA_MACIP_TYPE_SYNC_PATH);
				/* supply the highest peer seq number to zebra
				 * for MM seq syncing
				 */
				seq = bgp_evpn_attr_get_sync_seq(pi->attr);
				/* if any of the paths from the peer have the
				 * ROUTER flag set install the local entry as a
				 * router entry
				 */
				if (is_evpn_prefix_ipaddr_v6(p) &&
				    CHECK_FLAG(pi->attr->es_flags, ATTR_ES_PEER_ROUTER))
					SET_FLAG(flags, ZEBRA_MACIP_TYPE_ROUTER_FLAG);

				if (!CHECK_FLAG(pi->attr->es_flags, ATTR_ES_PEER_ACTIVE))
					SET_FLAG(flags, ZEBRA_MACIP_TYPE_PROXY_ADVERT);
			} else
				seq = mac_mobility_seqnum(pi->attr);
		}

		uint8_t nhfamily = NEXTHOP_FAMILY(pi->attr->mp_nexthop_len);

		switch (nhfamily) {
		case AF_INET:
			SET_IPADDR_V4(&vtep_ip);
			vtep_ip.ipaddr_v4 = pi->attr->mp_nexthop_global_in;
			break;
		case AF_INET6:
			SET_IPADDR_V6(&vtep_ip);
			IPV6_ADDR_COPY(&vtep_ip.ipaddr_v6, &pi->attr->mp_nexthop_global);
			break;
		}

		ret = bgp_zebra_send_remote_macip(
			bgp, evi, p,
			(is_evpn_prefix_ipaddr_none(p)
				 ? NULL /* MAC update */
				 : evpn_type2_path_info_get_mac(
					   pi) /* MAC-IP update */),
			&vtep_ip, 1, flags, seq,
			bgp_evpn_attr_get_esi(pi->attr));
	} else if (p->prefix.route_type == BGP_EVPN_AD_ROUTE) {
		ret = bgp_evpn_remote_es_evi_add(bgp, evi, p, pi);
	} else {
		switch (bgp_attr_get_pmsi_tnl_type(pi->attr)) {
		case PMSI_TNLTYPE_INGR_REPL:
			flood_control = VXLAN_FLOOD_HEAD_END_REPL;
			break;

		case PMSI_TNLTYPE_PIM_SM:
			flood_control = VXLAN_FLOOD_PIM_SM;
			break;

		case PMSI_TNLTYPE_NO_INFO:
		case PMSI_TNLTYPE_RSVP_TE_P2MP:
		case PMSI_TNLTYPE_MLDP_P2MP:
		case PMSI_TNLTYPE_PIM_SSM:
		case PMSI_TNLTYPE_PIM_BIDIR:
		case PMSI_TNLTYPE_MLDP_MP2MP:
			flood_control = VXLAN_FLOOD_DISABLED;
			break;
		}

		ret = bgp_zebra_send_remote_vtep(bgp, evi, p, flood_control, 1);
	}

	return ret;
}

/* Uninstall EVPN route from zebra. */
enum zclient_send_status evpn_zebra_uninstall(struct bgp *bgp,
					      struct bgp_evpn_evi *evi,
					      const struct prefix_evpn *p,
					      struct bgp_path_info *pi,
					      bool is_sync)
{
	enum zclient_send_status ret = ZCLIENT_SEND_SUCCESS;
	struct ipaddr vtep_ip;

	if (p->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) {
		uint8_t nhfamily = NEXTHOP_FAMILY(pi->attr->mp_nexthop_len);

		switch (nhfamily) {
		case AF_INET:
			SET_IPADDR_V4(&vtep_ip);
			vtep_ip.ipaddr_v4 = pi->attr->mp_nexthop_global_in;
			break;
		case AF_INET6:
			SET_IPADDR_V6(&vtep_ip);
			IPV6_ADDR_COPY(&vtep_ip.ipaddr_v6, &pi->attr->mp_nexthop_global);
			break;
		}
	}

	if (p->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE)
		ret = bgp_zebra_send_remote_macip(
			bgp, evi, p,
			(is_evpn_prefix_ipaddr_none(p)
				 ? NULL /* MAC update */
				 : evpn_type2_path_info_get_mac(
					   pi) /* MAC-IP update */),
			(is_sync ? &zero_vtep_ip : &vtep_ip), 0, 0, 0,
			NULL);
	else if (p->prefix.route_type == BGP_EVPN_AD_ROUTE)
		ret = bgp_evpn_remote_es_evi_del(bgp, evi, p, pi);
	else
		ret = bgp_zebra_send_remote_vtep(bgp, evi, p,
						 VXLAN_FLOOD_DISABLED, 0);

	return ret;
}

/*
 * Due to MAC mobility, the prior "local" best route has been supplanted
 * by a "remote" best route. The prior route has to be deleted and withdrawn
 * from peers.
 */
static void evpn_delete_old_local_route(struct bgp *bgp, struct bgp_evpn_evi *evi,
					struct bgp_dest *dest,
					struct bgp_path_info *old_local,
					struct bgp_path_info *new_select)
{
	struct bgp_dest *global_dest;
	struct bgp_path_info *pi;
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;

	if (BGP_DEBUG(evpn_mh, EVPN_MH_RT)) {
		char esi_buf[ESI_STR_LEN];
		char esi_buf2[ESI_STR_LEN];
		struct prefix_evpn *evp =
			(struct prefix_evpn *)bgp_dest_get_prefix(dest);

		zlog_debug("local path deleted %pFX es %s; new-path-es %s", evp,
			   esi_to_str(&old_local->attr->esi, esi_buf,
				      sizeof(esi_buf)),
			   new_select ? esi_to_str(&new_select->attr->esi,
						   esi_buf2, sizeof(esi_buf2))
				      : "");
	}

	/* Locate route node in the global EVPN routing table. Note that
	 * this table is a 2-level tree (RD-level + Prefix-level) similar to
	 * L3VPN routes.
	 */
	global_dest = bgp_evpn_global_node_lookup(
		bgp->rib[afi][safi], safi,
		(const struct prefix_evpn *)bgp_dest_get_prefix(dest),
		&evi->prd, old_local);
	if (global_dest) {
		/* Delete route entry in the global EVPN table. */
		pi = bgp_evpn_delete_route_entry(bgp, afi, safi, global_dest, NULL, 0);

		/* Schedule for processing - withdraws to peers happen from
		 * this table.
		 */
		if (pi)
			bgp_process(bgp, global_dest, pi, afi, safi);
		bgp_dest_unlock_node(global_dest);
	}

	/* Delete route entry in the VNI route table, caller to remove. */
	bgp_path_info_mark_for_delete(dest, old_local);
}

/*
 * Calculate the best path for an EVPN route. Install/update best path in zebra,
 * if appropriate.
 * Note: vpn is NULL for local EAD-ES routes.
 */
int evpn_route_select_install(struct bgp *bgp, struct bgp_evpn_evi *evi,
			      struct bgp_dest *dest, struct bgp_path_info *pi)
{
	struct bgp_path_info *old_select, *new_select, *first;
	struct bgp_path_info_pair old_and_new;
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;
	int ret = 0;

	/* If the flag BGP_NODE_SELECT_DEFER is set, do not add route to
	 * the workqueue
	 */
	if (CHECK_FLAG(dest->flags, BGP_NODE_SELECT_DEFER)) {
		if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
			zlog_debug("%s: SELECT_DEFER flag set for EVPN route %pBD, dest %p",
				   bgp->name_pretty, dest, dest);

		return ret;
	}

	first = bgp_dest_get_bgp_path_info(dest);
	SET_FLAG(pi->flags, BGP_PATH_UNSORTED);
	if (pi != first) {
		if (pi->next)
			pi->next->prev = pi->prev;
		if (pi->prev)
			pi->prev->next = pi->next;

		if (first)
			first->prev = pi;
		pi->next = first;
		pi->prev = NULL;
		bgp_dest_set_bgp_path_info(dest, pi);
	}

	/* Compute the best path. */
	bgp_best_selection(bgp, dest, &bgp->maxpaths[afi][safi], &old_and_new,
			   afi, safi);
	old_select = old_and_new.old;
	new_select = old_and_new.new;

	/* If the best path hasn't changed - see if there is still something to
	 * update to zebra RIB.
	 * Remote routes and SYNC route (i.e. local routes with
	 * SYNCED_FROM_PEER flag) need to updated to zebra on any attr
	 * change.
	 */
	if (old_select && old_select == new_select
	    && old_select->type == ZEBRA_ROUTE_BGP
	    && (old_select->sub_type == BGP_ROUTE_IMPORTED ||
			bgp_evpn_attr_is_sync(old_select->attr))
	    && !CHECK_FLAG(dest->flags, BGP_NODE_USER_CLEAR)
	    && !CHECK_FLAG(old_select->flags, BGP_PATH_ATTR_CHANGED)
	    && !bgp_addpath_is_addpath_used(&bgp->tx_addpath, afi, safi)) {
		if (bgp_zebra_has_route_changed(old_select)) {
			/* BP is disabled when  BGP instance is being deleted or
			 * GR is in progress.
			 */
			if (CHECK_FLAG(bgp->flags, BGP_FLAG_DELETE_IN_PROGRESS) ||
			    CHECK_FLAG(bgp->gr_info[afi][safi].flags, BGP_GR_SKIP_BP))
				ret = evpn_zebra_install(bgp, evi,
							 (const struct prefix_evpn *)
								 bgp_dest_get_prefix(dest),
							 old_select);
			else
				bgp_zebra_route_install(dest, old_select, bgp,
							true, evi, false);
		}

		UNSET_FLAG(old_select->flags, BGP_PATH_MULTIPATH_CHG);
		UNSET_FLAG(old_select->flags, BGP_PATH_LINK_BW_CHG);
		bgp_zebra_clear_route_change_flags(dest);
		return ret;
	}

	/* If the user did a "clear" this flag will be set */
	UNSET_FLAG(dest->flags, BGP_NODE_USER_CLEAR);

	/* bestpath has changed; update relevant fields and install or uninstall
	 * into the zebra RIB.
	 */
	if (old_select || new_select)
		bgp_bump_version(dest);

	if (old_select)
		bgp_path_info_unset_flag(dest, old_select, BGP_PATH_SELECTED);
	if (new_select) {
		bgp_path_info_set_flag(dest, new_select, BGP_PATH_SELECTED);
		bgp_path_info_unset_flag(dest, new_select,
					 BGP_PATH_ATTR_CHANGED);
		UNSET_FLAG(new_select->flags, BGP_PATH_MULTIPATH_CHG);
		UNSET_FLAG(new_select->flags, BGP_PATH_LINK_BW_CHG);
	}

	/* a local entry with the SYNC flag also results in a MAC-IP update
	 * to zebra
	 */
	if (new_select && new_select->type == ZEBRA_ROUTE_BGP
	    && (new_select->sub_type == BGP_ROUTE_IMPORTED ||
			bgp_evpn_attr_is_sync(new_select->attr))) {
		if (CHECK_FLAG(bgp->flags, BGP_FLAG_DELETE_IN_PROGRESS) ||
		    CHECK_FLAG(bgp->gr_info[afi][safi].flags, BGP_GR_SKIP_BP))
			ret = evpn_zebra_install(bgp, evi,
						 (const struct prefix_evpn *)bgp_dest_get_prefix(
							 dest),
						 new_select);
		else
			bgp_zebra_route_install(dest, new_select, bgp, true,
						evi, false);

		/* If an old best existed and it was a "local" route, the only
		 * reason
		 * it would be supplanted is due to MAC mobility procedures. So,
		 * we
		 * need to do an implicit delete and withdraw that route from
		 * peers.
		 */
		if (new_select->sub_type == BGP_ROUTE_IMPORTED &&
				old_select && old_select->peer == bgp->peer_self
				&& old_select->type == ZEBRA_ROUTE_BGP
				&& old_select->sub_type == BGP_ROUTE_STATIC
				&& evi)
			evpn_delete_old_local_route(bgp, evi, dest,
					old_select, new_select);
	} else {
		if (old_select && old_select->type == ZEBRA_ROUTE_BGP &&
		    old_select->sub_type == BGP_ROUTE_IMPORTED) {
			if (CHECK_FLAG(bgp->flags, BGP_FLAG_DELETE_IN_PROGRESS) ||
			    CHECK_FLAG(bgp->flags, BGP_FLAG_VNI_DOWN) ||
			    CHECK_FLAG(bgp->gr_info[afi][safi].flags, BGP_GR_SKIP_BP))
				ret = evpn_zebra_uninstall(bgp, evi,
							   (const struct prefix_evpn *)
								   bgp_dest_get_prefix(dest),
							   old_select, false);
			else
				bgp_zebra_route_install(dest, old_select, bgp,
							false, evi, false);
		}
	}

	/* Clear any route change flags. */
	bgp_zebra_clear_route_change_flags(dest);

	/* Reap old select bgp_path_info, if it has been removed */
	if (old_select && CHECK_FLAG(old_select->flags, BGP_PATH_REMOVED))
		bgp_path_info_reap(dest, old_select);

	return ret;
}

static struct bgp_path_info *bgp_evpn_route_get_local_path(struct bgp *bgp, struct bgp_dest *dest,
							   uint32_t addpath_id)
{
	struct bgp_path_info *pi = NULL;

	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
		if (bgp_evpn_is_path_local(bgp, pi) && pi->addpath_rx_id == addpath_id)
			return pi;
	}

	return NULL;
}

/*
 * Delete an EVPN route entry in the ESI/VNI table or the global table.
 * Does not trigger any processing or withdraws to peers - caller to do that!
 */
struct bgp_path_info *bgp_evpn_delete_route_entry(struct bgp *bgp, afi_t afi, safi_t safi,
					      struct bgp_dest *dest,
					      const struct bgp_path_info *originator,
					      uint32_t addpath_id)
{
	struct bgp_path_info *pi = NULL;

	/* Now, find matching route. */
	if (originator) {
		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
			if (!bgp_evpn_is_path_local(bgp, pi))
				continue;

			if (pi->extra->evpn->type5_originator == originator)
				break;
		}
	} else
		pi = bgp_evpn_route_get_local_path(bgp, dest, addpath_id);

	/* Mark route for delete. */
	if (pi)
		bgp_path_info_mark_for_delete(dest, pi);

	return pi;
}

/* Helper function for bgp_evpn_upsert_type5_route that actually upserts the route entry */
static int _bgp_evpn_vrf_upsert_type5_route_entry(struct bgp *bgp_evpn_mi, struct bgp *bgp_vrf, afi_t afi,
					 safi_t safi, struct bgp_dest *dest,
					 struct bgp_path_info *originator, struct attr *attr,
					 int *route_changed, struct bgp_path_info **entry,
					 uint32_t addpath_id)
{
	struct attr *attr_new = NULL;
	struct bgp_path_info *pi = NULL;
	struct bgp_labels bgp_labels = {};
	struct bgp_path_info *local_pi = NULL;
	struct bgp_path_info *tmp_pi = NULL;
	struct aspath *new_aspath;
	struct attr static_attr = { 0 };

	*route_changed = 0;

	for (local_pi = bgp_dest_get_bgp_path_info(dest); local_pi; local_pi = local_pi->next) {
		if (!bgp_evpn_is_path_local(bgp_evpn_mi, local_pi))
			continue;

		if (local_pi->extra->evpn->type5_originator == originator)
			break;
	}

	static_attr = *attr;

	/*
	 * create a new route entry if one doesn't exist.
	 * Otherwise see if route attr has changed
	 */
	if (!local_pi) {

		/* route has changed as this is the first entry */
		*route_changed = 1;

		/*
		 * if the asn values are different, copy the as of
		 * source vrf to the target entry
		 */
		if (bgp_vrf->as != bgp_evpn_mi->as) {
			new_aspath = aspath_dup(static_attr.aspath);
			new_aspath = aspath_add_seq(new_aspath, bgp_vrf->as);
			static_attr.aspath = new_aspath;
		}

		/* Add (or update) attribute to hash. */
		attr_new = bgp_attr_intern(&static_attr);
		bgp_attr_flush(&static_attr);

		/* create the route info from attribute */
		pi = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_STATIC, 0,
			       bgp_evpn_mi->peer_self, attr_new, dest);
		SET_FLAG(pi->flags, BGP_PATH_VALID);
		if (local_pi)
			SET_FLAG(pi->flags, BGP_PATH_MULTIPATH);

		/* Type-5 routes advertise the L3-VNI */
		bgp_evpn_path_info_extra_get(pi);
		pi->extra->evpn->type5_originator = originator;
		vni2label(bgp_vrf->l3vni, &bgp_labels.label[0]);
		bgp_labels.num_labels = 1;
		if (!bgp_path_info_labels_same(pi, &bgp_labels.label[0],
					       bgp_labels.num_labels)) {
			bgp_labels_unintern(&pi->extra->labels);
			pi->extra->labels = bgp_labels_intern(&bgp_labels);
		}

		/* handle addpath: use the original route's tx id as our rx id */
		pi->addpath_rx_id = addpath_id;

		/* add the route entry to route node*/
		bgp_path_info_add(dest, pi);
		*entry = pi;
	} else {
		tmp_pi = local_pi;
		if (!attrhash_cmp(tmp_pi->attr, attr)) {
			if (originator != local_pi->extra->evpn->type5_originator)
				zlog_warn(
					"Changing the originator of a type5 route, this is not right");

			local_pi->extra->evpn->type5_originator = originator;

			/* attribute changed */
			*route_changed = 1;

			/* if the asn values are different, copy the asn of
			 * source vrf to the target (evpn) vrf entry.
			 */
			if (bgp_vrf->as != bgp_evpn_mi->as) {
				new_aspath = aspath_dup(static_attr.aspath);
				new_aspath = aspath_add_seq(new_aspath, bgp_vrf->as);
				static_attr.aspath = new_aspath;
			}
			/* The attribute has changed. */
			/* Add (or update) attribute to hash. */
			attr_new = bgp_attr_intern(&static_attr);
			bgp_attr_flush(&static_attr);
			bgp_path_info_set_flag(dest, tmp_pi,
					       BGP_PATH_ATTR_CHANGED);

			/* Restore route, if needed. */
			if (CHECK_FLAG(tmp_pi->flags, BGP_PATH_REMOVED))
				bgp_path_info_restore(dest, tmp_pi);

			/* Unintern existing, set to new. */
			bgp_attr_unintern(&tmp_pi->attr);
			tmp_pi->attr = attr_new;
			tmp_pi->uptime = monotime(NULL);
			tmp_pi->addpath_rx_id = addpath_id;
		}
		*entry = local_pi;
	}
	return 0;
}

/*
 * Low Level function that creates or updates a type-5 route in the global EVPN table
 * and schedules it for advertisement
 * The afi/safi and src_attr passed to this function correspond to those of the
 * source IP prefix (best path in the case of the attr. In the case of a local prefix (when
 * we are advertising local subnets), the src_attr will be NULL.
 */
static int bgp_evpn_upsert_type5_route(struct bgp *bgp_vrf, struct bgp_path_info *originator,
				   struct prefix_evpn *evp, struct attr *src_attr, afi_t src_afi,
				   safi_t src_safi, uint32_t addpath_id)
{
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;
	struct attr attr;
	struct bgp_dest *dest = NULL;
	struct bgp *bgp_evpn_mi = NULL;
	int route_changed = 0;
	struct bgp_path_info *pi = NULL;
	struct ipaddr vtep_ip;

	bgp_evpn_mi = bgp_get_evpn_master_instance();
	if (!bgp_evpn_mi)
		return 0;

	/* Build path attribute for this route - use the source attr, if
	 * present, else treat as locally originated.
	 */
	if (src_attr)
		attr = *src_attr;
	else {
		memset(&attr, 0, sizeof(attr));
		bgp_attr_default_set(&attr, bgp_vrf, BGP_ORIGIN_IGP);
	}

	/* Advertise Primary IP (PIP) is enabled, send individual
	 * IP (default instance router-id) as nexthop.
	 * PIP is disabled or vrr interface is not present
	 * use anycast-IP as nexthop and anycast RMAC.
	 */
	bgp_evpn_fill_rmac_nh_to_attr(bgp_vrf, &attr, evp, &vtep_ip);

	if (bgp_debug_zebra(NULL))
		zlog_debug("VRF %s type-5 route evp %pFX RMAC %pEA nexthop %pI4 mp_nexthop %pI6 orig vtep %pIA",
			   vrf_id_to_name(bgp_vrf->vrf_id), evp, &attr.rmac, &attr.nexthop,
			   &attr.mp_nexthop_global, &bgp_vrf->originator_ip);

	frrtrace(4, frr_bgp, evpn_advertise_type5, bgp_vrf->vrf_id, evp, &attr.rmac, &vtep_ip);

	if (src_afi == AFI_IP6 &&
	    CHECK_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
		       BGP_L2VPN_EVPN_ADV_IPV6_UNICAST_GW_IP)) {
		if (src_attr &&
		    !IN6_IS_ADDR_UNSPECIFIED(&src_attr->mp_nexthop_global)) {
			struct bgp_route_evpn *bre =
				XCALLOC(MTYPE_BGP_EVPN_OVERLAY,
					sizeof(struct bgp_route_evpn));

			bre->type = OVERLAY_INDEX_GATEWAY_IP;
			SET_IPADDR_V6(&bre->gw_ip);
			memcpy(&bre->gw_ip.ipaddr_v6,
			       &src_attr->mp_nexthop_global,
			       sizeof(struct in6_addr));
			bgp_attr_set_evpn_overlay(&attr, bre);
		}
	} else if (src_afi == AFI_IP &&
		   CHECK_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
			      BGP_L2VPN_EVPN_ADV_IPV4_UNICAST_GW_IP)) {
		if (src_attr && src_attr->nexthop.s_addr != 0) {
			struct bgp_route_evpn *bre =
				XCALLOC(MTYPE_BGP_EVPN_OVERLAY,
					sizeof(struct bgp_route_evpn));

			bre->type = OVERLAY_INDEX_GATEWAY_IP;
			SET_IPADDR_V4(&bre->gw_ip);
			memcpy(&bre->gw_ip.ipaddr_v4, &src_attr->nexthop,
			       sizeof(struct in_addr));
			bgp_attr_set_evpn_overlay(&attr, bre);
		}
	}

	/* Setup RT and encap extended community */
	bgp_evpn_build_route_type_5_extcomm(bgp_vrf, &attr);

	/* get the route node in global table */
	dest = bgp_evpn_global_node_get(bgp_evpn_mi->rib[afi][safi], afi, safi,
					evp, &bgp_vrf->vrf_prd, NULL);
	assert(dest);

	/* create or update the route entry within the route node */
	_bgp_evpn_vrf_upsert_type5_route_entry(bgp_evpn_mi, bgp_vrf, afi, safi, dest, originator, &attr,
				      &route_changed, &pi, addpath_id);

	/* schedule for processing and unlock node */
	if (route_changed) {
		bgp_process(bgp_evpn_mi, dest, pi, afi, safi);
		bgp_dest_unlock_node(dest);
	}

	/* unintern temporary */
	if (!src_attr)
		aspath_unintern(&attr.aspath);
	return 0;
}

/*
 * Low Level function that deletes a type-5 route in the global EVPN table
 * and schedules it for withdrawal
 */
static int bgp_evpn_vrf_delete_type5_route(struct bgp *bgp_vrf, const struct bgp_path_info *originator,
				   struct prefix_evpn *evp, uint32_t addpath_id)
{
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;
	struct bgp_dest *dest = NULL;
	struct bgp_path_info *pi = NULL;
	struct bgp *bgp_evpn_mi = NULL; /* evpn bgp instance */

	bgp_evpn_mi = bgp_get_evpn_master_instance();
	if (!bgp_evpn_mi)
		return 0;

	/* locate the global route entry for this type-5 prefix */
	dest = bgp_evpn_global_node_lookup(bgp_evpn_mi->rib[afi][safi], safi, evp,
					   &bgp_vrf->vrf_prd, NULL);
	if (!dest)
		return 0;

	frrtrace(2, frr_bgp, evpn_withdraw_type5, bgp_vrf->vrf_id, evp);

	pi = bgp_evpn_delete_route_entry(bgp_evpn_mi, afi, safi, dest, originator, addpath_id);

	/* schedule for processing and unlock node */
	if (pi)
		bgp_process(bgp_evpn_mi, dest, pi, afi, safi);
	bgp_dest_unlock_node(dest);
	return 0;
}

/*
 * Low Level function that creates or updates a type-5 route corresponding to an IP prefix,
 * and schedules it for advertisement (core function to originate a prefix)
 * The afi/safi and src_attr passed to this function correspond to those of the
 * source IP prefix (best path in the case of the attr. In the case of a local prefix (when
 * we are advertising local subnets), the src_attr will be NULL.
 */
void bgp_evpn_vrf_upsert_prefix_as_type5_route(struct bgp *bgp_vrf, struct bgp_path_info *originator,
				    const struct prefix *p, struct attr *src_attr, afi_t afi,
				    safi_t safi, uint32_t addpath_id)
{
	int ret = 0;
	struct prefix_evpn evp;

	bgp_evpn_build_type5_prefix_evpn_from_ip_prefix(&evp, p);
	ret = bgp_evpn_upsert_type5_route(bgp_vrf, originator, &evp, src_attr, afi, safi, addpath_id);
	if (ret)
		flog_err(EC_BGP_EVPN_ROUTE_CREATE,
			 "%u: Failed to create type-5 route for prefix %pFX",
			 bgp_vrf->vrf_id, p);
}

/*
 * Low Level function that delete a type-5 route corresponding to an IP prefix,
 * and schedules it for advertisement (core function to stop originating a prefix
 * / undo bgp_evpn_vrf_upsert_prefix_as_type5_route)
 * The afi/safi and src_attr passed to this function correspond to those of the
 * source IP prefix (best path in the case of the attr. In the case of a local prefix (when
 * we are advertising local subnets), the src_attr will be NULL.
 */
void bgp_evpn_vrf_delete_prefix_as_type5_route(struct bgp *bgp_vrf, const struct bgp_path_info *originator,
				   const struct prefix *p, afi_t afi, safi_t safi,
				   uint32_t addpath_id)
{
	int ret = 0;
	struct prefix_evpn evp;

	bgp_evpn_build_type5_prefix_evpn_from_ip_prefix(&evp, p);
	ret = bgp_evpn_vrf_delete_type5_route(bgp_vrf, originator, &evp, addpath_id);
	if (ret)
		flog_err(
			EC_BGP_EVPN_ROUTE_DELETE,
			"%u failed to delete type-5 route for prefix %pFX in vrf %s",
			bgp_vrf->vrf_id, p, vrf_id_to_name(bgp_vrf->vrf_id));
}

/*
 * Inject a specific prefix of a particular address-family (currently, IPv4 or
 * IPv6 unicast) from the VRF into EVPN, put its corresponding type-5 routes into the global table
 * and originate the type-5 route.
 */
void bgp_evpn_vrf_inject_prefix_and_originate_as_type5_route(struct bgp *bgp, struct bgp_dest *dest, struct bgp_path_info *pi,
				 afi_t afi, safi_t safi)
{
	const struct prefix *prefix = bgp_dest_get_prefix(dest);
	route_map_result_t ret;
	struct bgp_path_info tmp_pi;
	struct bgp_path_info_extra tmp_pie;
	struct attr tmp_attr;
	uint32_t addpath_id;

	/* For addpath we need to have valid TX addpath IDs when exporting to
	 * EVPN (well, at least the ID for ALL strategy). Those will be used as
	 * the RX ID in the EVPN paths, helping identifying them for withdraws.
	 * Such IDs are populated after bestpath selection, which is a bummer
	 * for us. Force populate those.
	 */
	bgp_addpath_update_ids(bgp, dest, afi, safi);

	addpath_id = bgp_evpn_addpath_id_for_path(bgp, pi, afi);
	if (!bgp->adv_cmd_rmap[afi][safi].map) {
		bgp_evpn_vrf_upsert_prefix_as_type5_route(bgp, pi, prefix, pi->attr, afi, safi, addpath_id);
		return;
	}

	tmp_attr = *pi->attr;

	/* Fill temp path_info */
	prep_for_rmap_apply(&tmp_pi, &tmp_pie, dest, pi, pi->peer, NULL, &tmp_attr);
	RESET_FLAG(tmp_attr.rmap_change_flags);

	ret = route_map_apply(bgp->adv_cmd_rmap[afi][safi].map, prefix, &tmp_pi);
	if (ret == RMAP_DENYMATCH) {
		bgp_attr_flush(&tmp_attr);
		return;
	}
	bgp_evpn_vrf_upsert_prefix_as_type5_route(bgp, pi, prefix, &tmp_attr, afi, safi, addpath_id);
}


/* Inject all prefixes of a particular address-family (currently, IPv4 or
 * IPv6 unicast) from the VRFinto EVPN, put their corresponding type-5 routes into the global table
 * and originate the type-5 routes.
 * This is invoked e.g. when the advertisement ("advertise <afi> <safi> ...") is enabled.
 */
void bgp_evpn_vrf_inject_safi_afi_prefixes_and_originate_as_type5_routes(struct bgp *bgp_vrf, afi_t afi,
				     safi_t safi)
{
	struct bgp_table *table = NULL;
	struct bgp_dest *dest = NULL;
	struct bgp_path_info *pi;

	table = bgp_vrf->rib[afi][safi];
	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
		/* Need to identify the "selected" route entry to use its
		 * attribute. Also, ensure that the route is injectable
		 * into EVPN.
		 */
		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
			if (!is_route_injectable_into_evpn(pi))
				continue;

			if (!CHECK_FLAG(pi->flags, BGP_PATH_SELECTED) &&
			    !CHECK_FLAG(pi->flags, BGP_PATH_MULTIPATH))
				continue;

			bgp_evpn_vrf_inject_prefix_and_originate_as_type5_route(bgp_vrf, dest, pi, afi, safi);

			if (bgp_evpn_should_originate_type5_routes_bestpath(bgp_vrf, afi))
				break;
		}
	}
}

/* For all injectable prefixes of a particular address family, delete and
 * withdraw their corresponding type-5 routes.
 * Bit of a silly naming, but makes clear this is the opposite to
 * bgp_evpn_vrf_inject_safi_afi_prefixes_and_originate_as_type5_routes
 * This is invoked e.g. when the advertisement is disabled ("no advertise <afi> <safi> ...")
 */
void bgp_evpn_vrf_eject_afi_safi_prefixes_and_withdraw_their_type5_routes(struct bgp *bgp_vrf, afi_t afi, safi_t safi)
{
	struct bgp_table *table = NULL;
	struct bgp_dest *dest = NULL;
	struct bgp_path_info *pi;
	uint32_t addpath_id;

	table = bgp_vrf->rib[afi][safi];
	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
		/* Only care about "selected" and "multipath" routes. Also
		 * ensure that these are routes that are injectable into EVPN.
		 */
		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
			if (!is_route_injectable_into_evpn(pi))
				continue;
			addpath_id = bgp_evpn_addpath_id_for_path(bgp_vrf, pi, afi);
			bgp_evpn_vrf_delete_prefix_as_type5_route(bgp_vrf, pi, bgp_dest_get_prefix(dest), afi,
						      safi, addpath_id);

			if (bgp_evpn_should_originate_type5_routes_bestpath(bgp_vrf, afi))
				break;
		}
	}
}





static void bgp_evpn_get_sync_info(struct bgp *bgp, esi_t *esi,
				   struct bgp_dest *dest, uint32_t loc_seq,
				   uint32_t *max_sync_seq, bool *active_on_peer,
				   bool *peer_router, bool *proxy_from_peer,
				   const struct ethaddr *mac)
{
	struct bgp_path_info *tmp_pi;
	struct bgp_path_info *second_best_path = NULL;
	uint32_t tmp_mm_seq = 0;
	esi_t *tmp_esi;
	int paths_eq;
	struct ethaddr *tmp_mac;
	bool mac_cmp = false;
	struct prefix_evpn *evp = (struct prefix_evpn *)&dest->rn->p;


	/* mac comparison is not needed for MAC-only routes */
	if (mac && !is_evpn_prefix_ipaddr_none(evp))
		mac_cmp = true;

	/* find the best non-local path. a local path can only be present
	 * as best path
	 */
	for (tmp_pi = bgp_dest_get_bgp_path_info(dest); tmp_pi;
	     tmp_pi = tmp_pi->next) {
		if (tmp_pi->sub_type != BGP_ROUTE_IMPORTED ||
			!CHECK_FLAG(tmp_pi->flags, BGP_PATH_VALID))
			continue;

		/* ignore paths that have a different mac */
		if (mac_cmp) {
			tmp_mac = evpn_type2_path_info_get_mac(tmp_pi);
			if (memcmp(mac, tmp_mac, sizeof(*mac)))
				continue;
		}

		if (bgp_evpn_path_info_cmp(bgp, tmp_pi, second_best_path,
					   &paths_eq, false))
			second_best_path = tmp_pi;
	}

	if (!second_best_path)
		return;

	tmp_esi = bgp_evpn_attr_get_esi(second_best_path->attr);
	/* if this has the same ES destination as the local path
	 * it is a sync path
	 */
	if (!memcmp(esi, tmp_esi, sizeof(esi_t))) {
		tmp_mm_seq = mac_mobility_seqnum(second_best_path->attr);
		if (tmp_mm_seq < loc_seq)
			return;

		/* we have a non-proxy path from the ES peer.  */
		if (second_best_path->attr->es_flags &
					ATTR_ES_PROXY_ADVERT) {
			*proxy_from_peer = true;
		} else {
			*active_on_peer = true;
		}

		if (CHECK_FLAG(second_best_path->attr->evpn_flags,
			       ATTR_EVPN_FLAG_ROUTER))
			*peer_router = true;

		/* we use both proxy and non-proxy imports to
		 * determine the max sync sequence
		 */
		if (tmp_mm_seq > *max_sync_seq)
			*max_sync_seq = tmp_mm_seq;
	}
}

/* Bubble up sync-info from all paths (non-best) to the local-path.
 * This is need for MM sequence number syncing and proxy advertisement.
 * Note: The local path can only exist as a best path in the
 * VPN route table. It will take precedence over all sync paths.
 */
static void update_evpn_route_entry_sync_info(struct bgp *bgp,
					      struct bgp_dest *dest,
					      struct attr *attr,
					      uint32_t loc_seq, bool setup_sync,
					      const struct ethaddr *mac)
{
	esi_t *esi;
	struct prefix_evpn *evp =
		(struct prefix_evpn *)bgp_dest_get_prefix(dest);

	if (evp->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE)
		return;

	esi = bgp_evpn_attr_get_esi(attr);
	if (bgp_evpn_is_esi_valid(esi)) {
		if (setup_sync) {
			uint32_t max_sync_seq = 0;
			bool active_on_peer = false;
			bool peer_router = false;
			bool proxy_from_peer = false;

			bgp_evpn_get_sync_info(bgp, esi, dest, loc_seq,
					       &max_sync_seq, &active_on_peer,
					       &peer_router, &proxy_from_peer,
					       mac);
			attr->mm_sync_seqnum = max_sync_seq;
			if (active_on_peer)
				SET_FLAG(attr->es_flags, ATTR_ES_PEER_ACTIVE);
			else
				UNSET_FLAG(attr->es_flags, ATTR_ES_PEER_ACTIVE);
			if (proxy_from_peer)
				SET_FLAG(attr->es_flags, ATTR_ES_PEER_PROXY);
			else
				UNSET_FLAG(attr->es_flags, ATTR_ES_PEER_PROXY);
			if (peer_router)
				SET_FLAG(attr->es_flags, ATTR_ES_PEER_ROUTER);
			else
				UNSET_FLAG(attr->es_flags, ATTR_ES_PEER_ROUTER);

			if (BGP_DEBUG(evpn_mh, EVPN_MH_RT)) {
				char esi_buf[ESI_STR_LEN];

				zlog_debug("setup sync info for %pFX es %s max_seq %d %s%s%s",
					   evp,
					   esi_to_str(esi, esi_buf,
						      sizeof(esi_buf)),
					   max_sync_seq,
					   CHECK_FLAG(attr->es_flags,
						      ATTR_ES_PEER_ACTIVE)
						   ? "peer-active "
						   : "",
					   CHECK_FLAG(attr->es_flags,
						      ATTR_ES_PEER_PROXY)
						   ? "peer-proxy "
						   : "",
					   CHECK_FLAG(attr->es_flags,
						      ATTR_ES_PEER_ROUTER)
						   ? "peer-router "
						   : "");
			}
		}
	} else {
		attr->mm_sync_seqnum = 0;
		UNSET_FLAG(attr->es_flags, ATTR_ES_PEER_ACTIVE);
		UNSET_FLAG(attr->es_flags, ATTR_ES_PEER_PROXY);
	}
}

/*
 * Check if the route is a type-2 MAC-IP route with a valid global address
 * (IPv4 or non-link-local IPv6) and the EVI belongs to a VRF with a proper
 * L3VNI configured
 */
static inline bool bgp_evpn_is_macip_with_l3vni(struct bgp_evpn_evi *evi, const struct prefix_evpn *p)
{
	return p->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE &&
	       (is_evpn_prefix_ipaddr_v4(p) ||
		(is_evpn_prefix_ipaddr_v6(p) &&
		 !IN6_IS_ADDR_LINKLOCAL(&p->prefix.macip_addr.ip.ipaddr_v6))) &&
	       CHECK_FLAG(evi->flags, EVI_FLAG_USE_TWO_LABELS) && bgp_evpn_evi_get_l3vni(evi);
}

/*
 * Check whether it's okay to add L3 / VRF related attributes such as MPLS Label2 (L3VNI)
 * RMAC or the VRF's Route Targets to the route
 * esi parameter is optional, maybe specified if route belongs to an ES
 */
static inline bool bgp_evpn_route_add_l3_attrs_ok(struct bgp_evpn_evi *evi, const struct prefix_evpn *p,
						  esi_t *esi)
{
	return bgp_evpn_is_macip_with_l3vni(evi, p) && bgp_evpn_es_add_l3_attrs_ok(esi);
}

/*
 * Create or update an EVPN EVI route entry. This could be in the EVI route tables
 * or the global route table.
 */
static int bgp_evpn_evi_update_route_entry(struct bgp *bgp, struct bgp_evpn_evi *evi,
				   afi_t afi, safi_t safi,
				   struct bgp_dest *dest, struct attr *attr,
				   const struct ethaddr *mac,
				   const struct ipaddr *ip, int add,
				   struct bgp_path_info **pi, uint8_t flags,
				   uint32_t seq, bool vpn_rt, bool *old_is_sync)
{
	struct bgp_path_info *tmp_pi;
	struct bgp_path_info *local_pi;
	struct attr *attr_new;
	struct attr local_attr;
	struct bgp_labels bgp_labels = {};
	int route_change = 1;
	const struct prefix_evpn *evp;

	*pi = NULL;
	evp = (const struct prefix_evpn *)bgp_dest_get_prefix(dest);

	/* See if this is an update of an existing route, or a new add. */
	local_pi = bgp_evpn_route_get_local_path(bgp, dest, 0);

	/* If route doesn't exist already, create a new one, if told to.
	 * Otherwise act based on whether the attributes of the route have
	 * changed or not.
	 */
	if (!local_pi && !add)
		return 0;

	if (old_is_sync && local_pi)
		*old_is_sync = bgp_evpn_attr_is_sync(local_pi->attr);

	/* if a local path is being added with a non-zero esi look
	 * for SYNC paths from ES peers and bubble up the sync-info
	 */
	update_evpn_route_entry_sync_info(bgp, dest, attr, seq, vpn_rt, mac);

	/* For non-GW MACs, update MAC mobility seq number, if needed. */
	if (seq && !CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_GW))
		add_mac_mobility_to_attr(seq, attr);

	if (!local_pi) {
		local_attr = *attr;

		/* Extract MAC mobility sequence number, if any. */
		local_attr.mm_seqnum = bgp_attr_mac_mobility_seqnum(&local_attr);

		/* Add (or update) attribute to hash. */
		attr_new = bgp_attr_intern(&local_attr);

		/* Create new route with its attribute. */
		tmp_pi = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_STATIC, 0,
				   bgp->peer_self, attr_new, dest);
		SET_FLAG(tmp_pi->flags, BGP_PATH_VALID);
		bgp_path_info_extra_get(tmp_pi);

		/* The VNI goes into the 'label' field of the route
		 * EVPN calls this "MPLS Label1" (yes, even for VXLAN)
		 */
		vni2label(evi->vni, &bgp_labels.label[0]);
		bgp_labels.num_labels = 1;

		/* Type-2 routes may carry a second VNI - the L3VNI of the associated VRF
		 * EVPN calls this "MPLS Label2" (yes, even for VXLAN)
		 * Only attach the second label if we are advertising two labels for
		 * type-2 routes.
		 */
		if (bgp_evpn_is_macip_with_l3vni(evi, evp)) {
			vni_t l3vni;

			l3vni = bgp_evpn_evi_get_l3vni(evi);
			if (l3vni) {
				vni2label(l3vni, &bgp_labels.label[1]);
				bgp_labels.num_labels++;
			}
		}

		if (!bgp_path_info_labels_same(tmp_pi, &bgp_labels.label[0],
					       bgp_labels.num_labels)) {
			bgp_labels_unintern(&tmp_pi->extra->labels);
			tmp_pi->extra->labels = bgp_labels_intern(&bgp_labels);
		}

		if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) {
			if (mac)
				evpn_type2_path_info_set_mac(tmp_pi, *mac);
			else if (ip)
				evpn_type2_path_info_set_ip(tmp_pi, *ip);
		}

		/* Mark route as self type-2 route */
		if (flags && CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_SVI_IP))
			tmp_pi->extra->evpn->af_flags =
				BGP_EVPN_MACIP_TYPE_SVI_IP;
		bgp_path_info_add(dest, tmp_pi);
	} else {
		tmp_pi = local_pi;
		if (!CHECK_FLAG(tmp_pi->flags, BGP_PATH_REMOVED) && attrhash_cmp(tmp_pi->attr, attr))
			route_change = 0;
		else {
			/*
			 * The attributes have changed, type-2 routes needs to
			 * be advertised with right labels.
			 */
			vni2label(evi->vni, &bgp_labels.label[0]);
			bgp_labels.num_labels = 1;
			if (bgp_evpn_is_macip_with_l3vni(evi, evp)) {
				vni_t l3vni;

				l3vni = bgp_evpn_evi_get_l3vni(evi);
				if (l3vni) {
					vni2label(l3vni, &bgp_labels.label[1]);
					bgp_labels.num_labels++;
				}
			}
			if (!bgp_path_info_labels_same(tmp_pi,
						       &bgp_labels.label[0],
						       bgp_labels.num_labels)) {
				bgp_labels_unintern(&tmp_pi->extra->labels);
				tmp_pi->extra->labels =
					bgp_labels_intern(&bgp_labels);
			}

			if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) {
				if (mac)
					evpn_type2_path_info_set_mac(tmp_pi,
								     *mac);
				else if (ip)
					evpn_type2_path_info_set_ip(tmp_pi,
								    *ip);
			}

			/* The attribute has changed. */
			/* Add (or update) attribute to hash. */
			local_attr = *attr;
			bgp_path_info_set_flag(dest, tmp_pi,
					       BGP_PATH_ATTR_CHANGED);

			/* Extract MAC mobility sequence number, if any. */
			local_attr.mm_seqnum =
				bgp_attr_mac_mobility_seqnum(&local_attr);

			attr_new = bgp_attr_intern(&local_attr);

			/* Restore route, if needed. */
			if (CHECK_FLAG(tmp_pi->flags, BGP_PATH_REMOVED))
				bgp_path_info_restore(dest, tmp_pi);

			/* Unintern existing, set to new. */
			bgp_attr_unintern(&tmp_pi->attr);
			tmp_pi->attr = attr_new;
			tmp_pi->uptime = monotime(NULL);
		}
	}

	/* local MAC-IP routes in the VNI table are linked to
	 * the destination ES
	 */
	if (route_change && vpn_rt
	    && (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE))
		bgp_evpn_path_es_link(tmp_pi, evi->vni,
				      bgp_evpn_attr_get_esi(tmp_pi->attr));

	/* Return back the route entry. */
	*pi = tmp_pi;
	return route_change;
}

static void evpn_zebra_reinstall_best_route(struct bgp *bgp,
					    struct bgp_evpn_evi *evi,
					    struct bgp_dest *dest)
{
	struct bgp_path_info *tmp_ri;
	struct bgp_path_info *curr_select = NULL;

	for (tmp_ri = bgp_dest_get_bgp_path_info(dest); tmp_ri;
	     tmp_ri = tmp_ri->next) {
		if (CHECK_FLAG(tmp_ri->flags, BGP_PATH_SELECTED)) {
			curr_select = tmp_ri;
			break;
		}
	}

	if (curr_select && curr_select->type == ZEBRA_ROUTE_BGP &&
	    (curr_select->sub_type == BGP_ROUTE_IMPORTED ||
	     bgp_evpn_attr_is_sync(curr_select->attr))) {
		if (CHECK_FLAG(bgp->flags, BGP_FLAG_DELETE_IN_PROGRESS))
			evpn_zebra_install(bgp, evi,
					   (const struct prefix_evpn *)
						   bgp_dest_get_prefix(dest),
					   curr_select);
		else
			bgp_zebra_route_install(dest, curr_select, bgp, true,
						evi, false);
	}
}

/*
 * If the local route was not selected evict it and tell zebra to re-add
 * the best remote dest.
 *
 * Typically a local path added by zebra is expected to be selected as
 * best. In which case when a remote path wins as best (later)
 * evpn_route_select_install itself evicts the older-local-best path.
 *
 * However if bgp's add and zebra's add cross paths (race condition) it
 * is possible that the local path is no longer the "older" best path.
 * It is a path that was never designated as best and hence requires
 * additional handling to prevent bgp from injecting and holding on to a
 * non-best local path.
 */
static struct bgp_dest *
evpn_cleanup_local_non_best_route(struct bgp *bgp, struct bgp_evpn_evi *evi,
				  struct bgp_dest *dest,
				  struct bgp_path_info *local_pi)
{
	/* local path was not picked as the winner; kick it out */
	if (bgp_debug_zebra(NULL))
		zlog_debug("evicting local evpn prefix %pBD as remote won",
			   dest);

	evpn_delete_old_local_route(bgp, evi, dest, local_pi, NULL);

	/* tell zebra to re-add the best remote path */
	evpn_zebra_reinstall_best_route(bgp, evi, dest);

	return bgp_path_info_reap(dest, local_pi);
}

/*
 * Create or update EVPN route (of type based on prefix) for specified EVI
 * and schedule for processing.
 */
static int bgp_evpn_evi_update_route(struct bgp *bgp, struct bgp_evpn_evi *evi,
			     struct prefix_evpn *p, uint8_t flags,
			     uint32_t seq, esi_t *esi)
{
	struct bgp_dest *dest;
	struct attr attr;
	struct attr *attr_new;
	bool add_l3_attrs = false;
	struct bgp_path_info *pi;
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;
	int route_change;
	bool old_is_sync = false;
	bool mac_only = false;
	struct ecommunity *macvrf_soo = NULL;

	memset(&attr, 0, sizeof(attr));

	/* Build path-attribute for this route. */
	bgp_attr_default_set(&attr, bgp, BGP_ORIGIN_IGP);
	bgp_evpn_vtep_ip_to_attr_nh(&evi->originator_ip, &attr);
	if (CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_STICKY))
		SET_FLAG(attr.evpn_flags, ATTR_EVPN_FLAG_STICKY);
	if (CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_GW))
		SET_FLAG(attr.evpn_flags, ATTR_EVPN_FLAG_DEFAULT_GW);
	if (CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_ROUTER_FLAG))
		SET_FLAG(attr.evpn_flags, ATTR_EVPN_FLAG_ROUTER);
	if (CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_PROXY_ADVERT))
		SET_FLAG(attr.es_flags, ATTR_ES_PROXY_ADVERT);

	if (esi && bgp_evpn_is_esi_valid(esi)) {
		memcpy(&attr.esi, esi, sizeof(esi_t));
		/* ES should not be marked local if ESI is in bypass */
		if (bgp_evpn_is_esi_local_and_non_bypass(esi))
			SET_FLAG(attr.es_flags, ATTR_ES_IS_LOCAL);
		else
			UNSET_FLAG(attr.es_flags, ATTR_ES_IS_LOCAL);
	}

	/* PMSI is only needed for type-3 routes */
	if (p->prefix.route_type == BGP_EVPN_IMET_ROUTE) {
		SET_FLAG(attr.flag, ATTR_FLAG_BIT(BGP_ATTR_PMSI_TUNNEL));
		bgp_attr_set_pmsi_tnl_type(&attr, PMSI_TNLTYPE_INGR_REPL);
		if (attr.mp_nexthop_len == BGP_ATTR_NHLEN_IPV4)
			ipv4_to_ipv4_mapped_ipv6(&attr.tunn_id, attr.mp_nexthop_global_in);
		else
			IPV6_ADDR_COPY(&attr.tunn_id, &attr.mp_nexthop_global);
	}

	/* router mac is only needed for type-2 routes here. */
	if (p->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) {
		uint8_t af_flags = 0;

		if (CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_SVI_IP))
			SET_FLAG(af_flags, BGP_EVPN_MACIP_TYPE_SVI_IP);

		bgp_evpn_get_rmac_nexthop(evi, p, &attr, af_flags);
	}

	if (bgp_debug_zebra(NULL)) {
		char buf3[ESI_STR_LEN];

		zlog_debug(
			"VRF %s vni %u type-%u route evp %pFX RMAC %pEA nexthop %pIA esi %s",
			evi->bgp_vrf ? vrf_id_to_name(evi->bgp_vrf->vrf_id)
				     : "None",
			evi->vni, p->prefix.route_type, p, &attr.rmac,
			&evi->originator_ip,
			esi_to_str(esi, buf3, sizeof(buf3)));
	}

	vni2label(evi->vni, &(attr.label));

	/* Include VRF related attributes (RTs, RMAC and MPLS Label2)
	 * for type-2 routes, if they're IPv4 or IPv6 global addresses and
	 * we're advertising L3VNI with these routes.
	 * Note that the L3VNI / MPLS Label2 is NOT added here, but rather in
	 * bgp_evpn_evi_update_route_entry
	 */
	add_l3_attrs = bgp_evpn_route_add_l3_attrs_ok(evi, p,
						      CHECK_FLAG(attr.es_flags, ATTR_ES_IS_LOCAL)
							      ? &attr.esi
							      : NULL);

	if (bgp->evpn_info)
		macvrf_soo = bgp->evpn_info->soo;

	/* Set up extended community. */
	bgp_evpn_build_route_type_2_3_extcomm(evi, &attr, add_l3_attrs, macvrf_soo);

	/* First, create (or fetch) route node within the VNI.
	 * NOTE: There is no RD here.
	 */
	dest = bgp_evpn_vni_node_get(evi, p, NULL);

	if ((p->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) &&
	    (is_evpn_prefix_ipaddr_none(p) == true))
		mac_only = true;

	/* Create or update route entry. */
	route_change = bgp_evpn_evi_update_route_entry(
		bgp, evi, afi, safi, dest, &attr,
		(mac_only ? NULL : &p->prefix.macip_addr.mac), NULL /* ip */, 1,
		&pi, flags, seq, true /* setup_sync */, &old_is_sync);
	assert(pi);
	attr_new = pi->attr;

	/* lock ri to prevent freeing in evpn_route_select_install */
	bgp_path_info_lock(pi);

	/* Perform route selection. Normally, the local route in the
	 * VNI is expected to win and be the best route. However, if
	 * there is a race condition where a host moved from local to
	 * remote and the remote route was received in BGP just prior
	 * to the local MACIP notification from zebra, the remote
	 * route would win, and we should evict the defunct local route
	 * and (re)install the remote route into zebra.
	 */
	evpn_route_select_install(bgp, evi, dest, pi);
	/*
	 * If the new local route was not selected evict it and tell zebra
	 * to re-add the best remote dest. BGP doesn't retain non-best local
	 * routes.
	 */
	if (CHECK_FLAG(pi->flags, BGP_PATH_REMOVED)) {
		route_change = 0;
	} else {
		if (!CHECK_FLAG(pi->flags, BGP_PATH_SELECTED)) {
			route_change = 0;
			dest = evpn_cleanup_local_non_best_route(bgp, evi, dest,
								 pi);
		} else {
			bool new_is_sync;

			/* If the local path already existed and is still the
			 * best path we need to also check if it transitioned
			 * from being a sync path to a non-sync path. If it
			 * it did we need to notify zebra that the sync-path
			 * has been removed.
			 */
			new_is_sync = bgp_evpn_attr_is_sync(pi->attr);
			if (!new_is_sync && old_is_sync) {
				if (CHECK_FLAG(bgp->flags,
					       BGP_FLAG_DELETE_IN_PROGRESS))
					evpn_zebra_uninstall(bgp, evi, p, pi,
							     true);
				else
					bgp_zebra_route_install(dest, pi, bgp,
								false, evi,
								true);
			}
		}
	}
	bgp_path_info_unlock(pi);

	if (dest)
		bgp_dest_unlock_node(dest);

	/* If this is a new route or some attribute has changed, export the
	 * route to the global table. The route will be advertised to peers
	 * from there. Note that this table is a 2-level tree (RD-level +
	 * Prefix-level) similar to L3VPN routes.
	 */
	if (route_change) {
		struct bgp_path_info *global_pi;

		dest = bgp_evpn_global_node_get(bgp->rib[afi][safi], afi, safi,
						p, &evi->prd, NULL);
		bgp_evpn_evi_update_route_entry(
			bgp, evi, afi, safi, dest, attr_new, NULL /* mac */,
			NULL /* ip */, 1, &global_pi, flags, seq,
			false /* setup_sync */, NULL /* old_is_sync */);

		/* Schedule for processing and unlock node. */
		bgp_process(bgp, dest, global_pi, afi, safi);
		bgp_dest_unlock_node(dest);
	}

	/* Unintern temporary. */
	aspath_unintern(&attr.aspath);

	return 0;
}

/*
 * Delete EVPN route (of type based on prefix) for specified EVI and
 * schedule for processing.
 */
static int bgp_evpn_evi_delete_route(struct bgp *bgp, struct bgp_evpn_evi *evi,
			     struct prefix_evpn *p)
{
	struct bgp_dest *dest, *global_dest;
	struct bgp_path_info *pi;
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;

	/* First, locate the route node within the VNI. If it doesn't exist,
	 * there
	 * is nothing further to do.
	 * NOTE: There is no RD here.
	 */
	dest = bgp_evpn_vni_node_lookup(evi, p, NULL);
	if (!dest)
		return 0;

	/* Next, locate route node in the global EVPN routing table. Note that
	 * this table is a 2-level tree (RD-level + Prefix-level) similar to
	 * L3VPN routes.
	 */
	global_dest = bgp_evpn_global_node_lookup(bgp->rib[afi][safi], safi, p,
						  &evi->prd, NULL);
	if (global_dest) {
		/* Delete route entry in the global EVPN table. */
		pi = bgp_evpn_delete_route_entry(bgp, afi, safi, global_dest, NULL, 0);

		/* Schedule for processing - withdraws to peers happen from
		 * this table.
		 */
		if (pi)
			bgp_process(bgp, global_dest, pi, afi, safi);
		bgp_dest_unlock_node(global_dest);
	}

	/* Delete route entry in the VNI route table. This can just be removed.
	 */
	pi = bgp_evpn_delete_route_entry(bgp, afi, safi, dest, NULL, 0);
	if (pi) {
		bgp_path_info_mark_for_delete(dest, pi);
		evpn_route_select_install(bgp, evi, dest, pi);
	}

	/* dest should still exist due to locking make coverity happy */
	assert(dest);
	bgp_dest_unlock_node(dest);

	return 0;
}

void bgp_evpn_evi_update_type2_route_entry(struct bgp *bgp, struct bgp_evpn_evi *evi,
				       struct bgp_dest *dest,
				       struct bgp_path_info *local_pi,
				       const char *caller)
{
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;
	struct bgp_path_info *pi;
	struct attr attr;
	struct attr *attr_new;
	uint32_t seq;
	bool add_l3_attrs = false;
	struct bgp_dest *global_dest;
	struct bgp_path_info *global_pi;
	struct prefix_evpn evp;
	int route_change;
	bool old_is_sync = false;
	struct ecommunity *macvrf_soo = NULL;

	if (CHECK_FLAG(local_pi->flags, BGP_PATH_REMOVED))
		return;

	/*
	 * VNI table MAC-IP prefixes don't have MAC so make sure it's set from
	 * path info here.
	 */
	if (is_evpn_prefix_ipaddr_none((struct prefix_evpn *)&dest->rn->p)) {
		/* VNI MAC -> Global */
		evpn_type2_prefix_global_copy(
			&evp, (struct prefix_evpn *)&dest->rn->p, NULL /* mac */,
			evpn_type2_path_info_get_ip(local_pi));
	} else {
		/* VNI IP -> Global */
		evpn_type2_prefix_global_copy(
			&evp, (struct prefix_evpn *)&dest->rn->p,
			evpn_type2_path_info_get_mac(local_pi), NULL /* ip */);
	}

	/*
	 * Build attribute per local route as the MAC mobility and
	 * some other values could differ for different routes. The
	 * attributes will be shared in the hash table.
	 */
	bgp_attr_default_set(&attr, bgp, BGP_ORIGIN_IGP);
	bgp_evpn_vtep_ip_to_attr_nh(&evi->originator_ip, &attr);
	attr.evpn_flags = local_pi->attr->evpn_flags;
	attr.es_flags = local_pi->attr->es_flags;
	if (CHECK_FLAG(local_pi->attr->evpn_flags, ATTR_EVPN_FLAG_DEFAULT_GW)) {
		SET_FLAG(attr.evpn_flags, ATTR_EVPN_FLAG_DEFAULT_GW);
		if (is_evpn_prefix_ipaddr_v6(&evp))
			SET_FLAG(attr.evpn_flags, ATTR_EVPN_FLAG_ROUTER);
	}
	memcpy(&attr.esi, &local_pi->attr->esi, sizeof(esi_t));
	/*
	 * We are evaluating a change in local/non-local status.
	 * The es_flags need to align with the local ES status
	 */
	if (bgp_evpn_is_esi_local_and_non_bypass(&attr.esi))
		SET_FLAG(attr.es_flags, ATTR_ES_IS_LOCAL);
	else
		UNSET_FLAG(attr.es_flags, ATTR_ES_IS_LOCAL);

	bgp_evpn_get_rmac_nexthop(evi, &evp, &attr, local_pi->extra->evpn->af_flags);
	vni2label(evi->vni, &(attr.label));

	/* Determine whether we should add L3 / VRF related attributes
	 * Note that the L3VNI / MPLS Label2 is NOT added here, but rather in
	 * bgp_evpn_evi_update_route_entry
	 */
	add_l3_attrs = bgp_evpn_route_add_l3_attrs_ok(evi, &evp,
						      CHECK_FLAG(attr.es_flags, ATTR_ES_IS_LOCAL)
							      ? &attr.esi
							      : NULL);

	if (bgp->evpn_info)
		macvrf_soo = bgp->evpn_info->soo;

	/* Set up extended community. */
	bgp_evpn_build_route_type_2_3_extcomm(evi, &attr, add_l3_attrs, macvrf_soo);
	seq = mac_mobility_seqnum(local_pi->attr);

	if (bgp_debug_zebra(NULL)) {
		char buf3[ESI_STR_LEN];

		zlog_debug(
			"VRF %s vni %u evp %pFX RMAC %pEA nexthop %pI4 esi %s esf 0x%x from %s",
			evi->bgp_vrf ? vrf_id_to_name(evi->bgp_vrf->vrf_id)
				     : " ",
			evi->vni, &evp, &attr.rmac, &attr.mp_nexthop_global_in,
			esi_to_str(&attr.esi, buf3, sizeof(buf3)),
			attr.es_flags, caller);
	}

	/* Update the route entry. */
	route_change = bgp_evpn_evi_update_route_entry(
		bgp, evi, afi, safi, dest, &attr, NULL /* mac */, NULL /* ip */,
		0, &pi, 0, seq, true /* setup_sync */, &old_is_sync);

	assert(pi);
	attr_new = pi->attr;
	/* lock ri to prevent freeing in evpn_route_select_install */
	bgp_path_info_lock(pi);

	/* Perform route selection. Normally, the local route in the
	 * VNI is expected to win and be the best route. However,
	 * under peculiar situations (e.g., tunnel (next hop) IP change
	 * that causes best selection to be based on next hop), a
	 * remote route could win. If the local route is the best,
	 * ensure it is updated in the global EVPN route table and
	 * advertised to peers; otherwise, ensure it is evicted and
	 * (re)install the remote route into zebra.
	 */
	evpn_route_select_install(bgp, evi, dest, pi);

	if (CHECK_FLAG(pi->flags, BGP_PATH_REMOVED)) {
		route_change = 0;
	} else {
		if (!CHECK_FLAG(pi->flags, BGP_PATH_SELECTED)) {
			route_change = 0;
			evpn_cleanup_local_non_best_route(bgp, evi, dest, pi);
		} else {
			bool new_is_sync;

			/* If the local path already existed and is still the
			 * best path we need to also check if it transitioned
			 * from being a sync path to a non-sync path. If it
			 * it did we need to notify zebra that the sync-path
			 * has been removed.
			 */
			new_is_sync = bgp_evpn_attr_is_sync(pi->attr);
			if (!new_is_sync && old_is_sync) {
				if (CHECK_FLAG(bgp->flags,
					       BGP_FLAG_DELETE_IN_PROGRESS))
					(void)evpn_zebra_uninstall(bgp, evi,
								   &evp, pi,
								   true);
				else
					bgp_zebra_route_install(dest, pi, bgp,
								false, evi,
								true);
			}
		}
	}


	/* unlock pi */
	bgp_path_info_unlock(pi);

	if (route_change) {
		/* Update route in global routing table. */
		global_dest = bgp_evpn_global_node_get(
			bgp->rib[afi][safi], afi, safi, &evp, &evi->prd, NULL);
		assert(global_dest);
		bgp_evpn_evi_update_route_entry(
			bgp, evi, afi, safi, global_dest, attr_new,
			NULL /* mac */, NULL /* ip */, 0, &global_pi, 0,
			mac_mobility_seqnum(attr_new), false /* setup_sync */,
			NULL /* old_is_sync */);

		/* Schedule for processing and unlock node. */
		bgp_process(bgp, global_dest, global_pi, afi, safi);
		bgp_dest_unlock_node(global_dest);
	}

	/* Unintern temporary. */
	aspath_unintern(&attr.aspath);
}

static void bgp_evpn_evi_update_type2_route(struct bgp *bgp, struct bgp_evpn_evi *evi,
			       struct bgp_dest *dest)
{
	struct bgp_path_info *tmp_pi;

	const struct prefix_evpn *evp =
		(const struct prefix_evpn *)bgp_dest_get_prefix(dest);

	if (evp->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE)
		return;

	/* Identify local route. */
	tmp_pi = bgp_evpn_route_get_local_path(bgp, dest, 0);
	if (!tmp_pi)
		return;

	bgp_evpn_evi_update_type2_route_entry(bgp, evi, dest, tmp_pi, __func__);
}

/*
 * Update all type-2 (MACIP) local routes for this EVI - these should also
 * be scheduled for advertise to peers.
 */
void bgp_evpn_evi_update_all_type2_routes(struct bgp *bgp, struct bgp_evpn_evi *evi)
{
	struct bgp_dest *dest;

	/* Walk this VNI's route MAC & IP table and update local type-2
	 * routes. For any routes updated, update corresponding entry in the
	 * global table too.
	 */
	for (dest = bgp_table_top(evi->mac_table); dest;
	     dest = bgp_route_next(dest))
		bgp_evpn_evi_update_type2_route(bgp, evi, dest);

	for (dest = bgp_table_top(evi->ip_table); dest;
	     dest = bgp_route_next(dest))
		bgp_evpn_evi_update_type2_route(bgp, evi, dest);
}

/*
 * Delete all type-2 (MACIP) local routes for this EVI - only from the
 * global routing table. These are also scheduled for withdraw from peers.
 */
static void bgp_evpn_evi_delete_global_type2_routes(struct bgp *bgp, struct bgp_evpn_evi *evi)
{
	afi_t afi;
	safi_t safi;
	struct bgp_dest *rddest, *dest;
	struct bgp_table *table;
	struct bgp_path_info *pi;

	afi = AFI_L2VPN;
	safi = SAFI_EVPN;

	rddest = bgp_node_lookup(bgp->rib[afi][safi],
				 (struct prefix *)&evi->prd);
	if (rddest) {
		table = bgp_dest_get_bgp_table_info(rddest);
		for (dest = bgp_table_top(table); dest;
		     dest = bgp_route_next(dest)) {
			const struct prefix_evpn *evp =
				(const struct prefix_evpn *)bgp_dest_get_prefix(
					dest);

			if (evp->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE)
				continue;

			pi = bgp_evpn_delete_route_entry(bgp, afi, safi, dest, NULL, 0);
			if (pi)
				bgp_process(bgp, dest, pi, afi, safi);
		}

		/* Unlock RD node. */
		bgp_dest_unlock_node(rddest);
	}
}

static struct bgp_dest *delete_vni_type2_route(struct bgp *bgp,
					       struct bgp_dest *dest)
{
	struct bgp_path_info *pi;
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;

	const struct prefix_evpn *evp =
		(const struct prefix_evpn *)bgp_dest_get_prefix(dest);

	if (evp->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE)
		return dest;

	pi = bgp_evpn_delete_route_entry(bgp, afi, safi, dest, NULL, 0);

	/* Route entry in local table gets deleted immediately. */
	if (pi)
		dest = bgp_path_info_reap(dest, pi);

	return dest;
}

static void bgp_evpn_evi_delete_type2_routes(struct bgp *bgp, struct bgp_evpn_evi *evi)
{
	struct bgp_dest *dest;

	/* Next, walk this VNI's MAC & IP route table and delete local type-2
	 * routes.
	 */
	for (dest = bgp_table_top(evi->mac_table); dest;
	     dest = bgp_route_next(dest)) {
		dest = delete_vni_type2_route(bgp, dest);
		assert(dest);
	}

	for (dest = bgp_table_top(evi->ip_table); dest;
	     dest = bgp_route_next(dest)) {
		dest = delete_vni_type2_route(bgp, dest);
		assert(dest);
	}
}

/*
 * Delete all type-2 (MACIP) local routes for this EVI - from the global
 * table as well as the per-VNI route table.
 */
static void bgp_evpn_evi_delete_all_type2_routes(struct bgp *bgp, struct bgp_evpn_evi *evi)
{
	/* First, walk the global route table for this VNI's type-2 local
	 * routes.
	 * EVPN routes are a 2-level table, first get the RD table.
	 */
	bgp_evpn_evi_delete_global_type2_routes(bgp, evi);
	bgp_evpn_evi_delete_type2_routes(bgp, evi);
}

/*
 * Delete all routes in the per-EVI route table.
 */
static void bgp_evpn_evi_delete_all_routes(struct bgp *bgp, struct bgp_evpn_evi *evi)
{
	struct bgp_dest *dest;
	struct bgp_path_info *pi, *nextpi;

	/* Walk this VNI's MAC & IP route table and delete all routes. */
	for (dest = bgp_table_top(evi->mac_table); dest;
	     dest = bgp_route_next(dest)) {
		for (pi = bgp_dest_get_bgp_path_info(dest);
		     (pi != NULL) && (nextpi = pi->next, 1); pi = nextpi) {
			bgp_evpn_remote_ip_hash_del(evi, pi);
			bgp_path_info_mark_for_delete(dest, pi);
			dest = bgp_path_info_reap(dest, pi);

			assert(dest);
		}
	}

	for (dest = bgp_table_top(evi->ip_table); dest;
	     dest = bgp_route_next(dest)) {
		for (pi = bgp_dest_get_bgp_path_info(dest);
		     (pi != NULL) && (nextpi = pi->next, 1); pi = nextpi) {
			bgp_path_info_mark_for_delete(dest, pi);
			dest = bgp_path_info_reap(dest, pi);

			assert(dest);
		}
	}
}

/* BUM traffic flood mode per-l2-vni */
static int bgp_evpn_evi_get_flood_mode(struct bgp *bgp,
					struct bgp_evpn_evi *evi)
{
	if (bgp_debug_zebra(NULL))
		zlog_debug("VRF %s vni %u flood mode %d (global flood mode %d)",
			   evi->bgp_vrf ? vrf_id_to_name(evi->bgp_vrf->vrf_id) : "UNKNOWN",
			   evi->vni, evi->vxlan_flood_ctrl, bgp->vxlan_flood_ctrl);

	/* If per-VNI flood mode is set and differs from global mode,
	 * use per-VNI mode.
	 */
	if (evi->vxlan_flood_ctrl != VXLAN_FLOOD_INHERIT_GLOBAL &&
	    evi->vxlan_flood_ctrl != bgp->vxlan_flood_ctrl)
		return evi->vxlan_flood_ctrl;

	/* if flooding has been globally disabled per-vni mode is
	 * not relevant
	 */
	if (bgp->vxlan_flood_ctrl == VXLAN_FLOOD_DISABLED)
		return VXLAN_FLOOD_DISABLED;

	/* if mcast group ip has been specified we use a PIM-SM MDT */
	if (evi->mcast_grp.s_addr != INADDR_ANY)
		return VXLAN_FLOOD_PIM_SM;

	/* default is ingress replication */
	return VXLAN_FLOOD_HEAD_END_REPL;
}

/*
 * Update (and advertise) all local routes for an EVI.
 * This includes
 * -  Type 1 (Ethernet Auto-Discovery Route)
 * -  Type 2 (MAC/IP Route Route)
 * -  Type 3 (Inclusive Multicast Ethernet Tag Route)
 * This function is invoked upon the EVI export RT getting modified or
 * a change to tunnel IP. Note that these
 * situations need the route in the per-VNI table as well as the global
 * table to be updated (as attributes change).
 */
int bgp_evpn_evi_update_routes(struct bgp *bgp, struct bgp_evpn_evi *evi)
{
	int ret;
	struct prefix_evpn p;

	update_type1_routes_for_evi(bgp, evi);

	/* Update and advertise the type-3 route (only one) followed by the
	 * locally learnt type-2 routes (MACIP) - for this VNI.
	 *
	 * RT-3 only if doing head-end replication
	 */
	if (bgp_evpn_evi_get_flood_mode(bgp, evi)
				== VXLAN_FLOOD_HEAD_END_REPL) {
		build_evpn_type3_prefix(&p, &evi->originator_ip);
		ret = bgp_evpn_evi_update_route(bgp, evi, &p, 0, 0, NULL);
		if (ret)
			return ret;
	}

	bgp_evpn_evi_update_all_type2_routes(bgp, evi);
	return 0;
}

/* Helper function / wrapper around bgp_evpn_evi_update_routes for hash_iterate()
 * Update Type-1/2/3 Routes for an EVI
 */
static void bgp_evpn_evi_update_routes_hash(struct hash_bucket *bucket,
				       struct bgp *bgp)
{
	struct bgp_evpn_evi *evi;

	if (!bucket)
		return;

	evi = (struct bgp_evpn_evi *)bucket->data;
	bgp_evpn_evi_update_routes(bgp, evi);
}

/*
 * Delete (and withdraw) local routes for specified EVI from the global
 * table and per-EVI table. After this, remove all other routes from
 * the per-EVI table. Invoked upon the EVI being deleted or EVPN
 * (advertise-all-vni) being disabled.
 */
static int bgp_evpn_evi_delete_routes(struct bgp *bgp, struct bgp_evpn_evi *evi)
{
	int ret;
	struct prefix_evpn p;

	/* Delete and withdraw locally learnt type-2 routes (MACIP)
	 * followed by type-3 routes (only one) - for this VNI.
	 */
	bgp_evpn_evi_delete_all_type2_routes(bgp, evi);

	build_evpn_type3_prefix(&p, &evi->originator_ip);

	/*
	 * To handle the following scenario:
	 *  - Say, the new zebra announce fifo list has few vni Evpn prefixes yet
	 *    to be sent to zebra.
	 *  - At this point if we have triggers like "no advertise-all-vni" or
	 *    "networking restart", where a vni is going down.
	 *
	 * Perform the below
	 *    1) send withdraw routes to zebra immediately in case it is installed.
	 *    2) before we blow up the vni table, we need to walk the list and
	 *       pop all the dest whose za_evi points to this vni.
	 */
	SET_FLAG(bgp->flags, BGP_FLAG_VNI_DOWN);
	ret = bgp_evpn_evi_delete_route(bgp, evi, &p);
	UNSET_FLAG(bgp->flags, BGP_FLAG_VNI_DOWN);
	if (ret)
		return ret;

	/* Delete all routes from the per-VNI table. */
	bgp_evpn_evi_delete_all_routes(bgp, evi);
	return 0;
}

/*
 * There is a flood mcast IP address change. Update the mcast-grp and
 * remove the type-3 route if any. A new type-3 route will be generated
 * post tunnel_ip update if the new flood mode is head-end-replication.
 */
static int bgp_evpn_evi_mcast_grp_change(struct bgp *bgp, struct bgp_evpn_evi *evi,
		struct in_addr mcast_grp)
{
	struct prefix_evpn p;

	evi->mcast_grp = mcast_grp;

	if (is_evi_live(evi)) {
		build_evpn_type3_prefix(&p, &evi->originator_ip);
		bgp_evpn_evi_delete_route(bgp, evi, &p);
	}

	return 0;
}

/*
 * If there is a tunnel endpoint IP address (VTEP-IP) change for this VNI.
     - Deletes tip_hash entry for old VTEP-IP
     - Adds tip_hash entry/refcount for new VTEP-IP
     - Deletes prior type-3 route for L2VNI (if needed)
     - Updates originator_ip
 * Note: Route re-advertisement happens elsewhere after other processing
 * other changes.
 */
static void handle_tunnel_ip_change(struct bgp *bgp_vrf, struct bgp *bgp_evpn,
				    struct bgp_evpn_evi *evi,
				    struct ipaddr *originator_ip)
{
	struct prefix_evpn p;
	struct ipaddr old_vtep_ip;

	if (bgp_vrf) /* L3VNI */
		old_vtep_ip = bgp_vrf->originator_ip;
	else /* L2VNI */
		old_vtep_ip = evi->originator_ip;

	/* TIP didn't change, nothing to do */
	if (ipaddr_is_same(&old_vtep_ip, originator_ip))
		return;

	/* If L2VNI is not live, we only need to update the originator_ip.
	 * L3VNIs are updated immediately, so we can't bail out early.
	 */
	if (!bgp_vrf && !is_evi_live(evi)) {
		evi->originator_ip = *originator_ip;
		return;
	}

	/* Update the tunnel-ip hash */
	bgp_tip_del(bgp_evpn, &old_vtep_ip);
	if (bgp_tip_add(bgp_evpn, originator_ip))
		/* The originator_ip was not already present in the
		 * bgp martian next-hop table as a tunnel-ip, so we
		 * need to go back and filter routes matching the new
		 * martian next-hop.
		 */
		bgp_filter_evpn_routes_upon_martian_change(bgp_evpn,
							   BGP_MARTIAN_TUN_IP);

	if (!bgp_vrf) {
		/* Need to withdraw type-3 route as the originator IP is part
		 * of the key.
		 */
		build_evpn_type3_prefix(&p, &evi->originator_ip);
		bgp_evpn_evi_delete_route(bgp_evpn, evi, &p);

		evi->originator_ip = *originator_ip;
	} else
		bgp_vrf->originator_ip = *originator_ip;

	return;
}

static struct bgp_path_info *
bgp_create_evpn_bgp_path_info(struct bgp_path_info *parent_pi,
			      struct bgp_dest *dest, struct attr *attr)
{
	struct attr *attr_new;
	struct bgp_path_info *pi;

	/* Add (or update) attribute to hash. */
	attr_new = bgp_attr_intern(attr);

	/* Create new route with its attribute. */
	pi = info_make(parent_pi->type, BGP_ROUTE_IMPORTED, 0, parent_pi->peer,
		       attr_new, dest);
	SET_FLAG(pi->flags, BGP_PATH_VALID);
	bgp_path_info_extra_get(pi);
	if (!pi->extra->vrfleak)
		pi->extra->vrfleak =
			XCALLOC(MTYPE_BGP_ROUTE_EXTRA_VRFLEAK,
				sizeof(struct bgp_path_info_extra_vrfleak));
	pi->extra->vrfleak->parent = bgp_path_info_lock(parent_pi);
	bgp_dest_lock_node((struct bgp_dest *)parent_pi->net);
	if (parent_pi->extra)
		pi->extra->igpmetric = parent_pi->extra->igpmetric;

	if (BGP_PATH_INFO_NUM_LABELS(parent_pi))
		pi->extra->labels = bgp_labels_intern(parent_pi->extra->labels);

	bgp_path_info_add(dest, pi);

	return pi;
}

/*
 * According to draft-ietf-bess-evpn-ipvpn-interworking-13, strip the following
 * extended communities for VRF routes imported from EVPN.
 *
 *   a. BGP Encapsulation extended communities.
 *   b. Route Target extended communities.
 *   c. All the extended communities of type EVPN.
 */
static bool bgp_evpn_filter_ecommunity(uint8_t *val, uint8_t size, void *arg)
{
	switch (val[0]) {
	case ECOMMUNITY_ENCODE_AS:
	case ECOMMUNITY_ENCODE_IP:
	case ECOMMUNITY_ENCODE_AS4:
		if (val[1] == ECOMMUNITY_ROUTE_TARGET)
			return false;
		break;
	case ECOMMUNITY_ENCODE_OPAQUE:
		if (val[1] == ECOMMUNITY_OPAQUE_SUBTYPE_ENCAP)
			return false;
		break;
	case ECOMMUNITY_ENCODE_EVPN:
		return false;
	}
	return true;
}

/*
 * Common handling for vni route tables install/selection.
 */
static int install_evpn_route_entry_in_vni_common(
	struct bgp *bgp, struct bgp_evpn_evi *evi, const struct prefix_evpn *p,
	struct bgp_dest *dest, struct bgp_path_info *parent_pi)
{
	struct bgp_path_info *pi;
	struct bgp_path_info *local_pi;
	struct attr *attr_new;
	int ret;
	bool old_local_es = false;
	bool new_local_es;

	/* Check if route entry is already present. */
	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
		if (pi->extra && pi->extra->vrfleak &&
		    (struct bgp_path_info *)pi->extra->vrfleak->parent ==
			    parent_pi)
			break;

	if (!pi) {
		/* Create an info */
		pi = bgp_create_evpn_bgp_path_info(parent_pi, dest,
						    parent_pi->attr);

		if (p->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) {
			if (is_evpn_type2_dest_ipaddr_none(dest))
				evpn_type2_path_info_set_ip(
					pi, p->prefix.macip_addr.ip);
			else
				evpn_type2_path_info_set_mac(
					pi, p->prefix.macip_addr.mac);
		}

		new_local_es = bgp_evpn_attr_is_local_es(pi->attr);
	} else {
		/* Return early if attributes haven't changed
		 * and dest isn't flagged for removal.
		 * dest will be unlocked by either
		 * bgp_evpn_evi_install_route_entry_mac() or
		 * bgp_evpn_evi_install_route_entry_ip()
		 */
		if (!CHECK_FLAG(pi->flags, BGP_PATH_REMOVED) &&
		    attrhash_cmp(pi->attr, parent_pi->attr))
			return 0;
		/* The attribute has changed. */
		/* Add (or update) attribute to hash. */
		attr_new = bgp_attr_intern(parent_pi->attr);

		/* Restore route, if needed. */
		if (CHECK_FLAG(pi->flags, BGP_PATH_REMOVED))
			bgp_path_info_restore(dest, pi);

		/* Mark if nexthop has changed. */
		if (pi->attr->mp_nexthop_len != attr_new->mp_nexthop_len) {
			/* Nexthop address family changed */
			SET_FLAG(pi->flags, BGP_PATH_IGP_CHANGED);
		} else if (BGP_ATTR_MP_NEXTHOP_LEN_IP6(pi->attr)) {
			/* IPv6 nexthop */
			if (!IPV6_ADDR_SAME(&pi->attr->mp_nexthop_global,
					    &attr_new->mp_nexthop_global))
				SET_FLAG(pi->flags, BGP_PATH_IGP_CHANGED);
			/* Also check link-local nexthop if present */
			else if ((pi->attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL ||
				  pi->attr->mp_nexthop_len == BGP_ATTR_NHLEN_VPNV6_GLOBAL_AND_LL) &&
				 !IPV6_ADDR_SAME(&pi->attr->mp_nexthop_local,
						 &attr_new->mp_nexthop_local))
				SET_FLAG(pi->flags, BGP_PATH_IGP_CHANGED);
		} else if (pi->attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV4 ||
			   pi->attr->mp_nexthop_len == BGP_ATTR_NHLEN_VPNV4) {
			/* IPv4 nexthop in mp_nexthop_global_in */
			if (!IPV4_ADDR_SAME(&pi->attr->mp_nexthop_global_in,
					    &attr_new->mp_nexthop_global_in))
				SET_FLAG(pi->flags, BGP_PATH_IGP_CHANGED);
		} else {
			/* IPv4 nexthop in nexthop field */
			if (!IPV4_ADDR_SAME(&pi->attr->nexthop, &attr_new->nexthop))
				SET_FLAG(pi->flags, BGP_PATH_IGP_CHANGED);
		}

		old_local_es = bgp_evpn_attr_is_local_es(pi->attr);
		new_local_es = bgp_evpn_attr_is_local_es(attr_new);
		/* If ESI is different or if its type has changed we
		 * need to reinstall the path in zebra
		 */
		if ((old_local_es != new_local_es)
		    || memcmp(&pi->attr->esi, &attr_new->esi,
			      sizeof(attr_new->esi))) {

			if (BGP_DEBUG(evpn_mh, EVPN_MH_RT))
				zlog_debug("VNI %d path %pFX chg to %s es",
					   evi->vni, &pi->net->rn->p,
					   new_local_es ? "local" : "non-local");
			bgp_path_info_set_flag(dest, pi, BGP_PATH_ATTR_CHANGED);
		}

		/* Unintern existing, set to new. */
		bgp_attr_unintern(&pi->attr);
		pi->attr = attr_new;
		pi->uptime = monotime(NULL);
	}

	bgp_dest_set_defer_flag(dest, false);

	/* Add this route to remote IP hashtable */
	bgp_evpn_remote_ip_hash_add(evi, pi);

	/* Perform route selection and update zebra, if required. */
	ret = evpn_route_select_install(bgp, evi, dest, pi);

	/* if the best path is a local path with a non-zero ES
	 * sync info against the local path may need to be updated
	 * when a remote path is added/updated (including changes
	 * from sync-path to remote-path)
	 */
	local_pi = bgp_evpn_route_get_local_path(bgp, dest, 0);
	if (local_pi && (old_local_es || new_local_es))
		bgp_evpn_evi_update_type2_route_entry(bgp, evi, dest, local_pi,
						  __func__);

	return ret;
}

/*
 * Common handling for vni route tables uninstall/selection.
 */
static int uninstall_evpn_route_entry_in_vni_common(
	struct bgp *bgp, struct bgp_evpn_evi *evi, const struct prefix_evpn *p,
	struct bgp_dest *dest, struct bgp_path_info *parent_pi)
{
	struct bgp_path_info *pi;
	struct bgp_path_info *local_pi;
	int ret;

	/* Find matching route entry. */
	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
		if (pi->extra && pi->extra->vrfleak &&
		    (struct bgp_path_info *)pi->extra->vrfleak->parent ==
			    parent_pi)
			break;

	if (!pi)
		return 0;

	bgp_evpn_remote_ip_hash_del(evi, pi);

	/* Mark entry for deletion */
	bgp_path_info_mark_for_delete(dest, pi);

	/* Perform route selection and update zebra, if required. */
	ret = evpn_route_select_install(bgp, evi, dest, pi);

	/* if the best path is a local path with a non-zero ES
	 * sync info against the local path may need to be updated
	 * when a remote path is deleted
	 */
	local_pi = bgp_evpn_route_get_local_path(bgp, dest, 0);
	if (local_pi && bgp_evpn_attr_is_local_es(local_pi->attr))
		bgp_evpn_evi_update_type2_route_entry(bgp, evi, dest, local_pi,
						  __func__);

	return ret;
}

/*
 * Install route entry into VNI IP table and invoke route selection.
 */
static int bgp_evpn_evi_install_route_entry_ip(struct bgp *bgp,
					      struct bgp_evpn_evi *evi,
					      const struct prefix_evpn *p,
					      struct bgp_path_info *parent_pi)
{
	int ret;
	struct bgp_dest *dest;

	/* Ignore MAC Only Type-2 */
	if ((p->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) &&
	    (is_evpn_prefix_ipaddr_none(p) == true))
		return 0;

	/* Create (or fetch) route within the VNI IP table. */
	dest = bgp_evpn_vni_ip_node_get(evi->ip_table, p, parent_pi);

	ret = install_evpn_route_entry_in_vni_common(bgp, evi, p, dest,
						     parent_pi);

	bgp_dest_unlock_node(dest);

	return ret;
}

/*
 * Install route entry into VNI MAC table and invoke route selection.
 */
static int bgp_evpn_evi_install_route_entry_mac(struct bgp *bgp,
					       struct bgp_evpn_evi *evi,
					       const struct prefix_evpn *p,
					       struct bgp_path_info *parent_pi)
{
	int ret;
	struct bgp_dest *dest;

	/* Only type-2 routes go into this table */
	if (p->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE)
		return 0;

	/* Create (or fetch) route within the VNI MAC table. */
	dest = bgp_evpn_vni_mac_node_get(evi->mac_table, p, parent_pi);

	ret = install_evpn_route_entry_in_vni_common(bgp, evi, p, dest,
						     parent_pi);

	bgp_dest_unlock_node(dest);

	return ret;
}

/*
 * Uninstall route entry from VNI IP table and invoke route selection.
 */
static int bgp_evpn_evi_uninstall_route_entry_ip(struct bgp *bgp,
						struct bgp_evpn_evi *evi,
						const struct prefix_evpn *p,
						struct bgp_path_info *parent_pi)
{
	int ret;
	struct bgp_dest *dest;

	/* Ignore MAC Only Type-2 */
	if ((p->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) &&
	    (is_evpn_prefix_ipaddr_none(p) == true))
		return 0;

	/* Locate route within the VNI IP table. */
	dest = bgp_evpn_vni_ip_node_lookup(evi->ip_table, p, parent_pi);
	if (!dest)
		return 0;

	ret = uninstall_evpn_route_entry_in_vni_common(bgp, evi, p, dest,
						       parent_pi);

	bgp_dest_unlock_node(dest);

	return ret;
}

/*
 * Uninstall route entry from VNI IP table and invoke route selection.
 */
static int
bgp_evpn_evi_uninstall_route_entry_mac(struct bgp *bgp, struct bgp_evpn_evi *evi,
				      const struct prefix_evpn *p,
				      struct bgp_path_info *parent_pi)
{
	int ret;
	struct bgp_dest *dest;

	/* Only type-2 routes go into this table */
	if (p->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE)
		return 0;

	/* Locate route within the VNI MAC table. */
	dest = bgp_evpn_vni_mac_node_lookup(evi->mac_table, p, parent_pi);
	if (!dest)
		return 0;

	ret = uninstall_evpn_route_entry_in_vni_common(bgp, evi, p, dest,
						       parent_pi);

	bgp_dest_unlock_node(dest);

	return ret;
}

/*
 * Low level function to install route entry into the VRF routing table,
 * invoke route selection and notify Zebra if appropriate.
 * Does not perform any checks (hence low level), internal function, avoid using directly!
 */
static int _bgp_evpn_vrf_install_route_entry(struct bgp *bgp_vrf,
					   const struct prefix_evpn *evp,
					   struct bgp_path_info *parent_pi)
{
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	struct attr attr;
	struct attr *attr_new;
	int ret = 0;
	struct prefix p;
	struct prefix *pp = &p;
	afi_t afi = 0;
	safi_t safi = 0;
	bool new_pi = false;
	bool use_l3nhg = false;
	bool is_l3nhg_active = false;
	char buf1[INET6_ADDRSTRLEN];
	struct bgp_route_evpn *bre;
	struct ecommunity *ecom;

	memset(pp, 0, sizeof(struct prefix));
	ip_prefix_from_evpn_prefix(evp, pp);

	if (bgp_debug_zebra(NULL))
		zlog_debug(
			"vrf %s: import evpn prefix %pFX parent %p flags 0x%x",
			vrf_id_to_name(bgp_vrf->vrf_id), evp, parent_pi,
			parent_pi->flags);

	if (bgp_vrf->vrf_id == VRF_UNKNOWN)
		return -1;

	/* Create (or fetch) route within the VRF. */
	/* NOTE: There is no RD here. */
	if (is_evpn_prefix_ipaddr_v4(evp)) {
		afi = AFI_IP;
		safi = SAFI_UNICAST;
		dest = bgp_node_get(bgp_vrf->rib[afi][safi], pp);
	} else if (is_evpn_prefix_ipaddr_v6(evp)) {
		afi = AFI_IP6;
		safi = SAFI_UNICAST;
		dest = bgp_node_get(bgp_vrf->rib[afi][safi], pp);
	} else
		return 0;

	/* EVPN routes currently only support a IPv4 next hop which corresponds
	 * to the remote VTEP. When importing into a VRF, if it is IPv6 host
	 * or prefix route, we have to convert the next hop to an IPv4-mapped
	 * address for the rest of the code to flow through. In the case of IPv4,
	 * make sure to set the flag for next hop attribute.
	 */
	attr = *parent_pi->attr;
	bre = bgp_attr_get_evpn_overlay(&attr);
	if (bre && bre->type == OVERLAY_INDEX_GATEWAY_IP) {
		/*
		 * If gateway IP overlay index is specified in the NLRI of
		 * EVPN RT-5, this gateway IP should be used as the nexthop
		 * for the prefix in the VRF
		 */
		if (bgp_debug_zebra(NULL)) {
			zlog_debug("Install gateway IP %s as nexthop for prefix %pFX in vrf %s",
				   inet_ntop(pp->family, &bre->gw_ip, buf1,
					     sizeof(buf1)),
				   pp, vrf_id_to_name(bgp_vrf->vrf_id));
		}

		if (afi == AFI_IP6) {
			memcpy(&attr.mp_nexthop_global, &bre->gw_ip.ipaddr_v6,
			       sizeof(struct in6_addr));
			attr.mp_nexthop_len = IPV6_MAX_BYTELEN;
		} else {
			attr.nexthop = bre->gw_ip.ipaddr_v4;
			SET_FLAG(attr.flag, ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP));
		}
	} else {
		if (afi == AFI_IP6)
			evpn_convert_nexthop_to_ipv6(&attr);
		else {
			attr.nexthop = attr.mp_nexthop_global_in;
			SET_FLAG(attr.flag, ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP));
		}
	}

	bgp_evpn_es_vrf_use_nhg(bgp_vrf, &parent_pi->attr->esi, &use_l3nhg,
				&is_l3nhg_active, NULL);
	if (use_l3nhg)
		SET_FLAG(attr.es_flags, ATTR_ES_L3_NHG_USE);
	if (is_l3nhg_active)
		SET_FLAG(attr.es_flags, ATTR_ES_L3_NHG_ACTIVE);

	ecom = ecommunity_filter(bgp_attr_get_ecommunity(&attr), bgp_evpn_filter_ecommunity, NULL);
	bgp_attr_set_ecommunity(&attr, ecom);

	/* Check if route entry is already present. */
	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
		if (pi->extra && pi->extra->vrfleak &&
		    (struct bgp_path_info *)pi->extra->vrfleak->parent ==
			    parent_pi)
			break;

	if (!pi) {
		pi = bgp_create_evpn_bgp_path_info(parent_pi, dest, &attr);
		new_pi = true;
	} else {
		if (!CHECK_FLAG(pi->flags, BGP_PATH_REMOVED) && attrhash_cmp(pi->attr, &attr)) {
			bgp_dest_unlock_node(dest);
			return 0;
		}
		/* The attribute has changed. */
		/* Add (or update) attribute to hash. */
		attr_new = bgp_attr_intern(&attr);

		/* Restore route, if needed. */
		if (CHECK_FLAG(pi->flags, BGP_PATH_REMOVED))
			bgp_path_info_restore(dest, pi);

		/* Mark if nexthop has changed. */
		if ((afi == AFI_IP
		     && !IPV4_ADDR_SAME(&pi->attr->nexthop, &attr_new->nexthop))
		    || (afi == AFI_IP6
			&& !IPV6_ADDR_SAME(&pi->attr->mp_nexthop_global,
					   &attr_new->mp_nexthop_global)))
			SET_FLAG(pi->flags, BGP_PATH_IGP_CHANGED);

		bgp_path_info_set_flag(dest, pi, BGP_PATH_ATTR_CHANGED);
		/* Unintern existing, set to new. */
		bgp_attr_unintern(&pi->attr);
		pi->attr = attr_new;
		pi->uptime = monotime(NULL);
	}

	bgp_dest_set_defer_flag(dest, false);

	/* Gateway IP nexthop should be resolved */
	if (bre && bre->type == OVERLAY_INDEX_GATEWAY_IP) {
		if (bgp_find_or_add_nexthop(bgp_vrf, bgp_vrf, afi, safi, pi, NULL, 0, NULL, NULL))
			bgp_path_info_set_flag(dest, pi, BGP_PATH_VALID);
		else {
			if (BGP_DEBUG(nht, NHT)) {
				inet_ntop(pp->family, &bre->gw_ip, buf1,
					  sizeof(buf1));
				zlog_debug("%s: gateway IP NH unresolved",
					   buf1);
			}
			bgp_path_info_unset_flag(dest, pi, BGP_PATH_VALID);
		}
	} else {
		/* as it is an importation, change nexthop */
		bgp_path_info_set_flag(dest, pi, BGP_PATH_ANNC_NH_SELF);
	}

	/* Link path to evpn nexthop */
	bgp_evpn_path_nh_add(bgp_vrf, pi);

	bgp_aggregate_increment(bgp_vrf, bgp_dest_get_prefix(dest), pi, afi,
				safi);

	/* Perform route selection and update zebra, if required. */
	bgp_process(bgp_vrf, dest, pi, afi, safi);

	/* Process for route leaking. */
	vpn_leak_from_vrf_update(bgp_get_default(), bgp_vrf, pi);

	if (bgp_debug_zebra(NULL)) {
		struct ipaddr nhip = {};

		if (pi->net->rn->p.family == AF_INET6) {
			SET_IPADDR_V6(&nhip);
			IPV6_ADDR_COPY(&nhip.ipaddr_v6, &pi->attr->mp_nexthop_global);
		} else {
			SET_IPADDR_V4(&nhip);
			IPV4_ADDR_COPY(&nhip.ipaddr_v4, &pi->attr->nexthop);
		}
		zlog_debug("... %s pi %s dest %p (l %d) pi %p (l %d, f 0x%x) nh %pIA",
			   new_pi ? "new" : "update",
			   bgp_vrf->name_pretty, dest,
			   bgp_dest_get_lock_count(dest), pi, pi->lock,
			   pi->flags, &nhip);
	}

	bgp_dest_unlock_node(dest);

	return ret;
}

/*
 * Low level function to uninstall route entry from the VRF routing table,
 * invoke route selection and notify Zebra if appropriate.
 * Does not perform any checks (hence low level), internal function, avoid using directly!
 */
int _bgp_evpn_vrf_uninstall_route_entry(struct bgp *bgp_vrf, const struct prefix_evpn *evp,
				      struct bgp_path_info *parent_pi)
{
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	int ret = 0;
	struct prefix p;
	struct prefix *pp = &p;
	afi_t afi = 0;
	safi_t safi = 0;

	memset(pp, 0, sizeof(struct prefix));
	ip_prefix_from_evpn_prefix(evp, pp);

	if (bgp_debug_zebra(NULL))
		zlog_debug(
			"vrf %s: unimport evpn prefix %pFX parent %p flags 0x%x",
			vrf_id_to_name(bgp_vrf->vrf_id), evp, parent_pi,
			parent_pi->flags);

	/* Locate route within the VRF. */
	/* NOTE: There is no RD here. */
	if (is_evpn_prefix_ipaddr_v4(evp)) {
		afi = AFI_IP;
		safi = SAFI_UNICAST;
		dest = bgp_node_lookup(bgp_vrf->rib[afi][safi], pp);
	} else {
		afi = AFI_IP6;
		safi = SAFI_UNICAST;
		dest = bgp_node_lookup(bgp_vrf->rib[afi][safi], pp);
	}

	if (!dest)
		return 0;

	/* Find matching route entry. */
	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
		if (pi->extra && pi->extra->vrfleak &&
		    (struct bgp_path_info *)pi->extra->vrfleak->parent ==
			    parent_pi)
			break;

	if (!pi) {
		bgp_dest_unlock_node(dest);
		return 0;
	}

	if (bgp_debug_zebra(NULL)) {
		struct ipaddr nhip = {};

		if (pi->net->rn->p.family == AF_INET6) {
			SET_IPADDR_V6(&nhip);
			IPV6_ADDR_COPY(&nhip.ipaddr_v6, &pi->attr->mp_nexthop_global);
		} else {
			SET_IPADDR_V4(&nhip);
			IPV4_ADDR_COPY(&nhip.ipaddr_v4, &pi->attr->nexthop);
		}

		zlog_debug("... delete pi %s dest %p (l %d) pi %p (l %d, f 0x%x) nh %pIA",
			   bgp_vrf->name_pretty, dest,
			   bgp_dest_get_lock_count(dest), pi, pi->lock,
			   pi->flags, &nhip);
	}

	/* Process for route leaking. */
	vpn_leak_from_vrf_withdraw(bgp_get_default(), bgp_vrf, pi);

	bgp_aggregate_decrement(bgp_vrf, bgp_dest_get_prefix(dest), pi, afi,
				safi);

	/* Force deletion */
	SET_FLAG(dest->flags, BGP_NODE_PROCESS_CLEAR);

	/* Mark entry for deletion */
	bgp_path_info_mark_for_delete(dest, pi);

	/* Unlink path to evpn nexthop */
	bgp_evpn_path_nh_del(bgp_vrf, pi);

	/* Perform route selection and update zebra, if required. */
	bgp_process(bgp_vrf, dest, pi, afi, safi);

	/* Unlock route node. */
	bgp_dest_unlock_node(dest);

	return ret;
}

/*
 * Install route entry into the EVI routing tables.
 */
static int bgp_evpn_evi_install_route_entry(struct bgp *bgp, struct bgp_evpn_evi *evi,
				    const struct prefix_evpn *p,
				    struct bgp_path_info *parent_pi)
{
	int ret = 0;
	char prefix_str[PREFIX2STR_BUFFER] = { 0 };
	struct prefix tmp;

	if (bgp_debug_update(parent_pi->peer, NULL, NULL, 1) || bgp_debug_zebra(NULL))
		zlog_debug(
			"%s (%u): Installing EVPN %pFX route in EVI %u IP/MAC table",
			vrf_id_to_name(bgp->vrf_id), bgp->vrf_id, p, evi->vni);

	tmp.family = p->family;
	tmp.prefixlen = p->prefixlen;
	tmp.u.prefix_evpn = p->prefix;
	prefix2str(&tmp, prefix_str, sizeof(prefix_str));
	frrtrace(4, frr_bgp, upd_evpn_route_entry, 1, bgp->vrf_id, prefix_str, evi->vni);

	ret = bgp_evpn_evi_install_route_entry_mac(bgp, evi, p, parent_pi);

	if (ret) {
		flog_err(
			EC_BGP_EVPN_FAIL,
			"%s (%u): Failed to install EVPN %pFX route in EVI %u MAC table",
			vrf_id_to_name(bgp->vrf_id), bgp->vrf_id, p, evi->vni);

		return ret;
	}

	ret = bgp_evpn_evi_install_route_entry_ip(bgp, evi, p, parent_pi);

	if (ret) {
		flog_err(
			EC_BGP_EVPN_FAIL,
			"%s (%u): Failed to install EVPN %pFX route in EVI %u IP table",
			vrf_id_to_name(bgp->vrf_id), bgp->vrf_id, p, evi->vni);

		return ret;
	}

	return ret;
}

/*
 * Uninstall route entry from the VNI routing tables.
 */
static int bgp_evpn_evi_uninstall_route_entry(struct bgp *bgp, struct bgp_evpn_evi *evi,
				      const struct prefix_evpn *p,
				      struct bgp_path_info *parent_pi)
{
	int ret = 0;
	char prefix_str[PREFIX2STR_BUFFER] = { 0 };
	struct prefix tmp;

	if (bgp_debug_update(parent_pi->peer, NULL, NULL, 1))
		zlog_debug(
			"%s (%u): Uninstalling EVPN %pFX route from VNI %u IP/MAC table",
			vrf_id_to_name(bgp->vrf_id), bgp->vrf_id, p, evi->vni);

	tmp.family = p->family;
	tmp.prefixlen = p->prefixlen;
	tmp.u.prefix_evpn = p->prefix;
	prefix2str(&tmp, prefix_str, sizeof(prefix_str));
	frrtrace(4, frr_bgp, upd_evpn_route_entry, 0, bgp->vrf_id, prefix_str, evi->vni);

	ret = bgp_evpn_evi_uninstall_route_entry_ip(bgp, evi, p, parent_pi);

	if (ret) {
		flog_err(
			EC_BGP_EVPN_FAIL,
			"%s (%u): Failed to uninstall EVPN %pFX route from VNI %u IP table",
			vrf_id_to_name(bgp->vrf_id), bgp->vrf_id, p, evi->vni);

		return ret;
	}

	ret = bgp_evpn_evi_uninstall_route_entry_mac(bgp, evi, p, parent_pi);

	if (ret) {
		flog_err(
			EC_BGP_EVPN_FAIL,
			"%s (%u): Failed to uninstall EVPN %pFX route from VNI %u MAC table",
			vrf_id_to_name(bgp->vrf_id), bgp->vrf_id, p, evi->vni);

		return ret;
	}

	return ret;
}

/*
 * Given a route entry and a VRF, check if this route matches
 * the import route targets for the VRF
 */
static int bgp_evpn_vrf_check_route_matches_import_rts(struct bgp *bgp_vrf,
				     struct bgp_path_info *pi)
{
	struct attr *attr = pi->attr;
	struct ecommunity *ecom;
	uint32_t i;

	assert(attr);
	/* Route should have valid RT to be even considered. */
	if (!bgp_attr_exists(attr, BGP_ATTR_EXT_COMMUNITIES))
		return 0;

	ecom = bgp_attr_get_ecommunity(attr);
	if (!ecom || !ecom->size)
		return 0;

	/* For each Route Target attached to the route, see if it matches this VRF.
	 * If any RT matches, we're done. Route Targets are BGP extended communities.
	 */
	for (i = 0; i < ecom->size; i++) {
		uint8_t *pnt;
		uint8_t sub_type;
		struct ecommunity_val *eval;

		/* Only deal with extended communities that are Route Targets */
		pnt = (ecom->val + (i * ecom->unit_size));
		eval = (struct ecommunity_val *)(ecom->val + (i * ecom->unit_size));
		/*type = **/pnt++;
		sub_type = *pnt++;
		if (sub_type != ECOMMUNITY_ROUTE_TARGET)
			continue;

		struct vrf_mapped_bgp_instance tmp_lookup;
		tmp_lookup.bgp = bgp_vrf;

		/* First check the wildcard route-target because auto import RTs are wildcards
		 * so we have a better chance succeeeding here!
		 */
		struct vrf_wildcard_irt_node* wildcard_irt = lookup_vrf_wildcard_irt_node_by_ecom_val(*eval);
		if(wildcard_irt != NULL && vrf_mapped_bgp_instance_slu_find(&wildcard_irt->vrfs, &tmp_lookup) != NULL)
			return 1;

		/* Now check for regular route targets */
		struct vrf_fq_irt_node* fq_irt = lookup_vrf_fq_irt_node_by_ecom_val(*eval);
		if (fq_irt != NULL && vrf_mapped_bgp_instance_slu_find(&fq_irt->vrfs, &tmp_lookup) != NULL)
			return 1;
	}

	return 0;
}

/*
 * Given a route entry and an EVI, check if this route matches
 * the import route targets for the EVI
 */
static int bgp_evpn_evi_check_route_matches_import_rts(struct bgp *bgp, struct bgp_evpn_evi *evi,
				     struct bgp_path_info *pi)
{
	struct attr *attr = pi->attr;
	struct ecommunity *ecom;
	uint32_t i;

	assert(attr);
	/* Route should have valid RT to be even considered. */
	if (!bgp_attr_exists(attr, BGP_ATTR_EXT_COMMUNITIES))
		return 0;

	ecom = bgp_attr_get_ecommunity(attr);
	if (!ecom || !ecom->size)
		return 0;

	/* For each Route Target attached to the route, see if it matches this EVI.
	 * If any RT matches, we're done. Route Targets are BGP extended communities.
	 */
	for (i = 0; i < ecom->size; i++) {
		uint8_t *pnt;
		uint8_t sub_type;
		struct ecommunity_val *eval;

		/* Only deal with extended communities that are Route Targets */
		pnt = (ecom->val + (i * ecom->unit_size));
		eval = (struct ecommunity_val *)(ecom->val + (i * ecom->unit_size));
		/*type = **/pnt++;
		sub_type = *pnt++;
		if (sub_type != ECOMMUNITY_ROUTE_TARGET)
			continue;

		struct evi_mapped_evi tmp_lookup;
		tmp_lookup.evi = evi;

		/* First check the wildcard route-target because auto import RTs are wildcards
		 * so we have a better chance succeeeding here!
		 */
		struct evi_wildcard_irt_node* wildcard_irt = lookup_evi_wildcard_irt_node_by_ecom_val(*eval);
		if(wildcard_irt != NULL && evi_mapped_evi_slu_find(&wildcard_irt->evis, &tmp_lookup) != NULL)
			return 1;

		/* Now check for regular route targets */
		struct evi_fq_irt_node* fq_irt = lookup_evi_fq_irt_node_by_ecom_val(*eval);
		if (fq_irt != NULL && evi_mapped_evi_slu_find(&fq_irt->evis, &tmp_lookup) != NULL)
			return 1;
	}

	return 0;
}

static bool bgp_evpn_route_matches_macvrf_soo(struct bgp_path_info *pi,
					      const struct prefix_evpn *evp)
{
	struct bgp *bgp_evpn_mi = bgp_get_evpn_master_instance();
	struct ecommunity *macvrf_soo;
	bool ret = false;

	if (!bgp_evpn_mi || !bgp_evpn_mi->evpn_info)
		return false;

	/* We only stamp the mac-vrf soo on routes from our local L2VNI.
	 * No need to filter additional EVPN routes that originated outside
	 * the MAC-VRF/L2VNI.
	 */
	if (evp->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE &&
	    evp->prefix.route_type != BGP_EVPN_IMET_ROUTE)
		return false;

	macvrf_soo = bgp_evpn_mi->evpn_info->soo;
	ret = route_matches_soo(pi, macvrf_soo);

	if (ret && bgp_debug_zebra(NULL)) {
		char *ecom_str;

		ecom_str = ecommunity_ecom2str(macvrf_soo,
					       ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
		zlog_debug(
			"import of evpn prefix %pFX skipped, local mac-vrf soo %s",
			evp, ecom_str);
		ecommunity_strfree(&ecom_str);
	}

	return ret;
}

/* This API will scan evpn routes for checking attribute's rmac
 * matches with bgp instance router mac. It avoid installing
 * route into bgp vrf table and remote rmac in bridge table.
 */
static int bgp_evpn_route_rmac_self_check(struct bgp *bgp_vrf,
					  const struct prefix_evpn *evp,
					  struct bgp_path_info *pi)
{
	/* evpn route could have learnt prior to L3vni has come up,
	 * perform rmac check before installing route and
	 * remote router mac.
	 * The route will be removed from global bgp table once
	 * SVI comes up with MAC and stored in hash, triggers
	 * bgp_mac_rescan_all_evpn_tables.
	 */
	if (memcmp(&bgp_vrf->rmac, &pi->attr->rmac, ETH_ALEN) == 0) {
		/* Only do expensive string formatting if debug or trace is enabled. */
		if (bgp_debug_update(pi->peer, NULL, NULL, 1) ||
		    frrtrace_enabled(frr_bgp, upd_prefix_denied_due_to_self_mac)) {
			char prefix_str[PREFIX2STR_BUFFER] = { 0 };
			char attr_str[BUFSIZ] = { 0 };
			struct prefix tmp;

			bgp_dump_attr(pi->attr, attr_str, sizeof(attr_str));

			if (bgp_debug_update(pi->peer, NULL, NULL, 1))
				zlog_debug("%s: bgp %u prefix %pFX with attr %s - DENIED due to self mac",
					   __func__, bgp_vrf->vrf_id, evp, attr_str);

			tmp.family = evp->family;
			tmp.prefixlen = evp->prefixlen;
			tmp.u.prefix_evpn = evp->prefix;
			prefix2str(&tmp, prefix_str, sizeof(prefix_str));
			frrtrace(3, frr_bgp, upd_prefix_denied_due_to_self_mac, bgp_vrf->vrf_id,
				 prefix_str, attr_str);
		}

		return 1;
	}

	return 0;
}

/* Helper for installing routes into VRFs:
 * Don't import routes that point to a local ethernet segment!
 */
bool bgp_evpn_skip_vrf_import_of_local_es(struct bgp *bgp_vrf, const struct prefix_evpn *evp,
					  struct bgp_path_info *pi, int install)
{
	esi_t *esi;

	if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) {
		esi = bgp_evpn_attr_get_esi(pi->attr);

		/* Don't import routes that point to a local destination */
		if (bgp_evpn_attr_is_local_es(pi->attr)) {
			if (BGP_DEBUG(evpn_mh, EVPN_MH_RT)) {
				char esi_buf[ESI_STR_LEN];

				zlog_debug(
					"vrf %s of evpn prefix %pFX skipped, local es %s",
					install ? "import" : "unimport", evp,
					esi_to_str(esi, esi_buf,
						   sizeof(esi_buf)));
			}
			return true;
		}
	}
	return false;
}

/*
 * Install or uninstall Route Type 2 (MAC-IP) or Route Type 5 (IP Prefix) routes
 * if the route is applicable - primarily checks Route targets, but also
 * performs some additional checks to filter out routes (e.g. don't import routes
 * that carry our own router MAC)
 */
int bgp_evpn_vrf_install_uninstall_route_entry_if_match(struct bgp *bgp_vrf,
					      struct bgp_path_info *pi,
					      int install)
{
	int ret = 0;
	const struct prefix_evpn *evp =
		(const struct prefix_evpn *)bgp_dest_get_prefix(pi->net);

	/* Consider "valid" remote routes applicable for
	 * this VRF.
	 */
	if (!(CHECK_FLAG(pi->flags, BGP_PATH_VALID) && pi->type == ZEBRA_ROUTE_BGP &&
	      pi->sub_type == BGP_ROUTE_NORMAL))
		/* TODO: Tracing? Would be nice to show the user WHY a route is denied */
		return 0;

	/* Actual hard work aka checking route targets is done by bgp_evpn_vrf_check_route_matches_import_rts */
	if (!bgp_evpn_vrf_check_route_matches_import_rts(bgp_vrf, pi))
		/* TODO: Tracing? Would be nice to show the user WHY a route is denied */
		return 0; /* route does not match VRF's import RTs -> skip */

	if (bgp_evpn_route_rmac_self_check(bgp_vrf, evp, pi))
		/* reject routes that carry our own router MAC
	     * While EVPN could probably theoretically work even if we import such routes
		 * it's pretty much a safe sign of a user messing up or some timing things during startup
		 * so let's just safe ourselves the headache and not import those routes
	     */
		/* TODO: Tracing? Would be nice to show the user WHY a route is denied */
		return 0;

	/* don't import hosts that are locally attached */
	if (install && (bgp_evpn_skip_vrf_import_of_local_es(bgp_vrf, evp, pi, install) ||
			bgp_evpn_route_matches_macvrf_soo(pi, evp)))
		/* TODO: Tracing? Would be nice to show the user WHY a route is denied */
		return 0;

	if (install)
		ret = _bgp_evpn_vrf_install_route_entry(bgp_vrf, evp, pi);
	else
		ret = _bgp_evpn_vrf_uninstall_route_entry(bgp_vrf, evp, pi);

	if (ret)
		flog_err(EC_BGP_EVPN_FAIL,
				"Failed to %s EVPN %pFX route in VRF %s",
				install ? "install" : "uninstall", evp,
				vrf_id_to_name(bgp_vrf->vrf_id));

	return ret;
}

/*
 * Walk entire global routing table to evaluate which
 * Route Type 2 (MAC-IP) or Route Type 5 (IP Prefix) routes are applicable for this VRF
 * and then install or uninstall them
 * Main work is performed by bgp_evpn_vrf_install_uninstall_route_entry_if_match
 *
 * Expensive operation due to global routing table walk! Use sparingly
 *
 * This function makes use of the effective RTs, so if you change the effective
 * RTs, make sure to call this with uninstall BEFORE you change the effective RTs
 * to ensure proper removal of old routes that no longer match the new RTs!
 */
static int bgp_evpn_vrf_install_uninstall_global_routes(struct bgp *bgp_vrf, bool install)
{
	afi_t afi;
	safi_t safi;
	struct bgp_dest *rd_dest, *dest;
	struct bgp_table *table;
	struct bgp_path_info *pi;
	int ret;
	struct bgp *bgp_evpn_mi = NULL;

	afi = AFI_L2VPN;
	safi = SAFI_EVPN;
	bgp_evpn_mi = bgp_get_evpn_master_instance();
	if (!bgp_evpn_mi)
		return -1;

	/* Walk entire global routing table and evaluate routes which could be
	 * imported into this VRF. Note that we need to loop through all global
	 * routes to determine which route matches the import rt on vrf
	 */
	for (rd_dest = bgp_table_top(bgp_evpn_mi->rib[afi][safi]); rd_dest;
	     rd_dest = bgp_route_next(rd_dest)) {
		table = bgp_dest_get_bgp_table_info(rd_dest);
		if (!table)
			continue;

		for (dest = bgp_table_top(table); dest;
		     dest = bgp_route_next(dest)) {
			const struct prefix_evpn *evp =
				(const struct prefix_evpn *)bgp_dest_get_prefix(
					dest);

			/* VRFs only import Route Type 2 (MAC-IP) or Route Type 5 (IP Prefix), so skip others */
			if (!(evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE ||
			      evp->prefix.route_type == BGP_EVPN_IP_PREFIX_ROUTE))
				/* TODO: Tracing? Would be nice to show the user WHY a route is denied */
				continue;

			/* If the route does not contain an IP address, skip it
			 * This can happen for Route Type 2 (MAC-IP), because the IP address is optional
			 * This should NOT happen for Route Type 5 (IP Prefix)...
			 */
			if (!(is_evpn_prefix_ipaddr_v4(evp) || is_evpn_prefix_ipaddr_v6(evp)))
				/* TODO: Tracing? Would be nice to show the user WHY a route is denied */
				continue;

			for (pi = bgp_dest_get_bgp_path_info(dest); pi != NULL; pi = pi->next) {
				/* Actual hard work is done by this function */
				ret = bgp_evpn_vrf_install_uninstall_route_entry_if_match(bgp_vrf, pi,
										install);
				if (ret) {
					bgp_dest_unlock_node(rd_dest);
					bgp_dest_unlock_node(dest);
					return ret;
				}
			}
		}
	}

	return 0;
}

/* Install remote Route Type 2 (MAC-IP) or Route Type 5 (IP Prefix) routes
 * applicable for this VRF into VRF RIB. This is invoked e.g. AFTER the effective
 * import VRF Route Targets change
 *
 * Walks the entire global routing table to evaluate which routes are
 * applicable for this VRF!
 * Expensive operation due to global routing table walk! Use sparingly
 */
int bgp_evpn_vrf_install_global_routes(struct bgp *bgp_vrf)
{
	return bgp_evpn_vrf_install_uninstall_global_routes(bgp_vrf, true);
}

/* Install remote Route Type 2 (MAC-IP) or Route Type 5 (IP Prefix) routes
 * applicable for this VRF into VRF RIB. This is invoked e.g. BEFORE the effective
 * import VRF Route Targets change
 * This function makes use of the effective RTs, so if you change the effective
 * RTs, make sure to call this BEFORE you change the effective RTs to ensure proper
 * removal of old routes that no longer match the new RTs
 * Walks the entire global routing table to evaluate which routes are
 * applicable for this VRF!
 * Expensive operation due to global routing table walk! Use sparingly
 */
int bgp_evpn_vrf_uninstall_global_routes(struct bgp *bgp_vrf)
{
	return bgp_evpn_vrf_install_uninstall_global_routes(bgp_vrf, false);
}



#define BGP_PROC_L2VNI_LIMIT 10
static int install_evpn_remote_route_per_l2vni(struct bgp *bgp, struct bgp_path_info *pi,
					       const struct prefix_evpn *evp)
{
	int ret = 0;
	uint8_t vni_iter = 0;
	struct bgp_evpn_evi *t_evi = NULL;
	struct bgp_evpn_evi *t_evi_next = NULL;

	for (t_evi = zebra_l2_vni_first(&bm->zebra_l2_vni_head);
	     t_evi && vni_iter < BGP_PROC_L2VNI_LIMIT; t_evi = t_evi_next) {
		t_evi_next = zebra_l2_vni_next(&bm->zebra_l2_vni_head, t_evi);
		vni_iter++;
		/*
		 * Skip install/uninstall if the route entry is not needed to
		 * be imported into the VNI i.e. RTs dont match
		 */
		if (!bgp_evpn_evi_check_route_matches_import_rts(bgp, t_evi, pi))
			continue;

		ret = bgp_evpn_evi_install_route_entry(bgp, t_evi, evp, pi);

		if (ret) {
			flog_err(EC_BGP_EVPN_FAIL,
				 "%u: Failed to install EVPN %s route in VNI %u during BP",
				 bgp->vrf_id, bgp_evpn_route_type_str[evp->prefix.route_type].str,
				 t_evi->vni);
			zebra_l2_vni_del(&bm->zebra_l2_vni_head, t_evi);

			return ret;
		}
	}

	return 0;
}

/*
 * Install or uninstall routes of specified type that are appropriate for this
 * particular EVI.
 */
int bgp_evpn_evi_install_uninstall_routes(struct bgp *bgp, struct bgp_evpn_evi *evi, bool install)
{
	afi_t afi;
	safi_t safi;
	struct bgp_dest *rd_dest, *dest;
	struct bgp_table *table;
	struct bgp_path_info *pi;
	int ret = 0;
	uint8_t count = 0;
	bool walk_fifo = false;

	afi = AFI_L2VPN;
	safi = SAFI_EVPN;

	/* Why is this not documented anywhere? Why can this be null?? */
	if (!bgp) {
		walk_fifo = true;
		bgp = bgp_get_evpn_master_instance();
		if (!bgp) {
			zlog_warn("%s: No BGP EVPN instance found...", __func__);

			return -1;
		}
	}

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("%s: Total %u L2VNI VPNs pending to be processed for remote route installation",
			   __func__, (uint32_t)zebra_l2_vni_count(&bm->zebra_l2_vni_head));
	/*
	 * Walk entire global routing table and evaluate routes which could be
	 * imported into this VPN. Note that we cannot just look at the routes
	 * for the VNI's RD - remote routes applicable for this VNI could have
	 * any RD.
	 * Note: EVPN routes are a 2-level table.
	 */
	for (rd_dest = bgp_table_top(bgp->rib[afi][safi]); rd_dest;
	     rd_dest = bgp_route_next(rd_dest)) {
		table = bgp_dest_get_bgp_table_info(rd_dest);
		if (!table)
			continue;

		for (dest = bgp_table_top(table); dest;
		     dest = bgp_route_next(dest)) {
			const struct prefix_evpn *evp =
				(const struct prefix_evpn *)bgp_dest_get_prefix(
					dest);

			/* Proceed only for AD, MAC_IP and IMET routes */
			switch (evp->prefix.route_type) {
			case BGP_EVPN_AD_ROUTE:
			case BGP_EVPN_MAC_IP_ROUTE:
			case BGP_EVPN_IMET_ROUTE:
				break;
			case BGP_EVPN_ES_ROUTE:
			case BGP_EVPN_IP_PREFIX_ROUTE:
				continue;
			}

			for (pi = bgp_dest_get_bgp_path_info(dest); pi;
			     pi = pi->next) {
				/*
				 * Skip install/uninstall if
				 * - Not a valid remote routes
				 * - Install & evpn route matchesi macvrf SOO
				 */
				if (!(CHECK_FLAG(pi->flags, BGP_PATH_VALID) &&
				      pi->type == ZEBRA_ROUTE_BGP &&
				      pi->sub_type == BGP_ROUTE_NORMAL) ||
				    (install && bgp_evpn_route_matches_macvrf_soo(pi, evp)))
					continue;

				if (walk_fifo) {
					ret = install_evpn_remote_route_per_l2vni(bgp, pi, evp);
					if (ret) {
						bgp_dest_unlock_node(rd_dest);
						bgp_dest_unlock_node(dest);
						return ret;
					}
				} else {
					/*
					 * Skip install/uninstall if the route
					 * entry is not needed to be imported
					 * into the VNI i.e. RTs dont match
					 */
					if (!bgp_evpn_evi_check_route_matches_import_rts(bgp, evi, pi))
						continue;

					if (install)
						ret = bgp_evpn_evi_install_route_entry(bgp, evi, evp, pi);
					else
						ret = bgp_evpn_evi_uninstall_route_entry(bgp, evi, evp, pi);

					if (ret) {
						flog_err(EC_BGP_EVPN_FAIL,
							 "%u: Failed to %s EVPN %s route in VNI %u",
							 bgp->vrf_id,
							 install ? "install" : "uninstall",
							 bgp_evpn_route_type_str[evp->prefix.route_type]
								 .str,
							 evi->vni);

						bgp_dest_unlock_node(rd_dest);
						bgp_dest_unlock_node(dest);
						return ret;
					}
				}
			}
		}
	}

	if (walk_fifo) {
		while (count < BGP_PROC_L2VNI_LIMIT) {
			evi = zebra_l2_vni_pop(&bm->zebra_l2_vni_head);
			if (!evi)
				return 0;

			UNSET_FLAG(evi->flags, EVI_FLAG_ADD);
			count++;
		}
	}

	return 0;
}


/*
 * Install or uninstall route in a list of VRFs - does NOT check whether the route
 * belongs there (NO Route Target check!)
 * Performs some sanity filtering like
 *  - only RT2 / RT5 (other routes cannot carry an IP address)
 *  - no routes without IP address (otherwise we have nothing to import into the VRF!)
 *  - no routes that point to a local ethernet segment
 * This is supposed to be used with imported routes (i.e. routes received from peers)
 */
static int bgp_evpn_install_uninstall_route_in_vrf_list(struct bgp *bgp_def, afi_t afi,
					   safi_t safi, struct prefix_evpn *evp,
					   struct bgp_path_info *pi,
					   struct vrf_mapped_bgp_instance_slu_head* vrfs, int install)
{
	struct vrf_mapped_bgp_instance *vrf_item;

	/* VRFs only import Route Type 2 (MAC-IP) or Route Type 5 (IP Prefix), so skip others */
	if (!(evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE ||
			evp->prefix.route_type == BGP_EVPN_IP_PREFIX_ROUTE))
		/* TODO: Tracing? Would be nice to show the user WHY a route is denied */
		return 0;

	/* If the route does not contain an IP address, skip it
	 * This can happen for Route Type 2 (MAC-IP), because the IP address is optional
	 * This should NOT happen for Route Type 5 (IP Prefix)...
	 */
	if (!(is_evpn_prefix_ipaddr_v4(evp) || is_evpn_prefix_ipaddr_v6(evp)))
		/* TODO: Tracing? Would be nice to show the user WHY a route is denied */
		return 0;

	frr_each(vrf_mapped_bgp_instance_slu, vrfs, vrf_item) {
		int ret;

		/* Don't import routes that point to a local ethernet segment! */
		if (install && bgp_evpn_skip_vrf_import_of_local_es(
				       vrf_item->bgp, evp, pi, install))
			return 0;

		if (install)
			ret = _bgp_evpn_vrf_install_route_entry(vrf_item->bgp, evp, pi);
		else
			ret = _bgp_evpn_vrf_uninstall_route_entry(vrf_item->bgp, evp,
								pi);

		if (ret) {
			flog_err(EC_BGP_EVPN_FAIL,
				 "%u: Failed to %s prefix %pFX in VRF %s",
				 bgp_def->vrf_id,
				 install ? "install" : "uninstall", evp,
				 vrf_id_to_name(vrf_item->bgp->vrf_id));
			return ret;
		}
	}

	return 0;
}

/*
 * Install or uninstall route in matching EVIs (list).
 */
static int bgp_evpn_install_uninstall_route_in_evi_list(struct bgp *bgp, afi_t afi,
					   safi_t safi, struct prefix_evpn *evp,
					   struct bgp_path_info *pi,
					   struct evi_mapped_evi_slu_head* evis, int install)
{
	struct evi_mapped_evi *evi_item;

	/* EVIs only import Route Type 1 (AD), Route Type 2 (MAC-IP) or Route Type 3 (IMET), so skip others */
	if (!(evp->prefix.route_type == BGP_EVPN_AD_ROUTE ||
			evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE ||
			evp->prefix.route_type == BGP_EVPN_IMET_ROUTE))
		/* TODO: Tracing? Would be nice to show the user WHY a route is denied */
		return 0;

	frr_each(evi_mapped_evi_slu, evis, evi_item) {
		int ret;

		if (install)
			ret = bgp_evpn_evi_install_route_entry(bgp, evi_item->evi, evp, pi);
		else
			ret = bgp_evpn_evi_uninstall_route_entry(bgp, evi_item->evi, evp, pi);

		if (ret) {
			const char *route_type_str = "Unknown";
			switch (evp->prefix.route_type) {
			case BGP_EVPN_AD_ROUTE:
				route_type_str = "AD";
				break;
			case BGP_EVPN_MAC_IP_ROUTE:
				route_type_str = "MACIP";
				break;
			case BGP_EVPN_IMET_ROUTE:
				route_type_str = "IMET";
				break;
			}
			flog_err(EC_BGP_EVPN_FAIL,
				 "%u: Failed to %s EVPN %s route in EVI with VNI %u",
				 bgp->vrf_id, install ? "install" : "uninstall",
				 route_type_str,
				 evi_item->evi->vni);
			return ret;
		}
	}

	return 0;
}

/*
 * Install or uninstall an EVPN route into appropriate VRFs / EVIs / ESs
 * This is supposed to be used with imported routes (i.e. routes received from peers)
 */
static int bgp_evpn_install_uninstall_route(struct bgp *bgp, afi_t afi, safi_t safi,
					const struct prefix *p,
					struct bgp_path_info *pi, int import)
{
	struct prefix_evpn *evp = (struct prefix_evpn *)p;
	struct attr *attr = pi->attr;
	struct ecommunity *ecom;
	uint32_t i;
	struct prefix_evpn ad_evp;

	assert(attr);

	/* Only EVPN route-types 1-5 are supported currently */
	if (!(evp->prefix.route_type == BGP_EVPN_AD_ROUTE /* Route Type 1 */
	      || evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE /* Route Type 2 */
	      || evp->prefix.route_type == BGP_EVPN_IMET_ROUTE /* Route Type 3 */
	      || evp->prefix.route_type == BGP_EVPN_ES_ROUTE /* Route Type 4 */
	      || evp->prefix.route_type == BGP_EVPN_IP_PREFIX_ROUTE /* Route Type 5 */))
		/* TODO: Tracing? Would be nice to show the user why a route is not imported */
		return 0;

	/* If we don't have Route Target, nothing much to do. */
	if (!bgp_attr_exists(attr, BGP_ATTR_EXT_COMMUNITIES))
		/* TODO: Tracing? Would be nice to show the user why a route is not imported */
		return 0;

	/* EAD prefix in the global table doesn't include the VTEP-IP so
	 * we need to create a different copy for the VNI
	 */
	if (evp->prefix.route_type == BGP_EVPN_AD_ROUTE)
		evp = evpn_type1_prefix_vni_ip_copy(&ad_evp, evp, attr);

	ecom = bgp_attr_get_ecommunity(attr);
	if (!ecom || !ecom->size)
		/* TODO: Tracing? Would be nice to show the user why a route is not imported */
		return -1;

	/* Filter routes carrying a Site-of-Origin that matches our
	 * local MAC-VRF SoO.
	 */
	if (import && bgp_evpn_route_matches_macvrf_soo(pi, evp))
		/* TODO: Tracing? Would be nice to show the user why a route is not imported */
		return 0;

	/* An EVPN route belongs to a VRF, an EVI or an ES based on the Route Targets
	 * attached to the route - iterate through all route targets and install the route
	 * into the appropriate VRFs / EVIs / ESs
	 */
	for (i = 0; i < ecom->size; i++) {
		uint8_t *pnt;
		uint8_t /*rt_type, */rt_sub_type;
		struct ecommunity_val *eval;
		struct bgp_evpn_es *es;

		/* Only deal with RTs */
		pnt = (ecom->val + (i * ecom->unit_size));
		eval = (struct ecommunity_val *)(ecom->val
						 + (i * ecom->unit_size));
		/* TODO: Perform validation of RT Type? But if the RT type is "wrong" or unsupported
		 * no import route target should match (wildcard import performs its own validation
		 * and will just bail out if the RT type is unexpected)
		 */
		/* rt_type = **/pnt++;
		rt_sub_type = *pnt++;
		if (rt_sub_type != ECOMMUNITY_ROUTE_TARGET)
			continue;

		/* non-local MAC-IP routes in the global route table are linked
		 * to the destination ES
		 */
		if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE)
			bgp_evpn_path_es_link(pi, 0,
					      bgp_evpn_attr_get_esi(pi->attr));

		/*
		 * AD/IMET routes (type-1/3) are imported into EVIs
		 * MACIP routes (type-2) are imported into VRFs and EVIs
		 * Prefix routes (type 5) are imported into VRFs
		 */
		if (evp->prefix.route_type == BGP_EVPN_AD_ROUTE ||
			evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE ||
		    evp->prefix.route_type == BGP_EVPN_IMET_ROUTE ||
		    evp->prefix.route_type == BGP_EVPN_IP_PREFIX_ROUTE) {


			/* Determine VRFs to import to for
			 * Route Type 2 (MAC-IP) and Route Type 5 (IP Prefix)
			 */
			if(evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE /* Route Type 2 */
				|| evp->prefix.route_type == BGP_EVPN_IP_PREFIX_ROUTE /* Route Type 5 */) {

				/* A route can match both a wildcard RT and a regular RT at the same time! */
				/* Check Wildcard RT first */
				struct vrf_wildcard_irt_node* vrf_wildcard_irt = lookup_vrf_wildcard_irt_node_by_ecom_val(*eval);
				if(vrf_wildcard_irt != NULL)
					bgp_evpn_install_uninstall_route_in_vrf_list(
					bgp, afi, safi, evp, pi, &vrf_wildcard_irt->vrfs,
					import);
				
				/* Now check for regular route targets */
				struct vrf_fq_irt_node* vrf_fq_irt = lookup_vrf_fq_irt_node_by_ecom_val(*eval);
				if (vrf_fq_irt != NULL)
					bgp_evpn_install_uninstall_route_in_vrf_list(
					bgp, afi, safi, evp, pi, &vrf_fq_irt->vrfs,
					import);
				
			}

			/* Determine list of EVIs to import to for
			 * Route Type 1 (AD), 2 (MACIP), 3 (IMET)
			 */
			if (evp->prefix.route_type == BGP_EVPN_AD_ROUTE /* Route Type 1 */
				|| evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE /* Route Type 2 */
				|| evp->prefix.route_type == BGP_EVPN_IMET_ROUTE /* Route Type 3 */) {

				/* A route can match both a wildcard RT and a regular RT at the same time! */
				/* Check Wildcard RT first */
				struct evi_wildcard_irt_node* evi_wildcard_irt = lookup_evi_wildcard_irt_node_by_ecom_val(*eval);
				if(evi_wildcard_irt != NULL)
					bgp_evpn_install_uninstall_route_in_evi_list(
					bgp, afi, safi, evp, pi, &evi_wildcard_irt->evis,
					import);
				
				/* Now check for regular route targets */
				struct evi_fq_irt_node* evi_fq_irt = lookup_evi_fq_irt_node_by_ecom_val(*eval);
				if (evi_fq_irt != NULL)
					bgp_evpn_install_uninstall_route_in_evi_list(
					bgp, afi, safi, evp, pi, &evi_fq_irt->evis,
					import);
				
			}
		} else if (evp->prefix.route_type == BGP_EVPN_ES_ROUTE) {
			/* ES routes are imported into the ES table
			 * We match based on the entire ESI to avoid importing
			 * an ES route for ES1 into ES2
			 */
			es = bgp_evpn_es_find(&evp->prefix.es_addr.esi);
			if (es && bgp_evpn_is_es_local(es))
				bgp_evpn_es_route_install_uninstall(
					bgp, es, afi, safi, evp, pi, import);
		} /* else -> should not happen */
	}

	return 0;
}

void bgp_evpn_import_type2_route(struct bgp_path_info *pi, int import)
{
	struct bgp *bgp_evpn_mi;

	bgp_evpn_mi = bgp_get_evpn_master_instance();
	if (!bgp_evpn_mi)
		return;

	bgp_evpn_install_uninstall_route(bgp_evpn_mi, AFI_L2VPN, SAFI_EVPN,
				     &pi->net->rn->p, pi, import);
}

/*
 * delete and withdraw all ipv4all originated route type 5 routes for all AFI / SAFI
 * (e.g. from routes injected from the the VRF table)
 */
static void bgp_evpn_vrf_delete_withdraw_originated_type_5_routes(struct bgp *bgp_vrf)
{
	/* Delete ipv4 default route and withdraw from peers */
	if (evpn_default_originate_set(bgp_vrf, AFI_IP, SAFI_UNICAST))
		bgp_evpn_install_uninstall_default_route(bgp_vrf, AFI_IP, SAFI_UNICAST, NULL,
							 false);

	/* delete all ipv4 routes and withdraw from peers */
	if (bgp_evpn_should_originate_type5_routes_bestpath(bgp_vrf, AFI_IP) ||
	    bgp_evpn_should_originate_type5_routes_multipath(bgp_vrf, AFI_IP))
		bgp_evpn_vrf_eject_afi_safi_prefixes_and_withdraw_their_type5_routes(bgp_vrf, AFI_IP, SAFI_UNICAST);

	/* Delete ipv6 default route and withdraw from peers */
	if (evpn_default_originate_set(bgp_vrf, AFI_IP6, SAFI_UNICAST))
		bgp_evpn_install_uninstall_default_route(bgp_vrf, AFI_IP6, SAFI_UNICAST, NULL,
							 false);

	/* delete all ipv6 routes and withdraw from peers */
	if (bgp_evpn_should_originate_type5_routes_bestpath(bgp_vrf, AFI_IP6) ||
	    bgp_evpn_should_originate_type5_routes_multipath(bgp_vrf, AFI_IP6))
		bgp_evpn_vrf_eject_afi_safi_prefixes_and_withdraw_their_type5_routes(bgp_vrf, AFI_IP6, SAFI_UNICAST);
}

/*
 * Create / Update and advertise all originated route type 5 routes for all AFI / SAFI
 * (e.g. from routes injected from the the VRF table)
 */
void bgp_evpn_vrf_update_advertise_originated_type_5_routes(struct bgp *bgp_vrf)
{
	struct bgp *bgp_evpn_mi = NULL; /* EVPN bgp instance */

	bgp_evpn_mi = bgp_get_evpn_master_instance();
	if (!bgp_evpn_mi)
		return;

	if (!is_l3vni_live(bgp_vrf))
		return; /* Nothing to do if no l3vni */

	/* update all ipv4 routes */
	if (bgp_evpn_should_originate_type5_routes_bestpath(bgp_vrf, AFI_IP) ||
	    bgp_evpn_should_originate_type5_routes_multipath(bgp_vrf, AFI_IP))
		bgp_evpn_vrf_inject_safi_afi_prefixes_and_originate_as_type5_routes(bgp_vrf, AFI_IP, SAFI_UNICAST);

	/* update ipv4 default route and withdraw from peers */
	if (evpn_default_originate_set(bgp_vrf, AFI_IP, SAFI_UNICAST))
		bgp_evpn_install_uninstall_default_route(bgp_vrf, AFI_IP, SAFI_UNICAST, NULL, true);

	/* update all ipv6 routes */
	if (bgp_evpn_should_originate_type5_routes_bestpath(bgp_vrf, AFI_IP6) ||
	    bgp_evpn_should_originate_type5_routes_multipath(bgp_vrf, AFI_IP6))
		bgp_evpn_vrf_inject_safi_afi_prefixes_and_originate_as_type5_routes(bgp_vrf, AFI_IP6, SAFI_UNICAST);

	/* update ipv6 default route and withdraw from peers */
	if (evpn_default_originate_set(bgp_vrf, AFI_IP6, SAFI_UNICAST))
		bgp_evpn_install_uninstall_default_route(bgp_vrf, AFI_IP6, SAFI_UNICAST, NULL,
							 true);
}

/*
 * update and advertise local routes for a VRF as type-5 routes.
 * This is invoked upon RD change for a VRF. Note that the processing is only
 * done in the global route table using the routes which already exist in the
 * VRF routing table
 */
static void update_router_id_vrf(struct bgp *bgp_vrf)
{
	/* skip if the RD is configured */
	if (is_vrf_rd_configured(bgp_vrf))
		return;

	/* derive the RD for the VRF based on new router-id */
	bgp_evpn_vrf_derive_auto_rd(bgp_vrf);

	/* update advertise ipv4|ipv6 routes as type-5 routes */
	bgp_evpn_vrf_update_advertise_originated_type_5_routes(bgp_vrf);
}

/*
 * Delete and withdraw all type-5 routes  for the RD corresponding to VRF.
 * This is invoked upon VRF RD change. The processing is done only from global
 * table.
 */
static void withdraw_router_id_vrf(struct bgp *bgp_vrf)
{
	/* skip if the RD is configured */
	if (is_vrf_rd_configured(bgp_vrf))
		return;

	/* delete/withdraw ipv4|ipv6 routes as type-5 routes */
	bgp_evpn_vrf_delete_withdraw_originated_type_5_routes(bgp_vrf);
}

static void bgp_evpn_evi_update_advertise_type_1_2_route(struct bgp *bgp, struct bgp_evpn_evi *evi,
				       struct bgp_dest *dest)
{
	struct bgp_dest *global_dest;
	struct bgp_path_info *pi, *global_pi;
	struct attr *attr;
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;

	struct prefix_evpn tmp_evp;
	const struct prefix_evpn *evp =
		(const struct prefix_evpn *)bgp_dest_get_prefix(dest);

	/*
	 * We have already processed type-3 routes.
	 * Process only type-1 and type-2 routes here.
	 */
	if (!(evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE ||
	      evp->prefix.route_type == BGP_EVPN_AD_ROUTE))
		return;

	pi = bgp_evpn_route_get_local_path(bgp, dest, 0);
	if (!pi)
		return;

	/*
	 * VNI table MAC-IP prefixes don't have MAC so make sure it's
	 * set from path info here.
	 */
	if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) {
		if (is_evpn_prefix_ipaddr_none(evp)) {
			/* VNI MAC -> Global */
			evpn_type2_prefix_global_copy(
				&tmp_evp, evp, NULL /* mac */,
				evpn_type2_path_info_get_ip(pi));
		} else {
			/* VNI IP -> Global */
			evpn_type2_prefix_global_copy(
				&tmp_evp, evp, evpn_type2_path_info_get_mac(pi),
				NULL /* ip */);
		}
	} else {
		memcpy(&tmp_evp, evp, sizeof(tmp_evp));
	}

	/* Create route in global routing table using this route entry's
	 * attribute.
	 */
	attr = pi->attr;
	global_dest = bgp_evpn_global_node_get(bgp->rib[afi][safi], afi, safi,
					       &tmp_evp, &evi->prd, NULL);
	assert(global_dest);

	if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) {
		/* Type-2 route */
		bgp_evpn_evi_update_route_entry(
			bgp, evi, afi, safi, global_dest, attr, NULL /* mac */,
			NULL /* ip */, 1, &global_pi, 0,
			mac_mobility_seqnum(attr), false /* setup_sync */,
			NULL /* old_is_sync */);
	} else {
		/* Type-1 route */
		struct bgp_evpn_es *es;
		int route_changed = 0;

		es = bgp_evpn_es_find(&evp->prefix.ead_addr.esi);
		bgp_evpn_mh_route_update(bgp, es, evi, afi, safi, global_dest,
					 attr, &global_pi, &route_changed);
	}

	/* Schedule for processing and unlock node. */
	bgp_process(bgp, global_dest, global_pi, afi, safi);
	bgp_dest_unlock_node(global_dest);
}

/*
 * Update and advertise local routes for a VNI. Invoked upon router-id/RD
 * change. Note that the processing is done only on the global route table
 * using routes that already exist in the per-VNI table.
 */
static void bgp_evpn_evi_update_advertise_routes(struct bgp *bgp, struct bgp_evpn_evi *evi)
{
	struct prefix_evpn p;
	struct bgp_dest *dest, *global_dest;
	struct bgp_path_info *pi;
	struct attr *attr;
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;

	/* Locate type-3 route for VNI in the per-VNI table and use its
	 * attributes to create and advertise the type-3 route for this VNI
	 * in the global table.
	 *
	 * RT-3 only if doing head-end replication
	 */
	if (bgp_evpn_evi_get_flood_mode(bgp, evi)
				== VXLAN_FLOOD_HEAD_END_REPL) {
		build_evpn_type3_prefix(&p, &evi->originator_ip);
		dest = bgp_evpn_vni_node_lookup(evi, &p, NULL);
		if (!dest) /* unexpected */
			return;
		pi = bgp_evpn_route_get_local_path(bgp, dest, 0);
		if (!pi) {
			bgp_dest_unlock_node(dest);
			return;
		}

		attr = pi->attr;

		global_dest = bgp_evpn_global_node_get(
			bgp->rib[afi][safi], afi, safi, &p, &evi->prd, NULL);
		bgp_evpn_evi_update_route_entry(
			bgp, evi, afi, safi, global_dest, attr, NULL /* mac */,
			NULL /* ip */, 1, &pi, 0, mac_mobility_seqnum(attr),
			false /* setup_sync */, NULL /* old_is_sync */);

		/* Schedule for processing and unlock node. */
		bgp_process(bgp, global_dest, pi, afi, safi);
		bgp_dest_unlock_node(global_dest);
	}

	/* Now, walk this VNI's MAC & IP route table and use the route and its
	 * attribute to create and schedule route in global table.
	 */
	for (dest = bgp_table_top(evi->mac_table); dest;
	     dest = bgp_route_next(dest))
		bgp_evpn_evi_update_advertise_type_1_2_route(bgp, evi, dest);

	for (dest = bgp_table_top(evi->ip_table); dest;
	     dest = bgp_route_next(dest))
		bgp_evpn_evi_update_advertise_type_1_2_route(bgp, evi, dest);
}

/*
 * Delete (and withdraw) local routes for a VNI - only from the global
 * table. Invoked upon router-id change.
 */
static int bgp_evpn_evi_delete_withdraw_routes(struct bgp *bgp, struct bgp_evpn_evi *evi)
{
	struct prefix_evpn p;
	struct bgp_dest *global_dest;
	struct bgp_path_info *pi;
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;

	/* Delete and withdraw locally learnt type-2 routes (MACIP)
	 * for this VNI - from the global table.
	 */
	bgp_evpn_evi_delete_global_type2_routes(bgp, evi);

	/* Remove type-3 route for this VNI from global table. */
	build_evpn_type3_prefix(&p, &evi->originator_ip);
	global_dest = bgp_evpn_global_node_lookup(bgp->rib[afi][safi], safi, &p,
						  &evi->prd, NULL);
	if (global_dest) {
		/* Delete route entry in the global EVPN table. */
		pi = bgp_evpn_delete_route_entry(bgp, afi, safi, global_dest, NULL, 0);

		/* Schedule for processing - withdraws to peers happen from
		 * this table.
		 */
		if (pi)
			bgp_process(bgp, global_dest, pi, afi, safi);
		bgp_dest_unlock_node(global_dest);
	}


	delete_global_ead_evi_routes(bgp, evi);
	return 0;
}

/*
 * Handle router-id change. Update and advertise local routes corresponding
 * to this VNI from peers. Note that this is invoked after updating the
 * router-id. The routes in the per-VNI table are used to create routes in
 * the global table and schedule them.
 */
static void update_router_id_vni(struct hash_bucket *bucket, struct bgp *bgp)
{
	struct bgp_evpn_evi *evi = (struct bgp_evpn_evi *)bucket->data;

	/* Skip VNIs with configured RD. */
	if (is_rd_configured(evi))
		return;

	bgp_evpn_evi_derive_auto_rd(bgp, evi);
	bgp_evpn_evi_update_advertise_routes(bgp, evi);
}

/*
 * Handle router-id change. Delete and withdraw local routes corresponding
 * to this VNI from peers. Note that this is invoked prior to updating
 * the router-id and is done only on the global route table, the routes
 * are needed in the per-VNI table to re-advertise with new router id.
 */
static void withdraw_router_id_vni(struct hash_bucket *bucket, struct bgp *bgp)
{
	struct bgp_evpn_evi *evi = (struct bgp_evpn_evi *)bucket->data;

	/* Skip VNIs with configured RD. */
	if (is_rd_configured(evi))
		return;

	bgp_evpn_evi_delete_withdraw_routes(bgp, evi);
}

static void advertise_withdraw_type3(struct hash_bucket *bucket, void *data)
{
	struct bgp_evpn_evi *evi = bucket->data;
	struct bgp *bgp = data;
	struct prefix_evpn p;
	int flood_control;

	if (!evi || !is_evi_live(evi))
		return;

	zlog_info("L2VPN EVPN BUM handling for VNI %u is %s", evi->vni,
		  vxlan_flood_control_str(evi->vxlan_flood_ctrl));

	bgp_zebra_vxlan_flood_control(bgp, evi);

	flood_control = bgp_evpn_evi_get_flood_mode(bgp, evi);

	/* Create RT-3 for a VNI and schedule for processing and advertisement.
	 * This is invoked upon flooding mode changing to head-end replication.
	 */
	if (flood_control == VXLAN_FLOOD_HEAD_END_REPL) {
		build_evpn_type3_prefix(&p, &evi->originator_ip);
		if (bgp_evpn_evi_update_route(bgp, evi, &p, 0, 0, NULL))
			flog_err(EC_BGP_EVPN_ROUTE_CREATE,
				 "Type3 route creation failure for VNI %u", evi->vni);
	} else if (flood_control == VXLAN_FLOOD_DISABLED) {
		/* Delete RT-3 for a VNI and schedule for processing and withdrawal.
		 * This is invoked upon flooding mode changing to drop BUM packets.
		 */
		build_evpn_type3_prefix(&p, &evi->originator_ip);
		bgp_evpn_evi_delete_route(bgp, evi, &p);
	}
}

/*
 * Parse and process received EVPN route type 2 route (MAC/IP Advertisement Route)
 * (BGP UPDATE, advertise or withdraw).
 */
static int bgp_evpn_parse_and_process_route_type_2(struct peer *peer, afi_t afi, safi_t safi,
			       struct attr *attr, uint8_t *pfx, int psize,
			       uint32_t addpath_id)
{
	struct prefix_rd prd;
	struct prefix_evpn p = {};
	uint8_t ipaddr_len;
	uint8_t macaddr_len;
	/* holds the VNI(s) as in packet */
	mpls_label_t label[BGP_MAX_LABELS] = {};
	uint8_t num_labels = 0;
	uint32_t eth_tag;
	int ret = 0;

	/* Type-2 route should be either 33, 37 or 49 bytes or an
	 * additional 3 bytes if there is a second label (VNI):
	 * RD (8), ESI (10), Eth Tag (4), MAC Addr Len (1),
	 * MAC Addr (6), IP len (1), IP (0, 4 or 16),
	 * MPLS Lbl1 (3), MPLS Lbl2 (0 or 3)
	 */
	if (psize != 33 && psize != 37 && psize != 49 && psize != 36
	    && psize != 40 && psize != 52) {
		flog_err(EC_BGP_EVPN_ROUTE_INVALID,
			 "%u:%s - Rx EVPN Type-2 NLRI with invalid length %d",
			 peer->bgp->vrf_id, peer->host, psize);
		return -1;
	}

	struct stream *pkt = stream_new(psize);
	stream_put(pkt, pfx, psize);

	/* Make prefix_rd */
	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;

	STREAM_GET(&prd.val, pkt, 8);

	/* Make EVPN prefix. */
	p.family = AF_EVPN;
	p.prefixlen = EVPN_ROUTE_PREFIXLEN;
	p.prefix.route_type = BGP_EVPN_MAC_IP_ROUTE;

	/* Copy Ethernet Seg Identifier */
	if (attr) {
		STREAM_GET(&attr->esi, pkt, sizeof(esi_t));

		if (bgp_evpn_is_esi_local_and_non_bypass(&attr->esi))
			SET_FLAG(attr->es_flags, ATTR_ES_IS_LOCAL);
		else
			UNSET_FLAG(attr->es_flags, ATTR_ES_IS_LOCAL);
	} else {
		STREAM_FORWARD_GETP(pkt, sizeof(esi_t));
	}

	/* Copy Ethernet Tag */
	STREAM_GET(&eth_tag, pkt, 4);
	p.prefix.macip_addr.eth_tag = ntohl(eth_tag);

	/* Get the MAC Addr len */
	STREAM_GETC(pkt, macaddr_len);

	/* Get the MAC Addr */
	if (macaddr_len == (ETH_ALEN * 8)) {
		STREAM_GET(&p.prefix.macip_addr.mac.octet, pkt, ETH_ALEN);
	} else {
		flog_err(
			EC_BGP_EVPN_ROUTE_INVALID,
			"%u:%s - Rx EVPN Type-2 NLRI with unsupported MAC address length %d",
			peer->bgp->vrf_id, peer->host, macaddr_len);
		goto fail;
	}


	/* Get the IP. */
	STREAM_GETC(pkt, ipaddr_len);

	if (ipaddr_len != 0 && ipaddr_len != IPV4_MAX_BITLEN
	    && ipaddr_len != IPV6_MAX_BITLEN) {
		flog_err(
			EC_BGP_EVPN_ROUTE_INVALID,
			"%u:%s - Rx EVPN Type-2 NLRI with unsupported IP address length %d",
			peer->bgp->vrf_id, peer->host, ipaddr_len);
		goto fail;
	}

	/* Validate ipaddr_len against the NLRI length */
	if ((psize != 33 + (ipaddr_len / 8)) && (psize != 36 + (ipaddr_len / 8))) {
		flog_err(EC_BGP_EVPN_ROUTE_INVALID,
			 "%u:%s - Rx EVPN Type-2 NLRI with invalid IP address length %d",
			 peer->bgp->vrf_id, peer->host, ipaddr_len);
		goto fail;
	}

	if (ipaddr_len) {
		ipaddr_len /= 8; /* Convert to bytes. */
		p.prefix.macip_addr.ip.ipa_type = (ipaddr_len == IPV4_MAX_BYTELEN)
					       ? IPADDR_V4
					       : IPADDR_V6;
		STREAM_GET(&p.prefix.macip_addr.ip.ip.addr, pkt, ipaddr_len);
	}

	/* Get the VNI(s). Stored as bytes here. */
	STREAM_GET(&label[0], pkt, BGP_LABEL_BYTES);
	num_labels++;

	/* Do we have a second VNI? */
	if (STREAM_READABLE(pkt)) {
		num_labels++;
		STREAM_GET(&label[1], pkt, BGP_LABEL_BYTES);
	}

	/* Process the route. */
	if (attr)
		bgp_update(peer, (struct prefix *)&p, addpath_id, attr, afi,
			   safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd,
			   &label[0], num_labels, 0, NULL);
	else
		bgp_withdraw(peer, (struct prefix *)&p, addpath_id, afi, safi,
			     ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd, &label[0],
			     num_labels);
	goto done;

fail:
stream_failure:
	flog_err(EC_BGP_EVPN_ROUTE_INVALID,
		 "%u:%s - Rx EVPN Type-2 NLRI - corrupt, discarding",
		 peer->bgp->vrf_id, peer->host);
	ret = -1;
done:
	stream_free(pkt);
	return ret;
}

/*
 * Parse and process received EVPN route type 3 route (Inclusive Multicast Ethernet Tag Route)
 * (BGP UPDATE, advertise or withdraw).
 */
static int bgp_evpn_parse_and_process_route_type_3(struct peer *peer, afi_t afi, safi_t safi,
			       struct attr *attr, uint8_t *pfx, int psize,
			       uint32_t addpath_id)
{
	struct prefix_rd prd;
	struct prefix_evpn p;
	uint8_t ipaddr_len;
	uint32_t eth_tag;

	/* Type-3 route should be either 17 or 29 bytes: RD (8), Eth Tag (4),
	 * IP len (1) and IP (4 or 16).
	 */
	if (psize != 17 && psize != 29) {
		flog_err(EC_BGP_EVPN_ROUTE_INVALID,
			 "%u:%s - Rx EVPN Type-3 NLRI with invalid length %d",
			 peer->bgp->vrf_id, peer->host, psize);
		return -1;
	}

	/* If PMSI is present, log if it is anything other than IR.
	 * Note: We just simply ignore the values as it is not clear if
	 * doing anything else is better.
	 */
	if (attr && bgp_attr_exists(attr, BGP_ATTR_PMSI_TUNNEL)) {
		enum pta_type pmsi_tnl_type = bgp_attr_get_pmsi_tnl_type(attr);

		if (pmsi_tnl_type != PMSI_TNLTYPE_INGR_REPL
		    && pmsi_tnl_type != PMSI_TNLTYPE_PIM_SM) {
			flog_warn(
				EC_BGP_EVPN_PMSI_PRESENT,
				"%u:%s - Rx EVPN Type-3 NLRI with unsupported PTA %d",
				peer->bgp->vrf_id, peer->host, pmsi_tnl_type);
		}
	}

	/* Make prefix_rd */
	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;
	memcpy(&prd.val, pfx, 8);
	pfx += 8;

	/* Make EVPN prefix. */
	memset(&p, 0, sizeof(p));
	p.family = AF_EVPN;
	p.prefixlen = EVPN_ROUTE_PREFIXLEN;
	p.prefix.route_type = BGP_EVPN_IMET_ROUTE;

	/* Copy Ethernet Tag */
	memcpy(&eth_tag, pfx, 4);
	p.prefix.imet_addr.eth_tag = ntohl(eth_tag);
	pfx += 4;

	/* Get the IP. */
	ipaddr_len = *pfx++;

	/* Validate */
	if (psize != 13 + (ipaddr_len / 8)) {
		flog_err(EC_BGP_EVPN_ROUTE_INVALID,
			 "%u:%s - Rx EVPN Type-3 NLRI with invalid IP address length %d",
			 peer->bgp->vrf_id, peer->host, ipaddr_len);
		return -1;
	}

	if (ipaddr_len == IPV4_MAX_BITLEN) {
		SET_IPADDR_V4(&p.prefix.imet_addr.ip);
		memcpy(&p.prefix.imet_addr.ip.ip.addr, pfx, IPV4_MAX_BYTELEN);
	} else if (ipaddr_len == IPV6_MAX_BITLEN) {
		SET_IPADDR_V6(&p.prefix.imet_addr.ip);
		IPV6_ADDR_COPY(&p.prefix.imet_addr.ip.ipaddr_v6, pfx);
	} else {
		flog_err(
			EC_BGP_EVPN_ROUTE_INVALID,
			"%u:%s - Rx EVPN Type-3 NLRI with unsupported IP address length %d",
			peer->bgp->vrf_id, peer->host, ipaddr_len);
		return -1;
	}

	/* Process the route. */
	if (attr)
		bgp_update(peer, (struct prefix *)&p, addpath_id, attr, afi,
			   safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd, NULL,
			   0, 0, NULL);
	else
		bgp_withdraw(peer, (struct prefix *)&p, addpath_id, afi, safi,
			     ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd, NULL, 0);
	return 0;
}

/*
 * Parse and process received EVPN route type 5 route (IP-Prefix Route)
 * (BGP UPDATE, advertise or withdraw).
 */
static int bgp_evpn_parse_and_process_route_type_5(struct peer *peer, afi_t afi, safi_t safi,
			       struct attr *attr, uint8_t *pfx, int psize,
			       uint32_t addpath_id)
{
	struct prefix_rd prd;
	struct prefix_evpn p;
	struct bgp_route_evpn *evpn = XCALLOC(MTYPE_BGP_EVPN_OVERLAY,
					      sizeof(struct bgp_route_evpn));
	uint8_t ippfx_len;
	uint32_t eth_tag;
	mpls_label_t label; /* holds the VNI as in the packet */
	bool is_valid_update = true;

	/* Type-5 route should be 34 or 58 bytes:
	 * RD (8), ESI (10), Eth Tag (4), IP len (1), IP (4 or 16),
	 * GW (4 or 16) and VNI (3).
	 * Note that the IP and GW should both be IPv4 or both IPv6.
	 */
	if (psize != 34 && psize != 58) {
		flog_err(EC_BGP_EVPN_ROUTE_INVALID,
			 "%u:%s - Rx EVPN Type-5 NLRI with invalid length %d",
			 peer->bgp->vrf_id, peer->host, psize);
		evpn_overlay_free(evpn);
		return -1;
	}

	/* Make prefix_rd */
	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;
	memcpy(&prd.val, pfx, 8);
	pfx += 8;

	/* Make EVPN prefix. */
	memset(&p, 0, sizeof(p));
	p.family = AF_EVPN;
	p.prefixlen = EVPN_ROUTE_PREFIXLEN;
	p.prefix.route_type = BGP_EVPN_IP_PREFIX_ROUTE;

	/* Fetch ESI overlay index */
	if (attr)
		memcpy(&evpn->eth_s_id, pfx, sizeof(esi_t));
	pfx += ESI_BYTES;

	/* Fetch Ethernet Tag. */
	memcpy(&eth_tag, pfx, 4);
	p.prefix.prefix_addr.eth_tag = ntohl(eth_tag);
	pfx += 4;

	/* Fetch IP prefix length. */
	ippfx_len = *pfx++;
	if (ippfx_len > IPV6_MAX_BITLEN) {
		flog_err(
			EC_BGP_EVPN_ROUTE_INVALID,
			"%u:%s - Rx EVPN Type-5 NLRI with invalid IP Prefix length %d",
			peer->bgp->vrf_id, peer->host, ippfx_len);
		evpn_overlay_free(evpn);
		return -1;
	}
	p.prefix.prefix_addr.ip_prefix_length = ippfx_len;

	/* Determine IPv4 or IPv6 prefix */
	/* Since the address and GW are from the same family, this just becomes
	 * a simple check on the total size.
	 */
	if (psize == 34) {
		if (ippfx_len > IPV4_MAX_BITLEN) {
			flog_err(EC_BGP_EVPN_ROUTE_INVALID,
				 "%u:%s - Rx EVPN Type-5 NLRI with IPv4 psize but IP Prefix length %d (max %d)",
				 peer->bgp->vrf_id, peer->host, ippfx_len, IPV4_MAX_BITLEN);
			evpn_overlay_free(evpn);
			return -1;
		}
		SET_IPADDR_V4(&p.prefix.prefix_addr.ip);
		memcpy(&p.prefix.prefix_addr.ip.ipaddr_v4, pfx, 4);
		pfx += 4;
		SET_IPADDR_V4(&evpn->gw_ip);
		memcpy(&evpn->gw_ip.ipaddr_v4, pfx, 4);
		pfx += 4;
	} else {
		SET_IPADDR_V6(&p.prefix.prefix_addr.ip);
		memcpy(&p.prefix.prefix_addr.ip.ipaddr_v6, pfx,
		       IPV6_MAX_BYTELEN);
		pfx += IPV6_MAX_BYTELEN;
		SET_IPADDR_V6(&evpn->gw_ip);
		memcpy(&evpn->gw_ip.ipaddr_v6, pfx, IPV6_MAX_BYTELEN);
		pfx += IPV6_MAX_BYTELEN;
	}

	/* Get the VNI (in MPLS label field). Stored as bytes here. */
	memset(&label, 0, sizeof(label));
	memcpy(&label, pfx, BGP_LABEL_BYTES);

	/*
	 * If in future, we are required to access additional fields,
	 * we MUST increment pfx by BGP_LABEL_BYTES in before reading the next
	 * field
	 */

	/*
	 * An update containing a non-zero gateway IP and a non-zero ESI
	 * at the same time is should be treated as withdraw
	 */
	if (bgp_evpn_is_esi_valid(&evpn->eth_s_id) &&
	    !ipaddr_is_zero(&evpn->gw_ip)) {
		flog_err(EC_BGP_EVPN_ROUTE_INVALID,
			 "%s - Rx EVPN Type-5 ESI and gateway-IP both non-zero.",
			 peer->host);
		is_valid_update = false;
	} else if (bgp_evpn_is_esi_valid(&evpn->eth_s_id))
		evpn->type = OVERLAY_INDEX_ESI;
	else if (!ipaddr_is_zero(&evpn->gw_ip))
		evpn->type = OVERLAY_INDEX_GATEWAY_IP;
	if (attr) {
		if (is_zero_mac(&attr->rmac) &&
		    !bgp_evpn_is_esi_valid(&evpn->eth_s_id) &&
		    ipaddr_is_zero(&evpn->gw_ip) && label == 0) {
			flog_err(EC_BGP_EVPN_ROUTE_INVALID,
				 "%s - Rx EVPN Type-5 ESI, gateway-IP, RMAC and label all zero",
				 peer->host);
			is_valid_update = false;
		}

		if (is_mcast_mac(&attr->rmac) || is_bcast_mac(&attr->rmac))
			is_valid_update = false;
	}

	/* Process the route. */
	if (attr && is_valid_update)
		bgp_update(peer, (struct prefix *)&p, addpath_id, attr, afi,
			   safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd,
			   &label, 1, 0, evpn);
	else {
		if (!is_valid_update) {
			char attr_str[BUFSIZ] = {0};

			bgp_dump_attr(attr, attr_str, BUFSIZ);
			zlog_warn(
				"Invalid update from peer %s vrf %u prefix %pFX attr %s - treat as withdraw",
				peer->hostname, peer->bgp->vrf_id, &p,
				attr_str);
		}
		bgp_withdraw(peer, (struct prefix *)&p, addpath_id, afi, safi,
			     ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd, &label, 1);
		evpn_overlay_free(evpn);
	}

	return 0;
}

static void evpn_mpattr_encode_type5(struct stream *s, const struct prefix *p,
				     const struct prefix_rd *prd,
				     mpls_label_t *label, uint8_t num_labels,
				     struct attr *attr)
{
	int len;
	char temp[16];
	const struct evpn_addr *p_evpn_p;
	struct bgp_route_evpn *bre = NULL;

	memset(&temp, 0, sizeof(temp));
	if (p->family != AF_EVPN)
		return;
	p_evpn_p = &(p->u.prefix_evpn);

	if (attr)
		bre = bgp_attr_get_evpn_overlay(attr);

	/* len denites the total len of IP and GW-IP in the route
	   IP and GW-IP have to be both ipv4 or ipv6
	 */
	if (IS_IPADDR_V4(&p_evpn_p->prefix_addr.ip))
		len = 8; /* IP and GWIP are both ipv4 */
	else
		len = 32; /* IP and GWIP are both ipv6 */
	/* Prefix contains RD, ESI, EthTag, IP length, IP, GWIP and VNI */
	stream_putc(s, 8 + 10 + 4 + 1 + len + 3);
	stream_put(s, prd->val, 8);
	if (attr && bre && bre->type == OVERLAY_INDEX_ESI)
		stream_put(s, &attr->esi, sizeof(esi_t));
	else
		stream_put(s, 0, sizeof(esi_t));
	stream_putl(s, p_evpn_p->prefix_addr.eth_tag);
	stream_putc(s, p_evpn_p->prefix_addr.ip_prefix_length);
	if (IS_IPADDR_V4(&p_evpn_p->prefix_addr.ip))
		stream_put_ipv4(s, p_evpn_p->prefix_addr.ip.ipaddr_v4.s_addr);
	else
		stream_put(s, &p_evpn_p->prefix_addr.ip.ipaddr_v6, 16);
	if (attr && bre && bre->type == OVERLAY_INDEX_GATEWAY_IP) {
		if (IS_IPADDR_V4(&p_evpn_p->prefix_addr.ip))
			stream_put_ipv4(s, bre->gw_ip.ipaddr_v4.s_addr);
		else
			stream_put(s, &(bre->gw_ip.ipaddr_v6), 16);
	} else {
		if (IS_IPADDR_V4(&p_evpn_p->prefix_addr.ip))
			stream_put_ipv4(s, 0);
		else
			stream_put(s, &temp, 16);
	}

	if (num_labels)
		stream_put(s, label, 3);
	else
		stream_put3(s, 0);
}

/*
 * In cases such as 'no advertise-all-vni' and L2 VNI DELETE, we need to
 * pop all the VPN routes present in the bgp_zebra_announce FIFO yet to
 * be processed regardless of VNI is configured or not.
 *
 * NOTE: NO need to pop the VPN routes in two cases
 *  1) In free_vni_entry
 *     - Called by bgp_free()->bgp_evpn_cleanup() or
 *       bgp_delete()->bgp_evpn_cleanup() when terminating.
 *     - Since bgp_delete is called before bgp_free and we pop all the dest
 *       pertaining to bgp under delete.
 *  2) evpn_delete_vni() when user configures "no vni" since the withdraw
 *     of all routes happen in normal cycle.
 */
void bgp_zebra_evpn_pop_items_from_announce_fifo(struct bgp_evpn_evi *evi)
{
	struct bgp_dest *dest = NULL;
	struct bgp_bp_install_node *inode = NULL;
	struct bgp_bp_install_node *inode_next = NULL;

	for (inode = zebra_announce_first(&bm->zebra_announce_early_head); inode;
	     inode = inode_next) {
		inode_next = zebra_announce_next(&bm->zebra_announce_early_head, inode);
		if (inode->type != BGP_BP_INSTALL_ROUTE)
			continue;
		dest = inode->ptr;
		if (dest->za_evi == evi) {
			zebra_announce_del(&bm->zebra_announce_early_head, inode);
			bgp_dest_table(dest)->bgp->zebra_announce_queue_cnt--;
			bgp_path_info_unlock(dest->za_bgp_pi);
			dest->za_inode = NULL;
			bgp_dest_unlock_node(dest);
			XFREE(MTYPE_BGP_BP_INSTALL_NODE, inode);
		}
	}
	for (inode = zebra_announce_first(&bm->zebra_announce_head); inode; inode = inode_next) {
		inode_next = zebra_announce_next(&bm->zebra_announce_head, inode);
		if (inode->type != BGP_BP_INSTALL_ROUTE)
			continue;
		dest = inode->ptr;
		if (dest->za_evi == evi) {
			zebra_announce_del(&bm->zebra_announce_head, inode);
			bgp_dest_table(dest)->bgp->zebra_announce_queue_cnt--;
			bgp_path_info_unlock(dest->za_bgp_pi);
			dest->za_inode = NULL;
			bgp_dest_unlock_node(dest);
			XFREE(MTYPE_BGP_BP_INSTALL_NODE, inode);
		}
	}
}
/*
 * Cleanup specific VNI upon EVPN (advertise-all-vni) being disabled.
 */
static void cleanup_vni_on_disable(struct hash_bucket *bucket, struct bgp *bgp)
{
	struct bgp_evpn_evi *evi = (struct bgp_evpn_evi *)bucket->data;

	/* Remove EVPN routes and schedule for processing. */
	bgp_evpn_evi_delete_routes(bgp, evi);

	/* Clear "live" flag and see if hash needs to be freed. */
	UNSET_FLAG(evi->flags, EVI_FLAG_LIVE);
	/* Pop items from bgp_zebra_announce FIFO for any VPN routes pending*/
	bgp_zebra_evpn_pop_items_from_announce_fifo(evi);
	if (!is_vni_configured(evi))
		bgp_evpn_evi_free(bgp, evi);
}

/*
 * Free a VNI entry; iterator function called during cleanup.
 */
static void free_vni_entry(struct hash_bucket *bucket, struct bgp *bgp)
{
	struct bgp_evpn_evi *evi = (struct bgp_evpn_evi *)bucket->data;

	bgp_evpn_evi_delete_all_routes(bgp, evi);
	bgp_evpn_evi_free(bgp, evi);
}

/*
 * Public functions.
 */

/*
 * evpn - enable advertisement of default g/w
 */
void bgp_evpn_install_uninstall_default_route(struct bgp *bgp_vrf, afi_t afi, safi_t safi,
					      struct bgp_path_info *originator, bool add)
{
	struct prefix ip_prefix;

	/* form the default prefix 0.0.0.0/0 */
	memset(&ip_prefix, 0, sizeof(ip_prefix));
	ip_prefix.family = afi2family(afi);

	if (add)
		bgp_evpn_vrf_upsert_prefix_as_type5_route(bgp_vrf, originator, &ip_prefix, NULL, afi, safi, 0);
	else
		bgp_evpn_vrf_delete_prefix_as_type5_route(bgp_vrf, originator, &ip_prefix, afi, safi, 0);
}


/*
 * Handle change to BGP router id. This is invoked twice by the change
 * handler, first before the router id has been changed and then after
 * the router id has been changed. The first invocation will result in
 * local routes for all VNIs/VRF being deleted and withdrawn and the next
 * will result in the routes being re-advertised.
 */
void bgp_evpn_handle_router_id_update(struct bgp *bgp_vrf, int withdraw)
{
	struct listnode *node;
	struct bgp *bgp_vrf_temp;

	struct bgp *bgp_evpn_mi = bgp_get_evpn_master_instance();
	assert(bgp_evpn_mi);


	if (withdraw) {

		/* delete and withdraw all the type-5 routes
		   stored in the global table for this vrf
		 */
		withdraw_router_id_vrf(bgp_vrf);

		/* delete all the VNI routes (type-2/type-3) routes for all the
		 * L2-VNIs
		 */
		hash_iterate(bgp_evpn_mi->evpn_master_instance_info.vnihash,
			     (void (*)(struct hash_bucket *,
				       void *))withdraw_router_id_vni,
			     bgp_vrf);

		if (bgp_vrf == bgp_evpn_mi) {
			for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp_vrf_temp)) {
				/* advertise pip is enabled,
				 * bgp instance L3VNI VTEP-IP is IPv4
				 * advertise pip IP is not user configured.
				 */
				if (bgp_vrf_temp->evpn_info->advertise_pip &&
				    IS_IPADDR_V4(&bgp_vrf_temp->originator_ip) &&
				    (bgp_vrf_temp->evpn_info->pip_ip_static.ipaddr_v4.s_addr ==
				     INADDR_ANY)) {
					bgp_vrf_temp->evpn_info->pip_ip.ipaddr_v4.s_addr = INADDR_ANY;
				}
			}
		}
	} else {

		/* Assign new default instance router-id */
		if (bgp_vrf == bgp_evpn_mi) {
			for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp_vrf_temp)) {
				/* advertise pip is enabled,
				 * bgp instance L3VNI VTEP-IP is IPv4
				 * advertise pip IP is not user configured.
				 * assign the bgp default router-id as pip IP.
				 */
				if (bgp_vrf_temp->evpn_info->advertise_pip &&
				    IS_IPADDR_V4(&bgp_vrf_temp->originator_ip) &&
				    (bgp_vrf_temp->evpn_info->pip_ip_static.ipaddr_v4.s_addr ==
				     INADDR_ANY)) {
					SET_IPADDR_V4(&bgp_vrf_temp->evpn_info->pip_ip);
					bgp_vrf_temp->evpn_info->pip_ip.ipaddr_v4 = bgp_vrf->router_id;
					/* advertise type-5 routes with
					 * new nexthop
					 */
					bgp_evpn_vrf_update_advertise_originated_type_5_routes(bgp_vrf_temp);
				}
			}
		}

		/* advertise all routes in the vrf as type-5 routes with the new
		 * RD
		 */
		update_router_id_vrf(bgp_vrf);

		/* advertise all the VNI routes (type-2/type-3) routes with the
		 * new RD
		 */
		hash_iterate(bgp_evpn_mi->evpn_master_instance_info.vnihash,
			     (void (*)(struct hash_bucket *,
				       void *))update_router_id_vni,
			     bgp_vrf);
	}
}

struct vni_gr_walk {
	struct bgp *bgp;
	uint16_t cnt;
};

/*
 * Iterate over all the deferred prefixes in this table
 * and calculate the bestpath.
 */
uint16_t bgp_deferred_path_selection(struct bgp *bgp, afi_t afi, safi_t safi,
				     struct bgp_table *table, uint16_t cnt, struct bgp_evpn_evi *evi,
				     bool evpn_select)
{
	struct bgp_dest *dest = NULL;

	for (dest = bgp_table_top(table);
	     dest && bgp->gr_info[afi][safi].gr_deferred != 0 && cnt < BGP_MAX_BEST_ROUTE_SELECT;
	     dest = bgp_route_next(dest)) {
		if (!CHECK_FLAG(dest->flags, BGP_NODE_SELECT_DEFER))
			continue;

		UNSET_FLAG(dest->flags, BGP_NODE_SELECT_DEFER);
		bgp->gr_info[afi][safi].gr_deferred--;

		if (evpn_select) {
			struct bgp_path_info *pi = bgp_dest_get_bgp_path_info(dest);

			/*
			 * Mark them all as unsorted and just pass
			 * the first one in to do work on.  Clear
			 * everything since at this point it is
			 * unknown what was or was not done for
			 * all the deferred paths
			 */
			while (pi) {
				SET_FLAG(pi->flags, BGP_PATH_UNSORTED);
				pi = pi->next;
			}

			evpn_route_select_install(bgp, evi, dest, bgp_dest_get_bgp_path_info(dest));
		} else
			bgp_process_main_one(bgp, dest, afi, safi);

		cnt++;
	}

	/* If iteration stopped before the entire table was traversed then the
	 * node needs to be unlocked.
	 */
	if (dest) {
		bgp_dest_unlock_node(dest);
		dest = NULL;
	}

	return cnt;
}

static void bgp_evpn_handle_deferred_bestpath_per_vni(struct hash_bucket *bucket, void *arg)
{
	struct bgp_evpn_evi *evi = bucket->data;
	struct vni_gr_walk *ctx = arg;
	struct bgp *bgp = ctx->bgp;
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;

	/*
	 * Now, walk this VNI's MAC & IP route table and do deferred bestpath
	 * selection
	 */
	if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
		zlog_debug("%s (%u): GR walking IP and MAC table for VNI %u. Deferred paths %d, batch cnt %d",
			   vrf_id_to_name(bgp->vrf_id), bgp->vrf_id, evi->vni,
			   bgp->gr_info[afi][safi].gr_deferred, ctx->cnt);

	if (!bgp->gr_info[afi][safi].gr_deferred || ctx->cnt >= BGP_MAX_BEST_ROUTE_SELECT)
		return;

	ctx->cnt += bgp_deferred_path_selection(bgp, afi, safi, evi->mac_table, ctx->cnt, evi,
						true);
	ctx->cnt += bgp_deferred_path_selection(bgp, afi, safi, evi->ip_table, ctx->cnt, evi, true);
}

void bgp_evpn_handle_deferred_bestpath_for_vnis(struct bgp *bgp, uint16_t cnt)
{
	struct vni_gr_walk ctx;

	ctx.bgp = bgp;
	ctx.cnt = cnt;

	hash_iterate(bgp->evpn_master_instance_info.vnihash,
		     (void (*)(struct hash_bucket *,
			       void *))bgp_evpn_handle_deferred_bestpath_per_vni,
		     &ctx);
}
/*
 * Handle change to export RT - update and advertise local routes.
 */
int bgp_evpn_evi_handle_export_rt_change(struct bgp *bgp, struct bgp_evpn_evi *evi)
{
	return bgp_evpn_evi_update_routes(bgp, evi);
}

void bgp_evpn_vrf_handle_rd_change(struct bgp *bgp_vrf, int withdraw)
{
	if (withdraw)
		bgp_evpn_vrf_delete_withdraw_originated_type_5_routes(bgp_vrf);
	else
		bgp_evpn_vrf_update_advertise_originated_type_5_routes(bgp_vrf);
}

/*
 * Handle change to RD. This is invoked twice by the change handler,
 * first before the RD has been changed and then after the RD has
 * been changed. The first invocation will result in local routes
 * of this VNI being deleted and withdrawn and the next will result
 * in the routes being re-advertised.
 */
void bgp_evpn_evi_handle_rd_change(struct bgp *bgp, struct bgp_evpn_evi *evi,
			       int withdraw)
{
	if (withdraw)
		bgp_evpn_evi_delete_withdraw_routes(bgp, evi);
	else
		bgp_evpn_evi_update_advertise_routes(bgp, evi);
}

/* "mac-vrf soo" vty handler
 * Handle change to the global MAC-VRF Site-of-Origin:
 *   - Unimport routes with new SoO from VNI/VRF
 *   - Import routes with old SoO into VNI/VRF
 *   - Update SoO on local VNI routes + re-advertise
 */
void bgp_evpn_handle_global_macvrf_soo_change(struct bgp *bgp,
					      struct ecommunity *new_soo)
{
	struct ecommunity *old_soo;

	old_soo = bgp->evpn_info->soo;

	/* cleanup and bail out if old_soo == new_soo */
	if (ecommunity_match(old_soo, new_soo)) {
		ecommunity_free(&new_soo);
		return;
	}

	/* set new_soo */
	bgp->evpn_info->soo = new_soo;

	/* Unimport routes matching the new_soo */
	bgp_filter_evpn_routes_upon_martian_change(bgp, BGP_MARTIAN_SOO);

	/* Reimport routes with old_soo and !new_soo.
	 */
	bgp_reimport_evpn_routes_upon_martian_change(
		bgp, BGP_MARTIAN_SOO, (void *)old_soo, (void *)new_soo);

	/* Update locally originated routes for all L2VNIs */
	hash_iterate(bgp->evpn_master_instance_info.vnihash,
		     (void (*)(struct hash_bucket *,
			       void *))bgp_evpn_evi_update_routes_hash,
		     bgp);

	/* clear old_soo */
	ecommunity_free(&old_soo);
}

/*
 * Install any existing remote routes applicable for this VNI into its
 * routing table. This is invoked when a VNI becomes "live" or its Import
 * RT is changed.
 */
int bgp_evpn_evi_install_routes(struct bgp *bgp, struct bgp_evpn_evi *evi)
{
	/*
	 * Install type-3 routes followed by type-2 routes - the ones applicable
	 * for this EVI.
	 */
	return bgp_evpn_evi_install_uninstall_routes(bgp, evi, true);
}

/*
 * Uninstall any existing remote routes for this EVI. One scenario in which
 * this is invoked is upon an import RT change.
 */
int bgp_evpn_evi_uninstall_routes(struct bgp *bgp, struct bgp_evpn_evi *evi)
{
	/*
	 * Uninstall type-2 routes followed by type-3 routes - the ones
	 * applicable for this EVI.
	 */
	return bgp_evpn_evi_install_uninstall_routes(bgp, evi, false);
}

/*
 * TODO: Hardcoded for a maximum of 2 VNIs right now
 */
char *bgp_evpn_label2str(mpls_label_t *label, uint8_t num_labels, char *buf,
			 int len)
{
	vni_t vni1, vni2;

	vni1 = label2vni(label);
	if (num_labels == 2) {
		vni2 = label2vni(label + 1);
		snprintf(buf, len, "%u/%u", vni1, vni2);
	} else
		snprintf(buf, len, "%u", vni1);
	return buf;
}

/*
 * Function to convert evpn route to json format.
 * NOTE: We don't use prefix2str as the output here is a bit different.
 */
void bgp_evpn_route2json(const struct prefix_evpn *p, json_object *json)
{
	char buf1[ETHER_ADDR_STRLEN];
	char buf2[PREFIX2STR_BUFFER];
	uint8_t family;
	uint8_t prefixlen;

	if (!json)
		return;

	json_object_int_add(json, "routeType", p->prefix.route_type);

	switch (p->prefix.route_type) {
	case BGP_EVPN_MAC_IP_ROUTE:
		json_object_int_add(json, "ethTag",
			p->prefix.macip_addr.eth_tag);
		json_object_int_add(json, "macLen", 8 * ETH_ALEN);
		json_object_string_add(json, "mac",
			prefix_mac2str(&p->prefix.macip_addr.mac, buf1,
			sizeof(buf1)));

		if (!is_evpn_prefix_ipaddr_none(p)) {
			family = is_evpn_prefix_ipaddr_v4(p) ? AF_INET :
				AF_INET6;
			prefixlen = (family == AF_INET) ?
				IPV4_MAX_BITLEN : IPV6_MAX_BITLEN;
			inet_ntop(family, &p->prefix.macip_addr.ip.ip.addr,
				buf2, PREFIX2STR_BUFFER);
			json_object_int_add(json, "ipLen", prefixlen);
			json_object_string_add(json, "ip", buf2);
		}
	break;

	case BGP_EVPN_IMET_ROUTE:
		json_object_int_add(json, "ethTag",
			p->prefix.imet_addr.eth_tag);
		family = is_evpn_prefix_ipaddr_v4(p) ? AF_INET : AF_INET6;
		prefixlen = (family == AF_INET) ?  IPV4_MAX_BITLEN :
			IPV6_MAX_BITLEN;
		inet_ntop(family, &p->prefix.imet_addr.ip.ip.addr, buf2,
			PREFIX2STR_BUFFER);
		json_object_int_add(json, "ipLen", prefixlen);
		json_object_string_add(json, "ip", buf2);
	break;

	case BGP_EVPN_IP_PREFIX_ROUTE:
		json_object_int_add(json, "ethTag",
			p->prefix.prefix_addr.eth_tag);
		family = is_evpn_prefix_ipaddr_v4(p) ? AF_INET : AF_INET6;
		inet_ntop(family, &p->prefix.prefix_addr.ip.ip.addr,
			  buf2, sizeof(buf2));
		json_object_int_add(json, "ipLen",
				    p->prefix.prefix_addr.ip_prefix_length);
		json_object_string_add(json, "ip", buf2);
	break;

	default:
	break;
	}
}

/*
 * Encode EVPN prefix in Update (MP_REACH)
 */
void bgp_evpn_encode_prefix(struct stream *s, const struct prefix *p,
			    const struct prefix_rd *prd, mpls_label_t *label,
			    uint8_t num_labels, struct attr *attr,
			    bool addpath_capable, uint32_t addpath_tx_id)
{
	struct prefix_evpn *evp = (struct prefix_evpn *)p;
	int len, ipa_len = 0;

	if (addpath_capable)
		stream_putl(s, addpath_tx_id);

	/* Route type */
	stream_putc(s, evp->prefix.route_type);

	switch (evp->prefix.route_type) {
	case BGP_EVPN_MAC_IP_ROUTE:
		if (is_evpn_prefix_ipaddr_v4(evp))
			ipa_len = IPV4_MAX_BYTELEN;
		else if (is_evpn_prefix_ipaddr_v6(evp))
			ipa_len = IPV6_MAX_BYTELEN;
		/* RD, ESI, EthTag, MAC+len, IP len, [IP], 1 VNI */
		len = 8 + 10 + 4 + 1 + 6 + 1 + ipa_len + 3;
		if (ipa_len && num_labels > 1) /* There are 2 VNIs */
			len += 3;
		stream_putc(s, len);
		stream_put(s, prd->val, 8);   /* RD */
		if (attr)
			stream_put(s, &attr->esi, ESI_BYTES);
		else
			stream_put(s, 0, 10);
		stream_putl(s, evp->prefix.macip_addr.eth_tag);	/* Ethernet Tag ID */
		stream_putc(s, 8 * ETH_ALEN); /* Mac Addr Len - bits */
		stream_put(s, evp->prefix.macip_addr.mac.octet, 6); /* Mac Addr */
		stream_putc(s, 8 * ipa_len); /* IP address Length */
		if (ipa_len) /* IP */
			stream_put(s, &evp->prefix.macip_addr.ip.ip.addr,
				   ipa_len);
		/* 1st label is the L2 VNI */
		stream_put(s, label, BGP_LABEL_BYTES);
		/* Include 2nd label (L3 VNI) if advertising MAC+IP */
		if (ipa_len && num_labels > 1)
			stream_put(s, label + 1, BGP_LABEL_BYTES);
		break;

	case BGP_EVPN_IMET_ROUTE: {
		uint8_t orig_ip_bits = 0;
		/* RFC-7432 IMET NLRI 13 = RD (8) + Ethtag (4) + IP length (1) */
		uint8_t total_bytes = 13; /* Fixed part excluding Originator IP */

		/* If Originator IP, add bytes to sizes */
		if (IS_IPADDR_V4(&evp->prefix.imet_addr.ip)) {
			orig_ip_bits = IPV4_MAX_BITLEN;
			total_bytes += IPV4_MAX_BYTELEN; /* V4 Originator IP */
		} else if (IS_IPADDR_V6(&evp->prefix.imet_addr.ip)) {
			orig_ip_bits = IPV6_MAX_BITLEN;
			total_bytes += IPV6_MAX_BYTELEN; /* V6 Originator IP */
		}

		stream_putc(s, total_bytes);
		stream_put(s, prd->val, 8);		       /* RD */
		stream_putl(s, evp->prefix.imet_addr.eth_tag); /* Ethernet Tag ID */

		stream_putc(s, orig_ip_bits); /* Originator IP address Length - bits */
		if (orig_ip_bits)
			stream_put(s, &evp->prefix.imet_addr.ip.ip, orig_ip_bits / 8);

		break;
	}

	case BGP_EVPN_ES_ROUTE: {
		uint8_t ipaddr_bits = 0;
		/* RFC-7432 ES NLRI 19 = RD (8) + ESI (10) + IP length (1) */
		uint8_t total_bytes = 19; /* Fixed independent of IP family */

		if (IS_IPADDR_V4(&evp->prefix.es_addr.ip)) {
			ipaddr_bits = IPV4_MAX_BITLEN;
			total_bytes += IPV4_MAX_BYTELEN; /* V4 Originator IP */
		} else if (IS_IPADDR_V6(&evp->prefix.es_addr.ip)) {
			ipaddr_bits = IPV6_MAX_BITLEN;
			total_bytes += IPV6_MAX_BYTELEN; /* V6 Originator IP */
		}

		stream_putc(s, total_bytes);
		stream_put(s, prd->val, 8); /* RD */
		stream_put(s, evp->prefix.es_addr.esi.val, 10); /* ESI */
		stream_putc(s, ipaddr_bits); /* Originator IP address Length - bits */
		/* VTEP IP */
		if (ipaddr_bits)
			stream_put(s, &evp->prefix.es_addr.ip.ip, ipaddr_bits / 8);
		else
			flog_err(EC_BGP_EVPN_ROUTE_CREATE,
				 "evpn ES route %pFX created with ip field as empty", evp);

		break;
	}

	case BGP_EVPN_AD_ROUTE:
		/* RD, ESI, EthTag, 1 VNI */
		len = RD_BYTES + ESI_BYTES + EVPN_ETH_TAG_BYTES + BGP_LABEL_BYTES;
		stream_putc(s, len);
		stream_put(s, prd->val, RD_BYTES); /* RD */
		stream_put(s, evp->prefix.ead_addr.esi.val, ESI_BYTES); /* ESI */
		stream_putl(s, evp->prefix.ead_addr.eth_tag); /* Ethernet Tag */
		stream_put(s, label, BGP_LABEL_BYTES);
		break;

	case BGP_EVPN_IP_PREFIX_ROUTE:
		evpn_mpattr_encode_type5(s, p, prd, label, num_labels, attr);
		break;

	default:
		break;
	}
}

int bgp_evpn_parse_and_process_evpn_nlri(struct peer *peer, struct attr *attr,
			struct bgp_nlri *packet, bool withdraw)
{
	uint8_t *pnt;
	uint8_t *lim;
	afi_t afi;
	safi_t safi;
	uint32_t addpath_id;
	bool addpath_capable;
	int psize = 0;
	uint8_t rtype;
	struct prefix p;

	/* Start processing the NLRI - there may be multiple in the MP_REACH */
	pnt = packet->nlri;
	lim = pnt + packet->length;
	afi = packet->afi;
	safi = packet->safi;
	addpath_id = 0;

	addpath_capable = bgp_addpath_encode_rx(peer, afi, safi);

	for (; pnt < lim; pnt += psize) {
		/* Clear prefix structure. */
		memset(&p, 0, sizeof(p));

		/* Deal with path-id if AddPath is supported. */
		if (addpath_capable) {
			/* When packet overflow occurs return immediately. */
			if (pnt + BGP_ADDPATH_ID_LEN > lim)
				return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;

			memcpy(&addpath_id, pnt, BGP_ADDPATH_ID_LEN);
			addpath_id = ntohl(addpath_id);
			pnt += BGP_ADDPATH_ID_LEN;
		}

		/* All EVPN NLRI types start with type and length. */
		if (pnt + 2 > lim)
			return BGP_NLRI_PARSE_ERROR_EVPN_MISSING_TYPE;

		rtype = *pnt++;
		psize = *pnt++;

		/* When packet overflow occur return immediately. */
		if (pnt + psize > lim)
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;

		switch (rtype) {
		case BGP_EVPN_AD_ROUTE: /* Route Type 1: Ethernet Auto-discovery Route */
			if (bgp_evpn_parse_and_process_route_type_1(peer, afi, safi,
						withdraw ? NULL : attr, pnt,
						psize, addpath_id)) {
				flog_err(
					EC_BGP_PKT_PROCESS,
					"%u:%s - Error in processing EVPN type-1 NLRI size %d",
					peer->bgp->vrf_id, peer->host, psize);
				return BGP_NLRI_PARSE_ERROR_EVPN_TYPE1_SIZE;
			}
			break;

		case BGP_EVPN_MAC_IP_ROUTE: /* Route Type 2: MAC/IP Advertisement Route */
			if (bgp_evpn_parse_and_process_route_type_2(peer, afi, safi,
						withdraw ? NULL : attr, pnt,
						psize, addpath_id)) {
				flog_err(
					EC_BGP_EVPN_FAIL,
					"%u:%s - Error in processing EVPN type-2 NLRI size %d",
					peer->bgp->vrf_id, peer->host, psize);
				return BGP_NLRI_PARSE_ERROR_EVPN_TYPE2_SIZE;
			}
			break;

		case BGP_EVPN_IMET_ROUTE: /* Route Type 3: Inclusive Multicast Ethernet Tag Route */
			if (bgp_evpn_parse_and_process_route_type_3(peer, afi, safi,
						withdraw ? NULL : attr, pnt,
						psize, addpath_id)) {
				flog_err(
					EC_BGP_PKT_PROCESS,
					"%u:%s - Error in processing EVPN type-3 NLRI size %d",
					peer->bgp->vrf_id, peer->host, psize);
				return BGP_NLRI_PARSE_ERROR_EVPN_TYPE3_SIZE;
			}
			break;

		case BGP_EVPN_ES_ROUTE: /* Route Type 4: Ethernet Segment Route */
			if (bgp_evpn_parse_and_process_route_type_4(peer, afi, safi,
						withdraw ? NULL : attr, pnt,
						psize, addpath_id)) {
				flog_err(
					EC_BGP_PKT_PROCESS,
					"%u:%s - Error in processing EVPN type-4 NLRI size %d",
					peer->bgp->vrf_id, peer->host, psize);
				return BGP_NLRI_PARSE_ERROR_EVPN_TYPE4_SIZE;
			}
			break;

		case BGP_EVPN_IP_PREFIX_ROUTE: /* Route Type 5: IP Prefix Route */
			if (bgp_evpn_parse_and_process_route_type_5(peer, afi, safi,
						withdraw ? NULL : attr, pnt,
						psize, addpath_id)) {
				flog_err(
					EC_BGP_PKT_PROCESS,
					"%u:%s - Error in processing EVPN type-5 NLRI size %d",
					peer->bgp->vrf_id, peer->host, psize);
				return BGP_NLRI_PARSE_ERROR_EVPN_TYPE5_SIZE;
			}
			break;

		default:
			/* TODO: Log invalid received route type? */
			break;
		}
	}

	/* Packet length consistency check. */
	if (pnt != lim)
		return BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;

	return BGP_NLRI_PARSE_OK;
}

/*
 * Derive RD automatically for VNI using passed information - it
 * is of the form RouterId:unique-id-for-vrf.
 */
void bgp_evpn_vrf_derive_auto_rd(struct bgp *bgp)
{
	if (is_vrf_rd_configured(bgp))
		return;

	form_auto_rd(bgp->router_id, bgp->vrf_rd_id, &bgp->vrf_prd);
}

/*
 * Derive RD automatically for VNI using passed information - it
 * is of the form RouterId:unique-id-for-vni.
 */
void bgp_evpn_evi_derive_auto_rd(struct bgp *bgp, struct bgp_evpn_evi *evi)
{
	char buf[BGP_EVPN_PREFIX_RD_LEN];

	evi->prd.family = AF_UNSPEC;
	evi->prd.prefixlen = 64;
	snprintfrr(buf, sizeof(buf), "%pI4:%hu", &bgp->router_id, evi->rd_id);
	(void)str2prefix_rd(buf, &evi->prd);
	if (evi->prd_pretty)
		XFREE(MTYPE_BGP_NAME, evi->prd_pretty);
	UNSET_FLAG(evi->flags, EVI_FLAG_RD_CFGD);
}

/*
 * Lookup L3-VNI
 */
bool bgp_evpn_lookup_l3vni_l2vni_table(vni_t vni)
{
	struct list *inst = bm->bgp;
	struct listnode *node;
	struct bgp *bgp_vrf;

	for (ALL_LIST_ELEMENTS_RO(inst, node, bgp_vrf)) {
		if (bgp_vrf->l3vni == vni)
			return true;
	}

	return false;
}

/*
 * Lookup VNI.
 */
struct bgp_evpn_evi *bgp_evpn_lookup_vni(struct bgp *bgp, vni_t vni)
{
	struct bgp_evpn_evi *evi;
	struct bgp_evpn_evi tmp;

	memset(&tmp, 0, sizeof(tmp));
	tmp.vni = vni;
	evi = hash_lookup(bgp->evpn_master_instance_info.vnihash, &tmp);
	return evi;
}

/*
 * Create a new EVPN EVI - invoked upon configuration or zebra notification.
 */
struct bgp_evpn_evi *bgp_evpn_evi_new(struct bgp *bgp, vni_t vni,
		struct ipaddr *originator_ip,
		vrf_id_t tenant_vrf_id,
		struct in_addr mcast_grp,
		ifindex_t svi_ifindex)
{
	struct bgp_evpn_evi *evi;

	evi = XCALLOC(MTYPE_BGP_EVPN_EVI, sizeof(struct bgp_evpn_evi));

	/* Set values - RD and RT set to defaults. */
	evi->vni = vni;
	evi->originator_ip = *originator_ip;
	evi->tenant_vrf_id = tenant_vrf_id;
	evi->mcast_grp = mcast_grp;
	evi->svi_ifindex = svi_ifindex;
	evi->vxlan_flood_ctrl = VXLAN_FLOOD_INHERIT_GLOBAL;

	/* Initialize legacy route-target import and export lists */
	evi->evi_import_rtl = list_new();
	evi->evi_import_rtl->cmp =
		(int (*)(void *, void *))bgp_evpn_route_target_ecom_cmp;
	evi->evi_import_rtl->del = bgp_evpn_xxport_delete_ecomm;
	evi->evi_export_rtl = list_new();
	evi->evi_export_rtl->cmp =
		(int (*)(void *, void *))bgp_evpn_route_target_ecom_cmp;
	evi->evi_export_rtl->del = bgp_evpn_xxport_delete_ecomm;


	evi->evi_rt_config = bgp_evpn_rt_config_new();
	bgp_evpn_effective_wildcard_rt_slu_init(&evi->effective_wildcard_import_rts);
	bgp_evpn_effective_fq_rt_slu_init(&evi->effective_fq_import_rts);
	bgp_evpn_effective_fq_rt_slu_init(&evi->effective_fq_export_rts);


	bf_assign_index(bm->rd_idspace, evi->rd_id);
	bgp_evpn_evi_derive_rd_rt(bgp, evi);

	/* Initialize EVPN route tables. */
	evi->ip_table = bgp_table_init(bgp, AFI_L2VPN, SAFI_EVPN);
	evi->mac_table = bgp_table_init(bgp, AFI_L2VPN, SAFI_EVPN);

	/* Add to hash */
	(void)hash_get(bgp->evpn_master_instance_info.vnihash, evi, hash_alloc_intern);

	bgp_evpn_remote_ip_hash_init(evi);
	bgp_evpn_link_to_vni_svi_hash(bgp, evi);

	/* add to l2vni list on corresponding vrf */
	bgp_evpn_evi_link_to_vrf(evi);

	bgp_evpn_vni_es_init(evi);

	QOBJ_REG(evi, bgp_evpn_evi);
	return evi;
}

/*
 * Free a given VPN - called in multiple scenarios such as zebra
 * notification, configuration being deleted, advertise-all-vni disabled etc.
 * This just frees appropriate memory, caller should have taken other
 * needed actions.
 */
void bgp_evpn_evi_free(struct bgp *bgp, struct bgp_evpn_evi *evi)
{
	bgp_evpn_remote_ip_hash_destroy(evi);
	bgp_evpn_vni_es_cleanup(evi);
	bgp_evpn_evi_unlink_from_vrf(evi);
	bgp_table_unlock(evi->ip_table);
	bgp_table_unlock(evi->mac_table);
	bgp_evpn_unmap_vni_from_its_rts(bgp, evi);
	/* Free legacy RT lists */
	list_delete(&evi->evi_import_rtl);
	list_delete(&evi->evi_export_rtl);

	bgp_evpn_rt_config_free(evi->evi_rt_config);

	struct bgp_evpn_effective_wildcard_rt* eff_wildcard_rt;
	while((eff_wildcard_rt = bgp_evpn_effective_wildcard_rt_slu_pop(&evi->effective_wildcard_import_rts))) {
		bgp_evpn_effective_wildcard_rt_free(eff_wildcard_rt);
	}
	struct bgp_evpn_effective_fq_rt* eff_fq_rt;
	while((eff_fq_rt = bgp_evpn_effective_fq_rt_slu_pop(&evi->effective_fq_import_rts))) {
		bgp_evpn_effective_fq_rt_free(eff_fq_rt);
	}
	while((eff_fq_rt = bgp_evpn_effective_fq_rt_slu_pop(&evi->effective_fq_export_rts))) {
		bgp_evpn_effective_fq_rt_free(eff_fq_rt);
	}


	bf_release_index(bm->rd_idspace, evi->rd_id);
	hash_release(bgp->vni_svi_hash, evi);
	hash_release(bgp->evpn_master_instance_info.vnihash, evi);
	if (evi->prd_pretty)
		XFREE(MTYPE_BGP_NAME, evi->prd_pretty);
	QOBJ_UNREG(evi);
	XFREE(MTYPE_BGP_EVPN_EVI, evi);
}

static void hash_evpn_free(struct bgp_evpn_evi *evi)
{
	XFREE(MTYPE_BGP_EVPN_EVI, evi);
}

/*
 * Import EVPN route from global table to VRFs/EVIs/ESs.
 */
int bgp_evpn_import_global_received_route(struct bgp *bgp, afi_t afi, safi_t safi,
			  const struct prefix *p, struct bgp_path_info *pi)
{
	return bgp_evpn_install_uninstall_route(bgp, afi, safi, p, pi, 1);
}

/*
 * Unimport evpn route from VRFs/EVIs/ESs.
 */
int bgp_evpn_unimport_route(struct bgp *bgp, afi_t afi, safi_t safi,
			    const struct prefix *p, struct bgp_path_info *pi)
{
	return bgp_evpn_install_uninstall_route(bgp, afi, safi, p, pi, 0);
}

/*
 * Unexport IPv[46] unicast route from VRF to global table
 */
void bgp_evpn_unexport_type5_route(struct bgp *bgp, const struct bgp_dest *dest,
				   const struct bgp_path_info *pi, afi_t afi, safi_t safi)
{
	const struct prefix *prefix = bgp_dest_get_prefix(dest);
	uint32_t addpath_id;

	addpath_id = bgp_evpn_addpath_id_for_path(bgp, pi, afi);
	bgp_evpn_vrf_delete_prefix_as_type5_route(bgp, pi, prefix, afi, safi, addpath_id);
}

/* Refresh previously-discarded EVPN routes carrying "self" MAC-VRF SoO.
 * Walk global EVPN rib + import remote routes with old_soo && !new_soo.
 */
void bgp_reimport_evpn_routes_upon_macvrf_soo_change(struct bgp *bgp,
						     struct ecommunity *old_soo,
						     struct ecommunity *new_soo)
{
	afi_t afi;
	safi_t safi;
	struct bgp_dest *rd_dest, *dest;
	struct bgp_table *table;
	struct bgp_path_info *pi;

	afi = AFI_L2VPN;
	safi = SAFI_EVPN;

	/* EVPN routes are a 2-level table: outer=prefix_rd, inner=prefix_evpn.
	 * A remote route could have any RD, so we need to walk them all.
	 */
	for (rd_dest = bgp_table_top(bgp->rib[afi][safi]); rd_dest;
	     rd_dest = bgp_route_next(rd_dest)) {
		table = bgp_dest_get_bgp_table_info(rd_dest);
		if (!table)
			continue;

		for (dest = bgp_table_top(table); dest;
		     dest = bgp_route_next(dest)) {
			const struct prefix *p;
			struct prefix_evpn *evp;

			p = bgp_dest_get_prefix(dest);
			evp = (struct prefix_evpn *)p;

			/* On export we only add MAC-VRF SoO to RT-2/3, so we
			 * can skip evaluation of other RTs.
			 */
			if (evp->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE &&
			    evp->prefix.route_type != BGP_EVPN_IMET_ROUTE)
				continue;

			for (pi = bgp_dest_get_bgp_path_info(dest); pi;
			     pi = pi->next) {
				bool old_soo_fnd = false;
				bool new_soo_fnd = false;

				/* Only consider routes learned from peers */
				if (!(pi->type == ZEBRA_ROUTE_BGP &&
				      pi->sub_type == BGP_ROUTE_NORMAL))
					continue;

				if (!CHECK_FLAG(pi->flags, BGP_PATH_VALID))
					continue;

				old_soo_fnd = route_matches_soo(pi, old_soo);
				new_soo_fnd = route_matches_soo(pi, new_soo);

				if (old_soo_fnd && !new_soo_fnd) {
					if (bgp_debug_update(pi->peer, p, NULL,
							     1)) {
						char attr_str[BUFSIZ] = {0};

						bgp_dump_attr(pi->attr,
							      attr_str, BUFSIZ);

						zlog_debug(
							"mac-vrf soo changed: evaluating reimport of prefix %pBD with attr %s",
							dest, attr_str);
					}

					bgp_evpn_import_global_received_route(bgp, afi, safi, p,
							      pi);
				}
			}
		}
	}
}

/* Filter learned (!local) EVPN routes carrying "self" attributes.
 * Walk the Global EVPN loc-rib unimporting martian routes from the appropriate
 * L2VNIs (MAC-VRFs) / L3VNIs (IP-VRFs), and deleting them from the Global
 * loc-rib when applicable (based on martian_type).
 * This function is the handler for new martian entries, which is triggered by
 * events occurring on the local system,
 * e.g.
 * - New VTEP-IP
 *   + bgp_zebra_process_local_vni
 *   + bgp_zebra_process_local_l3vni
 * - New MAC-VRF Site-of-Origin
 *   + bgp_evpn_handle_global_macvrf_soo_change
 * This will likely be extended in the future to cover these events too:
 * - New Interface IP
 *   + bgp_interface_address_add
 * - New Interface MAC
 *   + bgp_ifp_up
 *   + bgp_ifp_create
 * - New RMAC
 *   + bgp_zebra_process_local_l3vni
 */
static void bgp_evpn_log_martian_discard(struct bgp *bgp, struct bgp_path_info *pi,
					 struct bgp_dest *dest, const struct prefix *p,
					 enum bgp_martian_type martian_type)
{
	/* Only do expensive string formatting if debug or trace is enabled. */
	if (!bgp_debug_update(pi->peer, p, NULL, 1) &&
	    !frrtrace_enabled(frr_bgp, upd_attr_discarded_due_to_martian))
		return;

	char attr_str[BUFSIZ] = { 0 };
	char prefix_str[PREFIX2STR_BUFFER] = { 0 };

	bgp_dump_attr(pi->attr, attr_str, sizeof(attr_str));
	prefix2str(p, prefix_str, sizeof(prefix_str));

	if (bgp_debug_update(pi->peer, p, NULL, 1))
		zlog_debug("%u: prefix %pBD with attr %s - DISCARDED due to Martian/%s",
			   bgp->vrf_id, dest, attr_str, bgp_martian_type2str(martian_type));

	frrtrace(4, frr_bgp, upd_attr_discarded_due_to_martian, bgp->vrf_id, prefix_str, attr_str,
		 bgp_martian_type2str(martian_type));
}

void bgp_filter_evpn_routes_upon_martian_change(
	struct bgp *bgp, enum bgp_martian_type martian_type)
{
	afi_t afi;
	safi_t safi;
	struct bgp_dest *rd_dest, *dest;
	struct bgp_table *table;
	struct bgp_path_info *pi;
	struct ecommunity *macvrf_soo;

	afi = AFI_L2VPN;
	safi = SAFI_EVPN;
	macvrf_soo = bgp->evpn_info->soo;

	/* EVPN routes are a 2-level table: outer=prefix_rd, inner=prefix_evpn.
	 * A remote route could have any RD, so we need to walk them all.
	 */
	for (rd_dest = bgp_table_top(bgp->rib[afi][safi]); rd_dest;
	     rd_dest = bgp_route_next(rd_dest)) {
		table = bgp_dest_get_bgp_table_info(rd_dest);
		if (!table)
			continue;

		for (dest = bgp_table_top(table); dest;
		     dest = bgp_route_next(dest)) {
			struct bgp_path_info *next;

			for (pi = bgp_dest_get_bgp_path_info(dest);
			     (pi != NULL) && (next = pi->next, 1); pi = next) {
				bool affected = false;
				const struct prefix *p;

				/* Only consider routes learned from peers */
				if (!(pi->type == ZEBRA_ROUTE_BGP
				      && pi->sub_type == BGP_ROUTE_NORMAL))
					continue;

				p = bgp_dest_get_prefix(dest);

				switch (martian_type) {
				case BGP_MARTIAN_TUN_IP:
					affected = bgp_nexthop_self(
						bgp, afi, pi->type,
						pi->sub_type, pi->attr, dest);
					break;
				case BGP_MARTIAN_SOO:
					affected = route_matches_soo(
						pi, macvrf_soo);
					break;
				case BGP_MARTIAN_IF_IP:
				case BGP_MARTIAN_IF_MAC:
				case BGP_MARTIAN_RMAC:
					break;
				}

				if (affected) {
					bgp_evpn_log_martian_discard(bgp, pi, dest, p,
								     martian_type);

					bgp_evpn_unimport_route(bgp, afi, safi,
								p, pi);

					/* For now, retain existing handling of
					 * tip_hash updates: (Self SoO routes
					 * are unimported from L2VNI/VRF but
					 *  retained in global loc-rib, but Self
					 * IP/MAC routes are also deleted from
					 * global loc-rib).
					 * TODO: use consistent handling for all
					 * martian types
					 */
					if (martian_type == BGP_MARTIAN_TUN_IP)
						bgp_rib_remove(dest, pi,
							       pi->peer, afi,
							       safi);
				}
			}
		}
	}
}

/* Refresh previously-discarded EVPN routes carrying "self" attributes.
 * This function is the handler for deleted martian entries, which is triggered
 * by events occurring on the local system,
 * e.g.
 * - Del MAC-VRF Site-of-Origin
 *   + bgp_evpn_handle_global_macvrf_soo_change
 * This will likely be extended in the future to cover these events too:
 * - Del VTEP-IP
 *   + bgp_zebra_process_local_vni
 *   + bgp_zebra_process_local_l3vni
 * - Del Interface IP
 *   + bgp_interface_address_delete
 * - Del Interface MAC
 *   + bgp_ifp_down
 *   + bgp_ifp_destroy
 * - Del RMAC
 *   + bgp_zebra_process_local_l3vni
 */
void bgp_reimport_evpn_routes_upon_martian_change(
	struct bgp *bgp, enum bgp_martian_type martian_type, void *old_martian,
	void *new_martian)
{
	struct listnode *node;
	struct peer *peer;
	safi_t safi;
	afi_t afi;
	struct ecommunity *old_soo, *new_soo;

	afi = AFI_L2VPN;
	safi = SAFI_EVPN;

	/* Self-SoO routes are held in the global EVPN loc-rib, so we can
	 * reimport routes w/o triggering soft-reconfig/route-refresh.
	 */
	if (martian_type == BGP_MARTIAN_SOO) {
		old_soo = (struct ecommunity *)old_martian;
		new_soo = (struct ecommunity *)new_martian;

		/* If !old_soo, then we can skip the reimport because we
		 * wouldn't have filtered anything via the self-SoO import check
		 */
		if (old_martian)
			bgp_reimport_evpn_routes_upon_macvrf_soo_change(
				bgp, old_soo, new_soo);

		return;
	}

	/* Self-TIP/IP/MAC/RMAC routes are deleted from the global EVPN
	 * loc-rib, so we need to re-learn the routes via soft-reconfig/
	 * route-refresh.
	 */
	for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer)) {

		if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP))
			continue;

		if (peer->connection->status != Established)
			continue;

		if (CHECK_FLAG(peer->af_flags[afi][safi],
			       PEER_FLAG_SOFT_RECONFIG)) {
			if (bgp_debug_update(peer, NULL, NULL, 1))
				zlog_debug(
					"Processing EVPN Martian/%s change on peer %s (inbound, soft-reconfig)",
					bgp_martian_type2str(martian_type),
					peer->host);

			frrtrace(3, frr_bgp, upd_evpn_martian_change, peer->host,
				 bgp_martian_type2str(martian_type), 1);

			bgp_soft_reconfig_in(peer, afi, safi);
		} else {
			if (bgp_debug_update(peer, NULL, NULL, 1))
				zlog_debug(
					"Processing EVPN Martian/%s change on peer %s",
					bgp_martian_type2str(martian_type),
					peer->host);

			frrtrace(3, frr_bgp, upd_evpn_martian_change, peer->host,
				 bgp_martian_type2str(martian_type), 0);

			bgp_route_refresh_send(peer->connection, afi, safi, 0, REFRESH_IMMEDIATE,
					       0, BGP_ROUTE_REFRESH_NORMAL);
		}
	}
}

/*
 * Handle del of a local MACIP.
 */
int bgp_evpn_local_macip_del(struct bgp *bgp, vni_t vni, struct ethaddr *mac,
			     struct ipaddr *ip, int state)
{
	struct bgp_evpn_evi *evi;
	struct prefix_evpn p;
	struct bgp_dest *dest;

	/* Lookup VNI hash - should exist. */
	evi = bgp_evpn_lookup_vni(bgp, vni);
	if (!evi || !is_evi_live(evi)) {
		flog_warn(EC_BGP_EVPN_VPN_VNI,
			  "%u: VNI hash entry for VNI %u %s at MACIP DEL",
			  bgp->vrf_id, vni, evi ? "not live" : "not found");
		return -1;
	}

	build_evpn_type2_prefix(&p, mac, ip);
	if (state == ZEBRA_NEIGH_ACTIVE) {
		/* Remove EVPN type-2 route and schedule for processing. */
		bgp_evpn_evi_delete_route(bgp, evi, &p);
	} else {
		/* Re-instate the current remote best path if any */
		dest = bgp_evpn_vni_node_lookup(evi, &p, NULL);
		if (dest) {
			evpn_zebra_reinstall_best_route(bgp, evi, dest);
			bgp_dest_unlock_node(dest);
		}
	}

	return 0;
}

/*
 * Handle add of a local MACIP.
 */
int bgp_evpn_local_macip_add(struct bgp *bgp, vni_t vni, struct ethaddr *mac,
		struct ipaddr *ip, uint8_t flags, uint32_t seq, esi_t *esi)
{
	struct bgp_evpn_evi *evi;
	struct prefix_evpn p;

	/* Lookup VNI hash - should exist. */
	evi = bgp_evpn_lookup_vni(bgp, vni);
	if (!evi || !is_evi_live(evi)) {
		flog_warn(EC_BGP_EVPN_VPN_VNI,
			  "%u: VNI hash entry for VNI %u %s at MACIP ADD",
			  bgp->vrf_id, vni, evi ? "not live" : "not found");
		return -1;
	}

	/* Create EVPN type-2 route and schedule for processing. */
	build_evpn_type2_prefix(&p, mac, ip);
	if (bgp_evpn_evi_update_route(bgp, evi, &p, flags, seq, esi)) {
		flog_err(
			EC_BGP_EVPN_ROUTE_CREATE,
			"%u:Failed to create Type-2 route, VNI %u %s MAC %pEA IP %pIA (flags: 0x%x)",
			bgp->vrf_id, evi->vni,
			CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_STICKY)
				? "sticky gateway"
				: "",
			mac, ip, flags);
		return -1;
	}

	return 0;
}

/* Helper function around bgp_evpn_evi_link_to_vrf for hash_iterate */
static void bgp_evpn_evi_link_to_vrf_hash(struct hash_bucket *bucket,
				     struct bgp *bgp_vrf)
{
	struct bgp_evpn_evi *evi = (struct bgp_evpn_evi *)bucket->data;
	struct bgp *bgp_evpn_mi = NULL;

	bgp_evpn_mi = bgp_get_evpn_master_instance();
	assert(bgp_evpn_mi);

	if (evi->tenant_vrf_id == bgp_vrf->vrf_id)
		bgp_evpn_evi_link_to_vrf(evi);
}

/*
 * called whenever the an IP-VRF's L3VNI becomes active, also when changing the
 * VNI of an IP-VRF (_del is not called before on VNI change??)
 * Note that this may be called for VRFs that exist in the dataplane (Zebra)
 * but are not user-configured. In this case, we create a VRF and mark it as auto
 * created
 * prefix_routes_only is configured by the user via "vrf <X> vni <Y> prefix-routes-only"
 */
int bgp_evpn_add_local_l3vni(vni_t l3vni, vrf_id_t vrf_id,
			     struct ethaddr *svi_rmac,
			     struct ethaddr *vrr_rmac,
			     struct ipaddr *originator_ip,
				 /* Indicates that the L3VNI and generally the VRF should only be used for
				  * Type 5 (IP Prefix) routes when advertising routes
				  */
				 bool prefix_routes_only,
			     ifindex_t svi_ifindex,
			     bool is_anycast_mac)
{
	struct bgp *bgp_vrf = NULL; /* bgp VRF instance */
	struct bgp *bgp_evpn_mi = NULL; /* EVPN bgp instance */
	struct listnode *node = NULL;
	struct bgp_evpn_evi *evi = NULL;
	as_t as = 0;

	/* get the EVPN master instance - required to get the AS number for VRF
	 * auto-creation
	 */
	bgp_evpn_mi = bgp_get_evpn_master_instance();
	if (!bgp_evpn_mi) {
		flog_err(
			EC_BGP_NO_DFLT,
			"Cannot process L3VNI  %u ADD - EVPN BGP instance not yet created",
			l3vni);
		return -1;
	}

	if (CHECK_FLAG(bgp_evpn_mi->flags, BGP_FLAG_DELETE_IN_PROGRESS)) {
		flog_err(EC_BGP_NO_DFLT,
			  "Cannot process L3VNI %u ADD - EVPN BGP instance is shutting down",
			  l3vni);
		return -1;
	}

	as = bgp_evpn_mi->as;

	/* if the BGP vrf instance doesn't exist - create one */
	bgp_vrf = bgp_lookup_by_vrf_id(vrf_id);
	if (!bgp_vrf) {

		int ret = 0;

		ret = bgp_get_vty(&bgp_vrf, &as, vrf_id_to_name(vrf_id),
				  vrf_id == VRF_DEFAULT
					  ? BGP_INSTANCE_TYPE_DEFAULT
					  : BGP_INSTANCE_TYPE_VRF,
				  NULL, ASNOTATION_UNDEFINED);
		switch (ret) {
		case BGP_ERR_AS_MISMATCH:
			flog_err(EC_BGP_EVPN_AS_MISMATCH,
				 "BGP instance is already running; AS is %s",
				 bgp_vrf->as_pretty);
			return -1;
		case BGP_ERR_INSTANCE_MISMATCH:
			flog_err(EC_BGP_EVPN_INSTANCE_MISMATCH,
				 "BGP instance type mismatch");
			return -1;
		}

		/* mark as auto created */
		SET_FLAG(bgp_vrf->vrf_flags, BGP_VRF_AUTO);
	}

	bool import_auto_rt_active_before = bgp_evpn_vrf_should_generate_import_autort(bgp_vrf);
	bool export_auto_rt_active_before = bgp_evpn_vrf_should_generate_export_autort(bgp_vrf);

	/* associate the vrf with l3vni and related parameters */
	bgp_vrf->l3vni = l3vni;
	bgp_vrf->l3vni_svi_ifindex = svi_ifindex;
	bgp_vrf->evpn_info->is_anycast_mac = is_anycast_mac;

	/* Update tip_hash of the EVPN underlay BGP instance (bgp_evpn)
	 * if the VTEP-IP (originator_ip) has changed
	 */
	handle_tunnel_ip_change(bgp_vrf, bgp_evpn_mi, evi, originator_ip);

	/* copy anycast MAC from VRR MAC */
	memcpy(&bgp_vrf->rmac, vrr_rmac, ETH_ALEN);
	/* copy sys RMAC from SVI MAC */
	memcpy(&bgp_vrf->evpn_info->pip_rmac_zebra, svi_rmac, ETH_ALEN);
	/* PIP user configured mac is not present use svi mac as sys mac */
	if (is_zero_mac(&bgp_vrf->evpn_info->pip_rmac_static))
		memcpy(&bgp_vrf->evpn_info->pip_rmac, svi_rmac, ETH_ALEN);
	/* for v6 vtep_ip assign lo primary v6 address as pip,
	 * for v4 vtep_ip bgp instance router-id as pip in bgp_evpn_init.
	 */
	if (IS_IPADDR_V6(&bgp_vrf->originator_ip)) {
		struct interface *ifp;
		struct in6_addr addr;

		ifp = if_get_vrf_loopback(VRF_DEFAULT);
		if (ifp && if_get_ipv6_global(ifp, &addr)) {
			if (bgp_debug_zebra(NULL))
				zlog_debug("%s vni %u ifp %s addr %pI6 copy as pip", __func__,
					   bgp_vrf->l3vni, ifp->name, &addr);
			SET_IPADDR_V6(&bgp_vrf->evpn_info->pip_ip);
			IPV6_ADDR_COPY(&bgp_vrf->evpn_info->pip_ip.ipaddr_v6, &addr);
		} else if (ifp)
			if (bgp_debug_zebra(NULL))
				zlog_debug("%s vni %u ifp %s v6 addr not found, skip pip assignment",
					   __func__, bgp_vrf->l3vni, ifp->name);
	}

	/* auto derive RD before we advertise any routes */
	bgp_evpn_vrf_derive_auto_rd(bgp_vrf);

	if (prefix_routes_only) {
		SET_FLAG(bgp_vrf->vrf_flags, BGP_VRF_L3VNI_PREFIX_ROUTES_ONLY);
	} else {
		UNSET_FLAG(bgp_vrf->vrf_flags, BGP_VRF_L3VNI_PREFIX_ROUTES_ONLY);
	}

	if (bgp_debug_zebra(NULL))
		zlog_debug("VRF %s, VNI %u, RD %u, prefix only %s, pip %s, pip IP %pIA, pip RMAC %pEA, sys RMAC %pEA, static RMAC %pEA, is_anycast_mac %s",
			   vrf_id_to_name(bgp_vrf->vrf_id), bgp_vrf->l3vni,
			   bgp_vrf->vrf_rd_id,
			   CHECK_FLAG(bgp_vrf->vrf_flags, BGP_VRF_L3VNI_PREFIX_ROUTES_ONLY) ? "yes" : "no",
			   bgp_vrf->evpn_info->advertise_pip ? "enable" : "disable",
			   &bgp_vrf->evpn_info->pip_ip, &bgp_vrf->rmac,
			   &bgp_vrf->evpn_info->pip_rmac, &bgp_vrf->evpn_info->pip_rmac_static,
			   is_anycast_mac ? "yes" : "no");

	bool import_auto_rt_active_after = bgp_evpn_vrf_should_generate_import_autort(bgp_vrf);
	bool export_auto_rt_active_after = bgp_evpn_vrf_should_generate_export_autort(bgp_vrf);

	/* We don't optimize the case of "just prefix_routes_only flag change without VNI change"
	 * so for now we always assume that the L3VNI changed!
	 *
	 * A change of the L3VNI affects:
	 * - Whether EVI can be linked to the VRF (why even?) - no L3VNI -> EVI cannot be linked to VRF
	 * - Auto Derived Route Targets (Import/Export of Route Type 2/5 if Auto RT is being used)
	 * - If EVI_FLAG_USE_TWO_LABELS / !prefix_routes_only: Advertised Route Type 2
	 * - Advertised Route Type 5 (Route Type 5 includes the VRF's L3VNI)
	 */

	/* The effective Auto RT changes if:
	 * - We change from "AutoRT was not generated" to "AutoRT is generated" (-> RT Added to effective RTs)
	 * - We change from "AutoRT was generated" to "AutoRT is not generated" (-> RT Removed from effective RTs)
	 * - RT was / is generated and VNI is changed
	 * The only case when it does NOT change is if AutoRT is not generated in both old and new state
	 *
	 * The VRF's Import Auto RT affects:
	 * - Imported Route Type 2 (EVI's MAC/IP routes) into VRF
	 * - Imported Route Type 5 (VRF's IP Prefix routes) into VRF
	 * The VRF's Export Auto RT affects:
	 * - If !prefix_routes_only: Advertised Route Type 2 (EVI's MAC/IP routes)
	 * - Advertised Route Type 5 (VRF's IP Prefix routes)
	*/

	/* -> Always: update the advertised type-5 routes (affected by L3VNI change itself)
	 * -> If EVI_FLAG_USE_TWO_LABELS / !prefix_routes_only: Update Advertised Route Type 2 (affected by L3VNI change itself)
	 * If effective VRF Import RT changed: Update VRF's Imported Route Type 2 and 5
	 * If effective VRF Export RT changed: Update Advertised Route Type 2 and 5
	 */

	/* This approach avoids updating advertised type-2 routes twice */

	/* effective RTs always change except when the autort was inactive before and is still inactive */
	bool effective_import_rts_changed = !import_auto_rt_active_before && !import_auto_rt_active_after;
	bool effective_export_rts_changed = !export_auto_rt_active_before && !export_auto_rt_active_after;

	/* First, regenerate the auto-derived RTs if necessary
	 * We do this BEFORE touching the Ethernet segments to make sure the it uses the new route targets
	 * the good thing is that the ES stuff only uses bgp_evpn_vrf_install_uninstall_route_entry_if_match
	 * with install and has separate routines to make sure there are no orphaned routes, so we don't need to
	 * worry about special procedures uninstall ES's routes first, bgp_evpn_vrf_uninstall_global_routes
	 * will handle that
	 */
	if(effective_import_rts_changed) {
		/* Essentially what bgp_evpn_vrf_handle_import_rt_change does, but without the bgp_evpn_vrf_install_global_routes
		 * We perform bgp_evpn_vrf_install_global_routes later due to bgp_evpn_evi_link_to_vrf_hash
		 */
		bgp_evpn_vrf_uninstall_global_routes(bgp_vrf);
		bgp_evpn_vrf_unmap_from_vrf_irt_nodes(bgp_vrf);

		bgp_evpn_vrf_regenerate_effective_import_rts(bgp_vrf);

		bgp_evpn_vrf_map_to_vrf_irt_nodes(bgp_vrf);
	}
	if(effective_export_rts_changed) {
		bgp_evpn_vrf_regenerate_effective_export_rts(bgp_vrf);
	}


	/* link all corresponding EVIs to this VRF - usually only makes a difference when
	 * the VRF / L3VNI becomes active initially
	 * This will only do SET_FLAG(..., EVI_FLAG_USE_TWO_LABELS), never UNSET!
	 *
	 *
	 * Dangerous call chain:
	 * (bgp_evpn_evi_link_to_vrf_hash)
	 *
	 * bgp_evpn_evi_link_to_vrf
	 * v
	 * bgp_evpn_es_handle_evi_linked_to_vrf
	 * v
	 * bgp_evpn_es_link_es_per_evi_to_vrf
	 * v
	 * 		Path1:
	 * 		bgp_evpn_es_unlink_es_per_evi_from_vrf(es_evi);
	 *      v
	 * 		bgp_evpn_es_vrf_delete
	 *
	 * 		Path2:
	 * 		bgp_evpn_es_link_es_per_evi_to_vrf
	 *      v
	 * 		bgp_evpn_es_vrf_create
	 * v
	 * bgp_evpn_es_path_update_on_es_vrf_chg:
	 *
	 * 		for (ALL_LIST_ELEMENTS_RO(es->macip_global_path_list, node, es_info)) {
	 * 			...
	 * 			!!!bgp_evpn_vrf_install_uninstall_route_entry_if_match(es_vrf->bgp_vrf, pi, 1);!!!
	 * 		}
	 * v
	 * bgp_evpn_vrf_install_uninstall_route_entry_if_match(... 1 (= install))
	 * v
	 * !!bgp_evpn_vrf_check_route_matches_import_rts!!
	 * v
	 * install_evpn_route_entry_in_vrf
	 */
	hash_iterate(bgp_evpn_mi->evpn_master_instance_info.vnihash,
		     (void (*)(struct hash_bucket *,
			       void *))bgp_evpn_evi_link_to_vrf_hash,
		     bgp_vrf);

	/* Go through all our linked EVIs */
	for (ALL_LIST_ELEMENTS_RO(bgp_vrf->l2vnis, node, evi)) {
		bool old_use_two_labels = CHECK_FLAG(evi->flags, EVI_FLAG_USE_TWO_LABELS);
		bool new_use_two_labels = !prefix_routes_only;
		/* Make sure the EVI_FLAG_USE_TWO_LABELS flag is correct */
		if(new_use_two_labels) {
			SET_FLAG(evi->flags, EVI_FLAG_USE_TWO_LABELS);
		} else {
			UNSET_FLAG(evi->flags, EVI_FLAG_USE_TWO_LABELS);
		}

		/* Need update (EVI) advertised route type 2 if:
		* - change in EVI_FLAG_USE_TWO_LABELS / prefix_routes_only -> change whether the L3VNI & VRF Export RTs are included
		* - EVI_FLAG_USE_TWO_LABELS / !prefix_routes_only && L3VNI changed (-> Mpls Label 2 change) -> EVI_FLAG_USE_TWO_LABELS / !prefix_routes_only (we assume L3VNI always changes -> all type-2 routes need update if they include the L3VNI)
		* - EVI_FLAG_USE_TWO_LABELS / !prefix_routes_only && Export Auto RT changed (-> Included effective RTs change)
		* If the EVI wasn't previously linked to the VRF and the L3VNI becomes active with prefix_routes_only, this should also be fine because then the flag
		* would be set to false even after bgp_evpn_evi_link_to_vrf_hash
		*/
		if(new_use_two_labels || old_use_two_labels != new_use_two_labels) {
			bgp_evpn_evi_update_all_type2_routes(bgp_evpn_mi, evi);
		}
	}

	/* always update & advertise our originated type-5 routes (we assume L3VNI always changes -> all type-5 routes need update as they include the L3VNI) */
	bgp_evpn_vrf_update_advertise_originated_type_5_routes(bgp_vrf);

	if(effective_import_rts_changed)
		bgp_evpn_vrf_install_global_routes(bgp_vrf);

	return 0;
}

/*
 * called whenever the IP-VRF's L3VNI becomes inactive
 */
int bgp_evpn_del_local_l3vni(vni_t l3vni, vrf_id_t vrf_id)
{
	struct bgp *bgp_vrf = NULL;  /* bgp vrf instance */
	struct bgp *bgp_evpn_mi = NULL; /* EVPN bgp instance */
	struct listnode *node = NULL;
	struct listnode *next = NULL;
	struct bgp_evpn_evi *evi = NULL;

	bgp_vrf = bgp_lookup_by_vrf_id(vrf_id);
	if (!bgp_vrf) {
		flog_err(EC_BGP_NO_DFLT,
			 "Cannot process L3VNI %u Del - Could not find BGP instance", l3vni);
		return -1;
	}

	bgp_evpn_mi = bgp_get_evpn_master_instance();
	if (!bgp_evpn_mi) {
		flog_err(EC_BGP_NO_DFLT,
			 "Cannot process L3VNI %u Del - Could not find EVPN BGP instance", l3vni);
		return -1;
	}

	if (CHECK_FLAG(bgp_evpn_mi->flags, BGP_FLAG_DELETE_IN_PROGRESS)) {
		flog_err(EC_BGP_NO_DFLT,
			 "Cannot process L3VNI %u ADD - EVPN BGP instance is shutting down", l3vni);
		return -1;
	}

	bool is_auto_vrf = CHECK_FLAG(bgp_vrf->vrf_flags, BGP_VRF_AUTO);

	bool import_auto_rt_active_before = bgp_evpn_vrf_should_generate_import_autort(bgp_vrf);
	bool export_auto_rt_active_before = bgp_evpn_vrf_should_generate_export_autort(bgp_vrf);


	/* always delete/withdraw all type-5 routes - without VNI and with the current dataplane, we cannot advertise routes */
	bgp_evpn_vrf_delete_withdraw_originated_type_5_routes(bgp_vrf);

	/* Tunnel is no longer active.
	 * Delete VTEP-IP from EVPN underlay's tip_hash.
	 */
	bgp_tip_del(bgp_evpn_mi, &bgp_vrf->originator_ip);

	/* remove the l3vni from vrf instance */
	bgp_vrf->l3vni = 0;

	/* remove the Rmac from the BGP vrf */
	memset(&bgp_vrf->rmac, 0, sizeof(struct ethaddr));
	memset(&bgp_vrf->evpn_info->pip_rmac_zebra, 0, ETH_ALEN);
	if (is_zero_mac(&bgp_vrf->evpn_info->pip_rmac_static) &&
	    !is_zero_mac(&bgp_vrf->evpn_info->pip_rmac))
		memset(&bgp_vrf->evpn_info->pip_rmac, 0, ETH_ALEN);

	bool import_auto_rt_active_after = bgp_evpn_vrf_should_generate_import_autort(bgp_vrf);
	bool export_auto_rt_active_after = bgp_evpn_vrf_should_generate_export_autort(bgp_vrf);

	/* if auto rt was explicitly disabled, or the user had a manually configured non-auto RT, etc.. */
	bool effective_import_rts_changed = !import_auto_rt_active_before && !import_auto_rt_active_after;
	bool effective_export_rts_changed = !export_auto_rt_active_before && !export_auto_rt_active_after;

	/* Essentially what bgp_evpn_vrf_handle_import_rt_change does, but without the bgp_evpn_vrf_install_global_routes
	 * We perform bgp_evpn_vrf_install_global_routes later due to bgp_evpn_evi_link_to_vrf_hash
	 *
	 * + little optimization for auto VRFs - delete the routes because the VRF will be deleted
	 * and don't call bgp_evpn_vrf_uninstall_global_routes twice
	 */
	if(effective_import_rts_changed || is_auto_vrf) {
		/* For Auto VRF:
		 * Remove remote routes from BGP VRF if BGP_VRF_AUTO is configured, as
		 * bgp_delete would not remove/decrement bgp_path_info of the ip_prefix
		 * routes. This will uninstall the routes from zebra and decrement the
		 * bgp info count.
		 */
		bgp_evpn_vrf_uninstall_global_routes(bgp_vrf);
	}
	if(effective_import_rts_changed) {
		bgp_evpn_vrf_unmap_from_vrf_irt_nodes(bgp_vrf);

		bgp_evpn_vrf_regenerate_effective_import_rts(bgp_vrf);

		bgp_evpn_vrf_map_to_vrf_irt_nodes(bgp_vrf);
	}

	if(effective_export_rts_changed) {
		bgp_evpn_vrf_regenerate_effective_export_rts(bgp_vrf);
	}

	/* Update EVIs linked to this VRF */
	/* TODO: Why unlink the EVIs? Just because a VRF doesn't have an active L3VNI
	 * doesn't mean the EVIs shouldn't be mapped to their proper tenant VRF... Probably
	 * a workaround for something else..
	 */
	for (ALL_LIST_ELEMENTS(bgp_vrf->l2vnis, node, next, evi)) {
		/* Only need to update the exported routes if they made use of the VRF (VNI + Export RTs) */
		if (CHECK_FLAG(evi->flags, EVI_FLAG_USE_TWO_LABELS)) {
			UNSET_FLAG(evi->flags, EVI_FLAG_USE_TWO_LABELS);
			bgp_evpn_evi_update_routes(bgp_evpn_mi, evi);
		}
		bgp_evpn_evi_unlink_from_vrf(evi);
	}

	/* Reset the flag, because why not? Seems more like an attempt to mask / hide bugs.. */
	UNSET_FLAG(bgp_vrf->vrf_flags, BGP_VRF_L3VNI_PREFIX_ROUTES_ONLY);

	/* Re-Install received routes if required - just because we don't have a L3VNI, doesn't mean
	 * we can't import routes!
	*/
	if(!is_auto_vrf && effective_import_rts_changed) {
		bgp_evpn_vrf_install_global_routes(bgp_vrf);
	}

	/* Delete the instance if it was autocreated */
	if (is_auto_vrf) {
		bgp_delete(bgp_vrf);
	}

	return 0;
}

static void bgp_evpn_l2vni_remote_route_processing(struct bgp_evpn_evi *evi)
{
	/*
	 * Anytime BGP gets a Bulk of L2 VNIs ADD/UPD from zebra,
	 *  - Walking the entire global routing table per VNI is very expensive.
	 *  - The next read (say of another VNI ADD/UPD) from the socket does
	 *    not proceed unless this walk is complete.
	 *  This results in huge output buffer FIFO growth spiking up the
	 *  memory in zebra.
	 *
	 * To avoid this, idea is to hookup the VPN off the struct bgp_master
	 * and maintain a VPN FIFO list which is processed later on, where we
	 * walk a chunk of VPNs and do the remote route install.
	 */
	if (!CHECK_FLAG(evi->flags, EVI_FLAG_ADD)) {
		zebra_l2_vni_add_tail(&bm->zebra_l2_vni_head, evi);
		SET_FLAG(evi->flags, EVI_FLAG_ADD);
	}

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("Scheduling L2VNI ADD to be processed later for VNI %u", evi->vni);

	/*
	 * If there are no VNI's in the bgp VPN FIFO list i.e. an update
	 * for an already processed VNI comes in, schedule the remote
	 * route install immediately.
	 *
	 * In all other cases, it is ok to schedule the remote route install
	 * after a small sleep. This is to give benefit of doubt in case more
	 * L2VNI ADD events come.
	 */
	if (zebra_l2_vni_count(&bm->zebra_l2_vni_head))
		event_add_timer_msec(bm->master, bgp_zebra_process_remote_routes_for_l2vni, NULL,
				     10, &bm->t_bgp_zebra_l2_vni);
	else
		event_add_event(bm->master, bgp_zebra_process_remote_routes_for_l2vni, NULL, 0,
				&bm->t_bgp_zebra_l2_vni);
}

/*
 * When bgp instance goes down also clean up what might have been left over
 * from evpn.
 */
void bgp_evpn_instance_down(struct bgp *bgp)
{
	/* If we have a stale local vni, delete it */
	if (bgp->l3vni)
		bgp_evpn_del_local_l3vni(bgp->l3vni, bgp->vrf_id);
}

/*
 * Handle deletion of a local L2VNI.
 */
int bgp_evpn_del_local_l2vni(struct bgp *bgp, vni_t vni)
{
	struct bgp_evpn_evi *evi;

	/* Locate VNI hash */
	evi = bgp_evpn_lookup_vni(bgp, vni);
	if (!evi)
		return 0;

	/* Remove the VPN from the bgp VPN FIFO (if exists) */
	UNSET_FLAG(evi->flags, EVI_FLAG_ADD);
	zebra_l2_vni_del(&bm->zebra_l2_vni_head, evi);

	/* Remove all local EVPN routes and schedule for processing (to
	 * withdraw from peers).
	 */
	bgp_evpn_evi_delete_routes(bgp, evi);

	bgp_evpn_unlink_from_vni_svi_hash(bgp, evi);

	evi->svi_ifindex = 0;
	/* Tunnel is no longer active.
	 * Delete VTEP-IP from EVPN underlay's tip_hash.
	 */
	bgp_tip_del(bgp, &evi->originator_ip);

	/* Clear "live" flag and see if hash needs to be freed. */
	UNSET_FLAG(evi->flags, EVI_FLAG_LIVE);
	/* Pop items from bgp_zebra_announce FIFO for any VPN routes pending*/
	bgp_zebra_evpn_pop_items_from_announce_fifo(evi);
	if (!is_vni_configured(evi))
		bgp_evpn_evi_free(bgp, evi);

	return 0;
}

/*
 * Handle add (or update) of a local L2VNI. The VNI changes we care
 * about are for the local-tunnel-ip and the (tenant) VRF.
 */
int bgp_evpn_add_local_l2vni(struct bgp *bgp, vni_t vni,
			   struct ipaddr *originator_ip,
			   vrf_id_t tenant_vrf_id,
			   struct in_addr mcast_grp,
			   ifindex_t svi_ifindex)
{
	struct bgp_evpn_evi *evi;
	struct prefix_evpn p;
	struct bgp *bgp_evpn_mi = bgp_get_evpn_master_instance();

	/* Lookup VNI. If present and no change, exit. */
	evi = bgp_evpn_lookup_vni(bgp, vni);
	if (evi) {

		if (is_evi_live(evi)
		    && ipaddr_is_same(&evi->originator_ip, originator_ip)
		    && IPV4_ADDR_SAME(&evi->mcast_grp, &mcast_grp)
		    && evi->tenant_vrf_id == tenant_vrf_id
		    && evi->svi_ifindex == svi_ifindex)
			/* Probably some other param has changed that we don't
			 * care about.
			 */
			return 0;

		bgp_evpn_evi_mcast_grp_change(bgp, evi, mcast_grp);

		if (evi->svi_ifindex != svi_ifindex) {

			/*
			 * Unresolve all the gateway IP nexthops for this VNI
			 * for old SVI
			 */
			bgp_evpn_remote_ip_hash_iterate(
				evi,
				(void (*)(struct hash_bucket *, void *))
					bgp_evpn_remote_ip_hash_unlink_nexthop,
				evi);
			bgp_evpn_unlink_from_vni_svi_hash(bgp, evi);
			evi->svi_ifindex = svi_ifindex;
			bgp_evpn_link_to_vni_svi_hash(bgp, evi);

			/*
			 * Resolve all the gateway IP nexthops for this VNI
			 * for new SVI
			 */
			bgp_evpn_remote_ip_hash_iterate(
				evi,
				(void (*)(struct hash_bucket *, void *))
					bgp_evpn_remote_ip_hash_link_nexthop,
				evi);
		}

		/* Update tenant_vrf_id if it has changed. */
		if (evi->tenant_vrf_id != tenant_vrf_id) {

			/*
			 * Unresolve all the gateway IP nexthops for this VNI
			 * in old tenant vrf
			 */
			bgp_evpn_remote_ip_hash_iterate(
				evi,
				(void (*)(struct hash_bucket *, void *))
					bgp_evpn_remote_ip_hash_unlink_nexthop,
				evi);
			bgp_evpn_evi_unlink_from_vrf(evi);
			evi->tenant_vrf_id = tenant_vrf_id;
			bgp_evpn_evi_link_to_vrf(evi);

			/*
			 * Resolve all the gateway IP nexthops for this VNI
			 * in new tenant vrf
			 */
			bgp_evpn_remote_ip_hash_iterate(
				evi,
				(void (*)(struct hash_bucket *, void *))
					bgp_evpn_remote_ip_hash_link_nexthop,
				evi);
		}

		/* If tunnel endpoint IP has changed, update (and delete prior
		 * type-3 route, if needed.)
		 */
		handle_tunnel_ip_change(NULL, bgp, evi, originator_ip);

		/* Update all routes with new endpoint IP and/or export RT
		 * for VRFs
		 */
		if (is_evi_live(evi))
			bgp_evpn_evi_update_routes(bgp, evi);
	} else {
		/* Create or update as appropriate. */
		evi = bgp_evpn_evi_new(bgp, vni, originator_ip, tenant_vrf_id,
				   mcast_grp, svi_ifindex);
	}

	/* if the EVI is live already, there is nothing more to do */
	if (is_evi_live(evi))
		return 0;

	/* Mark as "live" */
	SET_FLAG(evi->flags, EVI_FLAG_LIVE);

	/* Tunnel is newly active.
	 * Add TIP to tip_hash of the EVPN underlay instance (bgp_get_evpn_master_instance()).
	 */
	if (bgp_tip_add(bgp, originator_ip))
		/* The originator_ip was not already present in the
		 * bgp martian next-hop table as a tunnel-ip, so we
		 * need to go back and filter routes matching the new
		 * martian next-hop.
		 */
		bgp_filter_evpn_routes_upon_martian_change(bgp_evpn_mi,
							   BGP_MARTIAN_TUN_IP);

	/*
	 * Create EVPN type-3 route and schedule for processing.
	 *
	 * RT-3 only if doing head-end replication
	 */
	if (bgp_evpn_evi_get_flood_mode(bgp, evi) == VXLAN_FLOOD_HEAD_END_REPL) {
		build_evpn_type3_prefix(&p, &evi->originator_ip);
		if (bgp_evpn_evi_update_route(bgp, evi, &p, 0, 0, NULL)) {
			flog_err(EC_BGP_EVPN_ROUTE_CREATE,
				 "%u: Type3 route creation failure for VNI %u",
				 bgp->vrf_id, vni);
			return -1;
		}
	}

	/* If we are advertising gateway mac-ip
	   It needs to be conveyed again to zebra */
	bgp_zebra_advertise_gw_macip(bgp, evi->advertise_gw_macip, evi->vni);

	/* advertise svi mac-ip knob to zebra */
	bgp_zebra_advertise_svi_macip(bgp, evi->advertise_svi_macip, evi->vni);

	bgp_evpn_l2vni_remote_route_processing(evi);

	return 0;
}

/*
 * Handle change in setting for BUM handling. The supported values
 * are head-end replication and dropping all BUM packets. Any change
 * should be registered with zebra. Also, if doing head-end replication,
 * need to advertise local VNIs as EVPN RT-3 whereas, if BUM packets are
 * to be dropped, the RT-3s must be withdrawn.
 */
void bgp_evpn_flood_control_change(struct bgp *bgp)
{
	hash_iterate(bgp->evpn_master_instance_info.vnihash, advertise_withdraw_type3, bgp);
}

/*
 * Cleanup EVPN information on disable - Need to delete and withdraw
 * EVPN routes from peers.
 */
void bgp_evpn_cleanup_on_disable(struct bgp *bgp)
{
	struct bgp_evpn_evi *evi = NULL;
	uint32_t vni_count = zebra_l2_vni_count(&bm->zebra_l2_vni_head);

	/* Cleanup VNI FIFO list from this bgp instance */
	while (vni_count) {
		evi = zebra_l2_vni_pop(&bm->zebra_l2_vni_head);
		UNSET_FLAG(evi->flags, EVI_FLAG_ADD);
		vni_count--;
	}

	hash_iterate(bgp->evpn_master_instance_info.vnihash, (void (*)(struct hash_bucket *, void *))cleanup_vni_on_disable,
		     bgp);
}

static void bgp_evpn_master_instance_info_init(struct bgp *bgp)
{
	evi_irt_nodes_init(&bgp->evpn_master_instance_info.evi_irt_nodes);
	vrf_wildcard_irt_nodes_init(&bgp->evpn_master_instance_info.vrf_wildcard_irt_nodes);
	vrf_fq_irt_nodes_init(&bgp->evpn_master_instance_info.vrf_fq_irt_nodes);
	evi_wildcard_irt_nodes_init(&bgp->evpn_master_instance_info.evi_wildcard_irt_nodes);
	evi_fq_irt_nodes_init(&bgp->evpn_master_instance_info.evi_fq_irt_nodes);
}

static void bgp_evpn_master_instance_info_cleanup(struct bgp *bgp)
{
	struct evi_irt_node *evi_irt;
	uint32_t idx = 0;

	while ((evi_irt = evi_irt_nodes_pop_all(&bgp->evpn_master_instance_info.evi_irt_nodes,
						&idx))) {

		evi_irt_nodes_del(&bgp->evpn_master_instance_info.evi_irt_nodes, evi_irt);
		/* No need to free the EVIs themselves, they are held in vnihash */
		list_delete(&evi_irt->evis);
		XFREE(MTYPE_BGP_EVPN_EVI_IRT_NODE, evi_irt);
	}
	evi_irt_nodes_fini(&bgp->evpn_master_instance_info.evi_irt_nodes);

	struct vrf_wildcard_irt_node *vrf_wildcard_irt;
	idx = 0;
	while ((vrf_wildcard_irt = vrf_wildcard_irt_nodes_pop_all(&bgp->evpn_master_instance_info.vrf_wildcard_irt_nodes, &idx))) {
		vrf_wildcard_irt_node_free(vrf_wildcard_irt);
	}
	vrf_wildcard_irt_nodes_fini(&bgp->evpn_master_instance_info.vrf_wildcard_irt_nodes);

	struct vrf_fq_irt_node *vrf_fq_irt;
	idx = 0;
	while ((vrf_fq_irt = vrf_fq_irt_nodes_pop_all(&bgp->evpn_master_instance_info.vrf_fq_irt_nodes, &idx))) {
		vrf_fq_irt_node_free(vrf_fq_irt);
	}
	vrf_fq_irt_nodes_fini(&bgp->evpn_master_instance_info.vrf_fq_irt_nodes);

	struct evi_wildcard_irt_node *evi_wildcard_irt;
	idx = 0;
	while ((evi_wildcard_irt = evi_wildcard_irt_nodes_pop_all(&bgp->evpn_master_instance_info.evi_wildcard_irt_nodes, &idx))) {
		evi_wildcard_irt_node_free(evi_wildcard_irt);
	}
	evi_wildcard_irt_nodes_fini(&bgp->evpn_master_instance_info.evi_wildcard_irt_nodes);

	struct evi_fq_irt_node *evi_fq_irt;
	idx = 0;
	while ((evi_fq_irt = evi_fq_irt_nodes_pop_all(&bgp->evpn_master_instance_info.evi_fq_irt_nodes, &idx))) {
		evi_fq_irt_node_free(evi_fq_irt);
	}
	evi_fq_irt_nodes_fini(&bgp->evpn_master_instance_info.evi_fq_irt_nodes);
}

/*
 * Cleanup EVPN information - invoked at the time of bgpd exit or when the
 * BGP instance (default) is being freed.
 */
void bgp_evpn_cleanup(struct bgp *bgp)
{
	/* Guard against double-call during termination */
	if (!bgp->evpn_master_instance_info.vnihash)
		return;

	bgp_evpn_master_instance_info_cleanup(bgp);

	hash_iterate(bgp->evpn_master_instance_info.vnihash,
		     (void (*)(struct hash_bucket *, void *))free_vni_entry,
		     bgp);

	hash_clean_and_free(&bgp->evpn_master_instance_info.vnihash, NULL);

	hash_clean_and_free(&bgp->vni_svi_hash,
			    (void (*)(void *))hash_evpn_free);


	/* No need to free the items themselves, they are held in vnihash */
	list_delete(&bgp->l2vnis);

	if (bgp->evpn_info) {
		ecommunity_free(&bgp->evpn_info->soo);
		XFREE(MTYPE_BGP_EVPN_INFO, bgp->evpn_info);
	}

	bgp_evpn_rt_config_free(bgp->vrf_route_target_config);

	struct bgp_evpn_effective_wildcard_rt* eff_wildcard_rt;
	while((eff_wildcard_rt = bgp_evpn_effective_wildcard_rt_slu_pop(&bgp->effective_wildcard_import_rts))) {
		bgp_evpn_effective_wildcard_rt_free(eff_wildcard_rt);
	}
	struct bgp_evpn_effective_fq_rt* eff_fq_rt;
	while((eff_fq_rt = bgp_evpn_effective_fq_rt_slu_pop(&bgp->effective_fq_import_rts))) {
		bgp_evpn_effective_fq_rt_free(eff_fq_rt);
	}
	while((eff_fq_rt = bgp_evpn_effective_fq_rt_slu_pop(&bgp->effective_fq_export_rts))) {
		bgp_evpn_effective_fq_rt_free(eff_fq_rt);
	}

	if (bgp->vrf_prd_pretty)
		XFREE(MTYPE_BGP_NAME, bgp->vrf_prd_pretty);
}

/*
 * Initialization for EVPN
 * Create
 *  VNI hash table
 *  hash for RT to VNI
 */
void bgp_evpn_init(struct bgp *bgp)
{
	bgp_evpn_master_instance_info_init(bgp);

	bgp->evpn_master_instance_info.vnihash =
		hash_create(vni_hash_key_make, vni_hash_cmp, "BGP VNI Hash");
	bgp->vni_svi_hash =
		hash_create(vni_svi_hash_key_make, vni_svi_hash_cmp,
			    "BGP VNI hash based on SVI ifindex");

	bgp->l2vnis = list_new();
	bgp->l2vnis->cmp = vni_list_cmp;
	bgp->evpn_info = XCALLOC(MTYPE_BGP_EVPN_INFO, sizeof(struct bgp_evpn_info));
	assert(bgp->evpn_info);


	/* By default Duplicate Address Detection is enabled.
	 * Max-moves (N) 5, detection time (M) 180
	 * default action is warning-only
	 * freeze action permanently freezes address,
	 * and freeze time (auto-recovery) is disabled.
	 */
	bgp->evpn_info->dup_addr_detect = true;
	bgp->evpn_info->dad_time = EVPN_DAD_DEFAULT_TIME;
	bgp->evpn_info->dad_max_moves = EVPN_DAD_DEFAULT_MAX_MOVES;
	bgp->evpn_info->dad_freeze = false;
	bgp->evpn_info->dad_freeze_time = 0;
	/* Initialize zebra vxlan */
	bgp_zebra_dup_addr_detection(bgp);
	/* Enable PIP feature by default for bgp vrf instance */
	if (bgp->inst_type == BGP_INSTANCE_TYPE_VRF) {
		struct bgp *bgp_default;

		bgp->evpn_info->advertise_pip = true;
		bgp_default = bgp_get_default();
		if (bgp_default) {
			SET_IPADDR_V4(&bgp->evpn_info->pip_ip);
			bgp->evpn_info->pip_ip.ipaddr_v4 = bgp_default->router_id;
		}
	}

	/* Default BUM handling is to do head-end replication. */
	bgp->vxlan_flood_ctrl = VXLAN_FLOOD_HEAD_END_REPL;

	bgp->vrf_route_target_config = bgp_evpn_rt_config_new();

	bgp_evpn_effective_wildcard_rt_slu_init(&bgp->effective_wildcard_import_rts);
	bgp_evpn_effective_fq_rt_slu_init(&bgp->effective_fq_import_rts);
	bgp_evpn_effective_fq_rt_slu_init(&bgp->effective_fq_export_rts);

	bgp_evpn_nh_init(bgp);
}

void bgp_evpn_vrf_delete(struct bgp *bgp_vrf)
{
	bgp_evpn_vrf_unmap_from_vrf_irt_nodes(bgp_vrf);
	bgp_evpn_nh_finish(bgp_vrf);
}

/*
 * Get the prefixlen of the ip prefix carried within the type5 evpn route.
 */
int bgp_evpn_get_type5_prefixlen(const struct prefix *pfx)
{
	struct prefix_evpn *evp = (struct prefix_evpn *)pfx;

	if (!pfx || pfx->family != AF_EVPN)
		return 0;

	if (evp->prefix.route_type != BGP_EVPN_IP_PREFIX_ROUTE)
		return 0;

	return evp->prefix.prefix_addr.ip_prefix_length;
}

/*
 * Should we register nexthop for this EVPN prefix for nexthop tracking?
 */
bool bgp_evpn_is_prefix_nht_supported(const struct prefix *pfx)
{
	struct prefix_evpn *evp = (struct prefix_evpn *)pfx;

	/*
	 * EVPN routes should be marked as valid only if the nexthop is
	 * reachable. Only if this happens, the route should be imported
	 * (into VNI or VRF routing tables) and/or advertised.
	 * Note: This is currently applied for EVPN type-1, type-2,
	 * type-3, type-4 and type-5 routes.
	 * It may be tweaked later on for other routes, or
	 * even removed completely when all routes are handled.
	 */
	if (pfx && pfx->family == AF_EVPN
	    && (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE
		|| evp->prefix.route_type == BGP_EVPN_AD_ROUTE
		|| evp->prefix.route_type == BGP_EVPN_ES_ROUTE
		|| evp->prefix.route_type == BGP_EVPN_IMET_ROUTE
		|| evp->prefix.route_type == BGP_EVPN_IP_PREFIX_ROUTE))
		return true;

	return false;
}

static void *bgp_evpn_remote_ip_hash_alloc(void *p)
{
	const struct evpn_remote_ip *key = (const struct evpn_remote_ip *)p;
	struct evpn_remote_ip *ip;

	ip = XMALLOC(MTYPE_EVPN_REMOTE_IP, sizeof(struct evpn_remote_ip));
	*ip = *key;
	ip->macip_path_list = list_new();

	return ip;
}

static unsigned int bgp_evpn_remote_ip_hash_key_make(const void *p)
{
	const struct evpn_remote_ip *ip = p;
	const struct ipaddr *addr = &ip->addr;

	if (IS_IPADDR_V4(addr))
		return jhash_1word(addr->ipaddr_v4.s_addr, 0);

	return jhash2(addr->ipaddr_v6.s6_addr32,
		      array_size(addr->ipaddr_v6.s6_addr32), 0);
}

static bool bgp_evpn_remote_ip_hash_cmp(const void *p1, const void *p2)
{
	const struct evpn_remote_ip *ip1 = p1;
	const struct evpn_remote_ip *ip2 = p2;

	return !ipaddr_cmp(&ip1->addr, &ip2->addr);
}

static void bgp_evpn_remote_ip_hash_init(struct bgp_evpn_evi *evi)
{
	if (!evpn_resolve_overlay_index())
		return;

	evi->remote_ip_hash = hash_create(bgp_evpn_remote_ip_hash_key_make,
					  bgp_evpn_remote_ip_hash_cmp,
					  "BGP EVPN remote IP hash");
}

static void bgp_evpn_remote_ip_hash_free(struct hash_bucket *bucket, void *args)
{
	struct evpn_remote_ip *ip = (struct evpn_remote_ip *)bucket->data;
	struct bgp_evpn_evi *evi = (struct bgp_evpn_evi *)args;

	bgp_evpn_remote_ip_process_nexthops(evi, &ip->addr, false);

	list_delete(&ip->macip_path_list);

	hash_release(evi->remote_ip_hash, ip);
	XFREE(MTYPE_EVPN_REMOTE_IP, ip);
}

static void bgp_evpn_remote_ip_hash_destroy(struct bgp_evpn_evi *evi)
{
	if (!evpn_resolve_overlay_index() || evi->remote_ip_hash == NULL)
		return;

	hash_iterate(evi->remote_ip_hash,
	(void (*)(struct hash_bucket *, void *))bgp_evpn_remote_ip_hash_free,
	evi);

	hash_free(evi->remote_ip_hash);
	evi->remote_ip_hash = NULL;
}

/* Add a remote MAC/IP route to hash table */
static void bgp_evpn_remote_ip_hash_add(struct bgp_evpn_evi *evi,
					struct bgp_path_info *pi)
{
	struct evpn_remote_ip tmp;
	struct evpn_remote_ip *ip;
	struct prefix_evpn *evp;

	if (!evpn_resolve_overlay_index())
		return;

	if (pi->type != ZEBRA_ROUTE_BGP || pi->sub_type != BGP_ROUTE_IMPORTED
	    || !CHECK_FLAG(pi->flags, BGP_PATH_VALID))
		return;

	evp = (struct prefix_evpn *)&pi->net->rn->p;

	if (evp->family != AF_EVPN
	    || evp->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE
	    || is_evpn_prefix_ipaddr_none(evp))
		return;

	tmp.addr = evp->prefix.macip_addr.ip;
	ip = hash_lookup(evi->remote_ip_hash, &tmp);
	if (ip) {
		if (listnode_lookup(ip->macip_path_list, pi) != NULL)
			return;
		(void)listnode_add(ip->macip_path_list, pi);
		return;
	}

	ip = hash_get(evi->remote_ip_hash, &tmp, bgp_evpn_remote_ip_hash_alloc);
	(void)listnode_add(ip->macip_path_list, pi);

	bgp_evpn_remote_ip_process_nexthops(evi, &ip->addr, true);
}

/* Delete a remote MAC/IP route from hash table */
static void bgp_evpn_remote_ip_hash_del(struct bgp_evpn_evi *evi,
					struct bgp_path_info *pi)
{
	struct evpn_remote_ip tmp;
	struct evpn_remote_ip *ip;
	struct prefix_evpn *evp;

	if (!evpn_resolve_overlay_index())
		return;

	evp = (struct prefix_evpn *)&pi->net->rn->p;

	if (evp->family != AF_EVPN
	    || evp->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE
	    || is_evpn_prefix_ipaddr_none(evp))
		return;

	tmp.addr = evp->prefix.macip_addr.ip;
	ip = hash_lookup(evi->remote_ip_hash, &tmp);
	if (ip == NULL)
		return;

	listnode_delete(ip->macip_path_list, pi);

	if (ip->macip_path_list->count == 0) {
		bgp_evpn_remote_ip_process_nexthops(evi, &ip->addr, false);
		hash_release(evi->remote_ip_hash, ip);
		list_delete(&ip->macip_path_list);
		XFREE(MTYPE_EVPN_REMOTE_IP, ip);
	}
}

static void bgp_evpn_remote_ip_hash_iterate(struct bgp_evpn_evi *evi,
					    void (*func)(struct hash_bucket *,
							 void *),
					    void *arg)
{
	if (!evpn_resolve_overlay_index())
		return;

	hash_iterate(evi->remote_ip_hash, func, arg);
}

static void show_remote_ip_entry(struct hash_bucket *bucket, void *args)
{
	char buf[INET6_ADDRSTRLEN];
	struct listnode *node = NULL;
	struct bgp_path_info *pi = NULL;
	struct vty *vty = (struct vty *)args;
	struct evpn_remote_ip *ip = (struct evpn_remote_ip *)bucket->data;

	vty_out(vty, "  Remote IP: %s\n",
		ipaddr2str(&ip->addr, buf, sizeof(buf)));
	vty_out(vty, "      Linked MAC/IP routes:\n");
	for (ALL_LIST_ELEMENTS_RO(ip->macip_path_list, node, pi))
		vty_out(vty, "        %pFX\n", &pi->net->rn->p);
}

void bgp_evpn_show_remote_ip_hash(struct hash_bucket *bucket, void *args)
{
	struct bgp_evpn_evi *evi = (struct bgp_evpn_evi *)bucket->data;
	struct vty *vty = (struct vty *)args;

	vty_out(vty, "VNI: %u\n", evi->vni);
	bgp_evpn_remote_ip_hash_iterate(
		evi,
		(void (*)(struct hash_bucket *, void *))show_remote_ip_entry,
		vty);
	vty_out(vty, "\n");
}

static void bgp_evpn_remote_ip_hash_link_nexthop(struct hash_bucket *bucket,
						 void *args)
{
	struct evpn_remote_ip *ip = (struct evpn_remote_ip *)bucket->data;
	struct bgp_evpn_evi *evi = (struct bgp_evpn_evi *)args;

	bgp_evpn_remote_ip_process_nexthops(evi, &ip->addr, true);
}

static void bgp_evpn_remote_ip_hash_unlink_nexthop(struct hash_bucket *bucket,
						   void *args)
{
	struct evpn_remote_ip *ip = (struct evpn_remote_ip *)bucket->data;
	struct bgp_evpn_evi *evi = (struct bgp_evpn_evi *)args;

	bgp_evpn_remote_ip_process_nexthops(evi, &ip->addr, false);
}

static unsigned int vni_svi_hash_key_make(const void *p)
{
	const struct bgp_evpn_evi *evi = p;

	return jhash_1word(evi->svi_ifindex, 0);
}

static bool vni_svi_hash_cmp(const void *p1, const void *p2)
{
	const struct bgp_evpn_evi *evi1 = p1;
	const struct bgp_evpn_evi *evi2 = p2;

	return (evi1->svi_ifindex == evi2->svi_ifindex);
}

static struct bgp_evpn_evi *bgp_evpn_vni_svi_hash_lookup(struct bgp *bgp,
						    ifindex_t svi)
{
	struct bgp_evpn_evi *evi;
	struct bgp_evpn_evi tmp;

	memset(&tmp, 0, sizeof(tmp));
	tmp.svi_ifindex = svi;
	evi = hash_lookup(bgp->vni_svi_hash, &tmp);
	return evi;
}

static void bgp_evpn_link_to_vni_svi_hash(struct bgp *bgp, struct bgp_evpn_evi *evi)
{
	if (evi->svi_ifindex == 0)
		return;

	(void)hash_get(bgp->vni_svi_hash, evi, hash_alloc_intern);
}

static void bgp_evpn_unlink_from_vni_svi_hash(struct bgp *bgp,
					      struct bgp_evpn_evi *evi)
{
	if (evi->svi_ifindex == 0)
		return;

	hash_release(bgp->vni_svi_hash, evi);
}

void bgp_evpn_show_vni_svi_hash(struct hash_bucket *bucket, void *args)
{
	struct bgp_evpn_evi *evpn = (struct bgp_evpn_evi *)bucket->data;
	struct vty *vty = (struct vty *)args;

	vty_out(vty, "SVI: %u VNI: %u\n", evpn->svi_ifindex, evpn->vni);
}

/*
 * This function is called for a bgp_nexthop_cache entry when the nexthop is
 * gateway IP overlay index.
 * This function returns true if there is a remote MAC/IP route for the gateway
 * IP in the EVI of the nexthop SVI.
 */
bool bgp_evpn_is_gateway_ip_resolved(struct bgp_nexthop_cache *bnc)
{
	struct bgp *bgp_evpn_mi = NULL;
	struct bgp_evpn_evi *evi = NULL;
	struct evpn_remote_ip tmp;
	struct prefix *p;

	if (!evpn_resolve_overlay_index())
		return false;

	if (!bnc->nexthop || bnc->nexthop->ifindex == 0)
		return false;

	bgp_evpn_mi = bgp_get_evpn_master_instance();
	if (!bgp_evpn_mi)
		return false;

	/*
	 * Gateway IP is resolved by nht over SVI interface.
	 * Use this SVI to find corresponding EVI(L2 context)
	 */
	evi = bgp_evpn_vni_svi_hash_lookup(bgp_evpn_mi, bnc->nexthop->ifindex);
	if (!evi)
		return false;

	if (evi->bgp_vrf != bnc->bgp)
		return false;

	/*
	 * Check if the gateway IP is present in the EVI remote_ip_hash table
	 * which stores all the remote IP addresses received via MAC/IP routes
	 * in this EVI
	 */
	memset(&tmp, 0, sizeof(tmp));

	p = &bnc->prefix;
	if (p->family == AF_INET) {
		tmp.addr.ipa_type = IPADDR_V4;
		memcpy(&(tmp.addr.ipaddr_v4), &(p->u.prefix4),
		       sizeof(struct in_addr));
	} else if (p->family == AF_INET6) {
		tmp.addr.ipa_type = IPADDR_V6;
		memcpy(&(tmp.addr.ipaddr_v6), &(p->u.prefix6),
		       sizeof(struct in6_addr));
	} else
		return false;

	if (hash_lookup(evi->remote_ip_hash, &tmp) == NULL)
		return false;

	return true;
}

/* Resolve/Unresolve nexthops when a MAC/IP route is added/deleted */
static void bgp_evpn_remote_ip_process_nexthops(struct bgp_evpn_evi *evi,
						struct ipaddr *addr,
						bool resolve)
{
	afi_t afi;
	struct prefix p;
	struct bgp_nexthop_cache *bnc;
	struct bgp_nexthop_cache_head *tree = NULL;

	if (!evi->bgp_vrf || evi->svi_ifindex == 0)
		return;

	memset(&p, 0, sizeof(p));

	if (addr->ipa_type == IPADDR_V4) {
		afi = AFI_IP;
		p.family = AF_INET;
		memcpy(&(p.u.prefix4), &(addr->ipaddr_v4),
		       sizeof(struct in_addr));
		p.prefixlen = IPV4_MAX_BITLEN;
	} else if (addr->ipa_type == IPADDR_V6) {
		afi = AFI_IP6;
		p.family = AF_INET6;
		memcpy(&(p.u.prefix6), &(addr->ipaddr_v6),
		       sizeof(struct in6_addr));
		p.prefixlen = IPV6_MAX_BITLEN;
	} else
		return;

	tree = &evi->bgp_vrf->nexthop_cache_table[afi];
	bnc = bnc_find(tree, &p, 0, 0);

	if (!bnc || !bnc->is_evpn_gwip_nexthop)
		return;

	if (!bnc->nexthop || bnc->nexthop->ifindex != evi->svi_ifindex)
		return;

	if (BGP_DEBUG(nht, NHT))
		zlog_debug("%s(%u): vni %u mac/ip %s for NH %pFX",
			   evi->bgp_vrf->name_pretty, evi->tenant_vrf_id,
			   evi->vni, (resolve ? "add" : "delete"),
			   &bnc->prefix);

	/*
	 * MAC/IP route or SVI or tenant vrf being added to EVI.
	 * Set nexthop as valid only if it is already L3 reachable
	 */
	if (resolve && CHECK_FLAG(bnc->flags, BGP_NEXTHOP_EVPN_INCOMPLETE)) {
		UNSET_FLAG(bnc->flags, BGP_NEXTHOP_EVPN_INCOMPLETE);
		SET_FLAG(bnc->flags, BGP_NEXTHOP_VALID);
		SET_FLAG(bnc->change_flags, BGP_NEXTHOP_MACIP_CHANGED);
		evaluate_paths(bnc);
	}

	 /* MAC/IP route or SVI or tenant vrf being deleted from EVI */
	if (!resolve && CHECK_FLAG(bnc->flags, BGP_NEXTHOP_VALID)) {
		UNSET_FLAG(bnc->flags, BGP_NEXTHOP_VALID);
		SET_FLAG(bnc->flags, BGP_NEXTHOP_EVPN_INCOMPLETE);
		SET_FLAG(bnc->change_flags, BGP_NEXTHOP_MACIP_CHANGED);
		evaluate_paths(bnc);
	}
}

void bgp_evpn_handle_resolve_overlay_index_set(struct hash_bucket *bucket,
					       void *arg)
{
	struct bgp_evpn_evi *evi = (struct bgp_evpn_evi *)bucket->data;
	struct bgp_dest *dest;
	struct bgp_path_info *pi;

	bgp_evpn_remote_ip_hash_init(evi);

	for (dest = bgp_table_top(evi->ip_table); dest;
	     dest = bgp_route_next(dest))
		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
			bgp_evpn_remote_ip_hash_add(evi, pi);
}

void bgp_evpn_handle_resolve_overlay_index_unset(struct hash_bucket *bucket,
						 void *arg)
{
	struct bgp_evpn_evi *evi = (struct bgp_evpn_evi *)bucket->data;

	bgp_evpn_remote_ip_hash_destroy(evi);
}

/*
 * Helper function for getting the correct label index for l3vni.
 *
 * Returns the label with the l3vni of the path's label stack.
 *
 * L3vni is always last label. Type5 will only
 * have one label, Type2 will have two.
 *
 */
mpls_label_t *bgp_evpn_path_info_labels_get_l3vni(mpls_label_t *labels,
						  uint8_t num_labels)
{
	if (!labels)
		return NULL;

	if (!num_labels)
		return NULL;

	return &labels[num_labels - 1];
}

/*
 * Returns the l3vni of the path converted from the label stack.
 */
vni_t bgp_evpn_path_info_get_l3vni(const struct bgp_path_info *pi)
{
	if (!BGP_PATH_INFO_NUM_LABELS(pi))
		return 0;

	return label2vni(
		bgp_evpn_path_info_labels_get_l3vni(pi->extra->labels->label,
						    pi->extra->labels
							    ->num_labels));
}

/*
 * Returns true if the l3vni of any of this path doesn't match vrf's l3vni.
 */
static bool bgp_evpn_path_is_dvni(const struct bgp *bgp_vrf,
				  const struct bgp_path_info *pi)
{
	vni_t vni = 0;

	vni = bgp_evpn_path_info_get_l3vni(pi);

	if ((vni > 0) && (vni != bgp_vrf->l3vni))
		return true;

	return false;
}

/*
 * Returns true if the l3vni of any of the mpath's doesn't match vrf's l3vni.
 */
bool bgp_evpn_mpath_has_dvni(const struct bgp *bgp_vrf,
			     struct bgp_path_info *mpinfo)
{
	for (; mpinfo; mpinfo = bgp_path_info_mpath_next(mpinfo)) {
		if (bgp_evpn_path_is_dvni(bgp_vrf, mpinfo))
			return true;
	}

	return false;
}


/*
 * From tenant vrf instance's L3VNI source VTEP_IP fill V4 or V6
 * version of attr's nexthop field from PIP.
 */
void bgp_evpn_fill_rmac_nh_to_attr(struct bgp *bgp_vrf, struct attr *attr, struct prefix_evpn *evp,
				   struct ipaddr *vtep_ip)
{
	if (!bgp_vrf || !attr)
		return;
	/* Advertise Primary IP (PIP) is enabled, send individual
	 * IP (default instance router-id) as nexthop.
	 * PIP is disabled or vrr interface is not present
	 * use anycast-IP as nexthop and anycast RMAC.
	 */
	if (!bgp_vrf->evpn_info->advertise_pip || (!bgp_vrf->evpn_info->is_anycast_mac)) {
		memcpy(&attr->rmac, &bgp_vrf->rmac, ETH_ALEN);
		if (IS_IPADDR_V4(&bgp_vrf->originator_ip)) {
			attr->nexthop = bgp_vrf->originator_ip.ipaddr_v4;
			attr->mp_nexthop_global_in = bgp_vrf->originator_ip.ipaddr_v4;
			attr->mp_nexthop_len = BGP_ATTR_NHLEN_IPV4;
			bgp_attr_set(attr, BGP_ATTR_NEXT_HOP);
		} else {
			IPV6_ADDR_COPY(&attr->mp_nexthop_global, &bgp_vrf->originator_ip.ipaddr_v6);
			attr->mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL;
		}
		if (vtep_ip)
			*vtep_ip = bgp_vrf->originator_ip;
	} else {
		/* copy sys rmac */
		memcpy(&attr->rmac, &bgp_vrf->evpn_info->pip_rmac, ETH_ALEN);
		/* L3VNI VTEP-IP is IPv4 copy v4 PIP IP, otherwise copy
		 * v6 PIP IP for nexthop path attribute
		 */
		if (vtep_ip)
			*vtep_ip = bgp_vrf->evpn_info->pip_ip;

		if (IS_IPADDR_V4(&bgp_vrf->originator_ip)) {
			attr->mp_nexthop_len = BGP_ATTR_NHLEN_IPV4;
			if (bgp_vrf->evpn_info->pip_ip.ipaddr_v4.s_addr != INADDR_ANY) {
				attr->nexthop = bgp_vrf->evpn_info->pip_ip.ipaddr_v4;
				attr->mp_nexthop_global_in = bgp_vrf->evpn_info->pip_ip.ipaddr_v4;
				bgp_attr_set(attr, BGP_ATTR_NEXT_HOP);
			} else if (bgp_vrf->evpn_info->pip_ip.ipaddr_v4.s_addr == INADDR_ANY) {
				if (bgp_debug_zebra(NULL))
					zlog_debug("VRF %s evp %pFX advertise-pip primary ip is not configured",
						   vrf_id_to_name(bgp_vrf->vrf_id), evp);
			}
		} else if (IS_IPADDR_V6(&bgp_vrf->originator_ip)) {
			attr->mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL;
			if (!IN6_IS_ADDR_UNSPECIFIED(&bgp_vrf->evpn_info->pip_ip.ipaddr_v6)) {
				IPV6_ADDR_COPY(&attr->mp_nexthop_global,
					       &bgp_vrf->evpn_info->pip_ip.ipaddr_v6);
				if (bgp_debug_zebra(NULL))
					zlog_debug("%s ipv6 vtep, pip %pI6 address as nexthop",
						   __func__, &bgp_vrf->evpn_info->pip_ip.ipaddr_v6);
			} else if (IN6_IS_ADDR_UNSPECIFIED(&bgp_vrf->evpn_info->pip_ip.ipaddr_v6)) {
				if (bgp_debug_zebra(NULL))
					zlog_debug("VRF %s evp %pFX advertise-pip primary ip is not configured",
						   vrf_id_to_name(bgp_vrf->vrf_id), evp);
			}
		}
	}
}

/* Upon aggregate set trigger unimport suppressed routes
 * from EVPN
 */
void bgp_aggr_supp_withdraw_from_evpn(struct bgp *bgp, afi_t afi, safi_t safi)
{
	struct bgp_dest *agg_dest, *dest, *top;
	const struct prefix *aggr_p;
	struct bgp_aggregate *bgp_aggregate;
	struct bgp_table *table;
	struct bgp_path_info *pi;
	uint32_t addpath_id;

	if (!bgp_get_evpn_master_instance() || !(bgp_evpn_should_originate_type5_routes_bestpath(bgp, afi) ||
				 bgp_evpn_should_originate_type5_routes_multipath(bgp, afi)))
		return;

	/* Aggregate-address table walk. */
	table = bgp->rib[afi][safi];
	for (agg_dest = bgp_table_top(bgp->aggregate[afi][safi]); agg_dest;
	     agg_dest = bgp_route_next(agg_dest)) {
		bgp_aggregate = bgp_dest_get_bgp_aggregate_info(agg_dest);

		if (bgp_aggregate == NULL)
			continue;

		aggr_p = bgp_dest_get_prefix(agg_dest);

		/* Look all nodes below the aggregate prefix in
		 * global AFI/SAFI table (IPv4/IPv6).
		 * Trigger withdrawal (this will be Type-5 routes only)
		 * from EVPN Global table.
		 */
		top = bgp_node_get(table, aggr_p);
		for (dest = bgp_node_get(table, aggr_p); dest;
		     dest = bgp_route_next_until(dest, top)) {
			const struct prefix *dest_p = bgp_dest_get_prefix(dest);

			if (dest_p->prefixlen <= aggr_p->prefixlen)
				continue;

			for (pi = bgp_dest_get_bgp_path_info(dest); pi;
			     pi = pi->next) {
				if (pi->sub_type == BGP_ROUTE_AGGREGATE)
					continue;

				/* Only Suppressed route remove from EVPN */
				if (!bgp_path_suppressed(pi))
					continue;

				if (BGP_DEBUG(zebra, ZEBRA))
					zlog_debug("%s aggregated %pFX remove suppressed route %pFX",
						   __func__, aggr_p, dest_p);

				if (!is_route_injectable_into_evpn_non_supp(pi))
					continue;

				addpath_id = bgp_evpn_addpath_id_for_path(bgp, pi, afi);
				bgp_evpn_vrf_delete_prefix_as_type5_route(bgp, NULL, dest_p, afi, safi,
							      addpath_id);
			}
		}
	}
}

static uint32_t bgp_evpn_addpath_id_for_path(const struct bgp *bgp, const struct bgp_path_info *pi,
					     afi_t afi)
{
	if (!bgp || !pi)
		return 0;
	if (afi != AFI_IP && afi != AFI_IP6)
		return 0;
	if (!bgp_evpn_should_originate_type5_routes_multipath(bgp, afi))
		return 0;

	return pi->tx_addpath.addpath_tx_id[BGP_ADDPATH_ALL];
}
