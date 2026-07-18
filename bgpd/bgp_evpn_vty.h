// SPDX-License-Identifier: GPL-2.0-or-later
/* EVPN VTY functions to EVPN
 * Copyright (C) 2017 6WIND
 */

#ifndef _FRR_BGP_EVPN_VTY_H
#define _FRR_BGP_EVPN_VTY_H

extern void bgp_config_write_evpn_info(struct vty *vty, struct bgp *bgp,
				       afi_t afi, safi_t safi);
extern void bgp_ethernetvpn_init(void);

/* VNI create/delete cores (vty-free), shared with the proteus/northbound vni
 * list create/destroy callbacks (bgp_nb_evpn.c). */
extern struct bgpevpn *evpn_create_update_vni(struct bgp *bgp, vni_t vni);
extern void evpn_delete_vni(struct bgp *bgp, struct bgpevpn *vpn);

/* Instance-level EVPN advertise-flag setters (vty-free), shared with the
 * proteus/northbound flag-leaf modify callbacks (bgp_nb_evpn.c, M6 batch B2).
 * All are self-guarded/idempotent. The advertise-default-gw / advertise-svi-ip
 * setters take a vpn (pass NULL for the instance-level default). */
extern void evpn_set_advertise_all_vni(struct bgp *bgp);
extern void evpn_unset_advertise_all_vni(struct bgp *bgp);
extern void evpn_set_advertise_default_gw(struct bgp *bgp, struct bgpevpn *vpn);
extern void evpn_unset_advertise_default_gw(struct bgp *bgp, struct bgpevpn *vpn);
extern void evpn_set_advertise_svi_macip(struct bgp *bgp, struct bgpevpn *vpn, uint32_t set);
extern void bgp_evpn_set_unset_resolve_overlay_index(struct bgp *bgp, bool set);

/* Per-VNI RD configure/unconfigure (vty-free) and the subnet-advertisement
 * setters, shared with the proteus/northbound 'vni N' sub-leaf callbacks
 * (bgp_nb_evpn.c, M6 batch B6). rd_pretty is copied (XSTRDUP'd internally),
 * so a function-scope buffer is fine at the call site. */
extern void evpn_configure_rd(struct bgp *bgp, struct bgpevpn *vpn, struct prefix_rd *rd,
			      const char *rd_pretty);
extern void evpn_unconfigure_rd(struct bgp *bgp, struct bgpevpn *vpn);
extern void evpn_set_advertise_subnet(struct bgp *bgp, struct bgpevpn *vpn);
extern void evpn_unset_advertise_subnet(struct bgp *bgp, struct bgpevpn *vpn);

/* Per-VRF-instance role setters (vty-free), shared with the proteus/
 * northbound instance-level 'l2vpn-evpn' sub-leaf callbacks (bgp_nb_evpn.c,
 * M6 batch B7: 'rd' and 'default-originate').
 * rd_pretty is copied (XSTRDUP'd internally), so a function-scope buffer is
 * fine at the call site. evpn_process_default_originate_cmd() is the
 * un-static'd former DEFPY-local helper: 'add' true/false mirrors the
 * retired bgp_evpn_default_originate_cmd / no_ pair.
 */
extern void evpn_configure_vrf_rd(struct bgp *bgp_vrf, struct prefix_rd *rd,
				  const char *rd_pretty);
extern void evpn_unconfigure_vrf_rd(struct bgp *bgp_vrf);
extern void evpn_process_default_originate_cmd(struct bgp *bgp_vrf, afi_t afi, bool add);

/* Desired-state processors extracted from the retired advertise-type5 /
 * advertise-pip commands (vty-free), shared with the proteus/northbound
 * callbacks (bgp_nb_evpn.c, M6 batch B9b). Both fire their route
 * withdraw/re-advertise machinery only on a real transition; rmap_name,
 * ip and mac may be NULL for "none". */
extern void evpn_process_advertise_type5_cmd(struct bgp *bgp_vrf, afi_t afi,
					     enum overlay_index_type oly, const char *rmap_name,
					     bool add);
extern void evpn_process_advertise_pip_cmd(struct bgp *bgp_vrf, bool enable,
					   const struct in_addr *ip, const struct ethaddr *mac);

/* The per-L2VNI route-target configure/unconfigure cores and the autort
 * rfc8365/mode helpers un-static'd for M6 batch B9b are declared in
 * bgp_evpn_private.h next to their VRF-level counterparts (their
 * signatures need the typed-RT definitions from there, which this
 * header's other includers do not pull in). */

/* Loop over all extended-communities in 'rtl' and return true if 'ecomtarget'
 * matches one of them; un-static'd (was bgp_evpn_vty.c-local) for the
 * proteus/northbound 'ead-es-route-target export' list callbacks
 * (bgp_nb_evpn.c, M6 batch B5), which need the same duplicate-add/
 * missing-delete guards as the legacy bgp_evpn_ead_es_rt_cmd /
 * no_bgp_evpn_ead_es_rt_cmd DEFUNs it was written for. */
extern bool bgp_evpn_rt_matches_existing(struct list *rtl, struct ecommunity *ecomtarget);

#define L2VPN_HELP_STR        "Layer 2 Virtual Private Network\n"
#define EVPN_HELP_STR        "Ethernet Virtual Private Network\n"
#define VNI_HELP_STR "VXLAN Network Identifier\n"
#define VNI_NUM_HELP_STR "VNI number\n"
#define VNI_ALL_HELP_STR "All VNIs\n"
#define DETAIL_HELP_STR "Print Detailed Output\n"
#define VTEP_HELP_STR "Remote VTEP\n"
#define VTEP_IP_HELP_STR "Remote VTEP IPv4 address\n"
#define VTEP_IPV6_HELP_STR "Remote VTEP IPv6 address\n"

/* Parse type from "type <ead|1|...>", return -1 on failure */
extern int bgp_evpn_cli_parse_type(int *type, struct cmd_token **argv,
				   int argc);

extern int bgp_evpn_show_all_routes(struct vty *vty, struct bgp *bgp, int type,
				    bool use_json, int detail);

#endif /* _QUAGGA_BGP_EVPN_VTY_H */
