// SPDX-License-Identifier: GPL-2.0-or-later
/* bgpd route-map CLI (northbound commands for frr-bgp-route-map).
 *
 * Split out of bgp_routemap.c so this CLI can also be compiled into
 * mgmtd (bgpd-proteus-conversion M3, batch B-RM3), mirroring how
 * bgp_cli.c is compiled into mgmtd for the instance/process-level
 * commands. See bgp_routemap.c for why it still calls this
 * function too during the interim dual-installation period.
 */

#ifndef _BGP_ROUTEMAP_CLI_H
#define _BGP_ROUTEMAP_CLI_H

#ifdef __cplusplus
extern "C" {
#endif

extern void bgp_routemap_cli_init(void);

#ifdef __cplusplus
}
#endif

#endif /* _BGP_ROUTEMAP_CLI_H */
