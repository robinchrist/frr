// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * bgpd CLI compiled into mgmtd (zebra_cli.c / staticd pattern): the
 * milestone 1 proteus-bgp conversion slice.
 */
#ifndef _FRR_BGP_CLI_H_
#define _FRR_BGP_CLI_H_

#include "lib/northbound.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const struct frr_yang_module_info proteus_bgp_cli_info;

extern void bgp_cli_init(void);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_BGP_CLI_H_ */
