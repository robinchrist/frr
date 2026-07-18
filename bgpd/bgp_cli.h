// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Robin Christ, partimus GmbH */
/*
 * bgpd CLI compiled into mgmtd (zebra_cli.c / staticd pattern): the
 * milestone 1 proteus-bgp conversion slice. The DEFPY bodies and cli_show
 * callbacks this header's proteus_bgp_cli_info/bgp_cli_init() front now
 * live in bgpd/proteus/bgp_cli_{instance,process,neighbor,common}.c.
 */
#ifndef _FRR_BGP_CLI_H_
#define _FRR_BGP_CLI_H_

#include "lib/northbound.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const struct frr_yang_module_info proteus_bgp_cli_info;
extern const struct frr_yang_module_info proteus_interface_cli_info;
extern const struct frr_yang_module_info proteus_bgp_filter_cli_info;

extern void bgp_cli_init(void);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_BGP_CLI_H_ */
