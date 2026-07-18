// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP dump routine.
 * Copyright (C) 1999 Kunihiro Ishiguro
 */

#ifndef _QUAGGA_BGP_DUMP_H
#define _QUAGGA_BGP_DUMP_H

/* MRT compatible packet dump values.  */
/* type value */
#define MSG_PROTOCOL_BGP4MP    16
#define MSG_PROTOCOL_BGP4MP_ET 17

/* subtype value */
#define BGP4MP_STATE_CHANGE 0
#define BGP4MP_MESSAGE 1
#define BGP4MP_ENTRY 2
#define BGP4MP_SNAPSHOT 3
#define BGP4MP_MESSAGE_AS4 4
#define BGP4MP_STATE_CHANGE_AS4 5
#define BGP4MP_MESSAGE_ADDPATH 8
#define BGP4MP_MESSAGE_AS4_ADDPATH 9
#define BGP4MP_MESSAGE_LOCAL_ADDPATH 10
#define BGP4MP_MESSAGE_AS4_LOCAL_ADDPATH 11

#define BGP_DUMP_HEADER_SIZE 12
#define BGP_DUMP_MSG_HEADER  40

#define TABLE_DUMP_V2_PEER_INDEX_TABLE 1
#define TABLE_DUMP_V2_RIB_IPV4_UNICAST 2
#define TABLE_DUMP_V2_RIB_IPV4_MULTICAST 3
#define TABLE_DUMP_V2_RIB_IPV6_UNICAST 4
#define TABLE_DUMP_V2_RIB_IPV6_MULTICAST 5
#define TABLE_DUMP_V2_RIB_IPV4_UNICAST_ADDPATH 8
#define TABLE_DUMP_V2_RIB_IPV4_MULTICAST_ADDPATH 9
#define TABLE_DUMP_V2_RIB_IPV6_UNICAST_ADDPATH 10
#define TABLE_DUMP_V2_RIB_IPV6_MULTICAST_ADDPATH 11
#define TABLE_DUMP_V2_RIB_GENERIC_ADDPATH 12

#define TABLE_DUMP_V2_PEER_INDEX_TABLE_IP  0
#define TABLE_DUMP_V2_PEER_INDEX_TABLE_IP6 1
#define TABLE_DUMP_V2_PEER_INDEX_TABLE_AS2 0
#define TABLE_DUMP_V2_PEER_INDEX_TABLE_AS4 2

/* The three dump streams of proteus-bgp-dump.yang's 'dump' container: its
 * 'all' / 'updates' / 'routes-mrt' presence containers map 1:1 onto these
 * (the CLI's '-et' token variants select the extended-timestamp flag, not
 * a separate stream).
 */
enum bgp_dump_target {
	BGP_DUMP_TARGET_ALL,
	BGP_DUMP_TARGET_UPDATES,
	BGP_DUMP_TARGET_ROUTES,
};

struct peer;

extern void bgp_dump_target_set(enum bgp_dump_target target, const char *path,
				const char *interval_str, bool extended_timestamp);
extern void bgp_dump_target_unset(enum bgp_dump_target target);

extern void bgp_dump_init(void);
extern void bgp_dump_finish(void);
extern int bgp_dump_state(struct peer *peer);

#endif /* _QUAGGA_BGP_DUMP_H */
