/*
 * p_icmp.c -- decodes ICMP protocol
 * Copyright (C) 2004-2011  Davide Angelocola <davide.angelocola@gmail.com>
 *
 * Pangolin is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Pangolin is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <stdio.h>
#include <string.h>

#include "pangolin.h"

/* 
 * ICMP packet
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |      Code     |          Checksum             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Identifier          |       Sequence Number         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        Address Mask                           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#define ICMP_HDR_LEN 8

struct icmp_hdr {
    U8 icmp_type;
    U8 icmp_code;
    U16 icmp_cksum;
    union {
	U32 gateway;
#define icmp_gateway data.gateway

	struct {
	    U16 echo_id;
	    U16 echo_seq;
	} echo;
#define icmp_echo_id data.echo.echo_id
#define icmp_echo_seq data.echo.echo_seq

	struct {
	    U16 frag_unused;
	    U16 frag_mtu;
	} frag;
#define icmp_frag_mtu data.frag.frag_mtu
    } data;
};

#define ICMP_ECHO_REPLY   0
#define ICMP_UNREACH            3	/* dest unreachable, codes: */
#define ICMP_SOURCE_QUENCH       4	/* packet lost, slow down */
#define ICMP_REDIRECT           5	/* shorter route, codes: */
#define ICMP_ECHO_REQUEST               8	/* echo service */
#define ICMP_TIME_EXCEEDED           11	/* time exceeded, code: */
#define ICMP_PARAMETER_PROB          12	/* ip header bad */
#define ICMP_TIMESTAMP             13	/* timestamp request */
#define ICMP_TIMESTAMP_REPLY        14	/* timestamp reply */
#define ICMP_INFO_REQUEST               15	/* information request */
#define ICMP_INFO_REPLY          16	/* information reply */
#define ICMP_ADDRESS            17	/* address mask request */
#define ICMP_ADDRESS_REPLY         18	/* address mask reply */

PUBLIC void
icmp_dump(struct packet *packet, U8 * src, U8 * dst, struct context *ctx)
{
    struct icmp_hdr hdr;

    memset(&hdr, 0, sizeof(struct icmp_hdr));
    memcpy(&hdr, packet->data, sizeof(struct icmp_hdr));

    ctx->out("icmp %s > %s ", src, dst);

    switch (hdr.icmp_type) {
    case ICMP_ECHO_REQUEST:
    case ICMP_ECHO_REPLY:
	ctx->out("echo-%s id=%d seq=%d ",
		 hdr.icmp_type ==
		 ICMP_ECHO_REQUEST ? "request" : "reply",
		 TOHOST16(hdr.icmp_echo_id) & 0xFFFF,
		 TOHOST16(hdr.icmp_echo_seq) & 0xFFFF);
	break;

    case ICMP_UNREACH:
	ctx->out("destination unreachable");
	break;

    case ICMP_SOURCE_QUENCH:
	ctx->out("source quench");
	break;

    case ICMP_REDIRECT:
	ctx->out("redirect (change route)");
	break;

    case ICMP_TIME_EXCEEDED:
	ctx->out("time exceeded");
	break;

    case ICMP_PARAMETER_PROB:
	ctx->out("parameter problem");
	break;

    case ICMP_TIMESTAMP:
	ctx->out("timestamp request");
	break;

    case ICMP_TIMESTAMP_REPLY:
	ctx->out("timestamp reply");
	break;

    case ICMP_INFO_REQUEST:
	ctx->out("information request");
	break;

    case ICMP_INFO_REPLY:
	ctx->out("information reply");
	break;

    case ICMP_ADDRESS:
	ctx->out("address mask request");
	break;

    case ICMP_ADDRESS_REPLY:
	ctx->out("address mask reply");
	break;

    default:
	ctx->out("unknown");
    }
}
