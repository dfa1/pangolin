/*
 * p_ip.c -- decodes the IP protocol
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
#include <netdb.h>

#include "pangolin.h"

/* 
 * IP packet structure:
 *
 * 0                   1                   2                   3   
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Version|  IHL  |Type of Service|          Total Length         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Identification        |Flags|      Fragment Offset    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Time to Live |    Protocol   |         Header Checksum       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       Source Address                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Destination Address                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Options                    |    Padding    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

struct ip_hdr
{
    U8 ip_vh;
    U8 ip_tos;
    U16 ip_len;
    U16 ip_id;
    U16 ip_off;
    U8 ip_ttl;
    U8 ip_pro;
    U16 ip_sum;
    U32 ip_src;
    U32 ip_dst;
};

PRIVATE void
resolve(U8 *buf, U32 *raw) /* TODO: caching */
{
    struct hostent *hp;
    char *addr;
    size_t n;

    hp = gethostbyaddr(raw, 4, PF_INET);

    if (hp != NULL) {
        n = strlen(hp->h_name);

        if (n > 64)
            goto dotted;

        addr = hp->h_name;
    } else {
        struct in_addr in;

      dotted:
        memcpy(&in, raw, 4);
        addr = inet_ntoa(in);
        n = 16;
    }

    memcpy(buf, addr, n);
    buf[n] = 0;
}

PUBLIC void
ip_dump(struct packet *packet, struct context *ctx)
{
    struct ip_hdr hdr;
    U8 dst[64];
    U8 src[64];
    U8 vhl;

    memcpy(&vhl, packet->data, 1);
    memcpy(&hdr, packet->data, (vhl & 0xF) * 4);
    packet->data += (vhl & 0xF) * 4;
    if (ctx->resolve_dns) {
	resolve(src, &hdr.ip_src); 
	resolve(dst, &hdr.ip_dst);
    }

    switch (hdr.ip_pro) {
    case 0x01:
	icmp_dump(packet, src, dst, ctx);
	break;
	
    case 0x06:
	tcp_dump(packet, src, dst, ctx);
	break;
	
    case 0x11:
	udp_dump(packet, src, dst, ctx);
	break;
	
    default:
	fprintf(stdout, "unknown %s > %s ", src, dst);
	break;
    }
}
