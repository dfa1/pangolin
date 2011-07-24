/*
 * p_udp.c -- decodes the UDP protocol
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
 * UPD packet
 *
 * 0                   1                   2                   3   
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          Source Port          |       Destination Port        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Length              |           Checksum            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             data                              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
#define UDP_HDR_LEN 8

/* see RFC 768. */
struct udp_hdr
{
    U16 udp_sport;
    U16 udp_dport;
    U16 udp_len;
    U16 udp_cksum;
};

EXTERN const char *service(U16, U8);
EXTERN void bootp_dump(struct packet *);

PUBLIC void
udp_dump(struct packet *packet, U8 *src, U8 *dst)
{
    struct udp_hdr hdr;
    U16 s, d;
    struct protoent *pent;

    memset(&hdr, 0, UDP_HDR_LEN);
    memcpy(&hdr, packet->data, UDP_HDR_LEN);
    s = TOHOST16(hdr.udp_sport);
    d = TOHOST16(hdr.udp_dport);
    packet->data += UDP_HDR_LEN;

    if (s == 68 || d == 68 || s == 67 || d == 67) {
        bootp_dump(packet);
    }
    else {
        fprintf(stdout, "udp %s:", src);
        pent = getprotobynumber(s);

        if (pent == NULL) // TODO: refactor with p_tcp.c
            fprintf(stdout, "%d", s & 0xFFFF);
        else
            fprintf(stdout, "%s", pent->p_name);

        fprintf(stdout, " %s:", dst);
        pent = getprotobynumber(d);

        if (pent == NULL)
            fprintf(stdout, "%d", d & 0xFFFF);
        else
            fprintf(stdout, "%s", pent->p_name);
    }
}
