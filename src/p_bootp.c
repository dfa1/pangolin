/*
 * p_bootp.c -- decodes BOOTP protocol
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
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
 * +---------------+---------------+---------------+---------------+
 * |                            xid (4)                            |
 * +-------------------------------+-------------------------------+
 * |           secs (2)            |           flags (2)           |
 * +-------------------------------+-------------------------------+
 * |                          ciaddr  (4)                          |
 * +---------------------------------------------------------------+
 * |                          yiaddr  (4)                          |
 * +---------------------------------------------------------------+
 * |                          siaddr  (4)                          |
 * +---------------------------------------------------------------+
 * |                          giaddr  (4)                          |
 * +---------------------------------------------------------------+
 * |                          chaddr  (16)                         |
 * +---------------------------------------------------------------+
 * |                          sname   (64)                         |
 * +---------------------------------------------------------------+
 * |                          file    (128)                        |
 * +---------------------------------------------------------------+
 * |                          options (312)                        |
 * +---------------------------------------------------------------+
 */

struct bootp_hdr
{
    U8 bootp_op;
    U8 bootp_htype;
    U8 bootp_hlen;
    U8 bootp_hops;
    U32 bootp_id;
    U16 bootp_secs;
    U16 bootp_unused;
    U32 bootp_ca;
    U32 bootp_ya;
    U32 bootp_sa;
    U32 bootp_ga;
    U8 bootp_cha[16];
    U8 bootp_sname[64];
    U8 bootp_file[128];
    U8 bootp_vendor[64];
};

PRIVATE const char *
bootp_op2str(U8 op)
{
    switch (op) {
            case 0:
                return "ok";
            case 1:
                return "query";
            case 2:
                return "reply";
            case 3:
                return "error";
            default:
                return "unknown";
    }
}

PRIVATE void
bootp_ip(U8 *addr, U32 *raw)
{
    struct in_addr in;

    memcpy(&in, raw, 4);
    memcpy(addr, inet_ntoa(in), 16);
}

PUBLIC void
bootp_dump(struct packet *packet)
{
    struct bootp_hdr hdr;
    U8 sa[16], ca[16], ya[16], ga[16];

    memset(&hdr, 0, sizeof(struct bootp_hdr));
    memcpy(&hdr, packet->data, sizeof(struct bootp_hdr));
    bootp_ip(sa, &hdr.bootp_sa);
    bootp_ip(ca, &hdr.bootp_ca);
    bootp_ip(ya, &hdr.bootp_ya);
    bootp_ip(ga, &hdr.bootp_ga);
    fprintf(stdout, "BOOTP/DHCP %s: %s > %s ip %s gw %s",
            bootp_op2str(hdr.bootp_op), sa, ca, ya, ga);
}
