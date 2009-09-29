/*
 * p_tcp.c -- decodes the TCP protocol
 * Copyright (C) 2006  Davide Angelocola <davide.angelocola@gmail.com>
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

/* Lunghezza in byte dell'intestazione TCP. */
#define TCP_HDR_LEN 20

/* 
 * Intestazione di un pacchetto TCP. I nomi dei campi NON
 * corrispondono a quelli dell'RFC 793.
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          Source Port          |       Destination Port        |   
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
 * |                        Sequence Number                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Acknowledgment Number                      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Data |           |U|A|P|R|S|F|                               |   
 * | Offset| Reserved  |R|C|S|S|Y|I|            Window             |   
 * |       |           |G|K|H|T|N|N|                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Checksum            |         Urgent Pointer        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Options                    |    Padding    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             data                              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct tcp_hdr
{
    /* Parte FISSA dell'intestazione. */
    U16 tcp_sport;              /* Source Port. */
    U16 tcp_dport;              /* Destination Port. */
    U32 tcp_seq;                /* Sequence Number. */
    U32 tcp_ack;                /* Acknowledgment Number. */
    U8 tcp_off;                 /* Data Offset. */
    U8 tcp_flags;               /* Flags. */
    U16 tcp_win;                /* Window. */
    U16 tcp_sum;                /* Checksum. */
    U16 tcp_urp;                /* Urgent Pointer. */
    /* Parte VARIABILE dell'intestazione (Options + Padding). */
};

/* Flag per tcp_flags. */
#define TCP_FLAG_FIN (1 << 0)   /* FIN (0x01). */
#define TCP_FLAG_SYN (1 << 1)   /* SYN (0x02). */
#define TCP_FLAG_RST (1 << 2)   /* RST (0x04). */
#define TCP_FLAG_PUSH (1 << 3)  /* PUSH (0x08). */
#define TCP_FLAG_ACK (1 << 4)   /* ACK (0x10). */
#define TCP_FLAG_URP (1 << 5)   /* URP (0x20). */

EXTERN const char *service(U16, U8);

PUBLIC void
tcp_dump(struct packet *packet, U8 *src, U8 *dst)
{
    struct tcp_hdr hdr;
    struct protoent *pent;

    memset(&hdr, 0, TCP_HDR_LEN);
    memcpy(&hdr, packet->data, TCP_HDR_LEN);
    fprintf(stdout, "tcp %s:", src);

    pent = getprotobynumber(TOHOST16(hdr.tcp_sport));

    if (pent == NULL) {
        fprintf(stdout, "%d", TOHOST16(hdr.tcp_sport) & 0xFFFF);
    }
    else {
        fprintf(stdout, "%s", pent->p_name);
    }

    fprintf(stdout, " > %s:", dst);
    pent = getprotobynumber(TOHOST16(hdr.tcp_dport));

    if (pent == NULL) {
        fprintf(stdout, "%d", TOHOST16(hdr.tcp_dport) & 0xFFFF);
    }
    else {
        fprintf(stdout, "%s", pent->p_name);
    }

    if (hdr.tcp_flags & TCP_FLAG_PUSH)
        hdr.tcp_flags &= ~TCP_FLAG_ACK;

    if (hdr.tcp_flags & TCP_FLAG_FIN)
        hdr.tcp_flags &= ~TCP_FLAG_ACK;

    fprintf(stdout, " %c%c%c%c%c%c ",
            hdr.tcp_flags & TCP_FLAG_FIN ? 'F' : '\0',
            hdr.tcp_flags & TCP_FLAG_SYN ? 'S' : '\0',
            hdr.tcp_flags & TCP_FLAG_RST ? 'R' : '\0',
            hdr.tcp_flags & TCP_FLAG_PUSH ? 'P' : '\0',
            hdr.tcp_flags & TCP_FLAG_ACK ? (hdr.
                                            tcp_flags & TCP_FLAG_SYN ? 'A'
                                            : '-') : '\0',
            hdr.tcp_flags & TCP_FLAG_URP ? 'U' : '\0');


    if (hdr.tcp_flags & TCP_FLAG_SYN || hdr.tcp_flags & TCP_FLAG_FIN)
        fprintf(stdout, "seq %u ", TOHOST32(hdr.tcp_seq));

    if (hdr.tcp_flags & TCP_FLAG_ACK || hdr.tcp_flags & TCP_FLAG_PUSH
        || hdr.tcp_flags & TCP_FLAG_FIN)
        fprintf(stdout, "ack %u ", TOHOST32(hdr.tcp_ack));

    fprintf(stdout, "win %u", TOHOST16(hdr.tcp_win) & 0xFFFF);
}
