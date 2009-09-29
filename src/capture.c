/*
 * capture.c -- read a packet from the raw socket
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
#include <unistd.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include <linux/if_packet.h>

#include "pangolin.h"

EXTERN int loindex;
PRIVATE socklen_t fromlen = sizeof(struct sockaddr_ll);

PUBLIC int
capture(struct packet *packet, int fd)
{
    struct sockaddr_ll from;

    memset(packet, 0, sizeof(struct packet));

    /*
     * Ricevo il pacchetto. E' interessante notare sia la presenza
     * del parametro MSG_TRUNC sia il fatto che a questa chiamata
     * vengono passati *solo* pacchetti che sono stati accettati
     * dal filtro.
     */
    if (recvfrom(fd, packet->base, PKT_DATA_LEN, MSG_TRUNC,
                 (struct sockaddr *) &from, &fromlen) < 0) {
        fprintf(stderr, "error: recvfrom(): %s", strerror(errno));
        return -1;
    }

    /* Inizializzo gli altri campi del pacchetto. */
    packet->data = packet->base;
    packet->type = 0;

    /*
     * Se il pacchetto e' OUTGOING (cioe' sta uscendo da questa
     * macchina ed e' diretto verso l'interfaccia di loopback
     * allora lo posso scartare qui ritornando la costante 0.
     */
    if (from.sll_pkttype == PACKET_OUTGOING) {
        if (from.sll_ifindex == loindex)
            return 0;
        else
            packet->type = 0;
    }

    /* Chiamo la ioctl(SIOCGSTAMP) per prendere il timestamp di questo pacchetto. */
    if (ioctl(fd, SIOCGSTAMP, &packet->time) < 0) {
        fprintf(stderr, "error: ioctl(SIOCGSTAMP): %s", strerror(errno));
        return -1;
    }

    return 1;
}
