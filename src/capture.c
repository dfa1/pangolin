/*
 * capture.c -- read a packet from the raw socket
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
#include <unistd.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include <linux/if_packet.h>

#include "pangolin.h"

static socklen_t fromlen = sizeof(struct sockaddr_ll);

int capture(struct packet *packet, int fd, int loindex)
{
    struct sockaddr_ll from;

    memset(packet, 0, sizeof(struct packet));

    if (recvfrom(fd, packet->base, PKT_DATA_LEN, MSG_TRUNC,
		 (struct sockaddr *)&from, &fromlen) < 0) {
	fprintf(stderr, "error: recvfrom(): %s", strerror(errno));
	return -1;
    }

    packet->data = packet->base;
    packet->type = 0;

    if (from.sll_pkttype == PACKET_OUTGOING) {
	if (from.sll_ifindex == loindex)
	    return 0;
	else
	    packet->type = 0;
    }

    if (ioctl(fd, SIOCGSTAMP, &packet->time) < 0) {
	fprintf(stderr, "error: ioctl(SIOCGSTAMP): %s", strerror(errno));
	return -1;
    }

    return 1;
}
