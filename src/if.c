/*
 * if.c -- network interfaces handling
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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <linux/if.h>
#include <netinet/ether.h>

#include <features.h>

#if (__GLIBC__ >= 2) && (__GLIBC_MINOR >= 1)
# include <netpacket/packet.h>
# include <net/ethernet.h>
#else
# include <asm/types.h>
# include <linux/if_packet.h>
# include <linux/if_ether.h>
#endif

#include "pangolin.h"

/* GNU libc version 2.1 doesn't define SOL_PACKET. */
#ifndef SOL_PACKET
# define SOL_PACKET 263
#endif

int if_list(void)
{
    struct ifconf ifc;
    struct ifreq *ifreqs, *ifr;
    int fd, nif, i, sts = 0;
    unsigned rqlen;

    fd = socket(PF_INET, SOCK_DGRAM, 0);

    if (fd < 0) {
	fprintf(stderr, "error: cannot create an helper socket: %s\n",
		strerror(errno));
	return -1;
    }

    ifc.ifc_buf = NULL;
    rqlen = 2 * sizeof(struct ifreq);	// TODO: this is a bug, ioctl
    // always returns two interfaces

    do {
	ifc.ifc_len = rqlen;
	ifc.ifc_buf = realloc(ifc.ifc_buf, ifc.ifc_len);

	if (ifc.ifc_buf == NULL) {
	    fprintf(stderr, "error: realloc()\n");
	    sts = 1;
	    goto outclose;
	}

	if (ioctl(fd, SIOCGIFCONF, &ifc) < 0) {
	    fprintf(stderr, "error: ioctl(SIOCGIFCONF): %s\n", strerror(errno));
	    sts = -1;

	    if (ifc.ifc_buf)
		free(ifc.ifc_buf);

	    goto outclose;
	}

	rqlen *= 2;
    }
    while (rqlen < sizeof(struct ifreq) + ifc.ifc_len);

    nif = ifc.ifc_len / sizeof(struct ifreq);
    ifr = ifreqs = realloc(ifc.ifc_buf, ifc.ifc_len);

    if (ifr == NULL) {
	fprintf(stderr, "error: realloc()\n");
	sts = -1;
	goto outclose;
    }

    fprintf(stdout, "Listing available interface(s):\n");

    for (i = 0; i < nif; i++, ifr++) {
	U8 mac[6];

	/* skip non IPv4 interfaces */
	if (ifr->ifr_addr.sa_family != PF_INET)
	    continue;

	/* skip PPP interfaces */
	if (ioctl(fd, SIOCGIFFLAGS, ifr) < 0) {
	    fprintf(stderr, "error: ioctl(SIOCGIFFLAGS): %s\n",
		    strerror(errno));
	    sts = -1;
	    goto outfree;
	}

	if (ifr->ifr_flags & IFF_POINTOPOINT)
	    continue;

	/* print accepted interface */
	memcpy(&mac, &ifr->ifr_hwaddr, 6);
	fprintf(stdout, "  %s\t%s%s%s\n", ifr->ifr_name,
		ifr->ifr_flags & IFF_UP ? "UP " : "",
		ifr->ifr_flags & IFF_LOOPBACK ? "LOOPBACK " : "",
		ifr->ifr_flags & IFF_PROMISC ? "PROMISC " : "");
    }

 outfree:
    free(ifreqs);

 outclose:
    close(fd);
    return sts;
}

int if_index(int fd, const char *iface)
{
    struct ifreq ifreq;

    memset(&ifreq, 0, sizeof(struct ifreq));
    strncpy(ifreq.ifr_name, iface, IFNAMSIZ);

    if (ioctl(fd, SIOCGIFINDEX, &ifreq) == -1) {
	fprintf(stderr, "error: interface %s: %s\n", iface, strerror(errno));
	return -1;
    }

    return ifreq.ifr_ifindex;
}

int if_promisc(int fd, const char *iface, int state)
{
    struct ifreq ifreq;

    memset(&ifreq, 0, sizeof(struct ifreq));
    strncpy(ifreq.ifr_name, iface, IFNAMSIZ);

    if (ioctl(fd, SIOCGIFFLAGS, &ifreq) < 0) {
	fprintf(stderr, "error: ioctl(SIOCGIFFLAGS): %s\n", strerror(errno));
	return -1;
    }

    if (state)
	ifreq.ifr_flags |= IFF_PROMISC;
    else
	ifreq.ifr_flags &= ~(IFF_PROMISC);

    if (ioctl(fd, SIOCSIFFLAGS, &ifreq) < 0) {
	fprintf(stderr, "error: ioctl(SIOCSIFFLAGS): %s\n", strerror(errno));
	return -1;
    }

    return 0;
}

int if_open(const char *iface)
{
    struct packet_mreq mreq;
    struct sockaddr_ll sll;
    int fd;
    int err;
    size_t errlen = sizeof(err);

    fd = socket(PF_PACKET, SOCK_RAW, TONET16(ETH_P_ALL));	// TODO: extension point

    if (fd < 0) {
	fprintf(stderr, "error: cannot create socket: %s\n", strerror(errno));
	err = -1;
	goto out;
    }

    /* bind socket to a specific interface */
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = PF_PACKET;
    sll.sll_ifindex = if_index(fd, iface);

    if (sll.sll_ifindex < 0) {
	err = -1;
	goto outclose;
    }

    sll.sll_protocol = TONET16(ETH_P_ALL);

    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) == -1) {
	fprintf(stderr, "error: bind(): %s\n", strerror(errno));
	err = -1;
	goto outclose;
    }

    /* check for pending errors on socket */
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) == -1) {
	fprintf(stderr, "error: getsockopt(): %s\n", strerror(errno));
	err = -1;
	goto outclose;
    }

    if (err > 0) {
	fprintf(stderr, "error: pending error: %s\n", strerror(errno));
	err = -1;
	goto outclose;
    }

    /* enable promisc mode */
    memset(&mreq, 0, sizeof(struct packet_mreq));
    mreq.mr_type = PACKET_MR_PROMISC;
    mreq.mr_ifindex = if_index(fd, iface);

    if (mreq.mr_ifindex < 0) {
	err = -1;
	goto outclose;
    }

    if (setsockopt
	(fd, SOL_SOCKET, PACKET_ADD_MEMBERSHIP, &mreq,
	 sizeof(struct packet_mreq)) < 0) {
	fprintf(stderr,
		"error: cannot enter promiscuous mode on interface %s: %s\n",
		iface, strerror(errno));
	err = -1;
	goto outclose;
    }

    /* enabling multicast */
    memset(&mreq, 0, sizeof(struct packet_mreq));
    mreq.mr_type = PACKET_MR_ALLMULTI;
    mreq.mr_ifindex = if_index(fd, iface);

    if (mreq.mr_ifindex < 0) {
	err = -1;
	goto outclose;
    }

    if (setsockopt
	(fd, SOL_SOCKET, PACKET_ADD_MEMBERSHIP, &mreq,
	 sizeof(struct packet_mreq)) < 0) {
	fprintf(stderr,
		"error: cannot receive all multicast packets on interface %s: %s\n",
		iface, strerror(errno));
	err = -1;
	goto outclose;
    }

    return fd;

 outclose:
    close(fd);

 out:
    return -1;
}

void if_close(int fd)
{
    (void)shutdown(fd, 2);
    (void)close(fd);
}

int if_stats(int fd)
{
    struct tpacket_stats stats;
    socklen_t statslen = sizeof(struct tpacket_stats);

    if (getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &stats, &statslen) < 0) {
	fprintf(stderr,
		"error: cannot fetch packet socket statistics: %s\n",
		strerror(errno));
	return -1;
    }

    fprintf(stdout, "\nPacket statistics\n-----------------\n");
    fprintf(stdout, "\n%u packet%s captured.", stats.tp_packets,
	    stats.tp_packets > 1 ? "s" : "");
    fprintf(stdout, "\n%u packet%s dropped.\n", stats.tp_drops,
	    stats.tp_drops > 1 ? "s" : "");
    return 0;
}

int if_filter(int fd, struct sock_filter *code, U16 size)
{
    struct sock_fprog filter;

    filter.len = size;
    filter.filter = code;

    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER,
		   &filter, sizeof(filter)) < 0) {
	// TODO: this cleanup is really necessary?
	int dummy;
	setsockopt(fd, SOL_SOCKET, SO_DETACH_FILTER, &dummy, sizeof(int));
	fprintf(stderr, "warning: cannot set the filter\n");
	return -1;
    }

    return 0;
}
