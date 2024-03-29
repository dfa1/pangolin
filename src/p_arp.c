/*
 * p_arp.c -- decodes the ARP protocol
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

/* for arp_hrd2str() */
#include <net/if_arp.h>

#include "pangolin.h"

#define ARP_HDR_LEN 8

struct arp_hdr {
    U16 arp_hrd;		/* format of hardware address. */
    U16 arp_pro;		/* format of protocol address. */
    U8 arp_hln;			/* hardware length address. */
    U8 arp_pln;			/* protocol length address. */
    U16 arp_op;			/* Opcode. */

#ifdef VARIABLE
    U8 arp_sha[];		/* Sender Hardware Address. */
    U8 arp_spa[];		/* Sender Protocol Address. */
    U8 arp_tha[];		/* Target Hardware Address. */
    U8 arp_tpa[];		/* Target Protocol Address. */
#endif
};

static const char *arp_hrd2str(U16 hrd)
{
    switch (hrd) {
    case ARPHRD_NETROM:
	return "NETROM";
    case ARPHRD_ETHER:
	return "ETHER";
    case ARPHRD_EETHER:
	return "EETHER";
    case ARPHRD_AX25:
	return "AX25";
    case ARPHRD_PRONET:
	return "PRONET";
    case ARPHRD_CHAOS:
	return "CHAOS";
    case ARPHRD_IEEE802:
	return "IEEE802";
    case ARPHRD_ARCNET:
	return "ARCNET";
    case ARPHRD_APPLETLK:
	return "APPLETLK";
    case ARPHRD_DLCI:
	return "DLCI";
    case ARPHRD_ATM:
	return "ATM";
    case ARPHRD_METRICOM:
	return "METRICOM";
    case ARPHRD_SLIP:
	return "SLIP";
    case ARPHRD_CSLIP:
	return "CSLIP";
    case ARPHRD_SLIP6:
	return "SLIP6";
    case ARPHRD_CSLIP6:
	return "CSLIP6";
    case ARPHRD_RSRVD:
	return "RSRVD";
    case ARPHRD_ADAPT:
	return "ADAPT";
    case ARPHRD_ROSE:
	return "ROSE";
    case ARPHRD_X25:
	return "X25";
#ifdef ARPHDR_HWX25
    case ARPHDR_HWX25:
	return "HWX25";
#endif
    case ARPHRD_PPP:
	return "PPP";
    case ARPHRD_CISCO:
	return "CISCO";
    case ARPHRD_LAPB:
	return "LAPB";
    case ARPHRD_DDCMP:
	return "DDCMP";
    case ARPHRD_RAWHDLC:
	return "RAWHDLC";
    case ARPHRD_TUNNEL:
	return "TUNNEL";
    case ARPHRD_TUNNEL6:
	return "TUNNEL6";
    case ARPHRD_FRAD:
	return "FRAD";
    case ARPHRD_SKIP:
	return "SKIP";
    case ARPHRD_LOOPBACK:
	return "LOOPBACK";
    case ARPHRD_LOCALTLK:
	return "LOCALTLK";
    case ARPHRD_FDDI:
	return "FDDI";
    case ARPHRD_BIF:
	return "BIF";
    case ARPHRD_SIT:
	return "SIT";
    case ARPHRD_IPDDP:
	return "IPDDP";
    case ARPHRD_IPGRE:
	return "IPGRE";
    case ARPHRD_PIMREG:
	return "PIMREG";
    case ARPHRD_HIPPI:
	return "HIPPI";
    case ARPHRD_ASH:
	return "ASH";
    case ARPHRD_ECONET:
	return "ECONET";
    case ARPHRD_IRDA:
	return "IRDA";
    case ARPHRD_FCPP:
	return "FCPP";
    case ARPHRD_FCAL:
	return "FCAL";
    case ARPHRD_FCPL:
	return "FCPL";
#ifdef ARPHRD_FCPFABRIC
    case ARPHRD_FCPFABRIC:
	return "FCPFABRIC";
#endif
    case ARPHRD_IEEE802_TR:
	return "IEEE802_TR";
    case ARPHRD_IEEE80211:
	return "IEEE80211";
    default:
	return "UNKNOWN";
    }
}

static const char *arp_op2str(U16 op)
{
    switch (op) {
    case ARPOP_REQUEST:
	return "ARP request";
    case ARPOP_REPLY:
	return "ARP reply";
    case ARPOP_RREQUEST:
	return "RARP request";
    case ARPOP_RREPLY:
	return "RARP reply";
    case ARPOP_InREQUEST:
	return "InARP request";
    case ARPOP_InREPLY:
	return "InARP reply";
    case ARPOP_NAK:
	return "ARP NAK";
    default:
	return "unkwnown";
    }
}

extern void eth_mac_addr(U8 *, char *, size_t);	// TODO: declare in pangolin.h 

void arp_dump(struct packet *packet, struct context *ctx)
{
    struct arp_hdr hdr;

    memset(&hdr, 0, ARP_HDR_LEN);
    memcpy(&hdr, packet->data, ARP_HDR_LEN);
    packet->data += ARP_HDR_LEN;

    if (TOHOST16(hdr.arp_pro) == 0x0800) {
	switch (TOHOST16(hdr.arp_op)) {
	case ARPOP_REQUEST:
	    {
		struct in_addr tpa;
		struct in_addr spa;
		U8 src[16], dst[16];

		memcpy(&tpa,
		       packet->data + (2 * hdr.arp_hln) +
		       hdr.arp_pln, sizeof(struct in_addr));
		memcpy(&spa, packet->data + hdr.arp_hln,
		       sizeof(struct in_addr));
		memcpy(dst, inet_ntoa(tpa), 16);
		memcpy(src, inet_ntoa(spa), 16);
		ctx->out("arp request %s tell %s ", dst, src);
		break;
	    }

	case ARPOP_REPLY:
	    {
		struct in_addr spa;
		U8 sha[6];
		char src[20];
		eth_mac_addr(sha, src, sizeof src);

		memcpy(sha, packet->data, 6);
		memcpy(&spa, packet->data + hdr.arp_hln,
		       sizeof(struct in_addr));
		ctx->out("arp reply %s is %s", inet_ntoa(spa), src);
		break;
	    }

	case ARPOP_RREQUEST:
	    {
		U8 sha[6];
		U8 tha[6];
		char src[20];
		char dst[20];

		memcpy(sha, packet->data, 6);
		memcpy(tha, packet->data + hdr.arp_hln + hdr.arp_pln, 6);
		eth_mac_addr(sha, src, sizeof src);
		eth_mac_addr(tha, dst, sizeof dst);
		ctx->out("rarp request %s tell %s", src, dst);
		break;
	    }

	case ARPOP_RREPLY:
	    {
		U8 tha[6];
		char src[20];
		struct in_addr tpa;

		memcpy(tha, packet->data + hdr.arp_hln + hdr.arp_pln, 6);
		memcpy(&tpa,
		       packet->data + (2 * hdr.arp_hln) +
		       hdr.arp_pln, sizeof(struct in_addr));
		eth_mac_addr(tha, src, sizeof src);
		ctx->out("rarp reply %s is %s", src, inet_ntoa(tpa));
		break;
	    }

	default:
	    ctx->out("op=%d", TOHOST16(hdr.arp_pro) & 0xFFFF);
	}
    } else {
	ctx->out("%s hardware: %s (#%d) (skip)",
		 arp_op2str(TOHOST16(hdr.arp_op)),
		 arp_hrd2str(TOHOST16(hdr.arp_hrd)),
		 TOHOST16(hdr.arp_hrd) & 0xFFFF);
    }
}
