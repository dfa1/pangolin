/*
 * p_eth.c -- dump an ethernet frame
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
#include <time.h>

#include "pangolin.h"

/* Ethernet header length as defined by 802.3 standard */
#define ETH_ADDR_LEN 6
#define ETH_HDR_LEN 14

struct eth_hdr {
    U8 eth_dhost[ETH_ADDR_LEN];
    U8 eth_shost[ETH_ADDR_LEN];
    U16 eth_type;
};

/* supported values for eth_type */
#define ETH_TYPE_IP   0x0800	/* IPv4  */
#define ETH_TYPE_ARP  0x0806	/* ARP   */
#define ETH_TYPE_RARP 0x8035	/* RARP  */

static struct eth_type {
    U16 begin;
    U16 end;
    char desc[76];
} eth_types[] = {
	/* *INDENT-OFF* */
        { 0x0600, 0x0600, "Xerox XNS IDP"},
	{ 0x0801, 0x0801, "X.75 Internet"},
	{ 0x0802, 0x0802, "NBS Internet"},
	{ 0x0803, 0x0803, "ECMA Internet"},
	{ 0x0804, 0x0804, "CHAOSnet"},
	{ 0x0805, 0x0805, "X.25 Level 3"},
	{ 0x0807, 0x0807, "Xerox XNS Compatibility"},
	{ 0x081C, 0x081C, "Symbolics Private"},
	{ 0x0888, 0x088A, "Xyplex"},
	{ 0x0900, 0x0900, "Ungermann-Bass network debugger"},
	{ 0x0A00, 0x0A00, "Xerox 802.3 PUP"},
	{ 0x0A01, 0x0A01, "Xerox 802.3 PUP Address Translation"},
	{ 0x0A02, 0x0A02, "Xerox PUP CAL Protocol (unused)"},
	{ 0x0BAD, 0x0BAD, "Banyan Systems, Inc."},
	{ 0x1000, 0x1000, "Berkeley Trailer negotiation"},
	{ 0x1001, 0x100F, "Berkeley Trailer encapsulation for IP"},
	{ 0x1066, 0x1066, "VALIS Systems"},
	{ 0x1600, 0x1600, "VALID Systems"},
	{ 0x3C01, 0x3C0D, "3Com Corporation"},
	{ 0x3C10, 0x3C14, "3Com Corporation"},
	{ 0x4242, 0x4242, "PCS Basic Block Protocol"},
	{ 0x5208, 0x5208, "BBN Simnet Private"},
	{ 0x6000, 0x6000, "DEC Unassigned"},
	{ 0x6001, 0x6001, "DEC MOP Dump/Load Assistance"},
	{ 0x6002, 0x6002, "DEC MOP Remote Console"},
	{ 0x6003, 0x6003, "DEC DECnet Phase IV"},
	{ 0x6004, 0x6004, "DEC LAT"},
	{ 0x6005, 0x6005, "DEC DECnet Diagnostic Protocol: DECnet Customer Use"},
        { 0x6007, 0x6007, "DEC DECnet LAVC"},
	{ 0x6008, 0x6008, "DEC Amber"},
	{ 0x6009, 0x6009, "DEC MUMPS"},
	{ 0x6010, 0x6014, "3Com Corporation"},
	{ 0x7000, 0x7000, "Ungermann-Bass download"},
	{ 0x7001, 0x7001, "Ungermann-Bass NIU"},
	{ 0x7002, 0x7002, "Ungermann-Bass diagnostic/loopback"},
	{ 0x7007, 0x7007, "OS/9 Microware"},
	{ 0x7020, 0x7028, "LRT (England)"},
	{ 0x7030, 0x7030, "Proteon"},
	{ 0x7034, 0x7034, "Cabletron"},
	{ 0x8003, 0x8003, "Cronus VLN"},
	{ 0x8004, 0x8004, "Cronus Direct"},
	{ 0x8005, 0x8005, "HP Probe protocol"},
	{ 0x8006, 0x8006, "Nestar"},
	{ 0x8008, 0x8008, "AT&T"},
	{ 0x8010, 0x8010, "Excelan"},
	{ 0x8013, 0x8013, "SGI diagnostic type (obsolete)"},
	{ 0x8014, 0x8014, "SGI network games (obsolete)"},
	{ 0x8015, 0x8015, "SGI reserved type (obsolete)"},
	{ 0x8016, 0x8016, "SGI bounce server (obsolete)"},
	{ 0x8019, 0x8019, "Apollo"},
	{ 0x802E, 0x802E, "Tymshare"},
	{ 0x802F, 0x802F, "Tigan, Inc."},
	{ 0x8036, 0x8036, "Aeonic Systems"},
	{ 0x8038, 0x8038, "DEC LANBridge"},
	{ 0x8039, 0x8039, "DEC DSM"},
	{ 0x803A, 0x803A, "DEC Aragon"},
	{ 0x803B, 0x803B, "DEC VAXELN"},
	{ 0x803C, 0x803C, "DEC NSMV"},
	{ 0x803D, 0x803D, "DEC Ethernet CSMA/CD Encryption Protocol"},
	{ 0x803E, 0x803E, "DEC DNA"},
	{ 0x803F, 0x803F, "DEC LAN Traffic Monitor"},
	{ 0x8040, 0x8040, "DEC NetBIOS"},
	{ 0x8041, 0x8041, "DEC MS/DOS"},
	{ 0x8042, 0x8042, "DEC Unassigned"},
	{ 0x8044, 0x8044, "Planning Research Corporation"},
	{ 0x8046, 0x8046, "AT&T"},
	{ 0x8047, 0x8047, "AT&T"},
	{ 0x8049, 0x8049, "ExperData (France)"},
	{ 0x805B, 0x805B, "VMTP (Versatile Message Transaction Protocol, RFC-1045, Stanford)"},
        { 0x805C, 0x805C, "Stanford V Kernel production, Version 6.0"},
	{ 0x805D, 0x805D, "Evans & Sutherland"},
	{ 0x8060, 0x8060, "Little Machines"},
	{ 0x8062, 0x8062, "Counterpoint Computers"},
	{ 0x8065, 0x8065, "University of Massachusetts, Amherst"},
	{ 0x8066, 0x8066, "University of Massachusetts, Amherst"},
	{ 0x8067, 0x8067, "Veeco Integrated Automation"},
	{ 0x8068, 0x8068, "General Dynamics"},
	{ 0x8069, 0x8069, "AT&T"},
	{ 0x806A, 0x806A, "Autophon (Switzerland)"},
	{ 0x806C, 0x806C, "ComDesign"},
	{ 0x806D, 0x806D, "Compugraphic Corporation"},
	{ 0x806E, 0x8077, "Landmark Graphics Corporation"},
	{ 0x807A, 0x807A, "Matra (France)"},
	{ 0x807B, 0x807B, "Dansk Data Elektronic A/S (Denmark)"},
	{ 0x807C, 0x807C, "Merit Intermodal"},
	{ 0x807D, 0x807D, "VitaLink Communications"},
	{ 0x807E, 0x807E, "VitaLink Communications"},
	{ 0x807F, 0x807F, "VitaLink Communications"},
	{ 0x8080, 0x8080, "VitaLink Communications bridge"},
	{ 0x8081, 0x8081, "Counterpoint Computers"},
	{ 0x8082, 0x8082, "Counterpoint Computers"},
	{ 0x8083, 0x8083, "Counterpoint Computers"},
	{ 0x8088, 0x8088, "Xyplex"},
	{ 0x8089, 0x8089, "Xyplex"},
	{ 0x808A, 0x808A, "Xyplex"},
	{ 0x809B, 0x809B, "AppleTalk and Kinetics AppleTalk over Ethernet"},
        { 0x809C, 0x809C, "Datability"},
	{ 0x809D, 0x809D, "Datability"},
	{ 0x809E, 0x809E, "Datability"},
	{ 0x809F, 0x809F, "Spider Systems, Ltd. (England)"},
	{ 0x80A3, 0x80A3, "Nixdorf Computer (West Germany)"},
	{ 0x80A4, 0x80B3, "Siemens Gammasonics, Inc."},
	{ 0x80C0, 0x80C0, "Digital Communication Associates"},
	{ 0x80C1, 0x80C1, "Digital Communication Associates"},
	{ 0x80C2, 0x80C2, "Digital Communication Associates"},
	{ 0x80C3, 0x80C3, "Digital Communication Associates"},
	{ 0x80C6, 0x80C6, "Pacer Software"},
	{ 0x80C7, 0x80C7, "Applitek Corporation"},
	{ 0x80C8, 0x80CC, "Intergraph Corporation"},
	{ 0x80CD, 0x80CD, "Harris Corporation"},
	{ 0x80CE, 0x80CE, "Harris Corporation"},
	{ 0x80CF, 0x80D2, "Taylor Inst."},
	{ 0x80D3, 0x80D3, "Rosemount Corporation"},
	{ 0x80D4, 0x80D4, "Rosemount Corporation"},
	{ 0x80D5, 0x80D5, "IBM SNA Services over Ethernet"},
	{ 0x80DD, 0x80DD, "Varian Associates"},
	{ 0x80DE, 0x80DE, "Integrated Solutions TRFS (Transparent Remote File System)"},
        { 0x80DF, 0x80DF, "Integrated Solutions"},
	{ 0x80E0, 0x80E3, "Allen-Bradley"},
	{ 0x80E4, 0x80F0, "Datability"},
	{ 0x80F2, 0x80F2, "Retix"},
	{ 0x80F3, 0x80F3, "Kinetics, AppleTalk ARP (AARP)"},
	{ 0x80F4, 0x80F4, "Kinetics"},
	{ 0x80F5, 0x80F5, "Kinetics"},
	{ 0x80F7, 0x80F7, "Apollo Computer"},
	{ 0x80FF, 0x8103, "Wellfleet Communications"},
	{ 0x8107, 0x8107, "Symbolics Private"},
	{ 0x8108, 0x8108, "Symbolics Private"},
	{ 0x8109, 0x8109, "Symbolics Private"},
	{ 0x8130, 0x8130, "Waterloo Microsystems"},
	{ 0x8131, 0x8131, "VG Laboratory Systems"},
	{ 0x8137, 0x8137, "Novell (old) NetWare IPX"},
	{ 0x8138, 0x8138, "Novell"},
	{ 0x8139, 0x813D, "KTI"},
	{ 0x9000, 0x9000, "Loopback (Configuration Test Protocol)"},
	{ 0x9001, 0x9001, "Bridge Communications XNS Systems Management"},
	{ 0x9002, 0x9002, "Bridge Communications TCP/IP Systems Management"},
        { 0x9003, 0x9003, "Bridge Communications"},
	{ 0xFF00, 0xFF00, "BBN VITAL LANBridge cache wakeup"},
	{ 0xFFFF, 0xFFFF, ""}     /* Sentinella. */
	/* *INDENT-ON* */
};

static const char *eth_type2str(short n)
{
    struct eth_type *p;		// TODO: rewrite using gperf
    char *res = "unknown";

    for (p = eth_types; p->begin != 0xFFFF; p++) {
	if ((p->begin <= n) && (p->end >= n)) {
	    res = p->desc;
	    break;
	}
    }

    return res;
}

static const char *timestamp(struct timeval *tv)
{
    size_t c;
    struct tm *h;
    static char s[9];

    h = localtime(&tv->tv_sec);
    c = strftime(s, 9, "%H:%M", h);
    s[c] = '\0';
    return s;
}

void eth_mac_addr(U8 * mac, char *buf, size_t bufsize)
{
    if (!(mac[5] ^ 0xFF) && !(mac[0] ^ 0xFF)) {
	int x = mac[1] ^ mac[2] ^ mac[3] ^ mac[4];

	if (!x) {
	    snprintf(buf, bufsize, "%s", "broadcast");
	    return;
	}

    }

    snprintf(buf, bufsize, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
	     mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void eth_dump_raw(struct packet *packet, struct context *ctx)
{
    int i;

    for (i = 0; i < 200; i++) {
	ctx->out("%02x ", packet->data[i]);
    }

    ctx->out("\n");
}

void eth_dump(struct packet *packet, struct context *ctx)
{
    if (ctx->dump_raw_packet) {
	eth_dump_raw(packet, ctx);
	return;
    }
    
    struct eth_hdr hdr;
    U16 type;
    U8 s;

    if (!packet->type) {
	memset(&hdr, 0, ETH_HDR_LEN);
	memcpy(&hdr, packet->data, ETH_HDR_LEN);
	type = TOHOST16(hdr.eth_type);
    } else {
	type = TOHOST16(packet->type);
    }

    s = packet->time.tv_sec % 60;
    ctx->out("%s:%c%2.6f ", timestamp(&packet->time),
	     s < 10 ? '0' : '\0', s + (float)packet->time.tv_usec / 1000000);

    if (ctx->print_mac_addr) {
	char src[20];
	char dst[20];
	eth_mac_addr(hdr.eth_shost, src, sizeof src);
	eth_mac_addr(hdr.eth_dhost, dst, sizeof dst);
	ctx->out("%s > %s: ", src, dst);
    }

    if (type <= 0x05DC) {
	ctx->out("IEEE 802.3 Length len=%d", type & 0xFFFF);
    } else {
	packet->data += ETH_HDR_LEN;

	switch (type) {
	case ETH_TYPE_IP:
	    ip_dump(packet, ctx);
	    break;

	case ETH_TYPE_ARP:
	case ETH_TYPE_RARP:
	    arp_dump(packet, ctx);
	    break;

	default:
	    ctx->out("%s (skip)", eth_type2str(type));
	    break;
	}
    }

    ctx->out("\n");
}
