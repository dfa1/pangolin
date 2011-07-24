/*
 * main.c -- the main()
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
#include <signal.h>
#include <unistd.h>
#include <argp.h>

#include "config.h"
#include "pangolin.h"

/* if.c */
EXTERN int if_open(const char *);
EXTERN void if_close(int);
EXTERN int if_list(void);
EXTERN int if_index(int, const char *);
EXTERN int if_promisc(int, const char *, int);
EXTERN int if_stats(int);
EXTERN int if_filter(int, struct sock_filter *, U16);

/* capture.c */
EXTERN int capture(struct packet *, int);

/* p_eth.c */
EXTERN int eth_dump(struct packet *, int);

/* filters.c */
EXTERN void filter_host(struct sock_filter *, U32);
EXTERN void filter_port(struct sock_filter *, U16);

EXTERN struct sock_filter ARP_code[];
EXTERN struct sock_filter RARP_code[];
EXTERN struct sock_filter IP_code[];
EXTERN struct sock_filter ICMP_code[];
EXTERN struct sock_filter TCP_code[];
EXTERN struct sock_filter UDP_code[];

EXTERN struct sock_filter PORT_code[]; // customizable
EXTERN struct sock_filter HOST_code[]; // customizable

PUBLIC int loindex; // TODO: really a global?

PRIVATE int fd = -1;

struct arguments
{
    char *iface;

    /* by protocol filters */
    int filter;
    int arp;
    int rarp;
    int ip;
    int icmp;
    int tcp;
    int udp;

    long host;
    int port;

    int promisc;

    int count;
    int list;
    int mac;
    int raw;
};

PRIVATE struct arguments args;

PRIVATE void 
cleanup(int sts) 
{
    if (sts != EXIT_FAILURE)
        if (if_stats(fd))
            sts = EXIT_FAILURE;

    if (fd != -1) {
        if (if_promisc(fd, args.iface, 0))
            sts = EXIT_FAILURE;
        if_close(fd);
    }

    exit(sts);
}

PRIVATE void
sigint_handler(int signal)
{
    (void) signal;              
    cleanup(EXIT_SUCCESS);
}

PRIVATE void
sigterm_handler(int signal)
{
    (void) signal;              
    cleanup(EXIT_FAILURE);
}


const char *argp_program_version = PACKAGE_VERSION;
const char *argp_program_bug_address = PACKAGE_BUGREPORT;
const char program_doc[] = "a simple sniffer for GNU/linux";

/* *INDENT-OFF* */
PRIVATE const struct argp_option options[] = {
	{ 0, 'i', "interface", 0, "select which interface to sniff" },
	{ 0, 'p', "protocol", 0, "protocol filtering: arp, rarp, ip, icmp, tcp, udp"},
 	{ 0, 'h', "host", 0, "host filtering"},
 	{ 0, 's', "port", 0, "port filtering"},
	{ 0, 'n', 0, 0, "don't switch to promiscuous mode"},
	{ 0, 'c', "count", 0, "stop after count packet" },
	{ 0, 'l', 0, 0, "list interfaces" },
	{ 0, 'e', 0, 0, "print ethernet mac addresses" },
	{ 0, 'r', 0, 0, "dump raw packets" },
	{ 0 }
};
/* *INDENT-ON* */

PRIVATE error_t
parse_opt(int key, char *arg, struct argp_state *state)
{
    struct arguments *args = state->input;
    char *ep;

    switch (key) {
            case 'c':
                args->count = strtol(arg, &ep, 10);

                if (*ep != '\0' || args->count < 0) {
                    fprintf(stderr, "error: invalid count\n");
                    return -1;
                }

                break;
		
            case 'r':
		 args->raw = 1;
		 break;

            case 'e':
                args->mac = 1;
                break;

            case 'h':{
                struct in_addr in;
                long t;

                memset(&in, 0, sizeof(struct in_addr));

                if (!inet_aton(arg, &in)) {
                    fprintf(stderr, "error: invalid IP address\n");
                    return -1;
                }

                memcpy(&t, &in, sizeof(long));
                args->host = TOHOST32(t);
                args->filter = 1;
                break;
            }

            case 'i':
                args->iface = arg;
                break;

            case 'l':
                args->list = 1;
                break;

            case 'n':
                args->promisc = 0;
                break;

#define EQ(p,s) (strcmp((p),(s)) == 0) // TODO: useless

            case 'p':
                if (args->filter) {
                    fprintf(stderr,
                            "error: only one filter can be defined at once\n");
                    return -1;
                }

                if (EQ(arg, "arp"))
                    args->arp = 1, args->filter = 1;
                else if (EQ(arg, "rarp"))
                    args->rarp = 1, args->filter = 1;
                else if (EQ(arg, "ip"))
                    args->ip = 1, args->filter = 1;
                else if (EQ(arg, "icmp"))
                    args->icmp = 1, args->filter = 1;
                else if (EQ(arg, "tcp"))
                    args->tcp = 1, args->filter = 1;
                else if (EQ(arg, "udp"))
                    args->udp = 1, args->filter = 1;
                else {
                    fprintf(stderr,
                            "error: %s is not a valid protocol\n", arg);
                    return -1;
                }


                break;
#undef EQ

            case 's':
                args->port = strtol(arg, &ep, 10);

                if (*ep != '\0' || args->port < 1 || args->port > 0xFFFF) {
                    fprintf(stderr, "error: invalid port\n");
                    return -1;
                }

                args->filter = 1;
                break;

            default:
                return ARGP_ERR_UNKNOWN;
    }


    return 0;
}

PRIVATE struct argp argp = { options, parse_opt, NULL, program_doc };

PUBLIC int
main(int argc, char **argv)
{
    int c = 0;

    /* defaults */
    args.iface = NULL;
    args.filter = 0;
    args.arp = 0;
    args.rarp = 0;
    args.ip = 0;
    args.icmp = 0;
    args.tcp = 0;
    args.udp = 0;
    args.promisc = 1;
    args.count = 0;
    args.list = 0;
    args.mac = 0;
    args.port = 0;
    args.raw = 1;

    if (argp_parse
        (&argp, argc, argv, ARGP_PARSE_ARGV0 | ARGP_NO_EXIT, 0, &args) != 0)
        cleanup(EXIT_FAILURE);

    if (args.list)
        return if_list();

    if (!args.iface) {
        argp_help(&argp, stderr, ARGP_HELP_USAGE, argv[0]);
        cleanup(EXIT_FAILURE);
    }

    fd = if_open(args.iface);

    if (fd < 0)
        cleanup(EXIT_FAILURE);

    if (args.promisc)
        if (if_promisc(fd, args.iface, 1))
            cleanup(EXIT_FAILURE);

    if (args.arp)
        if_filter(fd, ARP_code, 4);

    if (args.rarp)
        if_filter(fd, RARP_code, 4);

    if (args.ip)
        if_filter(fd, IP_code, 4);

    if (args.icmp)
        if_filter(fd, ICMP_code, 6);

    if (args.tcp)
        if_filter(fd, TCP_code, 6);

    if (args.udp)
        if_filter(fd, UDP_code, 6);

    if (args.port) {
        U16 port;

        port = args.port & 0xFFFF;
        PORT_code[10].k = port;
        PORT_code[12].k = port;
        if_filter(fd, PORT_code, 15);
    }

    if (args.host) {
        HOST_code[3].k = args.host;
        HOST_code[5].k = args.host;
        HOST_code[9].k = args.host;
        HOST_code[11].k = args.host;
        if_filter(fd, HOST_code, 14);
    }


    loindex = if_index(fd, "lo");


    // TODO: this should be done asap
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigterm_handler);

    for (;;) {
        struct packet packet, *ppacket = &packet;

        switch (capture(ppacket, fd)) {
                case 0:
                    if (!errno)
                        continue;

                case -1:
                    fprintf(stderr,
                            "error: capture() failed: %s\n", strerror(errno));
                    goto out;


                default:
                    if (args.count > 0)
                        if (++c > args.count)
                            goto out;
        }

	if (args.raw) {
	    dump_raw(ppacket);
	}
	
	
        eth_dump(ppacket, args.mac);
    }

  out:
    cleanup(EXIT_SUCCESS);
    return 0;			/* XXX: shut up compiler */
}

void 
dump_raw(struct packet *ppacket) 
{
    int i;
    fprintf(stdout, "type = %d\n", ppacket->type);

    for (i = 0; i < 200; i++) {
	fprintf(stdout, "%02x ", ppacket->data[i]);
    }
    fprintf(stdout, "\n");
}
