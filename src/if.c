/*
 * if.c -- network interfaces handling
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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <features.h>           /* per i numeri di versione delle GLIBC. */

#include <sys/ioctl.h>
#include <sys/socket.h>

#include <linux/if.h>
#include <netinet/ether.h>

/* Protocolli al secondo livello. */
#if (__GLIBC__ >= 2) && (__GLIBC_MINOR >= 1)
# include <netpacket/packet.h>
# include <net/ethernet.h>
#else
# include <asm/types.h>
# include <linux/if_packet.h>
# include <linux/if_ether.h>
#endif

#include "pangolin.h"

/* La libreria C GNU (glibc) versione 2.1 non definisce SOL_PACKET. */
#ifndef SOL_PACKET
# define SOL_PACKET 263
#endif

/*
 * Lista tutte le interfacce di rete che rispondono ai seguenti criteri:
 *  - sono IPv4
 *  - non sono di connessione Point-To-Point (IFF_POINTOPOINT)
 */
PUBLIC int
if_list(void)
{
    struct ifconf ifc;
    struct ifreq *ifreqs, *ifr;
    int fd, nif, i, sts = 0;
    unsigned rqlen;

    /*
     * Questo e' un cosidetto helper, serve per poter chiamare la
     * ioctl() la quale necessita di un file descriptor valido.
     */
    fd = socket(PF_INET, SOCK_DGRAM, 0);

    if (fd < 0) {
        fprintf(stderr, "error: cannot create an helper socket: %s\n",
                strerror(errno));
        return -1;
    }

    /* Richiedo al kernel di prendere tutte le interfacce. */
    ifc.ifc_buf = NULL;

    /*
     * Inizialmente creo spazio per due interfacce (dovrebbe andar
     * bene quasi sempre :).
     */
    rqlen = 2 * sizeof(struct ifreq);

    do {
        /*
         * Riempo la struttura della richiesta con rqlen e
         * alloco un buffer per il valore di ritorno.
         */
        ifc.ifc_len = rqlen;
        ifc.ifc_buf = realloc(ifc.ifc_buf, ifc.ifc_len);

        /*
         * Se l'allocazione della memoria fallisce chiudo il
         * file descriptor e ritorno errore.
         */
        if (ifc.ifc_buf == NULL) {
            fprintf(stderr, "error: realloc()\n");
            sts = 1;
            goto outclose;
        }

        /* Chiamo la ioctl(SIOCGIFCONF). */
        if (ioctl(fd, SIOCGIFCONF, &ifc) < 0) {
            fprintf(stderr, "error: ioctl(SIOCGIFCONF): %s\n",
                    strerror(errno));
            sts = -1;

            /* Dealloco il buffer delle interfacce, se necessario. */
            if (ifc.ifc_buf)
                free(ifc.ifc_buf);

            goto outclose;
        }

        rqlen *= 2;
    } while (rqlen < sizeof(struct ifreq) + ifc.ifc_len);

    /*
     * A questo non devo far altro che trasformare il buffer
     * tornato dalla ioctl(SIOCGIFCONF) in un array di strutture
     * ifreq.
     */
    nif = ifc.ifc_len / sizeof(struct ifreq);
    ifr = ifreqs = realloc(ifc.ifc_buf, ifc.ifc_len);

    /*
     * Se l'allocazione della memoria fallisce chiudo il
     * file descriptor e ritorno errore.
     */
    if (ifr == NULL) {
        fprintf(stderr, "error: realloc()\n");
        sts = -1;
        goto outclose;
    }

    fprintf(stdout, "Listing available interface(s):\n");

    /* Itero sull'array in cerca di interfacce "interessanti". */
    for (i = 0; i < nif; i++, ifr++) {
        U8 mac[6];

        /* Sono interessato solo a interfacce IPv4. */
        if (ifr->ifr_addr.sa_family != PF_INET)
            continue;

        /*
         * Richiedo i flags per l'interfaccia poiche'
         * ioctl(SIOCGIFCONF) inizializza solo i membri name,
         * family and address.
         */
        if (ioctl(fd, SIOCGIFFLAGS, ifr) < 0) {
            fprintf(stderr, "error: ioctl(SIOCGIFFLAGS): %s\n",
                    strerror(errno));
            sts = -1;
            goto outfree;
        }

        /* Non ci interessano le interfacce Point-To-Point. */
        if (ifr->ifr_flags & IFF_POINTOPOINT)
            continue;

        /*
         * Ok, questa interfaccia soddisfa i miei criteri
         * quindi la posso annoverare nella lista delle
         * interfacce valide.
         */
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

/*
 * Questa chiamata ioctl() serve per prendere l'indice
 * dell'interfaccia. Questa informazione e' essenziale
 * per diversi tipi di richiesta con ioctl().
 */
PUBLIC int
if_index(int fd, const char *iface)
{
    struct ifreq ifreq;

    /* Preparo la richiesta. */
    memset(&ifreq, 0, sizeof(struct ifreq));
    strncpy(ifreq.ifr_name, iface, IFNAMSIZ);

    /*
     * Richiedo l'indice di interfaccia al kernel. In presenza di
     * errori questa funzione * * NON CHIUDE * * il socket
     * descriptor: e' responsabilita' del chiamante farlo.
     */
    if (ioctl(fd, SIOCGIFINDEX, &ifreq) == -1) {
        fprintf(stderr, "error: interface %s: %s\n", iface, strerror(errno));
        return -1;
    }

    return ifreq.ifr_ifindex;
}


PUBLIC int
if_promisc(int fd, const char *iface, int state)
{
    struct ifreq ifreq;

    /* Preparo la richiesta. */
    memset(&ifreq, 0, sizeof(struct ifreq));
    strncpy(ifreq.ifr_name, iface, IFNAMSIZ);

    /* Entro in modalita' promiscua. */
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


/*
 * Crea un file descriptor in grado di catturare in modo promiscuo
 * tutti i pacchetti dell'interfaccia specificata dal parametro
 * iface.
 */
PUBLIC int
if_open(const char *iface)
{
    struct packet_mreq mreq;
    struct sockaddr_ll sll;
    int fd;
    int err;
    size_t errlen = sizeof(int);

    /*
     * Viene creato il socket come PF_PACKET poiche' deve essere
     * in grado di leggere i pacchetti al livello 2 (OSI Physical
     * Layer). Il parametro SOCK_RAW serve per indicare al kernel
     * di far passare i pacchetti dal driver di dispositivo senza
     * fare nessuna modifica al payload del pacchetto mentre
     * ETH_P_ALL (3 parametro della socket, indica che tipo di
     * protocollo si vuole) e' usato per poter leggere pacchetti
     * di qualsiasi protocollo (tutto:).
     *
     * Solo a processi con effective uid pari a 0 (o che hanno la
     * capability CAP_NET_RAW) possono aprire socket PF_PACKET.
     */
    fd = socket(PF_PACKET, SOCK_RAW, TONET16(ETH_P_ALL));

    if (fd < 0) {
        fprintf(stderr, "error: cannot create socket: %s\n", strerror(errno));
        err = -1;
        goto out;
    }


    /*
     * Viene collegato il packet socket all'intefaccia
     * specificata. Questo permette di sniffare solo pacchetti in
     * arrivo su questa interfaccia altrimenti verrebbero
     * catturati anche pacchetti OUTGOING provenienti da altre
     * interfacce.
     */
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = PF_PACKET;
    sll.sll_ifindex = if_index(fd, iface);

    if (sll.sll_ifindex < 0) {
        err = -1;
        goto outclose;
    }

    sll.sll_protocol = TONET16(ETH_P_ALL);

    if (bind(fd, (struct sockaddr *) &sll, sizeof(sll)) == -1) {
        fprintf(stderr, "error: bind(): %s\n", strerror(errno));
        err = -1;
        goto outclose;
    }


    /* Mi assicuro che non si sono errori pendenti sul descrittore socket */
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

    /*
     * Viene chiamata setsockopt() con l'indice di interfaccia e
     * con il parametro PACKET_MR_PROMISC per poter mettere
     * l'interfaccia in modo promiscuo.
     */
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

    /*
     * Viene chiamata setsockopt() per permettere al socket
     * descriptor fd di ricevere anche i pacchetti multicast.
     */
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

/* Chiude il socket descriptor. */
PUBLIC void
if_close(int fd)
{
    (void) shutdown(fd, 2);
    (void) close(fd);
}


/*
 * Chiama la getsockopt() in modo da prendere le statistiche sui
 * pacchetti. 
 */
PUBLIC int
if_stats(int fd)
{
    struct tpacket_stats stats;
    socklen_t statslen = sizeof(struct tpacket_stats);

    /*
     * Richiedo le statistiche al kernel. In presenza di errori
     * questa funzione * * NON CHIUDE * * il socket descriptor: e'
     * responsabilita' del chiamante farlo.
     *
     * Inoltre in queste statistiche e usando i socket PF_PACKET
     * valgono le seguenti affermazioni:
     *
     * - tp_packets non conta il numero di pacchetti arrivati al
     *   filtro, ma il numero di pacchetti che hanno passato il
     *   filtro stesso
     *
     * - tp_drops e' il numero di pacchetti perche' il buffer
     *   di ricezione del socket non era abbastanza grande.
     */
    if (getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &stats, &statslen) < 0) {
        fprintf(stderr,
                "error: cannot fetch packet socket statistics: %s\n",
                strerror(errno));
        return -1;
    }

    /*
     * Stampo le statistiche. E' interessante notare che al numero
     * di drops fatto dal kernel e' stato sommato il numero di
     * drops fatto dallo sniffer.
     */
    fprintf(stdout, "\nPacket statistics\n-----------------\n");
    fprintf(stdout, "\n%u packet%s captured.", stats.tp_packets,
            stats.tp_packets > 1 ? "s" : "");
    fprintf(stdout, "\n%u packet%s dropped.\n", stats.tp_drops,
            stats.tp_drops > 1 ? "s" : "");
    return 0;
}

PUBLIC int
if_filter(int fd, struct sock_filter *code, U16 size)
{
    struct sock_fprog filter;

    /* Inizializzo il filtro. */
    filter.len = size;
    filter.filter = code;

    /* Aggancio il filtro. */
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER,
                   &filter, sizeof(filter)) < 0) {
        int dummy;

        /* Rimuovo il filtro e avverto l'utente. */
        setsockopt(fd, SOL_SOCKET, SO_DETACH_FILTER, &dummy, sizeof(int));
        fprintf(stderr, "warning: cannot set the filter\n");
        return -1;
    }

    
    return 0;
}
