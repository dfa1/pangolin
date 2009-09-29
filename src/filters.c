/*
 * filters.c -- predefined filters
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

#include "pangolin.h"

/*
 * Filtro per pacchetti ARP:
 */
PUBLIC struct sock_filter ARP_code[] = {
    {0x28, 0, 0, 0x0000000c},
    {0x15, 0, 1, 0x00000806},
    {0x6, 0, 0, 0x00000044},
    {0x6, 0, 0, 0x00000000}
};

/*
 * Filtro per pacchetti ARP:
 */
PUBLIC struct sock_filter RARP_code[] = {
    {0x28, 0, 0, 0x0000000c},
    {0x15, 0, 1, 0x00008035},
    {0x6, 0, 0, 0x00000044},
    {0x6, 0, 0, 0x00000000}
};

/*
 * Filtro per pacchetti IP:
 */
PUBLIC struct sock_filter IP_code[] = {
    {0x28, 0, 0, 0x0000000c},
    {0x15, 0, 1, 0x00000800},
    {0x6, 0, 0, 0x00000044},
    {0x6, 0, 0, 0x00000000}
};

/*
 * Filtro per pacchetti TCP:
 */
PUBLIC struct sock_filter TCP_code[] = {
    {0x28, 0, 0, 0x0000000c},
    {0x15, 0, 3, 0x00000800},
    {0x30, 0, 0, 0x00000017},
    {0x15, 0, 1, 0x00000006},
    {0x6, 0, 0, 0x00000044},
    {0x6, 0, 0, 0x00000000}
};

/*
 * Filtro per pacchetti UDP:
 */
PUBLIC struct sock_filter UDP_code[] = {
    {0x28, 0, 0, 0x0000000c},
    {0x15, 0, 3, 0x00000800},
    {0x30, 0, 0, 0x00000017},
    {0x15, 0, 1, 0x00000011},
    {0x6, 0, 0, 0x00000044},
    {0x6, 0, 0, 0x00000000}
};

/*
 * Filtro per pacchetti ICMP:
 */
PUBLIC struct sock_filter ICMP_code[] = {
    {0x28, 0, 0, 0x0000000c},
    {0x15, 0, 3, 0x00000800},
    {0x30, 0, 0, 0x00000017},
    {0x15, 0, 1, 0x00000001},
    {0x6, 0, 0, 0x00000044},
    {0x6, 0, 0, 0x00000000}
};

/*
 * Filtro per indirizzo IP. Questo filtro e' piu' complicato degli
 * altri: infatti bisogna anche cambiare l'ip all'interno della
 * struttura del filtro:
 */
PUBLIC struct sock_filter HOST_code[] = {
    {0x28, 0, 0, 0x0000000c},
    {0x15, 0, 4, 0x00000800},
    {0x20, 0, 0, 0x0000001a},
    {0x15, 8, 0, 0xffffffff},   /* <--- IP */
    {0x20, 0, 0, 0x0000001e},
    {0x15, 6, 7, 0xffffffff},   /* <--- IP */
    {0x15, 1, 0, 0x00000806},
    {0x15, 0, 5, 0x00008035},
    {0x20, 0, 0, 0x0000001c},
    {0x15, 2, 0, 0xffffffff},   /* <--- IP */
    {0x20, 0, 0, 0x00000026},
    {0x15, 0, 1, 0xffffffff},   /* <--- IP */
    {0x6, 0, 0, 0x00000044},
    {0x6, 0, 0, 0x00000000}
};

/*
 * Filtro per i protocolli TCP/IP o UDP/IP. Questo filtro seleziona
 * solo il traffico con porta sorgente e/o destinazione uguale a
 * quella specificata dall'utente:
 */
PUBLIC struct sock_filter PORT_code[] = {
    {0x28, 0, 0, 0x0000000c},
    {0x15, 0, 12, 0x00000800},
    {0x30, 0, 0, 0x00000017},
    {0x15, 2, 0, 0x00000084},
    {0x15, 1, 0, 0x00000006},
    {0x15, 0, 8, 0x00000011},
    {0x28, 0, 0, 0x00000014},
    {0x45, 6, 0, 0x00001fff},
    {0xb1, 0, 0, 0x0000000e},
    {0x48, 0, 0, 0x0000000e},
    {0x15, 2, 0, 0x000000ff},   /* <--- PORT */
    {0x48, 0, 0, 0x00000010},
    {0x15, 0, 1, 0x000000ff},   /* <--- PORT */
    {0x6, 0, 0, 0x00000044},
    {0x6, 0, 0, 0x00000000}
};

/* *INDENT-ON* */
