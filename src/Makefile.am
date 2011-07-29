bin_PROGRAMS = pangolin 

pangolin_CPPFLAGS = -D_GNU_SOURCE
pangolin_CFLAGS = -W -Wall -std=c99 -pedantic 

pangolin_SOURCES = \
	capture.c	\
	filters.c	\
	if.c		\
	main.c		\
	p_arp.c		\
	p_bootp.c	\
	p_eth.c		\
	p_icmp.c	\
	p_ip.c		\
	p_tcp.c		\
	p_udp.c

EXTRA_DIST = pangolin.h
