#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <netdb.h>

#include <stdint.h>

typedef int8_t I8;
typedef uint8_t U8;

typedef int16_t I16;
typedef uint16_t U16;

typedef int32_t I32;
typedef uint32_t U32;

/* handy macros */
#define TOHOST16(x) (U16) ntohs((U16)(x))
#define TOHOST32(x) (U32) ntohl((U32)(x))

#define TONET16(x) (U16) htons((U16)(x))
#define TONET32(x) (U32) htonl((U32)(x))

/* TODO: can be safety removed */
#define PRIVATE static
#define PUBLIC
#define EXTERN extern

/* (2^16) should be greater than any MTU */
#define PKT_DATA_LEN (1024 * 64)

struct packet {
    struct timeval time;
    U8 base[PKT_DATA_LEN];
    U8 *data;
    U8 type;
};

struct sock_filter {
    U16 code;			/* Actual filter code */
    U8 jt;			/* Jump true */
    U8 jf;			/* Jump false */
    U32 k;			/* Generic multiuse field */
};

struct sock_fprog {		/* Required for SO_ATTACH_FILTER. */
    U16 len;
    struct sock_filter *filter;
};

/* decoding context */
struct context {
    int print_mac_addr;
    int resolve_dns;

    void (*out) (const char *fmt, ...);
    void (*err) (const char *fmt, ...);
};

EXTERN int eth_dump(struct packet *, struct context *);
EXTERN void arp_dump(struct packet *, struct context *);
EXTERN void ip_dump(struct packet *, struct context *);
EXTERN void icmp_dump(struct packet *, U8 *, U8 *, struct context *);
EXTERN void tcp_dump(struct packet *, U8 *, U8 *, struct context *);
EXTERN void udp_dump(struct packet *, U8 *, U8 *, struct context *);
EXTERN void bootp_dump(struct packet *, struct context *);
