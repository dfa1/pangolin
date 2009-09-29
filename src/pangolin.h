/* Includiamo questi file qui per comodita'. */
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <netdb.h>

/*
 * Tipi interi ``garantiti'' (perlomeno su macchine con wordsize a 32 bit :)
 * a 8, 16 e 32 bit, sia con segno I{8,16,32} sia senza U{8,16,32}.
 */
#include <stdint.h>

typedef int8_t I8;
typedef uint8_t U8;

typedef int16_t I16;
typedef uint16_t U16;

typedef int32_t I32;
typedef uint32_t U32;

/*
 * Macro per convertire interi a 16 e 32 bit nel formato "little
 * endian" TO_HOST_{16,32} e nel formato "big endian" TO_NET_{16,32}.
 */
#define TOHOST16(x) (U16) ntohs((U16)(x))
#define TOHOST32(x) (U32) ntohl((U32)(x))
#define TONET16(x) (U16) htons((U16)(x))
#define TONET32(x) (U32) htonl((U32)(x))

/* Visibilita' delle variabili e delle funzioni. */
#define PRIVATE static
#define PUBLIC
#define EXTERN extern

/* Quando catturiamo i pacchetti da qualsiasi interfaccia usiamo
 * questa dimensione per il buffer di lettura. Questa dimensione
 * (2^16) dovrebbe essere piu' grande di qualsiasi MTU. */
#define PKT_DATA_LEN (1024 * 64)

/* Intestazione dei pacchetti che catturiamo.. */
struct packet
{
    struct timeval time;
    U8 base[PKT_DATA_LEN];
    U8 *data;
    U8 type;
};

/* Per i filtri del kernel  */
struct sock_filter
{
    U16 code;                   /* Actual filter code */
    U8 jt;                      /* Jump true */
    U8 jf;                      /* Jump false */
    U32 k;                      /* Generic multiuse field */
};

struct sock_fprog               /* Required for SO_ATTACH_FILTER. */
{
    U16 len;
    struct sock_filter *filter;
};
