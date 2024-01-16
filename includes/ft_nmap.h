#ifndef FT_NMAP_H
# define FT_NMAP_H

//https://www.devdungeon.com/content/using-libpcap-c#intro

// printf
#include <stdio.h>

// bzero
#include <strings.h>


// malloc, free
#include <stdlib.h>


#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

typedef int bool ;  //définition du type booléen,

#define false  0 /* affectation des valeurs conventionnelles*/

#define true  1

#define USAGE      "> ft_nmap [--help] [--ports[NUMBER/RANGED]] --ip   IP_ADDRESS [--speedup[NUMBER]] [--scan [TYPE]]"
#define USAGE_FILE "          [--help] [--ports[NUMBER/RANGED]] --file FILE       [--speedup[NUMBER]] [--scan [TYPE]]"


#define SCAN_SYN 0x01
#define SCAN_NULL 0x02
#define SCAN_ACK 0x04
#define SCAN_FIN 0x08
#define SCAN_XMAS 0x10
#define SCAN_UDP 0x20

typedef struct s_scan {
    union {
        struct {
            char syn:1;
            char null:1;
            char ack:1;
            char fin:1;
            char xmas:1;
            char udp:1;
        } type;
        char mask;
    };
} t_scan;

typedef struct s_data {
    short ports[1024]; // ports need to be scan store as a list
    short ports_number;
    char **ip_address; // the list of ip address that need to be scan
    short speedup; // default 0, max 250
    t_scan scanmask; // SYN, NULL, ACK, FIN, XMAS, UDP
} t_data;


// ******************* UTILS SECTIONS ******************* //

int		ft_atoi(const char *str);
void	ft_bzero(void *s, size_t n);
char	**ft_strsplit(const char *s, char c, int *len);
char	*ft_strsub(char const *s, unsigned int start, size_t len);
void	*ft_malloc(size_t size);
char    *ft_trim(char *s);
char	*ft_strchr(const char *s, int c);
int     ft_strlen(const char *str);
char	*ft_strcpy(char *dest, const char *str);
void    free_tab(char **x);

// ****************** PARSING SECTIONS ****************** //

#define MIN_SPEEDUP 1
#define MAX_SPEEDUP 250
void set_speedup_value(char *value, t_data *data);

#define MIN_PORT 1
#define MAX_PORT 1024
void set_ports_value(char *str, t_data *data);

void show_help();

#endif