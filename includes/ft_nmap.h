#ifndef FT_NMAP_H
#define FT_NMAP_H

// https://www.devdungeon.com/content/using-libpcap-c#intro

// printf
#include <stdio.h>

// bzero
#include <strings.h>

// malloc, free
#include <stdlib.h>

#include <errno.h>
#include <netdb.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#ifndef __USE_MISC
#define __USE_MISC
#endif
#include <netinet/tcp.h>
#include <limits.h>

typedef int bool; // définition du type booléen,

#define false 0 /* affectation des valeurs conventionnelles*/

#define true 1

#define USAGE                                                                  \
  "> ft_nmap [--help] [--ports[NUMBER/RANGED]] --ip   IP_ADDRESS "             \
  "[--speedup[NUMBER]] [--scan [TYPE]]"
#define USAGE_FILE                                                             \
  "          [--help] [--ports[NUMBER/RANGED]] --file FILE       "             \
  "[--speedup[NUMBER]] [--scan [TYPE]]"

struct shtcp {
  unsigned int src;
  unsigned int dst;
  char reserved;
  char protocol;
  short tcp_len;
};

typedef struct packet {
  union {
    struct iphdr iphdr;
    struct {
      char padding[8];
      struct shtcp hdr;
    } shtcp;
  };
  union {
    struct udphdr udphdr;
    struct tcphdr tcphdr;
  };
} t_packet;

typedef struct mac_header {
  char dest[6];
  char src[6];
  short type;
} t_mac_header;

typedef struct ethernet_trame {
  t_mac_header machdr;
  struct iphdr iphdr;
  union {
    struct udphdr udphdr;
    struct tcphdr tcphdr;
    struct icmphdr icmphdr;
  };} __attribute__((packed)) t_trame;

typedef struct s_scan {
  union {
    struct {
      char syn : 1;
      char null : 1;
      char ack : 1;
      char fin : 1;
      char xmas : 1;
      char udp : 1;
    } type;
    char mask;
  };
} t_scan;

typedef struct {
  u_int32_t pubip;
  u_int32_t destip;
  u_int16_t ports[1024];
  t_scan    scan;
  int       nb_port;
  char      *device;
} thread_data;

typedef struct s_data {
  short ports[1024]; // ports need to be scan store as a list
  short ports_number;
  char **ip_address; // the list of ip address that need to be scan
  short speedup;     // default 0, max 250
  t_scan scanmask;   // SYN, NULL, ACK, FIN, XMAS, UDP
} t_data;

// ******************* UTILS SECTIONS ******************* //

char *ft_itoa(int n);
char *ft_strjoin(char const *s1, char const *s2);
int ft_atoi(const char *str);
void ft_bzero(void *s, size_t n);
char **ft_strsplit(const char *s, char c, int *len);
char *ft_strsub(char const *s, unsigned int start, size_t len);
void *ft_malloc(size_t size);
void *ft_memset(void *b, int c, size_t len);
char *ft_trim(char *s);
char *ft_strchr(const char *s, int c);
int ft_strlen(const char *str);
char *ft_strcpy(char *dest, const char *str);
int ft_strcmp(const char *s1, const char *s2);
void free_tab(char **x);

u_int32_t get_public_ip(const char *host);

/* SOCKET */
int create_socket(int protoType);

/* HEADERS */
void fill_UDP_Header(struct udphdr *udphdr, uint16_t sport, uint16_t dport);
void fill_TCP_Header(struct tcphdr *tcphdr, t_scan flags, uint16_t src_port,
                     uint16_t dst_port);
void fill_SHTCP_Header(struct shtcp *header, uint32_t daddr, uint32_t saddr);
void fill_IP_Header(struct iphdr *header, uint32_t daddr, u_int8_t protocol);

void lookup_host(const char *host, struct sockaddr **sockaddr);
unsigned short checksum(void *b, int len);

/* PCAP RULES */

void set_filter(pcap_t *p);
void compile_host_rule(pcap_t *p, char *host,
                       struct bpf_program *filter_program, char *host_family);
void compile_portrange_rule(pcap_t *p, int port_min, int port_max,
                            struct bpf_program *filter_program,
                            char *port_family);

// ****************** PARSING SECTIONS ****************** //

// option --speedup
#define MIN_SPEEDUP 1
#define MAX_SPEEDUP 250
void set_speedup_value(char *value, t_data *data);

// option --ports
#define MIN_PORT 1
#define MAX_PORT USHRT_MAX
#define MAX_PORT_NUMBER 1024
void set_ports_value(char *str, t_data *data);

// option --help
void show_help();

// option --file
char **parse_file(char *file_name);

// option --ip
char **parse_ip_line(char *line);

// option --scan
t_scan parse_scan(char *line);

// display parsed data struct
void print_data(t_data *data);

// display the usage
void usage();

// free parsed data
void free_data(t_data *data);

//
bool parse_arguments(int ac, char **av, t_data *data);

// ****************** OTHERS SECTIONS ****************** //

void send_packets(thread_data *data, int socket);
void dispatch_thread(t_data *data, char *device, u_int32_t pubip, u_int32_t desip);
void my_packet_handler(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body);
void print_packet_info(t_trame *trame, struct pcap_pkthdr packet_header);
#endif
