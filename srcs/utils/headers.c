#include "../../includes/ft_nmap.h"

void fill_ICMP_Header(struct packet *pkt) {
    pkt->icmphdr.type = ICMP_ECHO;
    pkt->icmphdr.code = 0;
    pkt->icmphdr.checksum = 0;
    pkt->icmphdr.un.echo.id = 0;
    pkt->icmphdr.un.echo.sequence = 0;
    pkt->icmphdr.checksum = checksum(&pkt->icmphdr, sizeof(struct icmphdr));
}

void fill_UDP_Header(struct udphdr *udphdr, uint16_t sport, uint16_t dport) {
  udphdr->source = htons(sport);
  udphdr->dest = htons(dport);
  udphdr->len = htons(sizeof(struct udphdr));
  udphdr->check = 0;
}

unsigned short checksum(void *b, int len) {
  unsigned short *buf = b;
  unsigned int sum = 0;
  unsigned short result;

  for (sum = 0; len > 1; len -= 2)
    sum += *buf++;
  if (len == 1)
    sum += *(unsigned char *)buf;
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  result = ~sum;
  return result;
}

void fill_TCP_Header(struct tcphdr *tcphdr, t_scan flags, uint16_t  src_port, uint16_t dst_port) {
  ft_bzero(tcphdr, sizeof(struct tcphdr));
  tcphdr->source = htons(src_port);
  tcphdr->dest = htons(dst_port);
  tcphdr->seq = 0;
  tcphdr->ack_seq = 0;
  tcphdr->doff = sizeof(struct tcphdr) / 4;
  tcphdr->ack = flags.type.ack;
  tcphdr->syn = flags.type.syn;
  tcphdr->fin = flags.type.fin || flags.type.xmas;
  tcphdr->urg = flags.type.xmas;
  tcphdr->psh = flags.type.xmas;
  tcphdr->res1 = 0;
  tcphdr->window = USHRT_MAX;
  tcphdr->urg_ptr = 0;
}

void fill_IP_Header(struct iphdr *header, uint32_t daddr, u_int8_t protocol) {

  header->version = IPVERSION;
  header->ihl = 5;
  header->tos = 0;
  header->tot_len = 0;
  header->id = 154;
  header->frag_off = 0;
  header->ttl = 255;
  header->protocol = protocol;
  header->check = 0;
  header->saddr = INADDR_ANY;
  header->daddr = daddr;
}

void fill_SHTCP_Header(struct shtcp *header, uint32_t daddr, uint32_t saddr) {
  header->dst = daddr;
  header->src = saddr;
  header->protocol = IPPROTO_TCP;
  header->reserved = 0;
  header->tcp_len = htons(sizeof(struct tcphdr));
}

void lookup_host(const char *host, struct sockaddr *sockaddr) {
  struct addrinfo hints;
  struct addrinfo *res;

  ft_bzero(&hints, sizeof(hints));

  hints.ai_family = PF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = 0;
  hints.ai_flags = AI_CANONNAME;

  if (!getaddrinfo(host, NULL, &hints, &res)) {
    *sockaddr = *res->ai_addr;
    freeaddrinfo(res);
  }
}
