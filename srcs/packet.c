#include "ft_nmap.h"

static void create_udp_packet(t_packet *pkt, uint32_t daddr, uint16_t sport, uint16_t dport) {
  fill_IP_Header(&pkt->iphdr, daddr, IPPROTO_UDP);
  fill_UDP_Header(&pkt->udphdr, sport, dport);
}

static t_scan convert_scan_name_to_flag(char *scan_name) {

}

static void create_tcp_packet(t_packet *pkt, char *scan) {
  fill_SHTCP_Header(&pkt->shtcp.hdr,
                    (uint32_t)((struct sockaddr_in *)addr)->sin_addr.s_addr,
                    src);

  t_scan flag = convert_scan_name_to_flag(scan);
  fill_TCP_Header(&pkt->tcphdr, flag);
  pkt->tcphdr.check = checksum(&pkt->shtcp.hdr, sizeof(struct shtcp) + sizeof(struct tcphdr));
}

void create_scan_packet(E_SCAN scan, char *src_host, struct sockaddr *dst, t_packet *pkt) {
    uint32_t    addr;
    int         protocol;

    ft_bzero(pkt, sizeof(t_packet));

    if (scan == UDP) fill_udp_packet();
    else fill_tcp_packet();

    protocol = udp ? IPPROTO_UDP : IPPROTO_TCP;
    addr = (uint32_t)((struct sockaddr_in *)dst)->sin_addr.s_addr;
    fill_IP_Header(&pkt->iphdr, addr, protocol);
}