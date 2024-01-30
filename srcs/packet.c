#include "ft_nmap.h"

static void create_udp_packet(t_packet *pkt, uint32_t daddr, struct sockaddr *src, struct sockaddr *dst) {
  uint16_t  dest_port;
  uint16_t  src_port;
  uint32_t  dest_addr;

  dest_port = (uint16_t)((struct sockaddr_in *)dst)->sin_port;
  src_port = (uint16_t)((struct sockaddr_in *)src)->sin_port;
  dest_addr = (uint32_t)((struct sockaddr_in *)dst)->sin_addr.s_addr;
  fill_IP_Header(&pkt->iphdr, dest_addr, IPPROTO_UDP);
  fill_UDP_Header(&pkt->udphdr, src_port, dest_port);
}

static t_scan convert_scan_name_to_flag(E_SCAN scan) {
  t_scan s;
  s.mask = 0;
  switch (scan)
  {
    case ACK:
      s.type.ack = 1;
    break;
    case SYN:
      s.type.syn = 1;
    break;
    case FIN:
      s.type.fin = 1;
    break;
    case XMAS:
      s.type.xmas = 1;
    break;
    default:
    break;
  }
  return s;
}

static void create_tcp_packet(E_SCAN scan, struct sockaddr *src, struct sockaddr *dst, t_packet *pkt) {
  t_scan    flag;
  uint16_t  dest_port;
  uint16_t  src_port;
  uint32_t  dest_addr;
  uint32_t  src_addr;

  dest_port = (uint16_t)((struct sockaddr_in *)dst)->sin_port;
  src_port = (uint16_t)((struct sockaddr_in *)src)->sin_port;
  dest_addr = (uint32_t)((struct sockaddr_in *)dst)->sin_addr.s_addr;
  src_addr = (uint32_t)((struct sockaddr_in *)src)->sin_addr.s_addr;
  fill_SHTCP_Header(&pkt->shtcp.hdr, dest_addr, src_addr);
  fill_TCP_Header(&pkt->tcphdr, convert_scan_name_to_flag(scan), src_port, dest_port);
  pkt->tcphdr.check = checksum(&pkt->shtcp.hdr, sizeof(struct shtcp) + sizeof(struct tcphdr));
  fill_IP_Header(&pkt->iphdr, dest_addr, IPPROTO_TCP);
}

void create_scan_packet(E_SCAN scan, struct sockaddr *src, struct sockaddr *dst, t_packet *pkt) {
    ft_bzero(pkt, sizeof(t_packet));
    (scan == UDP) ? fill_udp_packet() : fill_tcp_packet();
}