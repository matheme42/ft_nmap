#include "ft_nmap.h"

static void create_udp_packet(t_packet *pkt, struct sockaddr *src, struct sockaddr *dst) {
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
    if (scan == UDP) {
      create_udp_packet(pkt, src, dst);
      return ;
    }
    create_tcp_packet(scan, src, dst, pkt);
}

void send_packet(thread_data *data, int socket) {
    struct sockaddr src_addr;
    struct sockaddr dest_addr;
    t_packet packet;

    ((struct sockaddr_in *)&src_addr)->sin_addr.s_addr = data->pubip;
    ((struct sockaddr_in *)&src_addr)->sin_port = 34443;  

    ((struct sockaddr_in *)&dest_addr)->sin_addr.s_addr = data->destip;
    ((struct sockaddr_in *)&dest_addr)->sin_port = 1000;

    create_scan_packet(UDP, &src_addr, &dest_addr, &packet);
    sendto(socket, &packet, sizeof(struct packet), 0, ((struct sockaddr *)&dest_addr), sizeof(struct sockaddr_in));
}