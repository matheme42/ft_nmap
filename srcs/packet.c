#include "../includes/ft_nmap.h"

static void create_udp_packet(t_packet *pkt, struct sockaddr *src,
                              struct sockaddr *dst) {
  uint16_t dest_port;
  uint16_t src_port;
  uint32_t dest_addr;

  dest_port = (uint16_t)((struct sockaddr_in *)dst)->sin_port;
  src_port = (uint16_t)((struct sockaddr_in *)src)->sin_port;
  dest_addr = (uint32_t)((struct sockaddr_in *)dst)->sin_addr.s_addr;
  fill_IP_Header(&pkt->iphdr, dest_addr, IPPROTO_UDP);
  fill_UDP_Header(&pkt->udphdr, src_port, dest_port);
}

static void create_tcp_packet(t_scan scan, struct sockaddr *src, struct sockaddr *dst, t_packet *pkt) {
  t_scan    flag;
  uint16_t  dest_port;
  uint16_t  src_port;
  uint32_t  dest_addr;
  uint32_t  src_addr;

  dest_port = (uint16_t)((struct sockaddr_in *)dst)->sin_port;
  src_port = (uint16_t)((struct sockaddr_in *)src)->sin_port;
  dest_addr = (uint32_t)((struct sockaddr_in *)dst)->sin_addr.s_addr;
  src_addr = (uint32_t)((struct sockaddr_in *)src)->sin_addr.s_addr;
  fill_SHTCP_Header(&(pkt->shtcp.hdr), dest_addr, src_addr);
  fill_TCP_Header(&(pkt->tcphdr), scan, src_port, dest_port);
  pkt->tcphdr.check = checksum(&(pkt->shtcp.hdr), sizeof(struct shtcp) + sizeof(struct tcphdr));
  fill_IP_Header(&(pkt->iphdr), dest_addr, IPPROTO_TCP);
}

void create_scan_packet(t_scan scan, struct sockaddr *src, struct sockaddr *dst, t_packet *pkt) {
    ft_bzero(pkt, sizeof(t_packet));
    if (scan.type.udp) {
      create_udp_packet(pkt, src, dst);
      return ;
    }
    create_tcp_packet(scan, src, dst, pkt);
}

void send_packets(thread_data *data, int socket) {
    struct sockaddr src_addr;
    struct sockaddr dest_addr;
    t_packet packet;
    t_scan local_scan;

    for (int i = 0; i < 6; i++) {
      local_scan.mask = 0;
      if (i == 0) local_scan.type.ack = data->scan.type.ack;
      else if (i == 1) local_scan.type.fin = data->scan.type.fin;
      else if (i == 2) local_scan.type.null = data->scan.type.null;
      else if (i == 3) local_scan.type.syn = data->scan.type.syn;
      else if (i == 4) local_scan.type.udp = data->scan.type.udp;
      else if (i == 5) local_scan.type.xmas = data->scan.type.xmas;

      if (local_scan.mask == 0) continue;
      for (short port_idx = 0; port_idx < data->nb_port; port_idx++) {
      ((struct sockaddr_in *)&src_addr)->sin_addr.s_addr = data->pubip;
        ((struct sockaddr_in *)&src_addr)->sin_port = 34443 + port_idx;  

        ((struct sockaddr_in *)&dest_addr)->sin_addr.s_addr = data->destip;
        ((struct sockaddr_in *)&dest_addr)->sin_port = data->ports[port_idx];

        create_scan_packet(local_scan, &src_addr, &dest_addr, &packet);
        sendto(socket, &packet, sizeof(struct packet), 0, ((struct sockaddr *)&dest_addr), sizeof(struct sockaddr_in));
      }
    }
}
