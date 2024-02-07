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
    t_packet        packet;

    ft_bzero(&src_addr, sizeof(struct sockaddr));
    ft_bzero(&dest_addr, sizeof(struct sockaddr));
    for (short port_idx = 0; port_idx < data->nb_port; port_idx++) {
      ((struct sockaddr_in *)&src_addr)->sin_addr.s_addr = data->pubip;
      ((struct sockaddr_in *)&src_addr)->sin_port = 34443 + port_idx;  
      ((struct sockaddr_in *)&src_addr)->sin_family = AF_INET;
      ((struct sockaddr_in *)&dest_addr)->sin_addr.s_addr = data->destip;
      ((struct sockaddr_in *)&dest_addr)->sin_port = data->ports[port_idx];
      ((struct sockaddr_in *)&dest_addr)->sin_family = AF_INET;
      create_scan_packet(data->current_scan, &src_addr, &dest_addr, &packet);
     sendto(socket, &packet, sizeof(struct packet), 0, ((struct sockaddr *)&dest_addr), sizeof(struct sockaddr_in));
    }
}
