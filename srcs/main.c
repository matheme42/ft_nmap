#include "../includes/ft_nmap.h"
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <pcap.h>
#include <stdio.h>
#include <time.h>

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
  printf("Packet capture length: %d\n", packet_header.caplen);
  printf("Packet total length %d\n", packet_header.len);
}

void my_packet_handler(u_char *args, const struct pcap_pkthdr *packet_header,
                       const u_char *packet_body) {
  print_packet_info(packet_body, *packet_header);
  return;
}

char *get_devname_by_ip(pcap_if_t *alldevsp, char *ip) {
  char errbuf[PCAP_ERRBUF_SIZE];
  bpf_u_int32 netp, maskp;
  pcap_if_t *dev;
  int srcIp = 0;
  int srcIpMask = 0;
  int devIpMask = 0;

  dev = alldevsp;

  inet_pton(AF_INET, ip, &srcIp);
  while (dev) {
    if (pcap_lookupnet(dev->name, &netp, &maskp, errbuf)) {
      dev = dev->next;
      continue;
    }
    srcIpMask = (srcIp & maskp);
    devIpMask = (netp & maskp);
    if (srcIpMask == devIpMask && devIpMask != 0) return (dev->name);
    dev = dev->next;
  }
}

void print_devs(pcap_if_t *alldevsp) {
  char errbuf[PCAP_ERRBUF_SIZE];
  char ipbuff[INET_ADDRSTRLEN + 1];
  bpf_u_int32 netp, maskp;
  pcap_if_t *dev;

  ipbuff[INET_ADDRSTRLEN] = 0;
  dev = alldevsp;
  printf("devs:\n");
  while (dev) {
    if (pcap_lookupnet(dev->name, &netp, &maskp, errbuf)) {
      fprintf(stderr, "Error lookupnet: %s\n", errbuf);
      dev = dev->next;
      continue;
    }
    printf("name %s\n", dev->name);
    inet_ntop(AF_INET, &netp, ipbuff, INET_ADDRSTRLEN);
    printf("ip %s\n", ipbuff);
    inet_ntop(AF_INET, &maskp, ipbuff, INET_ADDRSTRLEN);
    printf("mask %s\n\n", ipbuff);
    dev = dev->next;
  }
}

void set_filter(pcap_t *p) {
  struct bpf_program program;
  const char *str = "greater 200";

  if (pcap_compile(p, &program, str, 1, PCAP_NETMASK_UNKNOWN)) {
    fprintf(stderr, "Could not compile program : %s\n", pcap_geterr(p));
    return;
  }
  if (pcap_setfilter(p, &program)) {
    fprintf(stderr, "Could not set filter : %s\n", pcap_geterr(p));
    return;
  }
  free(program.bf_insns);
  // pcap_freecode(&program);
}

// int create_socket() {
//   int sockId;
//   int option;
//
//   if ((sockId = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
//     dprintf(2, "ft_traceroute: Socket creation failed\n");
//     return 0;
//   }
//
//   // set custom header to true
//   option = 1;
//   if (setsockopt(sockId, IPPROTO_IP, IP_HDRINCL, &option, sizeof(option))) {
//     dprintf(2, "ft_traceroute: Failed to set socket option\n");
//     return 0;
//   }
//   return (sockId);
// }

void send_tcp_packet(char *ipsrc) {
  struct packet pkt;
  struct sockaddr *addr;
  t_scan flag;

  lookup_host("google.com", &addr);

  int sock = create_socket(IPPROTO_TCP);

  flag.mask = 0;
  flag.type.ack = 0;
  ((struct sockaddr_in *)addr)->sin_family = AF_INET;
  ((struct sockaddr_in *)addr)->sin_port = htons(443);

  int src;
  inet_pton(AF_INET, ipsrc, &src);

  fill_SHTCP_Header(&pkt.shtcp.hdr,
                    (uint32_t)((struct sockaddr_in *)addr)->sin_addr.s_addr,
                    src);
  fill_TCP_Header(&pkt.tcphdr, flag);
  pkt.tcphdr.check =
      checksum(&pkt.shtcp.hdr, sizeof(struct shtcp) + sizeof(struct tcphdr));
  fill_IP_Header(&pkt.iphdr,
                 (uint32_t)((struct sockaddr_in *)addr)->sin_addr.s_addr,
                 IPPROTO_TCP);
  sendto(sock, &pkt, sizeof(struct packet), 0, ((struct sockaddr *)addr),
         sizeof(struct sockaddr_in));
}

int main(int argc, char **argv) {

  t_data data;

  //  if (!parse_arguments(argc, argv, &data)) return (1);

  // print_data(&data);
  //  execute program


  dprintf(1, "%s\n", get_public_ip());


  char *device;
  char error_buffer[PCAP_ERRBUF_SIZE];
  pcap_t *handle;
  pcap_if_t *alldevsp;
  int timeout_limit = 1000; /* In milliseconds */

  if (pcap_findalldevs(&alldevsp, error_buffer)) {
    fprintf(stderr, "Error finding devs: %s\n", error_buffer);
    return 1;
  }
//  print_devs(alldevsp);
  char *str = get_public_ip();
  char *dev = get_devname_by_ip(alldevsp, str);
  /* Open device for live capture */
  handle =
      pcap_open_live(dev, BUFSIZ, 0, timeout_limit, error_buffer);

 // print_devs(alldevsp);
  if (handle == NULL) {
    fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
    return 2;
  }

  pcap_freealldevs(alldevsp);
  set_filter(handle);
  return 0;
  send_tcp_packet(str);
  free(str);

  return 0;
  pcap_dispatch(handle, 0, my_packet_handler, NULL);

  pcap_close(handle);
  return 0;
}
