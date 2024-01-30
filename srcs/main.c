#include "../includes/ft_nmap.h"
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <stdio.h>
#include <time.h>

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
  dprintf(1, "we got %u bytes\n", packet_header.len);
  for (int i = 0; i < packet_header.len; i++) {
    if (i % 8 == 0 && i != 0)
      dprintf(1, "\n");
    dprintf(1, "%02hhx ", packet[i]);
  }
  dprintf(1, "\n\n");

  t_packet *data = (t_packet *)packet;
  printf("source port %u\n", ntohs(data->udphdr.source));
  printf("dest port %u\n", ntohs(data->udphdr.dest));
}

void my_packet_handler(u_char *args, const struct pcap_pkthdr *packet_header,
                       const u_char *packet_body) {
  print_packet_info(packet_body, *packet_header);
  return;
}

char *get_devname_by_ip(pcap_if_t *alldevsp, u_int32_t ip) {
  char errbuf[PCAP_ERRBUF_SIZE];
  bpf_u_int32 netp, maskp;
  pcap_if_t *dev;
  int srcIpMask = 0;
  int devIpMask = 0;

  dev = alldevsp;
  while (dev) {
    if (pcap_lookupnet(dev->name, &netp, &maskp, errbuf)) {
      dev = dev->next;
      continue;
    }
    srcIpMask = (ip & maskp);
    devIpMask = (netp & maskp);
    if (srcIpMask == devIpMask && devIpMask != 0)
      return (dev->name);
    dev = dev->next;
  }
  return (NULL);
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

/*
>>>>>>> main
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
*/

void *thread_routine(void *ptr) {
  char error_buffer[PCAP_ERRBUF_SIZE];
  pcap_t *handle;
  int timeout_limit = 500; /* In milliseconds */
  thread_data *data = ptr;

  handle = pcap_open_live(data->device, BUFSIZ, 0, timeout_limit, error_buffer);
  set_filter(handle);

  struct sockaddr src_addr;
  struct sockaddr dest_addr;
  t_packet packet;

  ((struct sockaddr_in *)&src_addr)->sin_addr.s_addr = data->pubip;
  ((struct sockaddr_in *)&src_addr)->sin_port = 34443;

  ((struct sockaddr_in *)&dest_addr)->sin_addr.s_addr = data->destip;
  ((struct sockaddr_in *)&dest_addr)->sin_port = 1000;

  int sock = create_socket(IPPROTO_TCP);
  create_scan_packet(UDP, &src_addr, &dest_addr, &packet);
  sendto(sock, &packet, sizeof(struct packet), 0,
         ((struct sockaddr *)&dest_addr), sizeof(struct sockaddr_in));

  pcap_dispatch(handle, 0, my_packet_handler, NULL);
  pcap_close(handle);
  close(sock);
  return NULL;
}

void dispatch_thread(int threads, char *device, u_int32_t pubip) {
  pthread_t thread[MAX_SPEEDUP];
  thread_data data[MAX_SPEEDUP];

  for (int n = 0; n < threads; n++) {
    data[n].device = device;
    data[n].pubip = pubip;
    pthread_create(&thread[n], NULL, &thread_routine, &data[n]);
  }
  for (int n = 0; n < threads; n++)
    pthread_join(thread[n], NULL);
}

int main(int argc, char **argv) {

  // t_data data;

  //  if (!parse_arguments(argc, argv, &data)) return (1);

  // print_data(&data);
  //  execute program

  char error_buffer[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevsp = 0;

  ft_bzero(error_buffer, PCAP_ERRBUF_SIZE);
  if (pcap_findalldevs(&alldevsp, error_buffer)) {
    fprintf(stderr, "Error finding devs: %s\n", error_buffer);
    return 1;
  }

  u_int32_t pubip = get_public_ip("google.com");
  char *dev = get_devname_by_ip(alldevsp, pubip);
  if (!dev)
    return 2;

  dispatch_thread(1, dev, pubip);

  // set_filter(handle);
  // send_tcp_packet(str);
  pcap_freealldevs(alldevsp);
  return 0;
}
