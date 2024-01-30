#include "../includes/ft_nmap.h"
#include <pthread.h>

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

  // printf("source port %u\n", data->udphdr.source);
  // printf("dest port %u\n", data->udphdr.dest);
}

void my_packet_handler(u_char *args, const struct pcap_pkthdr *packet_header,
                       const u_char *packet_body) {
  print_packet_info(packet_body, *packet_header);
  return;
}

static void *thread_routine(void *ptr) {
  char error_buffer[PCAP_ERRBUF_SIZE];
  pcap_t *handle;
  int timeout_limit = 500; /* In milliseconds */
  int socket;
  thread_data *data = ptr;

  if (!(socket = create_socket(IPPROTO_TCP)) ||
      !(handle = pcap_open_live(data->device, BUFSIZ, 0, timeout_limit,
                                error_buffer)))
    return (NULL);
  set_filter(handle);

  send_packet(data, socket);

  pcap_dispatch(handle, 0, my_packet_handler, NULL);
  pcap_close(handle);
  close(socket);
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
