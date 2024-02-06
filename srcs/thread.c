#include "ft_nmap.h"
#include <signal.h>

void my_packet_handler(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body) {
  t_trame *trame = (t_trame *)packet_body;
  thread_data *data = (thread_data *)args;
  if (data->destip == trame->iphdr.daddr) return ;

  t_response response; 
  print_packet_info(trame, *packet_header);
  return;
}

static void *thread_routine(void *ptr) {
  char        error_buffer[PCAP_ERRBUF_SIZE];
  pcap_t      *handle;
  int         timeout_limit = 300; /* In milliseconds */
  int         socket;
  thread_data *data = ptr;
  int udp_socket = create_socket(IPPROTO_ICMP);

  if (!(socket = create_socket(IPPROTO_TCP)) ||
      !(handle = pcap_open_live(data->device, BUFSIZ, 0, timeout_limit, error_buffer)))
    return (NULL);

    for (int i = 0; i < 6; i++) {
      data->current_scan.mask = 0;
      if (i == 0) data->current_scan.type.ack = data->scan.type.ack;
      else if (i == 1) data->current_scan.type.fin = data->scan.type.fin;
      else if (i == 2) data->current_scan.type.null = data->scan.type.null;
      else if (i == 3) data->current_scan.type.syn = data->scan.type.syn;
      else if (i == 4) data->current_scan.type.udp = data->scan.type.udp;
      else if (i == 5) data->current_scan.type.xmas = data->scan.type.xmas;
      if (data->current_scan.mask == 0) continue;
      clear_filter(handle);
      //set_filter(handle);
      send_packets(data, socket);
      pcap_dispatch(handle, 0, my_packet_handler, ptr);
    }

  pcap_close(handle);
  close(socket);
  return NULL;
}

void dispatch_thread(t_data *data, char *device, u_int32_t pubip, u_int32_t desip) {
  pthread_t thread[MAX_SPEEDUP];
  thread_data thread_data[MAX_SPEEDUP];

  float threadPortRange = data->ports_number / (float)data->speedup;
  for (int n = 0; n < data->speedup; n++) {
    thread_data[n].device = device;
    thread_data[n].pubip = pubip;
    thread_data[n].destip = desip;
    thread_data[n].scan = data->scanmask;

    // fill port range
    thread_data[n].nb_port = (int)(threadPortRange * (n + 1)) - (int)(threadPortRange * n);
    memcpy(thread_data[n].ports, &data->ports[(int)(n * threadPortRange)], thread_data[n].nb_port * sizeof(short));
    pthread_create(&thread[n], NULL, &thread_routine, &thread_data[n]);
  }

  for (int n = 0; n < data->speedup; n++)
    pthread_join(thread[n], NULL);
}
