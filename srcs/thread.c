#include "ft_nmap.h"

void my_packet_handler(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body) {
  print_packet_info((t_trame *)packet_body, *packet_header);
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

  send_packets(data, socket);

  pcap_dispatch(handle, 0, my_packet_handler, NULL);
  pcap_close(handle);
  close(socket);
  return NULL;
}

void dispatch_thread(t_data *data, char *device, u_int32_t pubip, u_int32_t desip) {
  pthread_t thread[MAX_SPEEDUP];
  thread_data thread_data[MAX_SPEEDUP];

  int threadPortRange = data->ports_number / data->speedup;
  for (int n = 0; n < data->speedup; n++) {
    thread_data[n].device = device;
    thread_data[n].pubip = pubip;
    thread_data[n].destip = desip;
    thread_data[n].scan = data->scanmask;

    // set port number
    if (n == data->speedup - 1 && data->speedup > 1) {
      thread_data[n].nb_port = data->ports_number - (threadPortRange * data->speedup);
    } else {
      thread_data[n].nb_port = threadPortRange;
    }

    // fill port range
    memcpy(thread_data[n].ports, &data->ports[n * threadPortRange], thread_data[n].nb_port * sizeof(short));
    


    pthread_create(&thread[n], NULL, &thread_routine, &thread_data[n]);
  }
  for (int n = 0; n < data->speedup; n++)
    pthread_join(thread[n], NULL);
}
