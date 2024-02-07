#include "ft_nmap.h"
#include <signal.h>

int get_packet_port(t_trame *trame) {
  char *data;

  switch (trame->iphdr.protocol)
  {
    case IPPROTO_UDP:
      return htons(trame->udphdr.source);
    case IPPROTO_TCP:
      return htons(trame->tcphdr.source);
    case IPPROTO_ICMP:
      data = (char*)trame;
      data = &data[sizeof(t_trame)];
      t_packet *send_packet = (t_packet*)data;
      return htons(send_packet->tcphdr.dest);
  default:
    return 0;
  }
}

short get_port_id(u_int16_t *ports, short port_number, u_int16_t port) {
  for (int i = 0; i < port_number; i++)
    if (ports[i] == port) return i;
  return -1;
}

// 0 --> UDP
// 1 --> SYN/ACK
// 2 --> RST
// 3 --> ICMP code 3
// 4 --> ICMP autre code
// -1 --> error
void analize_response(t_scan current_scan, char packet_type, t_response *response) {
  switch (current_scan.mask) {
    case 0b1: //SYN
      if (response->syn != 0) return ;
      if (packet_type == 1) response->syn = S_OPEN;
      else if (packet_type == 2) response->syn = S_CLOSED;
      if (packet_type == 3 || packet_type == 4) response->syn = S_FILTERED;
      break;
    case 0b10: //NULL
      if (response->null != 0) return ;
      if (packet_type == 2) response->null = F_CLOSED;
      else if (packet_type == 3 || packet_type == 4) response->null = F_FILTERED;
      break;
    case 0b100: //ACK
      if (response->ack != 0) return ;
      if (packet_type == 2) response->ack = A_UNFILTERED;
      else if (packet_type == 3 || packet_type == 4) response->ack = A_FILTERED;
      break;
    case 0b1000: //FIN
      if (response->fin != 0) return ;
      if (packet_type == 2) response->fin = F_CLOSED;
      else if (packet_type == 3 || packet_type == 4) response->fin = F_FILTERED;
      break;
    case 0b10000: //XMAS
      if (response->xmas != 0) return ;
      if (packet_type == 2) response->xmas = F_CLOSED;
      else if (packet_type == 3 || packet_type == 4) response->xmas = F_FILTERED;
      break;
    case 0b100000: //UDP
      if (response->udp != 0) return ;
      if (packet_type == 0) response->udp = U_OPEN;
      else if (packet_type == 3) response->udp = U_CLOSED;
      if (packet_type == 4) response->udp = U_FILTERED;
      break;
    default:
      break;
  }
}
// 0 --> UDP
// 1 --> SYN/ACK
// 2 --> RST
// 3 --> ICMP code 3
// 4 --> ICMP autre code
// -1 --> error
char simplifize_response(t_trame *trame) {
  uint8_t code = 0;
 switch (trame->iphdr.protocol)
  {
    case IPPROTO_UDP:
      return 0; // response udp
    case IPPROTO_TCP:
      if (trame->tcphdr.ack == 1 && trame->tcphdr.syn == 1) return 1;
      if (trame->tcphdr.rst == 1) return 2;
      return -1;
    case IPPROTO_ICMP:
      if (trame->icmphdr.type == 3) {
        if (trame->icmphdr.code == 3) {
          code = trame->icmphdr.code;
          return 3;
        }
        else if (code == 1 || code == 2 || code == 3 || code == 9 || code == 10 || code == 13) {
          return 4;
        }
      }
      return -1;
    default:
      return -1;
  }
}

void my_packet_handler(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body) {
  t_trame *trame = (t_trame *)packet_body;
  thread_data *data = (thread_data *)args;
  if ((data->destip == trame->iphdr.daddr && data->destip != 16777343) && trame->iphdr.id != getuid()) return ;
  
  unsigned short port = get_packet_port(trame);
  short id = get_port_id(data->ports, data->nb_port, port);
  if (id < 0) return ;
  char response_type = simplifize_response(trame);
  if (response_type < 0) return ;
  analize_response(data->current_scan, response_type, &(data->response[id]));
 // print_packet_info(trame, *packet_header);
  return;
}

static void *thread_routine(void *ptr) {
  char        error_buffer[PCAP_ERRBUF_SIZE];
  pcap_t      *handle;
  int         timeout_limit = 300; /* In milliseconds */
  int         socket;
  thread_data *data = ptr;
//  int udp_socket = create_socket(IPPROTO_ICMP);

  if (data->nb_port <= 0 ||
    !(socket = create_socket(IPPROTO_TCP)))
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
    if (!(handle = pcap_open_live(data->device, BUFSIZ, -1, timeout_limit, error_buffer)))
      continue;
    set_filter(handle, data);
    send_packets(data, socket);
    pcap_dispatch(handle, 0, my_packet_handler, ptr);
    pcap_close(handle);
  }
  close(socket);
  return NULL;
}

void dispatch_thread(t_data *data, char *device, u_int32_t pubip, u_int32_t desip) {
  pthread_t thread[MAX_SPEEDUP];
  thread_data thread_data[MAX_SPEEDUP];

  ft_bzero(thread_data, sizeof(thread_data));

  float threadPortRange = data->ports_number / (float)data->speedup;
  for (int n = 0; n < data->speedup; n++) {
    thread_data[n].device = device;
    thread_data[n].pubip = pubip;
    thread_data[n].destip = desip;
    thread_data[n].scan = data->scanmask;
    // fill port range
    thread_data[n].nb_port = (int)(threadPortRange * (n + 1)) - (int)(threadPortRange * n);
    ft_memcpy(thread_data[n].ports, &data->ports[(int)(n * threadPortRange)], thread_data[n].nb_port * sizeof(short));
    pthread_create(&thread[n], NULL, &thread_routine, &thread_data[n]);
  }

  for (int n = 0; n < data->speedup; n++)
    pthread_join(thread[n], NULL);

  display_response(thread_data, data->speedup);
}
