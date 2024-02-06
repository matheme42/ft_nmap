#include "ft_nmap.h"


void replacevalue(char *dest, char value) {
  static const char base[16] = "0123456789abcdef";

  dest[1] =  base[(value & 0xf)];
  dest[0] =  base[((value >> 4) & 0xf)];
}

void print_packet_info(t_trame *trame, struct pcap_pkthdr packet_header) {
    
  char *packet = (char*)trame;

  char machdr[] = "\x1B[32m00 00 00 00 00 00\x1B[34m 00 00\n00 00 00 00\x1B[35m 00 00";

  for (int i = 0, idx = 5; i < sizeof(t_mac_header); i++) {
    replacevalue(&machdr[idx], packet[i]);
    idx += 3 + ((i + 1) % 6 == 0) * 5;
  }

  char iphdr[] = "\x1B[33m00 00\n00 00 00 00 00 00 00 \x1B[31m00\x1B[33m\n00 00 00 00 00 00 00 00\n00 00\x1B[0m";

  for (int i = sizeof(t_mac_header), idx = 5; i < sizeof(struct iphdr) + sizeof(t_mac_header); i++) {
    replacevalue(&iphdr[idx], packet[i]);
    idx += 3;
    if (i == 22 ||i == 23) idx += 5;
  }


  dprintf(1, "%s %s", machdr, iphdr);

  for (int i = 34; i < packet_header.len; i++) {
    dprintf(1, "%c%02hhx",  (i % 8 == 0 && i != 0) ? '\n' : (i == 0) ? '\r' : ' ', ((char*)packet)[i]);
  }


  dprintf(1, "\n\n");
 /* for (int i = 0; i < packet_header.len; i++) {
    dprintf(1, "%c%02hhx",  (i % 8 == 0 && i != 0) ? '\n' : (i == 0) ? '\r' : ' ', ((char*)packet)[i]);
  }*/
}
