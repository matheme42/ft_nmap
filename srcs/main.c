#include "../includes/ft_nmap.h"
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <stdio.h>
#include <time.h>

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

u_int32_t htoi(char *host) {
  struct sockaddr dest;
  struct sockaddr *destPoiteur = &dest;

  lookup_host(host, &destPoiteur);

  return ((struct sockaddr_in*)destPoiteur)->sin_addr.s_addr;
}

void		ft_quicksort(uint16_t *tab, int len)
{
	uint16_t compa;
	uint16_t	tmp;
	int		n;
	int		m;

	if (len < 2)
		return ;
	compa = tab[(len - 1)];
	m = 0;
	n = -1;
	while (++n < len)
		if (tab[n] <= compa) {
			if (m != n) {
				tmp = tab[m];
				tab[m] = tab[n];
				tab[n] = tmp;
			}
			m++;
		}
	ft_quicksort(tab, --m);
	ft_quicksort(&tab[m], len - m);
}


int main(int argc, char **argv) {
  t_data data;
  char error_buffer[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevsp;
  u_int32_t pubip;
  char      *dev;

  if (!parse_arguments(argc, argv, &data)) return (1);
  print_data(&data);
  ft_quicksort(data.ports, data.ports_number);

  ft_bzero(error_buffer, PCAP_ERRBUF_SIZE);
  if (pcap_findalldevs(&alldevsp, error_buffer)) {
    fprintf(stderr, "Error finding devs: %s\n", error_buffer);
    return 1;
  }

  int i = -1;
  while (*data.ip_address) {
    dprintf(1, "\nscanning: %s\n", *data.ip_address);


    pubip = get_public_ip(*data.ip_address);
    if (!(dev = get_devname_by_ip(alldevsp, pubip))) continue;
    dispatch_thread(&data, dev, pubip, htoi(*data.ip_address));
    data.ip_address++;
  }
  
  pcap_freealldevs(alldevsp);
  return 0;
}
