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

  lookup_host(host, &dest);
  return ((struct sockaddr_in*)&dest)->sin_addr.s_addr;
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

void run_routine(t_data *data, char *device, u_int32_t pubip, u_int32_t destip) {
  thread_data routine_data;

  printf("running routine\n");
  ft_bzero(&routine_data, sizeof(thread_data));
  routine_data.device = device;
  routine_data.pubip = pubip;
  routine_data.destip = destip;
  routine_data.scan = data->scanmask;
  routine_data.nb_port = data->ports_number;
  ft_memcpy(routine_data.ports, data->ports, routine_data.nb_port * sizeof(u_int16_t));
  thread_routine(&routine_data);
  display_response(&routine_data, 1, data->display_all, data->scanmask);
}



int main(int argc, char **argv) {
  t_data data;
  char error_buffer[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevsp;
  u_int32_t pubip;
  char      *dev;
  int       n;

  if (!parse_arguments(argc, argv, &data)) return (1);
  print_data(&data);
  ft_quicksort(data.ports, data.ports_number);

  ft_bzero(error_buffer, PCAP_ERRBUF_SIZE);
  if (pcap_findalldevs(&alldevsp, error_buffer)) {
    fprintf(stderr, "Error finding devs: %s\n", error_buffer);
    free_tab(data.ip_address);
    return 1;
  }

  n = 0;
  while (data.ip_address[n]) {
    dprintf(1, "\nscanning: %s\n", data.ip_address[n]);

    pubip = get_public_ip(data.ip_address[n]);
    if (!pubip) continue ;
    if (!(dev = get_devname_by_ip(alldevsp, pubip))) continue;
    uint32_t destAddr = htoi(data.ip_address[n]);
    if (data.speedup)
      dispatch_thread(&data, dev, pubip, destAddr);
    else
      run_routine(&data, dev, pubip, destAddr);
    n++;
  }
  free_tab(data.ip_address);
  pcap_freealldevs(alldevsp);
  return 0;
}
