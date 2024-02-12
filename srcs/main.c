#include "../includes/ft_nmap.h"
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <stdio.h>
#include <time.h>

#ifndef __USE_POSIX
#define __USE_POSIX
#endif

#include <signal.h>

pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

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

struct global_data g_data;

struct timeval run_routine(t_data *data, char *device, u_int32_t pubip, u_int32_t destip) {
  thread_data routine_data;
  struct timeval end;

  g_data.threads = 1;
  g_data.data = &routine_data;
  ft_bzero(&routine_data, sizeof(thread_data));
  routine_data.device = device;
  routine_data.pubip = pubip;
  routine_data.destip = destip;
  routine_data.scan = data->scanmask;
  routine_data.nb_port = data->ports_number;
  ft_memcpy(routine_data.ports, data->ports, routine_data.nb_port * sizeof(u_int16_t));
  thread_routine(&routine_data);
  alarm(0);

  gettimeofday(&end, NULL);
  display_response(&routine_data, 1, data->display_all, data->scanmask);
  return end;
}


static void display_time(struct timeval *start, struct timeval *end, char*host) {
  long sec = end->tv_sec - start->tv_sec;
  long ms = end->tv_usec - start->tv_usec;
  long total_time = (sec * 1000000) + ms;
  dprintf(1, "scanning: %s in %ld.%lds\n", host, total_time / 1000000, (total_time % 1000000) / 1000);
}

void alarm_handler(int sig) {
  (void)sig;
  pthread_mutex_lock(&g_mutex);
  for (int n = 0; n < g_data.threads; n++)
    if (g_data.data[n].handle)
      pcap_breakloop(g_data.data[n].handle);
  pthread_mutex_unlock(&g_mutex);
}

int main(int argc, char **argv) {
  t_data data;
  char error_buffer[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevsp;
  u_int32_t pubip;
  struct timeval start_time, end_time;
  struct sigaction new, old;
  char      *dev;
  int       n;

  ft_bzero(&new, sizeof(struct sigaction));
  new.sa_handler = &alarm_handler;
  sigaction(SIGALRM, &new, &old);
  if (!parse_arguments(argc, argv, &data)) return (1);
  print_data(&data);
  ft_quicksort(data.ports, data.ports_number);

  ft_bzero(error_buffer, PCAP_ERRBUF_SIZE);
  if (pcap_findalldevs(&alldevsp, error_buffer)) {
    fprintf(stderr, "Error finding devs: %s\n", error_buffer);
    free_tab(data.ip_address);
    return 1;
  }

  n = -1;
  while (data.ip_address[++n]) {
    gettimeofday(&start_time, NULL);

    if (!(pubip = get_public_ip(data.ip_address[n])) ||
      !(dev = get_devname_by_ip(alldevsp, pubip))) {
        dprintf(2, "unable to contact: %s\n", data.ip_address[n]);
        continue;
      }
    dprintf(1, "\nscanning: %s\n", data.ip_address[n]);
    uint32_t destAddr = htoi(data.ip_address[n]);
    end_time = data.speedup ? dispatch_thread(&data, dev, pubip, destAddr) : run_routine(&data, dev, pubip, destAddr);
    display_time(&start_time, &end_time, data.ip_address[n]);
  }
  free_tab(data.ip_address);
  pcap_freealldevs(alldevsp);
  return 0;
}
