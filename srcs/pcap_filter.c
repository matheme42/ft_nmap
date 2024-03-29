#include "../includes/ft_nmap.h"
  
void set_filter(pcap_t *p, thread_data *data) {
    struct bpf_program filter_program;
    char *addr;
    char filter[1024];

    addr = inet_ntoa(*(struct in_addr*)&data->destip);
    sprintf(filter, "(icmp && src net %s) || ((tcp || udp) && ((src portrange %d-%d && src net %s) || (dst port %d && dst net %s)))",
    addr, data->ports[0], data->ports[data->nb_port - 1], addr, data->ports[0], addr);
    if (pcap_compile(p, &filter_program, filter, 1, PCAP_NETMASK_UNKNOWN) == PCAP_ERROR) {
        fprintf(stderr, "Cant compile filter : %s\n", pcap_geterr(p));
        return;
    }

    if (pcap_setfilter(p, &filter_program) < 0)
        fprintf(stderr, "Could not set filter : %s\n", pcap_geterr(p));
    free(filter_program.bf_insns);
}

int create_pcap_program(pcap_t *p, struct bpf_program *filter_program, thread_data *data) {
    char *addr;
    char filter[1024];

    addr = inet_ntoa(*(struct in_addr*)&data->destip);
    sprintf(filter, "(icmp && src net %s) || ((tcp || udp) && ((src portrange %d-%d && src net %s) || (dst port %d && dst net %s)))",
    addr, data->ports[0], data->ports[data->nb_port - 1], addr, data->ports[0], addr);
    if (pcap_compile(p, filter_program, filter, 1, PCAP_NETMASK_UNKNOWN) == PCAP_ERROR) {
        fprintf(stderr, "Cant compile filter : %s\n", pcap_geterr(p));
        return 0;
    }
    return 1;
}
