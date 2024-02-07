#include "../includes/ft_nmap.h"
  
void set_filter(pcap_t *p, thread_data *data) {
    struct bpf_program filter_program;
    char filter[1024];

    sprintf(filter, "(icmp) || ((tcp || udp) && src portrange %d-%d)", data->ports[0], data->ports[data->nb_port - 1]);
    printf("filter: %s\n", filter);
    if (pcap_compile(p, &filter_program, filter, 1, PCAP_NETMASK_UNKNOWN) == PCAP_ERROR) {
        fprintf(stderr, "Cant compile portrange rule %s\n", pcap_geterr(p));
        return;
    }

    if (pcap_setfilter(p, &filter_program) < 0)
        fprintf(stderr, "Could not set filter : %s\n", pcap_geterr(p));
    free(filter_program.bf_insns);
}

