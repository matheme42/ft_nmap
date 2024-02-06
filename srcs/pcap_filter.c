#include "../includes/ft_nmap.h"
  
void set_filter(pcap_t *p) {
    struct bpf_program filter_program;
    char filter[1024];

    sprintf(filter, "(icmp) || (tcp || udp)");
    if (pcap_compile(p, &filter_program, filter, 1, PCAP_NETMASK_UNKNOWN) == PCAP_ERROR)
        fprintf(stderr, "Cant compile portrange rule %s, exiting program...\n", pcap_geterr(p));

    if (pcap_setfilter(p, &filter_program) < 0)
        fprintf(stderr, "Could not set filter : %s\n", pcap_geterr(p));
    free(filter_program.bf_insns);
}

