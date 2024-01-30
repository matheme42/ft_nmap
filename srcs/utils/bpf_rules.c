#include "../../includes/ft_nmap.h"

void compile_rule(pcap_t *p, char *rule, struct bpf_program *filter_program) {
  if (pcap_compile(p, filter_program, rule, 1, PCAP_NETMASK_UNKNOWN)) {
    free(rule);
    fprintf(stderr, "Cant compile portrange rule %s, exiting program...\n",
            pcap_geterr(p));
    exit(0);
  }
  dprintf(1, "rule [%s] compiled \n", rule);
  free(rule);
}

void compile_portrange_rule(
    pcap_t *p, int port_min, int port_max, struct bpf_program *filter_program,
    char *port_family) { // port family can be equal to "" "source " or "dest "
  char *filter = ft_strjoin(port_family, "portrange ");
  char text[] = "-";

  char *res1 = ft_strjoin(filter, ft_itoa(port_min));
  char *res2 = ft_strjoin(text, ft_itoa(port_max));
  char *filter_rule = ft_strjoin(res1, res2);
  free(res1);
  free(res2);
  free(filter);
  compile_rule(p, filter_rule, filter_program);
}

void compile_host_rule(
    pcap_t *p, char *host, struct bpf_program *filter_program,
    char *host_family) { // can be equal to "" or "src " or "dst "
  char *temp = ft_strjoin(host_family, "host ");
  char *filter_rule = ft_strjoin(temp, host);
  free(temp);
  compile_rule(p, filter_rule, filter_program);
}

void set_filter(pcap_t *p) {
  struct bpf_program filter_program;
  // const char *str = "greater 200";

  int port_min = 30000;
  int port_max = 65000;
  compile_portrange_rule(p, port_min, port_max, &filter_program, "src ");

  if (pcap_setfilter(p, &filter_program)) {
    fprintf(stderr, "Could not set filter : %s\n", pcap_geterr(p));
    return;
  }
  free(filter_program.bf_insns);
}
