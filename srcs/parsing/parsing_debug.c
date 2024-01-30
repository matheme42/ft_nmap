#include "../../includes/ft_nmap.h"

void print_data(t_data *data) {

  dprintf(1, "Scan Configurations\n");
  dprintf(1, "Target Ip-Address : ");
  int i = 0;
  while (data->ip_address[i]) dprintf(1, "%s ", data->ip_address[i++]);
  dprintf(1, "\n");

  dprintf(1, "No of Ports to scan : %d\n", data->ports_number);
  t_scan mask = data->scanmask;
  dprintf(1, "Scans to be performed : ");
  dprintf(1, "%s %s %s %s %s %s\n", mask.type.ack ? "ACK" : "", mask.type.fin ? "FIN" : "", mask.type.null ? "NULL" : "", mask.type.syn ? "SYN" : "", mask.type.udp ? "UDP" : "", mask.type.xmas ? "XMAS" : "");
  dprintf(1, "No of threads : %d\n", data->speedup);
  dprintf(1, "Scanning...\n");
}
