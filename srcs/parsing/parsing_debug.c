#include "ft_nmap.h"

void print_data(t_data *data) {
    dprintf(1, "speedup: %d\n", data->speedup);
    dprintf(1, "mask: (%s %s %s %s %s %s)\n", data->scanmask.type.ack ? "ACK": "", data->scanmask.type.fin ? "FIN": "", data->scanmask.type.null ? "NULL": "", data->scanmask.type.syn ? "SYN": "", data->scanmask.type.udp ? "UDP": "", data->scanmask.type.xmas ? "XMAS": "");
    dprintf(1, "port number: %d\n", data->ports_number);
    char **str = data->ip_address;
    int i = 0;
    while(str[i]) {
        dprintf(1, "%s ", str[i]);
        i++;
    }
    dprintf(1, "\n");
}