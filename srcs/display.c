#include "ft_nmap.h"

char *convert_value(char scan, unsigned char v) {
    static char data[6][4][29] = {
        {"\e[0;37mFILTERED\e[0;0m", "\e[0;31mCLOSED  \e[0;0m", "\e[0;32mOPEN    \e[0;0m"}, // SYN
        {"\e[0;37mFILTERED  \e[0;0m", "\e[0;36mUNFILTERED\e[0;0m"}, // ACK
        {"\e[0;37mOPEN | FILTERED\e[0;0m", "\e[0;31mCLOSED         \e[0;0m", "\e[0;34mFILTERED       \e[0;0m"}, // FIN
        {"\e[0;37mOPEN | FILTERED\e[0;0m", "\e[0;31mCLOSED         \e[0;0m", "\e[0;34mFILTERED       \e[0;0m"}, // NULL
        {"\e[0;37mOPEN | FILTERED\e[0;0m", "\e[0;31mCLOSED         \e[0;0m", "\e[0;34mFILTERED       \e[0;0m"}, // XMAS
        {"\e[0;37mOPEN | FILTERED\e[0;0m", "\e[0;32mOPEN           \e[0;0m", "\e[0;31mCLOSED         \e[0;0m", "\e[0;34mFILTERED       \e[0;0m"} // UDP
    };
    return data[scan][v];
}


static void display_header(t_scan scan) {
    dprintf(1, "| PORT  |");
    dprintf(1, "| SERVICE     |");
    if (scan.type.syn)  dprintf(1, " SYN      |");
    if (scan.type.ack)  dprintf(1, " ACK        |");
    if (scan.type.fin)  dprintf(1, " FIN             |");
    if (scan.type.null) dprintf(1, " NULL            |");
    if (scan.type.xmas) dprintf(1, " XMAS            |");
    if (scan.type.udp)  dprintf(1, " UDP             |");
    dprintf(1, "\n");
}

static void display_line(t_scan scan, t_response response, int port) {
    static short line = 0;

    if (line++ == 0)  display_header(scan);

    struct servent *data = getservbyport(htons(port), 0);
    dprintf(1, "| %-5d |", port);
    dprintf(1, "| %-11s  |", data == NULL ? "UNASSIGNED" : data->s_name);
    if (scan.type.syn) dprintf(1, " %-8s |", convert_value(0, response.syn));
    if (scan.type.ack)  dprintf(1, " %-10s |", convert_value(1, response.ack));
    if (scan.type.fin)  dprintf(1, " %-15s |", convert_value(2, response.fin));
    if (scan.type.null) dprintf(1, " %-15s |", convert_value(3, response.null));
    if (scan.type.xmas) dprintf(1, " %-15s |", convert_value(4, response.xmas));
    if (scan.type.udp) dprintf(1, " %-15s |", convert_value(5, response.udp));
    dprintf(1, "\n");
}

void display_response(thread_data threads[MAX_SPEEDUP], int speedup, bool all, t_scan scan) {
    thread_data *data;

    for (int i = 0; i < speedup; i++) {
        data = &threads[i];

        for (int j = 0; j < data->nb_port; j++) {
            int port = data->ports[j];
            t_response response = data->response[j];
            if (response.value || all) {
               // dprintf(1, "port: %5d SYN (%-15s), ACK (%-15s), FIN (%-15s) NULL (%-15s) XMAS (%-15s) UDP (%-15s)\n", port, convert_value(0, response.syn), convert_value(1, response.ack), convert_value(2, response.fin), convert_value(3, response.null), convert_value(4, response.xmas), convert_value(5, response.udp));
                display_line(scan, response, port);
            }
        }
    }
}